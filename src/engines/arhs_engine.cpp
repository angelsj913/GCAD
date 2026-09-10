#include "gcad/engines/arhs_engine.hpp"

namespace gcad {

ARHSEngine::ARHSEngine() = default;
ARHSEngine::~ARHSEngine() { stop(); }

ErrorCode ARHSEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);

    if (watch_dirs_.empty()) {
#ifdef GCAD_PLATFORM_WINDOWS
        auto* profile = std::getenv("USERPROFILE");
        if (profile)
            watch_dirs_.push_back(std::string(profile) + "\\Desktop");
#else
        watch_dirs_.push_back("/home");
#endif
    }

    for (auto& dir : watch_dirs_) {
        std::error_code ec;
        if (std::filesystem::exists(dir, ec))
            scan_directory(dir);
    }

    watch_thread_ = std::thread(&ARHSEngine::watch_loop, this);
    GCAD_LOG(INFO, "ARHS engine started, watching " + std::to_string(watch_dirs_.size()) + " directories");
    return ErrorCode::OK;
}

ErrorCode ARHSEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (watch_thread_.joinable()) watch_thread_.join();
    {
        std::lock_guard lk(mtx_);
        for (auto& snap : snapshot_ring_) {
            secure_zero(snap.original_data.data(), snap.original_data.size());
            snap.original_data.clear();
        }
        snapshot_ring_.clear();
    }
    return ErrorCode::OK;
}

EngineStatus ARHSEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    {
        std::lock_guard lk(const_cast<std::mutex&>(mtx_));
        s.memory_bytes = 0;
        for (auto& snap : snapshot_ring_)
            s.memory_bytes += snap.original_data.size();
    }
    return s;
}

void ARHSEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void ARHSEngine::add_watch_directory(const std::filesystem::path& dir) {
    std::lock_guard lk(mtx_);
    watch_dirs_.push_back(dir);
}

void ARHSEngine::scan_directory(const std::filesystem::path& dir) {
    std::error_code ec;
    for (auto& entry : std::filesystem::recursive_directory_iterator(dir,
            std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        auto sz = entry.file_size(ec);
        if (ec || sz == 0 || sz > MAX_SNAPSHOT_FILE_SIZE) continue;

        std::string hash = SHA256::hash_file(entry.path());
        if (!hash.empty()) {
            std::lock_guard lk(mtx_);
            file_hashes_[entry.path().string()] = hash;
        }
        events_processed_.fetch_add(1);
    }
}

void ARHSEngine::take_snapshot_unlocked(const std::filesystem::path& path) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    if (ec || sz == 0 || sz > MAX_SNAPSHOT_FILE_SIZE) return;

    std::ifstream f(path, std::ios::binary);
    if (!f) return;

    CowSnapshot snap;
    snap.path = path;
    snap.original_size = sz;
    snap.original_data.resize(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(snap.original_data.data()), sz);
    snap.sha256_hash = SHA256::hash_bytes(snap.original_data.data(), snap.original_data.size());
    snap.capture_time = std::chrono::system_clock::now();

    if (snapshot_ring_.size() >= MAX_SNAPSHOTS) {
        secure_zero(snapshot_ring_.front().original_data.data(),
                    snapshot_ring_.front().original_data.size());
        snapshot_ring_.erase(snapshot_ring_.begin());
    }
    snapshot_ring_.push_back(std::move(snap));
}

void ARHSEngine::take_snapshot(const std::filesystem::path& path) {
    std::lock_guard lk(mtx_);
    take_snapshot_unlocked(path);
}

std::vector<SandboxedProcess> ARHSEngine::sandboxed_processes() const {
    std::lock_guard lk(mtx_);
    return sandboxed_;
}

void ARHSEngine::watch_loop() {
    while (running_.load()) {
        for (auto& dir : watch_dirs_) {
            std::error_code ec;
            for (auto& entry : std::filesystem::recursive_directory_iterator(dir,
                    std::filesystem::directory_options::skip_permission_denied, ec)) {
                if (!running_.load()) return;
                if (!entry.is_regular_file(ec)) continue;
                auto sz = entry.file_size(ec);
                if (ec || sz == 0 || sz > MAX_SNAPSHOT_FILE_SIZE) continue;

                std::string current_hash = SHA256::hash_file(entry.path());
                if (current_hash.empty()) continue;

                std::string key = entry.path().string();
                std::lock_guard lk(mtx_);
                auto it = file_hashes_.find(key);
                if (it != file_hashes_.end() && it->second != current_hash) {
                    take_snapshot_unlocked(entry.path());
                    recent_changes_.push_back({entry.path(), std::chrono::steady_clock::now()});
                    it->second = current_hash;
                    events_processed_.fetch_add(1);

                    double ent = 0.0;
                    {
                        std::ifstream f(entry.path(), std::ios::binary);
                        std::vector<uint8_t> data(static_cast<size_t>(sz));
                        f.read(reinterpret_cast<char*>(data.data()), sz);
                        ent = shannon_entropy(data.data(), data.size());
                    }

                    if (ent > RANSOMWARE_ENTROPY_THRESH) {
                        emit_threat(ThreatCategory::RANSOMWARE,
                            "High-entropy file modification detected: " + key +
                            " (entropy=" + std::format("{:.2f}", ent) + ")",
                            0, key);
                    }
                } else if (it == file_hashes_.end()) {
                    file_hashes_[key] = current_hash;
                }
            }
        }

        if (detect_rapid_encryption()) {
            emit_threat(ThreatCategory::FILE_ENCRYPT,
                "Rapid bulk file encryption detected (" +
                std::to_string(RAPID_CHANGE_THRESH) + "+ files in " +
                std::to_string(RAPID_CHANGE_WINDOW.count()) + "s)");
        }

        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

bool ARHSEngine::detect_rapid_encryption() {
    std::lock_guard lk(mtx_);
    auto now = std::chrono::steady_clock::now();
    recent_changes_.erase(
        std::remove_if(recent_changes_.begin(), recent_changes_.end(),
            [&](const ChangeRecord& r) { return (now - r.when) > RAPID_CHANGE_WINDOW; }),
        recent_changes_.end());
    return recent_changes_.size() >= RAPID_CHANGE_THRESH;
}

ErrorCode ARHSEngine::rollback_file(const std::filesystem::path& path) {
    std::lock_guard lk(mtx_);
    for (auto it = snapshot_ring_.rbegin(); it != snapshot_ring_.rend(); ++it) {
        if (it->path == path && !it->original_data.empty()) {
            std::ofstream f(path, std::ios::binary | std::ios::trunc);
            if (!f) return ErrorCode::ERR_ROLLBACK_FAIL;
            f.write(reinterpret_cast<const char*>(it->original_data.data()), it->original_data.size());
            f.flush();
            file_hashes_[path.string()] = it->sha256_hash;
            rollbacks_performed_.fetch_add(1);
            GCAD_LOG(INFO, "ARHS: rolled back " + path.string());
            return ErrorCode::OK;
        }
    }
    return ErrorCode::ERR_ROLLBACK_FAIL;
}

ErrorCode ARHSEngine::rollback_process(uint32_t pid) {
    std::lock_guard lk(mtx_);
    for (auto& sp : sandboxed_) {
        if (sp.pid == pid) {
            for (auto& snap : sp.snapshots) {
                std::ofstream f(snap.path, std::ios::binary | std::ios::trunc);
                if (f) {
                    f.write(reinterpret_cast<const char*>(snap.original_data.data()), snap.original_data.size());
                    rollbacks_performed_.fetch_add(1);
                }
            }
            return ErrorCode::OK;
        }
    }
    return ErrorCode::ERR_ROLLBACK_FAIL;
}

ErrorCode ARHSEngine::suspend_process(uint32_t pid, ThreatCategory reason) {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return ErrorCode::ERR_PLATFORM;
    using NtSuspendProcess_t = LONG(NTAPI*)(HANDLE);
    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        auto pNtSuspend = reinterpret_cast<NtSuspendProcess_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtSuspendProcess")));
        if (pNtSuspend) pNtSuspend(hProc);
    }
    CloseHandle(hProc);
#else
    if (kill(pid, SIGSTOP) != 0) return ErrorCode::ERR_PLATFORM;
#endif
    std::lock_guard lk(mtx_);
    SandboxedProcess sp;
    sp.pid = pid;
    sp.reason = reason;
    sp.suspended_at = std::chrono::system_clock::now();
    sandboxed_.push_back(std::move(sp));
    emit_threat(reason, "Process " + std::to_string(pid) + " suspended and sandboxed", pid);
    return ErrorCode::OK;
}

void ARHSEngine::emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid, const std::string& path) {
    threats_detected_.fetch_add(1);
    if (threat_cb_) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::CRITICAL;
        ev.category = cat;
        ev.process_id = pid;
        ev.file_path = path;
        ev.description = desc;
        threat_cb_(std::move(ev));
    }
}

} // namespace gcad
