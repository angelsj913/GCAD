#include "gcad/engines/file_integrity_engine.hpp"

namespace gcad {

FileIntegrityEngine::FileIntegrityEngine() = default;
FileIntegrityEngine::~FileIntegrityEngine() { stop(); }

std::vector<std::filesystem::path> FileIntegrityEngine::default_watch_paths() {
    std::vector<std::filesystem::path> paths;
#ifdef GCAD_PLATFORM_WINDOWS
    paths.push_back("C:\\Windows\\System32\\drivers\\etc\\hosts");
    paths.push_back("C:\\Windows\\System32\\config\\SAM");
    paths.push_back("C:\\Windows\\System32\\config\\SYSTEM");
    paths.push_back("C:\\Windows\\System32\\config\\SOFTWARE");
#else
    paths.push_back("/etc/hosts");
    paths.push_back("/etc/passwd");
    paths.push_back("/etc/shadow");
    paths.push_back("/etc/sudoers");
    paths.push_back("/etc/ssh/sshd_config");
#endif
    return paths;
}

void FileIntegrityEngine::add_watch_path(const std::filesystem::path& path) {
    std::lock_guard lk(mtx_);
    watch_paths_.push_back(path);
}

size_t FileIntegrityEngine::baseline_size() const {
    std::lock_guard lk(mtx_);
    return baseline_.size();
}

ErrorCode FileIntegrityEngine::start() {
    if (running_.load()) return ErrorCode::OK;

    if (watch_paths_.empty()) watch_paths_ = default_watch_paths();
    build_baseline();
    running_.store(true);
    monitor_thread_ = std::thread(&FileIntegrityEngine::monitor_loop, this);
    GCAD_LOG(INFO, "FIM engine started, baseline: " + std::to_string(baseline_.size()) + " files");
    return ErrorCode::OK;
}

ErrorCode FileIntegrityEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus FileIntegrityEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void FileIntegrityEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void FileIntegrityEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

void FileIntegrityEngine::build_baseline() {
    std::lock_guard lk(mtx_);
    baseline_.clear();
    for (auto& path : watch_paths_) {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(path, ec) || ec) continue;
        std::string hash = SHA256::hash_file(path);
        if (hash.empty()) continue;

        FileIntegrityEntry entry;
        entry.path = path;
        entry.sha256 = hash;
        entry.size = std::filesystem::file_size(path, ec);
        entry.mtime = std::filesystem::last_write_time(path, ec);
        baseline_[path.string()] = std::move(entry);
    }
}

void FileIntegrityEngine::check_integrity() {
    struct Alert { std::string evidence; std::string path; std::string sha256; };
    std::vector<Alert> alerts;

    {
        std::lock_guard lk(mtx_);
        for (auto& [path_str, entry] : baseline_) {
            std::error_code ec;
            if (!std::filesystem::exists(entry.path, ec) || ec) {
                alerts.push_back({"Critical file deleted: " + path_str, path_str, entry.sha256});
                continue;
            }
            auto current_mtime = std::filesystem::last_write_time(entry.path, ec);
            if (ec) continue;

            if (current_mtime != entry.mtime) {
                std::string current_hash = SHA256::hash_file(entry.path);
                if (!current_hash.empty() && current_hash != entry.sha256) {
                    alerts.push_back({"Critical file modified: " + path_str +
                                      " (was " + entry.sha256.substr(0, 16) + "...)", path_str, current_hash});
                    entry.sha256 = current_hash;
                    entry.size = std::filesystem::file_size(entry.path, ec);
                }
                entry.mtime = current_mtime;
            }
        }
    }

    for (auto& a : alerts) {
        emit_threat(ThreatCategory::FILE_INTEGRITY_VIOLATION, a.evidence, a.path);
        emit_observation(a.evidence, a.path, a.sha256);
    }
}

void FileIntegrityEngine::monitor_loop() {
    while (running_.load()) {
        for (int i = 0; i < 100 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;

        check_integrity();
        events_processed_.fetch_add(1);
    }
}

void FileIntegrityEngine::emit_threat(ThreatCategory cat, const std::string& desc, const std::string& file_path) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::CRITICAL;
        ev.category = cat;
        ev.description = desc;
        ev.file_path = file_path;
        cb(std::move(ev));
    }
}

void FileIntegrityEngine::emit_observation(const std::string& evidence, const std::string& file_path, const std::string& sha256) {
    std::function<void(security::SecurityObservation)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = observation_cb_;
    }
    if (cb) {
        security::SecurityObservation obs{};
        obs.source_id = "fim";
        obs.kind = security::ObservationKind::FILE_INTEGRITY;
        obs.timestamp = std::chrono::system_clock::now();
        obs.suggested_level = ThreatLevel::CRITICAL;
        obs.confidence = 0.95;
        obs.deterministic = true;
        obs.file_path = file_path;
        obs.sha256 = sha256;
        obs.evidence = evidence;
        cb(std::move(obs));
    }
}

} // namespace gcad
