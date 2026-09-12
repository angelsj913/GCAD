#include "gcad/engines/update_engine.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace gcad {

UpdateEngine::UpdateEngine() = default;
UpdateEngine::~UpdateEngine() { stop(); }

ErrorCode UpdateEngine::start() {
    if (running_.load()) return ErrorCode::OK;

    if (data_dir_.empty()) {
#ifdef GCAD_PLATFORM_WINDOWS
        char pd[260]{};
        DWORD len = GetEnvironmentVariableA("PROGRAMDATA", pd, sizeof(pd));
        if (len > 0 && len < sizeof(pd))
            data_dir_ = std::filesystem::path(pd) / "GCAD" / "data";
        else
#endif
            data_dir_ = std::filesystem::path("gcad_data");
    }

    std::error_code ec;
    std::filesystem::create_directories(data_dir_, ec);

    auto manifest_path = data_dir_ / "manifest.txt";
    if (std::filesystem::exists(manifest_path))
        read_manifest(manifest_path);

    running_.store(true);
    monitor_thread_ = std::thread(&UpdateEngine::monitor_loop, this);
    GCAD_LOG(INFO, "AutoUpdate engine started, data_dir=" + data_dir_.string());
    return ErrorCode::OK;
}

ErrorCode UpdateEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus UpdateEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void UpdateEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void UpdateEngine::set_data_dir(const std::filesystem::path& dir) {
    std::lock_guard lk(mtx_);
    data_dir_ = dir;
}

std::string UpdateEngine::compute_file_sha256(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";

    SHA256 hasher;
    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0)
        hasher.update(reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(f.gcount()));

    return SHA256::hex(hasher.finalize());
}

bool UpdateEngine::verify_checksum(const std::filesystem::path& path, const std::string& expected) {
    if (expected.empty()) return true;
    auto actual = compute_file_sha256(path);
    std::string exp_lower = expected;
    std::transform(exp_lower.begin(), exp_lower.end(), exp_lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return actual == exp_lower;
}

std::string UpdateEngine::parse_version_from_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return "0.0.0";

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] != '#') break;
        auto pos = line.find("version:");
        if (pos == std::string::npos) pos = line.find("Version:");
        if (pos != std::string::npos) {
            auto val = line.substr(pos + 8);
            while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                val.erase(val.begin());
            while (!val.empty() && (val.back() == ' ' || val.back() == '\r' || val.back() == '\n'))
                val.pop_back();
            if (!val.empty()) return val;
        }
    }
    return "1.0.0";
}

UpdateResult UpdateEngine::validate_and_update(const std::string& db_name,
                                                const std::filesystem::path& path,
                                                const std::string& expected_sha256) {
    if (!std::filesystem::exists(path))
        return UpdateResult::FILE_NOT_FOUND;

    if (!verify_checksum(path, expected_sha256))
        return UpdateResult::CHECKSUM_MISMATCH;

    auto new_version = parse_version_from_file(path);
    auto sha = compute_file_sha256(path);

    std::lock_guard lk(mtx_);
    std::string old_version = "0.0.0";
    bool found = false;
    for (auto& m : manifests_) {
        if (m.db_name == db_name) {
            if (m.sha256 == sha)
                return UpdateResult::ALREADY_CURRENT;
            old_version = m.version;
            m.version = new_version;
            m.sha256 = sha;
            m.file_path = path;
            m.updated_at = std::chrono::system_clock::now();
            found = true;
            break;
        }
    }
    if (!found) {
        UpdateManifest m;
        m.db_name = db_name;
        m.version = new_version;
        m.sha256 = sha;
        m.file_path = path;
        m.updated_at = std::chrono::system_clock::now();
        manifests_.push_back(std::move(m));
    }
    return UpdateResult::SUCCESS;
}

UpdateResult UpdateEngine::load_signature_db(const std::filesystem::path& path,
                                              const std::string& expected_sha256) {
    auto result = validate_and_update("signatures", path, expected_sha256);
    events_processed_.fetch_add(1);
    std::string old_ver, new_ver;
    {
        std::lock_guard lk(mtx_);
        for (auto& m : manifests_) {
            if (m.db_name == "signatures") { new_ver = m.version; break; }
        }
    }
    record_update("signatures", old_ver, new_ver, result);
    return result;
}

UpdateResult UpdateEngine::load_ioc_db(const std::filesystem::path& path,
                                        const std::string& expected_sha256) {
    auto result = validate_and_update("ioc", path, expected_sha256);
    events_processed_.fetch_add(1);
    std::string new_ver;
    {
        std::lock_guard lk(mtx_);
        for (auto& m : manifests_) {
            if (m.db_name == "ioc") { new_ver = m.version; break; }
        }
    }
    record_update("ioc", "", new_ver, result);
    return result;
}

UpdateResult UpdateEngine::load_yara_rules(const std::filesystem::path& path,
                                            const std::string& expected_sha256) {
    auto result = validate_and_update("yara", path, expected_sha256);
    events_processed_.fetch_add(1);
    std::string new_ver;
    {
        std::lock_guard lk(mtx_);
        for (auto& m : manifests_) {
            if (m.db_name == "yara") { new_ver = m.version; break; }
        }
    }
    record_update("yara", "", new_ver, result);
    return result;
}

bool UpdateEngine::write_manifest(const std::filesystem::path& path) const {
    std::lock_guard lk(mtx_);
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;

    f << "# GCAD Update Manifest\n";
    for (auto& m : manifests_) {
        f << m.db_name << "|" << m.version << "|" << m.sha256 << "|"
          << m.file_path.string() << "\n";
    }
    return true;
}

bool UpdateEngine::read_manifest(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return false;

    std::lock_guard lk(mtx_);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        std::string db_name, version, sha, fpath;
        if (!std::getline(ss, db_name, '|')) continue;
        if (!std::getline(ss, version, '|')) continue;
        std::getline(ss, sha, '|');
        std::getline(ss, fpath, '|');

        bool found = false;
        for (auto& m : manifests_) {
            if (m.db_name == db_name) {
                m.version = version;
                m.sha256 = sha;
                m.file_path = fpath;
                found = true;
                break;
            }
        }
        if (!found) {
            UpdateManifest m;
            m.db_name = db_name;
            m.version = version;
            m.sha256 = sha;
            m.file_path = fpath;
            manifests_.push_back(std::move(m));
        }
    }
    return true;
}

std::vector<UpdateManifest> UpdateEngine::current_versions() const {
    std::lock_guard lk(mtx_);
    return manifests_;
}

std::vector<UpdateRecord> UpdateEngine::recent_updates(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, update_log_.size());
    return {update_log_.end() - static_cast<ptrdiff_t>(count), update_log_.end()};
}

size_t UpdateEngine::check_for_updates() {
    std::lock_guard lk(mtx_);
    size_t changed = 0;
    for (auto& m : manifests_) {
        if (m.file_path.empty() || !std::filesystem::exists(m.file_path))
            continue;
        auto current_sha = compute_file_sha256(m.file_path);
        if (current_sha != m.sha256) {
            ++changed;
            auto new_ver = parse_version_from_file(m.file_path);
            auto old_ver = m.version;
            m.version = new_ver;
            m.sha256 = current_sha;
            m.updated_at = std::chrono::system_clock::now();

            UpdateRecord rec;
            rec.id = next_id_.fetch_add(1);
            rec.db_name = m.db_name;
            rec.old_version = old_ver;
            rec.new_version = new_ver;
            rec.result = UpdateResult::SUCCESS;
            rec.timestamp = std::chrono::system_clock::now();
            update_log_.push_back(std::move(rec));
            while (update_log_.size() > MAX_UPDATE_LOG) update_log_.pop_front();

            GCAD_LOG(INFO, "Auto-update detected: " + m.db_name + " " + old_ver + " -> " + new_ver);
        }
    }
    events_processed_.fetch_add(1);
    return changed;
}

void UpdateEngine::record_update(const std::string& db_name, const std::string& old_ver,
                                  const std::string& new_ver, UpdateResult result) {
    UpdateRecord rec;
    rec.id = next_id_.fetch_add(1);
    rec.db_name = db_name;
    rec.old_version = old_ver;
    rec.new_version = new_ver;
    rec.result = result;
    rec.timestamp = std::chrono::system_clock::now();

    std::lock_guard lk(mtx_);
    update_log_.push_back(std::move(rec));
    while (update_log_.size() > MAX_UPDATE_LOG) update_log_.pop_front();

    if (result == UpdateResult::CHECKSUM_MISMATCH) {
        threats_detected_.fetch_add(1);
        std::function<void(ThreatEvent)> cb = threat_cb_;
        if (cb) {
            ThreatEvent ev{};
            ev.level = ThreatLevel::HIGH;
            ev.category = ThreatCategory::ANTI_FORENSIC;
            ev.description = "Update integrity check failed for " + db_name +
                             " — possible tampering";
            ev.timestamp = std::chrono::system_clock::now();
            cb(std::move(ev));
        }
    }
}

void UpdateEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 60000 && running_.load(); slept += 200)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!running_.load()) break;
        check_for_updates();
    }
}

} // namespace gcad
