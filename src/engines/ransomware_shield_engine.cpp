#include "gcad/engines/ransomware_shield_engine.hpp"
#include <algorithm>
#include <cmath>
#include <array>
#include <fstream>

namespace gcad {

static const std::vector<std::string> known_ransomware_extensions = {
    ".encrypted", ".locked", ".crypt", ".crypto", ".enc",
    ".locky", ".zepto", ".cerber", ".cerber3", ".wallet",
    ".onion", ".zzzzz", ".micro", ".xxx", ".ttt",
    ".aaa", ".abc", ".xyz", ".ecc", ".ezz",
    ".vvv", ".exx", ".wncry", ".wncryt", ".wcry",
    ".crinf", ".r5a", ".xrnt", ".xtbl", ".crypt1",
    ".da_vinci_code", ".no_more_ransom", ".cryptolocker",
    ".petya", ".gandcrab", ".hermes", ".ryuk",
};

RansomwareShieldEngine::RansomwareShieldEngine() = default;
RansomwareShieldEngine::~RansomwareShieldEngine() { stop(); }

ErrorCode RansomwareShieldEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&RansomwareShieldEngine::monitor_loop, this);
    GCAD_LOG(INFO, "RansomwareShield engine started");
    return ErrorCode::OK;
}

ErrorCode RansomwareShieldEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus RansomwareShieldEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void RansomwareShieldEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void RansomwareShieldEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

double RansomwareShieldEngine::compute_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    std::array<uint64_t, 256> freq{};
    for (size_t i = 0; i < len; ++i)
        ++freq[data[i]];

    double entropy = 0.0;
    for (auto count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / static_cast<double>(len);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

double RansomwareShieldEngine::compute_entropy(const std::vector<uint8_t>& data) {
    return compute_entropy(data.data(), data.size());
}

bool RansomwareShieldEngine::is_ransomware_extension(const std::string& ext) {
    if (ext.empty()) return false;
    std::string lower = ext;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return std::find(known_ransomware_extensions.begin(),
                     known_ransomware_extensions.end(), lower)
           != known_ransomware_extensions.end();
}

double RansomwareShieldEngine::score_indicator(const RansomwareIndicator& ind) {
    double score = 0.0;

    if (ind.shadow_copy_delete)  score += 0.35;
    if (ind.honeyfile_triggered) score += 0.30;

    if (ind.files_modified >= 50) score += 0.20;
    else if (ind.files_modified >= 20) score += 0.12;
    else if (ind.files_modified >= 5)  score += 0.05;

    if (ind.files_renamed >= 20) score += 0.15;
    else if (ind.files_renamed >= 5) score += 0.08;

    if (ind.ransomware_ext_renames >= 3) score += 0.15;
    else if (ind.ransomware_ext_renames >= 1) score += 0.10;

    if (ind.files_deleted >= 10) score += 0.10;
    else if (ind.files_deleted >= 3) score += 0.05;

    if (ind.avg_entropy >= HIGH_ENTROPY_THRESHOLD) score += 0.15;
    else if (ind.avg_entropy >= 6.5) score += 0.08;

    return std::clamp(score, 0.0, 1.0);
}

void RansomwareShieldEngine::ingest_file_io(const FileIOEvent& ev) {
    events_processed_.fetch_add(1);

    std::function<void(ThreatEvent)> threat_cb;
    std::function<void(security::SecurityObservation)> obs_cb;
    std::vector<ThreatEvent> deferred_threats;
    std::vector<security::SecurityObservation> deferred_obs;

    {
        std::lock_guard lk(mtx_);
        threat_cb = threat_cb_;
        obs_cb = observation_cb_;

        FileIOEvent stored = ev;
        stored.id = next_id_.fetch_add(1);
        io_events_.push_back(stored);
        while (io_events_.size() > MAX_IO_EVENTS) io_events_.pop_front();

        auto& ind = indicators_[ev.process_id];
        if (ind.id == 0) {
            ind.id = next_indicator_id_.fetch_add(1);
            ind.process_id = ev.process_id;
            ind.process_name = ev.process_name;
            ind.first_seen = ev.timestamp;
        }
        ind.last_seen = ev.timestamp;

        switch (ev.type) {
            case FileIOType::IO_WRITE:
            case FileIOType::IO_CREATE:
                ++ind.files_modified;
                if (ind.avg_entropy < 0.0)
                    ind.avg_entropy = ev.entropy;
                else
                    ind.avg_entropy = ind.avg_entropy * 0.9 + ev.entropy * 0.1;
                break;
            case FileIOType::IO_RENAME:
                ++ind.files_renamed;
                if (is_ransomware_extension(
                        std::filesystem::path(ev.new_path).extension().string())) {
                    ++ind.ransomware_ext_renames;
                }
                break;
            case FileIOType::IO_DELETE:
                ++ind.files_deleted;
                break;
        }

        ind.risk_score = score_indicator(ind);

        if (ind.risk_score >= RISK_THRESHOLD_MALICIOUS) {
            threats_detected_.fetch_add(1);
            if (threat_cb) {
                ThreatEvent te{};
                te.level = ThreatLevel::CRITICAL;
                te.category = ThreatCategory::RANSOMWARE;
                te.process_id = ev.process_id;
                te.process_name = ev.process_name;
                te.file_path = ev.file_path;
                te.description = "Ransomware behavior detected: " + ev.process_name +
                                 " (PID " + std::to_string(ev.process_id) +
                                 ") — " + std::to_string(ind.files_modified) +
                                 " files modified, " + std::to_string(ind.files_renamed) +
                                 " renamed, risk=" +
                                 std::to_string(static_cast<int>(ind.risk_score * 100)) + "%";
                te.timestamp = std::chrono::system_clock::now();
                deferred_threats.push_back(std::move(te));
            }
        } else if (ind.risk_score >= RISK_THRESHOLD_SUSPICIOUS && obs_cb) {
            security::SecurityObservation obs;
            obs.kind = security::ObservationKind::FILE_INTEGRITY;
            obs.suggested_level = ThreatLevel::MEDIUM;
            obs.confidence = ind.risk_score;
            obs.source_id = "RansomwareShield";
            obs.process_id = ev.process_id;
            obs.process_name = ev.process_name;
            obs.file_path = ev.file_path;
            obs.evidence = "Suspicious file activity: " + ev.process_name +
                           " — " + std::to_string(ind.files_modified) + " modifications";
            obs.timestamp = std::chrono::system_clock::now();
            deferred_obs.push_back(std::move(obs));
        }
    }

    for (auto& te : deferred_threats)
        threat_cb(std::move(te));
    for (auto& obs : deferred_obs)
        obs_cb(std::move(obs));
}

void RansomwareShieldEngine::report_shadow_copy_delete(uint32_t pid,
                                                        const std::string& process_name) {
    events_processed_.fetch_add(1);
    threats_detected_.fetch_add(1);

    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;

        auto& ind = indicators_[pid];
        if (ind.id == 0) {
            ind.id = next_indicator_id_.fetch_add(1);
            ind.process_id = pid;
            ind.process_name = process_name;
            ind.first_seen = std::chrono::system_clock::now();
        }
        ind.shadow_copy_delete = true;
        ind.last_seen = std::chrono::system_clock::now();
        ind.risk_score = score_indicator(ind);
    }

    if (cb) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::CRITICAL;
        ev.category = ThreatCategory::RANSOMWARE;
        ev.process_id = pid;
        ev.process_name = process_name;
        ev.description = "Shadow copy deletion detected by " + process_name +
                         " (PID " + std::to_string(pid) + ")";
        ev.timestamp = std::chrono::system_clock::now();
        cb(std::move(ev));
    }
}

void RansomwareShieldEngine::add_honeyfile(const std::filesystem::path& path) {
    std::lock_guard lk(mtx_);
    HoneyFile hf;
    hf.path = path;

    std::ifstream f(path, std::ios::binary);
    if (f) {
        std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                                  std::istreambuf_iterator<char>());
        SHA256 hasher;
        hasher.update(buf.data(), buf.size());
        hf.sha256 = SHA256::hex(hasher.finalize());
    }

    honeyfiles_.push_back(std::move(hf));
}

void RansomwareShieldEngine::check_honeyfiles() {
    events_processed_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    std::vector<ThreatEvent> deferred;

    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;

        for (auto& hf : honeyfiles_) {
            if (hf.triggered) continue;

            if (!std::filesystem::exists(hf.path)) {
                hf.triggered = true;
                threats_detected_.fetch_add(1);
                if (cb) {
                    ThreatEvent ev{};
                    ev.level = ThreatLevel::CRITICAL;
                    ev.category = ThreatCategory::RANSOMWARE;
                    ev.file_path = hf.path.string();
                    ev.description = "Honeyfile deleted: " + hf.path.string();
                    ev.timestamp = std::chrono::system_clock::now();
                    deferred.push_back(std::move(ev));
                }
                continue;
            }

            if (hf.sha256.empty()) continue;

            std::ifstream f(hf.path, std::ios::binary);
            if (!f) continue;
            std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());
            SHA256 hasher;
            hasher.update(buf.data(), buf.size());
            auto current = SHA256::hex(hasher.finalize());

            if (current != hf.sha256) {
                hf.triggered = true;
                threats_detected_.fetch_add(1);
                if (cb) {
                    ThreatEvent ev{};
                    ev.level = ThreatLevel::CRITICAL;
                    ev.category = ThreatCategory::RANSOMWARE;
                    ev.file_path = hf.path.string();
                    ev.description = "Honeyfile tampered: " + hf.path.string();
                    ev.timestamp = std::chrono::system_clock::now();
                    deferred.push_back(std::move(ev));
                }
            }
        }
    }

    for (auto& ev : deferred)
        cb(std::move(ev));
}

std::vector<RansomwareIndicator> RansomwareShieldEngine::active_indicators(size_t n) const {
    std::lock_guard lk(mtx_);
    std::vector<RansomwareIndicator> result;
    result.reserve(indicators_.size());
    for (const auto& [pid, ind] : indicators_)
        result.push_back(ind);
    std::sort(result.begin(), result.end(),
              [](const RansomwareIndicator& a, const RansomwareIndicator& b) {
                  return a.risk_score > b.risk_score;
              });
    if (result.size() > n) result.resize(n);
    return result;
}

std::vector<HoneyFile> RansomwareShieldEngine::honeyfiles() const {
    std::lock_guard lk(mtx_);
    return honeyfiles_;
}

void RansomwareShieldEngine::analyze_burst_patterns() {
    std::function<void(ThreatEvent)> cb;
    std::vector<ThreatEvent> deferred;

    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
        if (!cb || io_events_.empty()) return;

        auto now = std::chrono::system_clock::now();
        auto window_start = now - std::chrono::seconds(BURST_WINDOW_SECONDS);

        std::unordered_map<uint32_t, size_t> burst_counts;
        for (auto it = io_events_.rbegin(); it != io_events_.rend(); ++it) {
            if (it->timestamp < window_start) break;
            ++burst_counts[it->process_id];
        }

        for (const auto& [pid, count] : burst_counts) {
            if (count < BURST_THRESHOLD) continue;

            auto it_ind = indicators_.find(pid);
            if (it_ind == indicators_.end()) continue;
            auto& ind = it_ind->second;

            if (ind.risk_score < RISK_THRESHOLD_SUSPICIOUS) continue;

            ThreatEvent ev{};
            ev.level = ThreatLevel::HIGH;
            ev.category = ThreatCategory::FILE_ENCRYPT;
            ev.process_id = pid;
            ev.process_name = ind.process_name;
            ev.description = "File I/O burst: " + ind.process_name +
                             " — " + std::to_string(count) + " operations in " +
                             std::to_string(BURST_WINDOW_SECONDS) + "s window";
            ev.timestamp = now;
            deferred.push_back(std::move(ev));
            threats_detected_.fetch_add(1);
        }
    }

    for (auto& ev : deferred)
        cb(std::move(ev));
}

void RansomwareShieldEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 5000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        check_honeyfiles();
        analyze_burst_patterns();
    }
}

} // namespace gcad
