#include "gcad/engines/registry_monitor_engine.hpp"

namespace gcad {

RegistryMonitorEngine::RegistryMonitorEngine() = default;
RegistryMonitorEngine::~RegistryMonitorEngine() { stop(); }

std::vector<RegistryMonitorEngine::AutorunKey> RegistryMonitorEngine::default_autorun_keys() {
    std::vector<AutorunKey> keys;
#ifdef GCAD_PLATFORM_WINDOWS
    keys.push_back({"HKLM", R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Run)", HKEY_LOCAL_MACHINE});
    keys.push_back({"HKLM", R"(SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce)", HKEY_LOCAL_MACHINE});
    keys.push_back({"HKCU", R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Run)", HKEY_CURRENT_USER});
    keys.push_back({"HKCU", R"(SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce)", HKEY_CURRENT_USER});
    keys.push_back({"HKLM", R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run)", HKEY_LOCAL_MACHINE});
    keys.push_back({"HKLM", R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon)", HKEY_LOCAL_MACHINE});
    keys.push_back({"HKLM", R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options)", HKEY_LOCAL_MACHINE});
    keys.push_back({"HKLM", R"(SYSTEM\CurrentControlSet\Services)", HKEY_LOCAL_MACHINE});
    keys.push_back({"HKCU", R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders)", HKEY_CURRENT_USER});
    keys.push_back({"HKLM", R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders)", HKEY_LOCAL_MACHINE});
#endif
    return keys;
}

ErrorCode RegistryMonitorEngine::start() {
    if (running_.load()) return ErrorCode::OK;

    auto initial = enumerate_autorun_values();
    {
        std::lock_guard lk(mtx_);
        baseline_.clear();
        for (auto& v : initial)
            baseline_[v.key_path + "\\" + v.value_name] = std::move(v);
    }

    running_.store(true);
    monitor_thread_ = std::thread(&RegistryMonitorEngine::monitor_loop, this);
    GCAD_LOG(INFO, "RegMon engine started, baseline: " + std::to_string(baseline_.size()) + " values");
    return ErrorCode::OK;
}

ErrorCode RegistryMonitorEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus RegistryMonitorEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void RegistryMonitorEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void RegistryMonitorEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

std::vector<RegistryValueSnapshot> RegistryMonitorEngine::enumerate_autorun_values() {
    std::vector<RegistryValueSnapshot> result;
#ifdef GCAD_PLATFORM_WINDOWS
    for (const auto& ak : default_autorun_keys()) {
        HKEY hk = nullptr;
        if (RegOpenKeyExA(ak.hive_root, ak.subkey.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            continue;

        for (DWORD idx = 0; ; ++idx) {
            char name_buf[512]{};
            DWORD name_len = sizeof(name_buf);
            uint8_t data_buf[4096]{};
            DWORD data_len = sizeof(data_buf);
            DWORD type = 0;

            LONG rc = RegEnumValueA(hk, idx, name_buf, &name_len, nullptr, &type, data_buf, &data_len);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;

            RegistryValueSnapshot snap;
            snap.key_path = ak.hive_name + "\\" + ak.subkey;
            snap.value_name = std::string(name_buf, name_len);
            snap.type = type;

            std::string hex;
            hex.reserve(data_len * 2);
            for (DWORD i = 0; i < data_len; ++i) {
                static const char digits[] = "0123456789abcdef";
                hex += digits[(data_buf[i] >> 4) & 0xF];
                hex += digits[data_buf[i] & 0xF];
            }
            snap.data_hex = std::move(hex);
            result.push_back(std::move(snap));
        }
        RegCloseKey(hk);
    }
#endif
    return result;
}

void RegistryMonitorEngine::monitor_loop() {
    while (running_.load()) {
        for (int i = 0; i < 50 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;

        auto current = enumerate_autorun_values();
        events_processed_.fetch_add(1);

        std::unordered_map<std::string, RegistryValueSnapshot> current_map;
        for (auto& v : current) {
            std::string key = v.key_path + "\\" + v.value_name;
            current_map[key] = std::move(v);
        }

        std::vector<std::string> alerts;
        {
            std::lock_guard lk(mtx_);
            for (auto& [key, snap] : current_map) {
                auto it = baseline_.find(key);
                if (it == baseline_.end()) {
                    alerts.push_back("New autorun entry: " + key);
                } else if (it->second.data_hex != snap.data_hex) {
                    alerts.push_back("Modified autorun entry: " + key);
                }
            }
            for (auto& [key, snap] : baseline_) {
                if (current_map.find(key) == current_map.end()) {
                    alerts.push_back("Deleted autorun entry: " + key);
                }
            }
            baseline_ = std::move(current_map);
        }

        for (auto& alert : alerts) {
            emit_threat(ThreatCategory::REGISTRY_TAMPER, alert);
            emit_observation(security::ObservationKind::REGISTRY_PERSISTENCE,
                             ThreatLevel::HIGH, 0.85, alert);
        }
    }
}

void RegistryMonitorEngine::emit_threat(ThreatCategory cat, const std::string& desc) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::HIGH;
        ev.category = cat;
        ev.description = desc;
        cb(std::move(ev));
    }
}

void RegistryMonitorEngine::emit_observation(security::ObservationKind kind, ThreatLevel level,
                                             double confidence, const std::string& evidence) {
    std::function<void(security::SecurityObservation)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = observation_cb_;
    }
    if (cb) {
        security::SecurityObservation obs{};
        obs.source_id = "registry-monitor";
        obs.kind = kind;
        obs.timestamp = std::chrono::system_clock::now();
        obs.suggested_level = level;
        obs.confidence = confidence;
        obs.deterministic = true;
        obs.evidence = evidence;
        cb(std::move(obs));
    }
}

} // namespace gcad
