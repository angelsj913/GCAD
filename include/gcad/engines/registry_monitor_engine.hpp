#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <unordered_map>

namespace gcad {

struct RegistryValueSnapshot {
    std::string key_path;
    std::string value_name;
    uint32_t    type{0};
    std::string data_hex;
};

class RegistryMonitorEngine final : public ISecurityEngine {
public:
    RegistryMonitorEngine();
    ~RegistryMonitorEngine() override;

    std::string_view name() const noexcept override { return "RegMon"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void on_observation(std::function<void(security::SecurityObservation)> cb);

    struct AutorunKey {
        std::string hive_name;
        std::string subkey;
#ifdef GCAD_PLATFORM_WINDOWS
        HKEY        hive_root;
#endif
    };
    static std::vector<AutorunKey> default_autorun_keys();
    static std::vector<RegistryValueSnapshot> enumerate_autorun_values();

private:
    std::atomic<bool>                        running_{false};
    std::atomic<uint64_t>                    events_processed_{0};
    std::atomic<uint64_t>                    threats_detected_{0};
    std::thread                              monitor_thread_;
    std::mutex                               mtx_;
    std::function<void(ThreatEvent)>         threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    std::unordered_map<std::string, RegistryValueSnapshot> baseline_;

    void monitor_loop();
    void emit_threat(ThreatCategory cat, const std::string& desc);
    void emit_observation(security::ObservationKind kind, ThreatLevel level,
                          double confidence, const std::string& evidence);
};

} // namespace gcad
