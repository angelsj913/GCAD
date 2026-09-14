#pragma once
#include "../i_security_engine.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>

namespace gcad {

struct WmiSubscription {
    std::string filter_name;
    std::string query;
    std::string consumer_name;
    std::string consumer_type; // e.g. "CommandLineEventConsumer", "ActiveScriptEventConsumer"
    std::string command_or_script;
    bool        is_suspicious{false};
    std::string reason;
};

struct BitsJobInfo {
    std::string job_id;
    std::string display_name;
    std::string remote_url;
    std::string local_file_path;
    uint32_t    state{0};
    bool        is_suspicious{false};
    std::string reason;
};

class WmiBitsEngine final : public ISecurityEngine {
    std::atomic<bool>                running_{false};
    std::thread                      monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    mutable std::mutex               mtx_;

    std::atomic<uint64_t>            events_processed_{0};
    std::atomic<uint64_t>            threats_detected_{0};

    std::unordered_set<std::string>  known_subscriptions_;
    std::unordered_set<std::string>  known_bits_jobs_;

    void monitor_loop();
    void emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid = 0);

public:
    WmiBitsEngine();
    ~WmiBitsEngine() override;

    std::string_view name() const noexcept override { return "WMI-BITS-Defense"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    std::vector<WmiSubscription> scan_wmi_subscriptions();
    std::vector<BitsJobInfo>      scan_bits_jobs();

    static bool evaluate_wmi_subscription(WmiSubscription& sub);
    static bool evaluate_bits_job(BitsJobInfo& job);
};

} // namespace gcad
