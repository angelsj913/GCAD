#pragma once
#include "../i_security_engine.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>

namespace gcad {

enum class WebhookFormat : uint8_t {
    JSON_GENERIC = 0,
    DISCORD,
    SLACK,
    SPLUNK_HEC,
    SYSLOG_CEF
};

struct WebhookConfig {
    bool          enabled{false};
    std::string   url;
    WebhookFormat format{WebhookFormat::JSON_GENERIC};
    uint32_t      timeout_ms{3000};
    uint8_t       min_level{2}; // 2 = MEDIUM+
};

class WebhookEngine final : public ISecurityEngine {
    std::atomic<bool>                running_{false};
    std::thread                      worker_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    mutable std::mutex               mtx_;
    std::condition_variable          cv_;

    WebhookConfig                    config_;
    std::queue<ThreatEvent>          event_queue_;
    std::vector<std::string>         dispatched_payloads_;

    std::atomic<uint64_t>            events_processed_{0};
    std::atomic<uint64_t>            threats_detected_{0};

    void worker_loop();

public:
    WebhookEngine();
    ~WebhookEngine() override;

    std::string_view name() const noexcept override { return "WebhookEngine"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void set_config(const WebhookConfig& cfg);
    WebhookConfig config() const;

    void enqueue_event(const ThreatEvent& event);
    size_t queue_size() const;
    std::vector<std::string> recent_dispatches(size_t limit = 10) const;

    // Formatting utilities
    static std::string format_discord_payload(const ThreatEvent& event);
    static std::string format_slack_payload(const ThreatEvent& event);
    static std::string format_splunk_hec_payload(const ThreatEvent& event);
    static std::string format_syslog_cef_payload(const ThreatEvent& event);
    static std::string format_generic_json(const ThreatEvent& event);
};

} // namespace gcad
