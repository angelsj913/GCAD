#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <unordered_set>

namespace gcad {

struct DnsQueryRecord {
    std::string                         domain;
    uint16_t                            qtype{0};
    std::chrono::system_clock::time_point timestamp{};
    double                              dga_score{0.0};
    bool                                blocked{false};
};

class DnsMonitorEngine final : public ISecurityEngine {
public:
    DnsMonitorEngine();
    ~DnsMonitorEngine() override;

    std::string_view name() const noexcept override { return "DnsMon"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void on_observation(std::function<void(security::SecurityObservation)> cb);

    static double dga_score(std::string_view domain);
    static bool parse_dns_query(const uint8_t* data, size_t len, std::string& out_domain, uint16_t& out_qtype);
    void analyze_domain(const std::string& domain);

    std::vector<DnsQueryRecord> recent_queries(size_t n = 50) const;
    const std::unordered_set<std::string>& blocklist() const { return blocklist_; }

    static constexpr double DGA_THRESHOLD = 0.70;

private:
    std::atomic<bool>                        running_{false};
    std::atomic<uint64_t>                    events_processed_{0};
    std::atomic<uint64_t>                    threats_detected_{0};
    std::thread                              monitor_thread_;
    mutable std::mutex                       mtx_;
    std::function<void(ThreatEvent)>         threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    std::deque<DnsQueryRecord>               query_log_;
    std::unordered_set<std::string>          blocklist_;
    std::unordered_set<std::string>          seen_domains_;

    void monitor_loop();
    void init_blocklist();
    void emit_threat(ThreatCategory cat, const std::string& desc);
    void emit_observation(security::ObservationKind kind, ThreatLevel level,
                          double confidence, const std::string& evidence);

    static constexpr size_t MAX_QUERY_LOG = 5000;
};

} // namespace gcad
