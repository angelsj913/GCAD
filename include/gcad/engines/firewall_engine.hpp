#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <vector>
#include <atomic>

namespace gcad {

enum class FirewallDirection : uint8_t { INBOUND = 0, OUTBOUND = 1 };
enum class FirewallAction    : uint8_t { ALLOW = 0, DENY = 1 };
enum class FirewallProto     : uint8_t { ANY = 0, TCP = 6, UDP = 17, ICMP = 1 };

struct FirewallRule {
    uint32_t        id{0};
    std::string     label;
    FirewallDirection direction{FirewallDirection::INBOUND};
    FirewallAction  action{FirewallAction::DENY};
    FirewallProto   protocol{FirewallProto::ANY};
    uint32_t        src_ip{0};
    uint32_t        src_mask{0};
    uint32_t        dst_ip{0};
    uint32_t        dst_mask{0};
    uint16_t        port_min{0};
    uint16_t        port_max{65535};
    bool            enabled{true};
    int             priority{100};
};

struct ConnectionLog {
    std::chrono::system_clock::time_point timestamp{};
    uint32_t        src_ip{0};
    uint32_t        dst_ip{0};
    uint16_t        src_port{0};
    uint16_t        dst_port{0};
    FirewallProto   protocol{FirewallProto::TCP};
    FirewallDirection direction{FirewallDirection::INBOUND};
    FirewallAction  action_taken{FirewallAction::ALLOW};
    uint32_t        matched_rule_id{0};
    size_t          packet_size{0};
};

struct SuspiciousTraffic {
    uint32_t        ip{0};
    size_t          connection_count{0};
    size_t          denied_count{0};
    ThreatCategory  suspected_category{ThreatCategory::NONE};
    std::string     reason;
};

class FirewallEngine final : public ISecurityEngine {
public:
    FirewallEngine();
    ~FirewallEngine() override;

    std::string_view name() const noexcept override { return "Firewall"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    uint32_t add_rule(FirewallRule rule);
    bool remove_rule(uint32_t rule_id);
    bool enable_rule(uint32_t rule_id, bool enabled);
    std::vector<FirewallRule> rules() const;

    FirewallAction evaluate(FirewallDirection dir, FirewallProto proto,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port);

    void log_connection(const ConnectionLog& entry);
    std::vector<ConnectionLog> recent_connections(size_t n = 100) const;
    std::vector<SuspiciousTraffic> suspicious_candidates() const;

    size_t total_allowed() const noexcept { return total_allowed_.load(); }
    size_t total_denied() const noexcept { return total_denied_.load(); }

    static uint32_t parse_ipv4(std::string_view s);
    static std::string ip_to_string(uint32_t ip);
    static uint32_t cidr_to_mask(unsigned prefix_len);

    static constexpr size_t MAX_CONNECTION_LOG = 10000;
    static constexpr size_t FLOOD_THRESHOLD    = 200;
    static constexpr size_t DENY_RATIO_THRESH  = 5;

private:
    std::atomic<bool>    running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<size_t>  total_allowed_{0};
    std::atomic<size_t>  total_denied_{0};

    mutable std::mutex   mtx_;
    std::vector<FirewallRule>   rules_;
    std::deque<ConnectionLog>   conn_log_;
    uint32_t                    next_rule_id_{1};

    std::thread          monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void monitor_loop();
    void analyze_traffic();
    void emit_threat(ThreatCategory cat, const std::string& desc,
                     uint32_t src_ip, uint16_t port);
    void emit_observation(security::ObservationKind kind, ThreatLevel level,
                          double confidence, const std::string& evidence);
    void install_default_rules();
};

} // namespace gcad
