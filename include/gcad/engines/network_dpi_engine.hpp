#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <array>
#include <unordered_set>

namespace gcad {

enum class DpiProtocol : uint8_t {
    PROTO_UNKNOWN  = 0,
    PROTO_HTTP     = 1,
    PROTO_HTTPS    = 2,
    PROTO_DNS      = 3,
    PROTO_SMTP     = 4,
    PROTO_FTP      = 5,
    PROTO_SSH      = 6,
    PROTO_RDP      = 7,
    PROTO_SMB      = 8,
    PROTO_IRC      = 9,
    PROTO_RAW      = 10,
};

enum class DpiVerdict : uint8_t {
    CLEAN       = 0,
    SUSPICIOUS  = 1,
    MALICIOUS   = 2,
    BLOCKED     = 3,
};

struct PacketMeta {
    uint64_t                              id{0};
    std::chrono::system_clock::time_point timestamp{};
    DpiProtocol                           protocol{DpiProtocol::PROTO_UNKNOWN};
    std::string                           src_ip;
    uint16_t                              src_port{0};
    std::string                           dst_ip;
    uint16_t                              dst_port{0};
    uint32_t                              payload_size{0};
    double                                payload_entropy{0.0};
    std::string                           hostname;
    std::string                           user_agent;
    std::string                           tls_issuer;
    std::string                           tls_subject;
    bool                                  tls_self_signed{false};
    bool                                  tls_expired{false};
    int                                   http_status{0};
    std::string                           http_method;
    std::string                           uri;
};

struct BeaconPattern {
    std::string dst_ip;
    uint16_t    dst_port{0};
    size_t      connection_count{0};
    double      interval_mean_ms{0.0};
    double      interval_stddev_ms{0.0};
    double      jitter_ratio{0.0};
    double      beacon_score{0.0};
};

struct DpiAlert {
    uint64_t    id{0};
    DpiVerdict  verdict{DpiVerdict::CLEAN};
    ThreatLevel level{ThreatLevel::SAFE};
    std::string rule_name;
    std::string description;
    std::string src_ip;
    std::string dst_ip;
    uint16_t    dst_port{0};
    DpiProtocol protocol{DpiProtocol::PROTO_UNKNOWN};
    std::chrono::system_clock::time_point timestamp{};
};

class NetworkDpiEngine final : public ISecurityEngine {
public:
    NetworkDpiEngine();
    ~NetworkDpiEngine() override;

    std::string_view name() const noexcept override { return "NetworkDPI"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    void inspect_packet(const PacketMeta& pkt);
    std::vector<DpiAlert> recent_alerts(size_t n = 100) const;
    std::vector<BeaconPattern> detected_beacons(size_t n = 50) const;

    static DpiProtocol classify_port(uint16_t port);
    static bool is_suspicious_user_agent(const std::string& ua);
    static bool is_suspicious_uri(const std::string& uri);
    static bool is_known_c2_port(uint16_t port);
    static double compute_beacon_score(double interval_mean_ms,
                                        double interval_stddev_ms,
                                        size_t count);

    static constexpr size_t   BEACON_MIN_CONNECTIONS = 5;
    static constexpr double   BEACON_SCORE_THRESHOLD = 0.70;
    static constexpr double   HIGH_ENTROPY_THRESHOLD = 7.2;
    static constexpr size_t   MAX_ALERTS   = 2000;
    static constexpr size_t   MAX_PACKETS  = 10000;

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};
    std::atomic<uint64_t> next_alert_id_{1};

    mutable std::mutex    mtx_;
    std::deque<PacketMeta>  packets_;
    std::deque<DpiAlert>    alerts_;

    struct ConnectionTimeline {
        std::deque<std::chrono::system_clock::time_point> timestamps;
        std::string dst_ip;
        uint16_t    dst_port{0};
    };
    std::unordered_map<std::string, ConnectionTimeline> conn_timelines_;
    std::unordered_set<std::string> reported_beacons_;

    std::thread           monitor_thread_;
    std::function<void(ThreatEvent)>                   threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void monitor_loop();
    void analyze_beacons();
    void check_protocol_anomalies(const PacketMeta& pkt);
    void check_tls_anomalies(const PacketMeta& pkt);
    void add_alert(DpiVerdict verdict, ThreatLevel level,
                   const std::string& rule, const std::string& desc,
                   const PacketMeta& pkt);
    std::string conn_key(const std::string& dst_ip, uint16_t dst_port) const;
};

} // namespace gcad
