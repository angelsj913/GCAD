#pragma once
#include "../i_security_engine.hpp"

namespace gcad {

struct PacketStats {
    double   shannon_entropy;
    double   chi_squared;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    size_t   payload_len;
    std::chrono::steady_clock::time_point timestamp;
};

class ETGRIEngine final : public ISecurityEngine {
    std::atomic<bool>                    running_{false};
    std::thread                          capture_thread_;
    std::function<void(ThreatEvent)>     threat_cb_;
    mutable std::mutex                   mtx_;

    static constexpr size_t  WINDOW_SIZE    = 64;
    static constexpr double  ENTROPY_THRESH_HIGH = 7.5;
    static constexpr double  ENTROPY_THRESH_LOW  = 0.5;
    static constexpr double  CHI2_THRESH    = 400.0;
    static constexpr size_t  FLOOD_THRESH   = 500;
    static constexpr auto    FLOOD_WINDOW   = std::chrono::seconds(1);

    std::vector<PacketStats>             sliding_window_;
    std::unordered_map<uint32_t, std::vector<std::chrono::steady_clock::time_point>> conn_tracker_;
    std::vector<uint32_t>                blocked_ips_;

    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> packets_captured_{0};

#ifdef GCAD_PLATFORM_WINDOWS
    SOCKET raw_socket_{INVALID_SOCKET};
#else
    int    raw_socket_{-1};
#endif

    void capture_loop();
    void analyze_packet(const uint8_t* data, size_t len);
    PacketStats compute_stats(const uint8_t* payload, size_t len, uint32_t src, uint32_t dst,
                              uint16_t sp, uint16_t dp, uint8_t proto);
    bool is_flood(uint32_t src_ip);
    bool is_blocked(uint32_t ip) const;
    void emit_threat(ThreatCategory cat, const std::string& desc, const std::string& src_ip_str, uint16_t port);
    ErrorCode create_raw_socket();
    void close_raw_socket();

public:
    ETGRIEngine();
    ~ETGRIEngine() override;

    std::string_view name() const noexcept override { return "ETG-RI"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    uint64_t packets_captured() const noexcept { return packets_captured_.load(); }
    std::vector<PacketStats> recent_packets(size_t n = 50) const;
    std::vector<uint32_t> get_blocked_ips() const;
    void block_ip(uint32_t ip);
    void unblock_ip(uint32_t ip);
};

} // namespace gcad
