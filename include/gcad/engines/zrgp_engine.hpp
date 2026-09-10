#pragma once
#include "../i_security_engine.hpp"

namespace gcad {

struct FakeBanner {
    uint16_t    port;
    std::string service_name;
    std::string version_string;
    std::string response_template;
};

struct DeceptionStats {
    uint32_t    attacker_ip;
    uint16_t    target_port;
    uint64_t    probes_received;
    uint64_t    fake_responses_sent;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
};

class ZRGPEngine final : public ISecurityEngine {
    std::atomic<bool>                    running_{false};
    std::thread                          listener_thread_;
    std::function<void(ThreatEvent)>     threat_cb_;
    mutable std::mutex                   mtx_;

    std::vector<FakeBanner>              banners_;
    std::unordered_map<uint32_t, DeceptionStats> attacker_stats_;
    std::mt19937                         rng_;

    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> fake_responses_{0};

    static constexpr size_t MAX_HONEY_PORTS = 64;
    static constexpr size_t RESPONSE_JITTER_MS = 200;

    void listener_loop();
    std::string generate_fake_banner(uint16_t port);
    std::string randomize_version();
    std::string generate_fake_http_response();
    std::string generate_fake_ssh_banner();
    std::string generate_fake_ftp_banner();
    std::string generate_fake_smtp_banner();
    void add_delay_jitter();
    void emit_threat(ThreatCategory cat, const std::string& desc, const std::string& src_ip, uint16_t port);

    void init_default_banners();

#ifdef GCAD_PLATFORM_WINDOWS
    std::vector<SOCKET> listen_sockets_;
#else
    std::vector<int> listen_sockets_;
#endif

public:
    ZRGPEngine();
    ~ZRGPEngine() override;

    std::string_view name() const noexcept override { return "ZRGP"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void add_honey_port(uint16_t port, std::string_view service);
    std::vector<DeceptionStats> get_attacker_stats() const;
    uint64_t total_fake_responses() const noexcept { return fake_responses_.load(); }
};

} // namespace gcad
