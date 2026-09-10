#pragma once
#include "../i_security_engine.hpp"

namespace gcad {

struct ShadowEntry {
    uintptr_t   original_addr;
    uint64_t    xor_key;
    uint64_t    canary;
    uint64_t    shadow_hash;
    std::chrono::steady_clock::time_point last_check;
    size_t      region_size{0};    // >0: a real in-process code/IAT region being watched
    uint64_t    content_hash{0};   // last known hash of the bytes at original_addr
};

class PMSREngine final : public ISecurityEngine {
    std::atomic<bool>                    running_{false};
    std::thread                          monitor_thread_;
    std::function<void(ThreatEvent)>     threat_cb_;
    mutable std::mutex                   mtx_;

    std::vector<ShadowEntry>             shadow_ring_;
    std::mt19937_64                      rng_;
    std::atomic<uint64_t>                events_processed_{0};
    std::atomic<uint64_t>                threats_detected_{0};

    static constexpr size_t RING_SIZE = 256;
    static constexpr uint64_t CANARY_MAGIC = 0xDEAD'BEEF'CAFE'BABEull;

    void monitor_loop();
    uint64_t generate_xor_key();
    uint64_t compute_shadow_hash(const ShadowEntry& entry) const noexcept;
    void rotate_keys();
    bool verify_canary(const ShadowEntry& entry) const noexcept;
    void emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid = 0);

public:
    PMSREngine();
    ~PMSREngine() override;

    std::string_view name() const noexcept override { return "PMSR"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void register_region(uintptr_t addr, size_t size);
    void inject_honey_iat(uintptr_t fake_addr, uint64_t trap_canary);
};

} // namespace gcad
