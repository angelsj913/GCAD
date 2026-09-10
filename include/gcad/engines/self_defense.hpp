#pragma once
#include "../i_security_engine.hpp"

namespace gcad {

class SelfDefenseEngine final : public ISecurityEngine {
    std::atomic<bool>                    running_{false};
    std::thread                          guard_thread_;
    std::function<void(ThreatEvent)>     threat_cb_;
    mutable std::mutex                   mtx_;

    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    uint32_t              own_pid_{0};

    void guard_loop();
    bool check_handle_integrity();
    bool check_memory_integrity();
    bool check_module_integrity();
    void emit_threat(ThreatCategory cat, const std::string& desc);

#ifdef GCAD_PLATFORM_WINDOWS
    std::vector<uint8_t> original_text_section_;
    uintptr_t            text_base_{0};
    size_t               text_size_{0};
#endif

public:
    SelfDefenseEngine();
    ~SelfDefenseEngine() override;

    std::string_view name() const noexcept override { return "SelfDefense"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
};

} // namespace gcad
