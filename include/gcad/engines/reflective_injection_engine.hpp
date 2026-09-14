#pragma once
#include "../i_security_engine.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

namespace gcad {

enum class InjectionTechnique : uint8_t {
    NONE = 0,
    PROCESS_HOLLOWING,
    EARLY_BIRD_APC,
    REFLECTIVE_DLL,
    THREAD_EXECUTION_HIJACK
};

struct InjectionEvidence {
    InjectionTechnique       technique{InjectionTechnique::NONE};
    uint32_t                 target_pid{0};
    std::string              process_name;
    uintptr_t                base_address{0};
    size_t                   region_size{0};
    std::string              detail;
    ThreatLevel              severity{ThreatLevel::HIGH};
};

class ReflectiveInjectionEngine final : public ISecurityEngine {
    std::atomic<bool>                running_{false};
    std::thread                      monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    mutable std::mutex               mtx_;

    std::atomic<uint64_t>            events_processed_{0};
    std::atomic<uint64_t>            threats_detected_{0};

    void monitor_loop();
    void emit_threat(const InjectionEvidence& ev);

public:
    ReflectiveInjectionEngine();
    ~ReflectiveInjectionEngine() override;

    std::string_view name() const noexcept override { return "ReflectiveInjection"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    // Detection APIs
    static bool is_rwx_reflective_pe(const uint8_t* memory_bytes, size_t len);
    static bool evaluate_hollowing_anomaly(bool is_suspended, bool unmapped_section, uint32_t entry_point_rva);
    static bool evaluate_early_bird_apc(bool thread_created_suspended, bool apc_queued_before_resume, bool is_known_safe);
    InjectionEvidence inspect_memory_region(uint32_t pid, const std::string& proc_name, uintptr_t base_addr, const uint8_t* buffer, size_t size, uint32_t protect_flags);
};

} // namespace gcad
