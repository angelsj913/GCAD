#pragma once
#include "../i_security_engine.hpp"

namespace gcad {

struct SyscallRecord {
    uint32_t    pid;
    uint32_t    tid;
    uint32_t    syscall_number;
    uintptr_t   caller_ip;
    uintptr_t   stack_base;
    bool        legitimate;
    std::string module_name;
    std::chrono::steady_clock::time_point timestamp;
};

class SyscallGuardEngine final : public ISecurityEngine {
    std::atomic<bool>                    running_{false};
    std::thread                          monitor_thread_;
    std::function<void(ThreatEvent)>     threat_cb_;
    mutable std::mutex                   mtx_;

    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};

    std::vector<SyscallRecord>           suspicious_records_;
    std::unordered_map<uint32_t, size_t> process_syscall_count_;

    static constexpr size_t DIRECT_SYSCALL_BURST_THRESH = 50;
    static constexpr auto   BURST_WINDOW = std::chrono::seconds(2);

    void monitor_loop();
    bool validate_caller_stack(uint32_t pid, uintptr_t caller_ip);
    bool detect_ntdll_unhook(uint32_t pid);
    bool detect_direct_syscall(uintptr_t caller_ip, uint32_t pid);
    void emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid);

#ifdef GCAD_PLATFORM_WINDOWS
    std::vector<uint8_t> pristine_ntdll_;
    uintptr_t            ntdll_text_base_{0};
    size_t               ntdll_text_size_{0};
    bool load_pristine_ntdll();
#endif

public:
    SyscallGuardEngine();
    ~SyscallGuardEngine() override;

    std::string_view name() const noexcept override { return "SyscallGuard"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    std::vector<SyscallRecord> get_suspicious_records(size_t n = 20) const;
};

} // namespace gcad
