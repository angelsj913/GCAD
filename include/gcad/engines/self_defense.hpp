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
    std::atomic<bool>    protection_applied_{false};

    bool apply_process_protection_dacl();
    bool verify_process_protection_dacl();
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

#ifdef GCAD_PLATFORM_WINDOWS
    // Whether the process-protection DACL was actually applied at start --
    // false in an environment that refuses WRITE_DAC even on our own
    // pseudo-handle, which check_handle_integrity() treats as "nothing to
    // verify yet" rather than evidence of tampering.
    bool protection_applied() const noexcept { return protection_applied_.load(); }
#endif

#ifdef GCAD_PLATFORM_WINDOWS
    // Pure classification, unit-testable without touching any OS object:
    // does this access mask include a right that lets its holder tamper with
    // GCAD's own process (write/execute memory, threads, termination) rather
    // than merely observe it (query/synchronize)?
    static bool is_dangerous_process_access(unsigned long granted_access) noexcept;

    struct RawAclEntry { uint8_t ace_type; uint32_t mask; };

    // Hand-rolled ACL/ACE binary parsing and construction against the
    // documented MS-DTYP structure layout -- GCAD does not call
    // SetEntriesInAcl/AllocateAndInitializeSid/SetSecurityInfo to have the OS
    // design the access list for it; it reads and writes the same ACL/ACE/SID
    // byte layout those functions would have produced, itself. Exposed as
    // public statics so both are directly unit-testable against synthetic
    // byte buffers, with no live security descriptor required.
    static std::vector<RawAclEntry> parse_acl_entries(const uint8_t* acl_bytes, size_t size) noexcept;
    static std::vector<uint8_t> build_acl_with_prepended_deny(
        const uint8_t* existing_acl_bytes, size_t existing_size, uint32_t deny_mask);
#endif
};

} // namespace gcad
