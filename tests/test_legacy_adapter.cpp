#include "gcad/common.hpp"
#include "gcad/security/legacy_adapter.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

gcad::ThreatEvent event_with(gcad::ThreatCategory category, gcad::ThreatLevel level) {
    gcad::ThreatEvent ev{};
    ev.category = category;
    ev.level = level;
    ev.process_id = 4242;
    ev.description = "controlled fixture event";
    return ev;
}

} // namespace

void register_legacy_adapter_tests() {
    register_test("legacy_adapter_uses_engine_name_as_source_id", [] {
        const auto ev = event_with(gcad::ThreatCategory::MEMORY_INJECTION, gcad::ThreatLevel::CRITICAL);
        const auto observation = gcad::security::adapt_legacy_event(ev, "PMSR");
        return observation.source_id == "PMSR";
    });

    register_test("legacy_adapter_marks_pmsr_memory_injection_deterministic", [] {
        const auto ev = event_with(gcad::ThreatCategory::MEMORY_INJECTION, gcad::ThreatLevel::CRITICAL);
        const auto observation = gcad::security::adapt_legacy_event(ev, "PMSR");
        return observation.deterministic && observation.confidence >= 0.85;
    });

    // Same ThreatCategory, two engines, two independently calibrated
    // confidences: SelfDefense parses its own process DACL for an exact
    // deny-ACE it applied at start, SyscallGuard memcmps a remote process's
    // live ntdll .text against an on-disk pristine copy -- both are exact
    // checks now, but category alone still must not decide the confidence
    // value, the emitting engine's specific mechanism does.
    register_test("legacy_adapter_marks_self_defense_dacl_check_deterministic", [] {
        const auto ev = event_with(gcad::ThreatCategory::EVASION_UNHOOK, gcad::ThreatLevel::CRITICAL);
        const auto observation = gcad::security::adapt_legacy_event(ev, "SelfDefense");
        return observation.deterministic && observation.confidence >= 0.85 && observation.confidence < 0.90;
    });

    register_test("legacy_adapter_marks_syscall_guard_unhook_deterministic", [] {
        const auto ev = event_with(gcad::ThreatCategory::EVASION_UNHOOK, gcad::ThreatLevel::CRITICAL);
        const auto observation = gcad::security::adapt_legacy_event(ev, "SyscallGuard");
        return observation.deterministic && observation.confidence >= 0.90;
    });

    register_test("legacy_adapter_calibrates_confidence_per_engine_not_just_category", [] {
        const auto ev = event_with(gcad::ThreatCategory::EVASION_UNHOOK, gcad::ThreatLevel::CRITICAL);
        const auto self_defense = gcad::security::adapt_legacy_event(ev, "SelfDefense");
        const auto syscall_guard = gcad::security::adapt_legacy_event(ev, "SyscallGuard");
        return self_defense.confidence != syscall_guard.confidence;
    });

    register_test("legacy_adapter_marks_arhs_ransomware_heuristic_not_deterministic", [] {
        const auto ev = event_with(gcad::ThreatCategory::RANSOMWARE, gcad::ThreatLevel::CRITICAL);
        const auto observation = gcad::security::adapt_legacy_event(ev, "ARHS");
        return !observation.deterministic;
    });

    register_test("legacy_adapter_marks_zrgp_honeypot_hit_deterministic", [] {
        const auto ev = event_with(gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::HIGH);
        const auto observation = gcad::security::adapt_legacy_event(ev, "ZRGP");
        return observation.deterministic;
    });

    register_test("legacy_adapter_marks_kernel_mon_ppid_spoof_deterministic", [] {
        const auto ev = event_with(gcad::ThreatCategory::PPID_SPOOF, gcad::ThreatLevel::HIGH);
        const auto observation = gcad::security::adapt_legacy_event(ev, "KernelMon");
        return observation.deterministic;
    });

    register_test("legacy_adapter_falls_back_to_level_confidence_for_unknown_engine", [] {
        const auto ev = event_with(gcad::ThreatCategory::ANTI_FORENSIC, gcad::ThreatLevel::HIGH);
        const auto observation = gcad::security::adapt_legacy_event(ev, "");
        if (observation.deterministic) return false;
        if (observation.confidence < 0.69 || observation.confidence > 0.71) return false;
        return observation.source_id.rfind("legacy:", 0) == 0;
    });

    register_test("legacy_adapter_preserves_process_and_file_fields", [] {
        auto ev = event_with(gcad::ThreatCategory::FILE_ENCRYPT, gcad::ThreatLevel::CRITICAL);
        ev.file_path = "C:/Users/test/Desktop/ransom.docx";
        ev.process_name = "evil.exe";
        const auto observation = gcad::security::adapt_legacy_event(ev, "ARHS");
        return observation.file_path == ev.file_path && observation.process_name == ev.process_name &&
               observation.process_id == ev.process_id;
    });
}
