#include "gcad/security/legacy_adapter.hpp"

namespace gcad::security {

namespace {

struct ConfidenceRule {
    std::string_view engine_name;
    ThreatCategory   category;
    double           confidence;
    bool             deterministic;
};

// Confidence and determinism verified against each engine's actual detection
// code, not assumed from the category name alone. `engine_name` must match
// ISecurityEngine::name() exactly (case-sensitive):
//
//   PMSR          MEMORY_INJECTION  exact FNV-1a hash mismatch of a registered
//                                   code region against its live bytes.
//   SelfDefense   EVASION_UNHOOK    fires only when an OS query on GCAD's own
//                                   token/DACL fails -- weak, not a tamper proof.
//   SelfDefense   MEMORY_INJECTION  exact memcmp of GCAD's own .text section.
//   SelfDefense   DLL_INJECTION     exact set-difference against a known-module
//                                   baseline captured at start (trust-on-first-use).
//   SyscallGuard  EVASION_UNHOOK    exact memcmp of a remote process's live
//                                   ntdll .text against an on-disk pristine copy.
//   SyscallGuard  DIRECT_SYSCALL    deterministic return-address bounds check;
//                                   some EDR-friendly software can trip it.
//   ARHS          RANSOMWARE        Shannon-entropy threshold on file rewrites.
//   ARHS          FILE_ENCRYPT      rapid bulk-change count threshold.
//   ETG-RI        ENTROPY_ANOMALY   packet-payload entropy threshold.
//   ETG-RI        RAW_SOCKET_PROBE  chi-squared statistical anomaly threshold.
//   ETG-RI        SYN_FLOOD         packet-rate threshold.
//   ZRGP          NETWORK_SCAN      any connection to a honeypot port: no
//                                   legitimate client should ever touch it.
//   KernelMon     EVASION_AMSI      exact byte-pattern match on AmsiScanBuffer.
//   KernelMon     EVASION_ETW       exact byte-pattern match on EtwEventWrite.
//   KernelMon     PPID_SPOOF        CreateTime ordering proof.
//   KernelMon     SUSPICIOUS_BINARY path-prefix heuristic (Linux only).
constexpr ConfidenceRule kRules[] = {
    {"PMSR",         ThreatCategory::MEMORY_INJECTION,  0.92, true},
    {"SelfDefense",  ThreatCategory::EVASION_UNHOOK,    0.35, false},
    {"SelfDefense",  ThreatCategory::MEMORY_INJECTION,  0.90, true},
    {"SelfDefense",  ThreatCategory::DLL_INJECTION,     0.75, true},
    {"SyscallGuard", ThreatCategory::EVASION_UNHOOK,    0.92, true},
    {"SyscallGuard", ThreatCategory::DIRECT_SYSCALL,    0.80, true},
    {"ARHS",         ThreatCategory::RANSOMWARE,        0.55, false},
    {"ARHS",         ThreatCategory::FILE_ENCRYPT,      0.60, false},
    {"ETG-RI",       ThreatCategory::ENTROPY_ANOMALY,   0.45, false},
    {"ETG-RI",       ThreatCategory::RAW_SOCKET_PROBE,  0.45, false},
    {"ETG-RI",       ThreatCategory::SYN_FLOOD,         0.65, false},
    {"ZRGP",         ThreatCategory::NETWORK_SCAN,      0.85, true},
    {"KernelMon",    ThreatCategory::EVASION_AMSI,      0.90, true},
    {"KernelMon",    ThreatCategory::EVASION_ETW,       0.85, true},
    {"KernelMon",    ThreatCategory::PPID_SPOOF,        0.90, true},
    {"KernelMon",    ThreatCategory::SUSPICIOUS_BINARY, 0.50, false},
};

double confidence_for_level(ThreatLevel level) noexcept {
    switch (level) {
        case ThreatLevel::LOW:      return 0.30;
        case ThreatLevel::MEDIUM:   return 0.50;
        case ThreatLevel::HIGH:     return 0.70;
        case ThreatLevel::CRITICAL: return 0.90;
        case ThreatLevel::SAFE:     return 0.0;
    }
    return 0.0;
}

} // namespace

SecurityObservation adapt_legacy_event(const ThreatEvent& event, std::string_view engine_name) {
    SecurityObservation observation{};
    observation.kind = ObservationKind::LEGACY_ENGINE;
    observation.timestamp = event.timestamp;
    observation.suggested_level = event.level;
    observation.process_id = event.process_id;
    observation.process_name = event.process_name;
    observation.file_path = event.file_path;
    observation.evidence = event.description.empty() ? "Legacy engine event" : event.description;

    for (const auto& rule : kRules) {
        if (rule.engine_name == engine_name && rule.category == event.category) {
            observation.source_id = std::string(engine_name);
            observation.confidence = rule.confidence;
            observation.deterministic = rule.deterministic;
            return observation;
        }
    }

    // Unrecognized (engine, category) pair: degrade safely to the original
    // level-only mapping rather than guessing at determinism.
    observation.source_id = engine_name.empty()
        ? "legacy:" + std::to_string(static_cast<unsigned>(event.category))
        : std::string(engine_name);
    observation.confidence = confidence_for_level(event.level);
    observation.deterministic = false;
    return observation;
}

} // namespace gcad::security
