#pragma once

#include "observation.hpp"

namespace gcad::security {

enum class ResponseAction : uint8_t {
    REPORT_ONLY,
    QUARANTINE_CANDIDATE,
};

enum class CandidateApprovalState : uint8_t {
    PENDING_APPROVAL,
    APPROVED,
    REJECTED,
};

struct SecurityFinding {
    uint64_t                            id{0};
    std::chrono::system_clock::time_point timestamp{};
    ThreatLevel                         level{ThreatLevel::SAFE};
    uint8_t                             risk_score{0};
    bool                                deterministic_signature{false};
    std::string                         correlation_key;
    std::string                         file_path;
    std::string                         sha256;
    std::string                         rationale;
    std::vector<std::string>            contributing_sources;
    std::vector<uint64_t>               observation_ids;
};

struct RemediationCandidate {
    uint64_t               finding_id{0};
    ResponseAction         requested_action{ResponseAction::REPORT_ONLY};
    CandidateApprovalState approval_state{CandidateApprovalState::PENDING_APPROVAL};
    std::string            target_path;
    std::string            expected_sha256; // captured at detection time; empty if unknown
    std::string            rationale;
};

struct LocalSecurityPolicy {
    uint8_t             critical_threshold{90};
    std::chrono::minutes finding_window{5};
    std::vector<std::string> protected_path_prefixes{
        "c:/windows/",
        "c:/program files/",
    };
};

class PolicyEngine final {
public:
    ResponseAction decide(const SecurityFinding& finding,
                          const LocalSecurityPolicy& policy) const noexcept;
    std::optional<RemediationCandidate> candidate_for(const SecurityFinding& finding,
                                                       const LocalSecurityPolicy& policy) const;

    // Exposed so components that later act on an already-created candidate
    // (e.g. QuarantineExecutor) can re-check the protected-path rule against
    // the policy in effect at execution time, not only at detection time.
    static bool is_protected_path(std::string_view path,
                                  const LocalSecurityPolicy& policy) noexcept;
};

} // namespace gcad::security
