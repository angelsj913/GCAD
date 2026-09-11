#include "gcad/security/policy.hpp"

namespace gcad::security {

namespace {

char ascii_lower(char value) noexcept {
    return (value >= 'A' && value <= 'Z')
        ? static_cast<char>(value - 'A' + 'a')
        : value;
}

bool path_starts_with(std::string_view path, std::string_view prefix) noexcept {
    if (path.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const char path_char = path[i] == '\\' ? '/' : ascii_lower(path[i]);
        const char prefix_char = prefix[i] == '\\' ? '/' : ascii_lower(prefix[i]);
        if (path_char != prefix_char) return false;
    }
    return true;
}

} // namespace

bool PolicyEngine::is_protected_path(std::string_view path,
                                     const LocalSecurityPolicy& policy) noexcept {
    return std::any_of(policy.protected_path_prefixes.begin(), policy.protected_path_prefixes.end(),
                       [path](const std::string& prefix) { return path_starts_with(path, prefix); });
}

ResponseAction PolicyEngine::decide(const SecurityFinding& finding,
                                    const LocalSecurityPolicy& policy) const noexcept {
    if (!finding.deterministic_signature || finding.level != ThreatLevel::CRITICAL ||
        finding.risk_score < policy.critical_threshold || finding.file_path.empty() ||
        is_protected_path(finding.file_path, policy)) {
        return ResponseAction::REPORT_ONLY;
    }
    return ResponseAction::QUARANTINE_CANDIDATE;
}

std::optional<RemediationCandidate> PolicyEngine::candidate_for(
    const SecurityFinding& finding, const LocalSecurityPolicy& policy) const {
    if (decide(finding, policy) != ResponseAction::QUARANTINE_CANDIDATE) return std::nullopt;

    RemediationCandidate candidate{};
    candidate.finding_id = finding.id;
    candidate.requested_action = ResponseAction::QUARANTINE_CANDIDATE;
    candidate.target_path = finding.file_path;
    candidate.expected_sha256 = finding.sha256;
    candidate.rationale = finding.rationale;
    return candidate;
}

} // namespace gcad::security
