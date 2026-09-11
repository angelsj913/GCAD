#pragma once

#include "correlation_engine.hpp"
#include "telemetry_bus.hpp"

namespace gcad::security {

class SecurityPipeline final {
public:
    explicit SecurityPipeline(size_t queue_capacity,
                              LocalSecurityPolicy policy = {});
    ~SecurityPipeline();

    ErrorCode start();
    ErrorCode stop();
    PublishResult publish(SecurityObservation observation);
    std::vector<SecurityFinding> recent_findings(size_t count) const;
    std::vector<RemediationCandidate> recent_candidates(size_t count) const;
    std::optional<RemediationCandidate> find_candidate(uint64_t finding_id) const;

    // Data-only approval state transitions -- neither call ever touches the
    // file system or a process. PENDING_APPROVAL -> APPROVED/REJECTED; the
    // opposite terminal state is refused (ERR_INVALID_TRANSITION); the same
    // terminal state again is idempotent (OK); an unknown finding id is
    // ERR_NOT_FOUND.
    ErrorCode approve_candidate(uint64_t finding_id);
    ErrorCode reject_candidate(uint64_t finding_id);

    TelemetryMetrics telemetry_metrics() const;
    bool running() const noexcept { return running_.load(); }

private:
    static constexpr size_t MAX_CANDIDATES = 2000;

    LocalSecurityPolicy                    policy_;
    TelemetryBus                           bus_;
    CorrelationEngine                      correlation_;
    PolicyEngine                           policy_engine_;
    std::atomic<bool>                      running_{false};
    std::thread                            worker_;
    mutable std::mutex                     candidates_mtx_;
    std::deque<RemediationCandidate>       candidates_;

    void worker_loop();
    void process(SecurityObservation observation);
};

} // namespace gcad::security
