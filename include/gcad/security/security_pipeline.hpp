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
