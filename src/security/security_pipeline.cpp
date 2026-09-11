#include "gcad/security/security_pipeline.hpp"

namespace gcad::security {

SecurityPipeline::SecurityPipeline(size_t queue_capacity, LocalSecurityPolicy policy)
    : policy_(std::move(policy)), bus_(queue_capacity), correlation_(policy_) {}

SecurityPipeline::~SecurityPipeline() {
    stop();
}

ErrorCode SecurityPipeline::start() {
    if (running_.exchange(true)) return ErrorCode::OK;
    if (bus_.closed()) {
        running_.store(false);
        return ErrorCode::ERR_ENGINE_START;
    }
    try {
        worker_ = std::thread(&SecurityPipeline::worker_loop, this);
    } catch (...) {
        running_.store(false);
        return ErrorCode::ERR_ENGINE_START;
    }
    return ErrorCode::OK;
}

ErrorCode SecurityPipeline::stop() {
    if (!running_.exchange(false)) return ErrorCode::OK;
    bus_.close();
    if (worker_.joinable()) worker_.join();
    return ErrorCode::OK;
}

PublishResult SecurityPipeline::publish(SecurityObservation observation) {
    if (!running_.load()) return PublishResult::CLOSED;
    return bus_.publish(std::move(observation));
}

std::vector<SecurityFinding> SecurityPipeline::recent_findings(size_t count) const {
    return correlation_.recent(count);
}

std::vector<RemediationCandidate> SecurityPipeline::recent_candidates(size_t count) const {
    std::lock_guard lk(candidates_mtx_);
    const size_t start = candidates_.size() > count ? candidates_.size() - count : 0;
    return {candidates_.begin() + static_cast<std::ptrdiff_t>(start), candidates_.end()};
}

TelemetryMetrics SecurityPipeline::telemetry_metrics() const {
    return bus_.metrics();
}

std::optional<RemediationCandidate> SecurityPipeline::find_candidate(uint64_t finding_id) const {
    std::lock_guard lk(candidates_mtx_);
    for (const auto& candidate : candidates_)
        if (candidate.finding_id == finding_id) return candidate;
    return std::nullopt;
}

namespace {
ErrorCode transition_candidate(std::deque<RemediationCandidate>& candidates, std::mutex& mtx,
                               uint64_t finding_id, CandidateApprovalState target) {
    std::lock_guard lk(mtx);
    for (auto& candidate : candidates) {
        if (candidate.finding_id != finding_id) continue;
        if (candidate.approval_state == target) return ErrorCode::OK; // idempotent
        if (candidate.approval_state != CandidateApprovalState::PENDING_APPROVAL)
            return ErrorCode::ERR_INVALID_TRANSITION; // terminal state already reached, and it's the other one
        candidate.approval_state = target;
        return ErrorCode::OK;
    }
    return ErrorCode::ERR_NOT_FOUND;
}
} // namespace

ErrorCode SecurityPipeline::approve_candidate(uint64_t finding_id) {
    return transition_candidate(candidates_, candidates_mtx_, finding_id, CandidateApprovalState::APPROVED);
}

ErrorCode SecurityPipeline::reject_candidate(uint64_t finding_id) {
    return transition_candidate(candidates_, candidates_mtx_, finding_id, CandidateApprovalState::REJECTED);
}

void SecurityPipeline::worker_loop() {
    for (;;) {
        SecurityObservation observation;
        if (bus_.wait_pop(observation, std::chrono::milliseconds{100})) {
            process(std::move(observation));
            continue;
        }
        if (bus_.closed()) break;
    }
}

void SecurityPipeline::process(SecurityObservation observation) {
    try {
        const auto finding = correlation_.ingest(observation);
        if (!finding) return;
        const auto candidate = policy_engine_.candidate_for(*finding, policy_);
        if (!candidate) return;

        std::lock_guard lk(candidates_mtx_);
        candidates_.push_back(*candidate);
        if (candidates_.size() > MAX_CANDIDATES) candidates_.pop_front();
    } catch (const std::exception& ex) {
        GCAD_LOG(ERR, std::string("Security pipeline observation dropped: ") + ex.what());
    } catch (...) {
        GCAD_LOG(ERR, "Security pipeline observation dropped: unknown error");
    }
}

} // namespace gcad::security
