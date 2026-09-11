#include "gcad/security/correlation_engine.hpp"

namespace gcad::security {

CorrelationEngine::CorrelationEngine(LocalSecurityPolicy policy)
    : policy_(std::move(policy)) {}

uint8_t CorrelationEngine::score_for(const ActiveState& state) noexcept {
    unsigned score = 0;
    for (const auto& [source_id, source] : state.sources) {
        (void)source_id;
        score += static_cast<unsigned>(std::lround(source.confidence * 50.0));
    }
    if (state.sources.size() >= 2) score += 20;
    return static_cast<uint8_t>(std::min(score, 100u));
}

bool CorrelationEngine::any_source_deterministic(const ActiveState& state) noexcept {
    for (const auto& [source_id, source] : state.sources) {
        (void)source_id;
        if (source.deterministic) return true;
    }
    return false;
}

ThreatLevel CorrelationEngine::level_for(uint8_t score) noexcept {
    if (score >= 90) return ThreatLevel::CRITICAL;
    if (score >= 75) return ThreatLevel::HIGH;
    if (score >= 50) return ThreatLevel::MEDIUM;
    if (score >= 25) return ThreatLevel::LOW;
    return ThreatLevel::SAFE;
}

void CorrelationEngine::evict_oldest_locked() {
    if (active_.size() < MAX_ACTIVE_KEYS) return;

    auto oldest = active_.begin();
    for (auto it = std::next(active_.begin()); it != active_.end(); ++it) {
        if (it->second.last_seen < oldest->second.last_seen) oldest = it;
    }
    active_.erase(oldest);
}

std::optional<SecurityFinding> CorrelationEngine::ingest(
    const SecurityObservation& observation, std::chrono::system_clock::time_point now) {
    if (!observation.valid()) return std::nullopt;

    const std::string key = observation.correlation_key();
    expire(now);
    std::lock_guard lk(mtx_);

    auto state_it = active_.find(key);
    if (state_it == active_.end()) {
        evict_oldest_locked();
        state_it = active_.emplace(key, ActiveState{}).first;
    }
    ActiveState& state = state_it->second;

    const auto source_it = state.sources.find(observation.source_id);
    if (source_it != state.sources.end() && now >= source_it->second.last_seen &&
        now - source_it->second.last_seen < DUPLICATE_WINDOW) {
        return std::nullopt;
    }

    state.last_seen = now;
    state.sources[observation.source_id] = SourceState{
        observation.confidence, observation.suggested_level, observation.deterministic, now};
    if (state.file_path.empty() && !observation.file_path.empty())
        state.file_path = observation.file_path;
    if (state.sha256.empty() && !observation.sha256.empty())
        state.sha256 = observation.sha256;
    if (state.rationale.empty()) state.rationale = observation.evidence;

    const uint8_t score = score_for(state);
    const ThreatLevel level = level_for(score);
    if (score <= state.last_reported_score && level <= state.last_reported_level)
        return std::nullopt;

    state.last_reported_score = score;
    state.last_reported_level = level;

    SecurityFinding finding{};
    finding.id = next_finding_id_++;
    finding.timestamp = now;
    finding.level = level;
    finding.risk_score = score;
    finding.deterministic_signature = any_source_deterministic(state);
    finding.correlation_key = key;
    finding.file_path = state.file_path;
    finding.sha256 = state.sha256;
    finding.rationale = state.rationale;
    finding.contributing_sources.reserve(state.sources.size());
    for (const auto& [source_id, source] : state.sources) {
        (void)source;
        finding.contributing_sources.push_back(source_id);
    }
    std::sort(finding.contributing_sources.begin(), finding.contributing_sources.end());

    findings_.push_back(finding);
    if (findings_.size() > MAX_FINDINGS) findings_.pop_front();
    return finding;
}

void CorrelationEngine::expire(std::chrono::system_clock::time_point now) {
    std::lock_guard lk(mtx_);
    for (auto it = active_.begin(); it != active_.end();) {
        const auto last_seen = it->second.last_seen;
        if (now >= last_seen && now - last_seen > policy_.finding_window) {
            it = active_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<SecurityFinding> CorrelationEngine::recent(size_t count) const {
    std::lock_guard lk(mtx_);
    const size_t start = findings_.size() > count ? findings_.size() - count : 0;
    return {findings_.begin() + static_cast<std::ptrdiff_t>(start), findings_.end()};
}

} // namespace gcad::security
