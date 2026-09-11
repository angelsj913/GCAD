#pragma once

#include "policy.hpp"
#include <deque>
#include <unordered_map>

namespace gcad::security {

class CorrelationEngine final {
public:
    explicit CorrelationEngine(LocalSecurityPolicy policy = {});

    std::optional<SecurityFinding> ingest(
        const SecurityObservation& observation,
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    void expire(std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    std::vector<SecurityFinding> recent(size_t count) const;

private:
    struct SourceState {
        double                              confidence{0.0};
        ThreatLevel                         suggested_level{ThreatLevel::SAFE};
        bool                                deterministic{false};
        std::chrono::system_clock::time_point last_seen{};
    };

    struct ActiveState {
        std::chrono::system_clock::time_point last_seen{};
        std::unordered_map<std::string, SourceState> sources;
        std::string                         file_path;
        std::string                         rationale;
        uint8_t                             last_reported_score{0};
        ThreatLevel                         last_reported_level{ThreatLevel::SAFE};
    };

    static constexpr size_t MAX_ACTIVE_KEYS = 4096;
    static constexpr size_t MAX_FINDINGS = 2000;
    static constexpr auto DUPLICATE_WINDOW = std::chrono::seconds{30};

    LocalSecurityPolicy                      policy_;
    mutable std::mutex                       mtx_;
    std::unordered_map<std::string, ActiveState> active_;
    std::deque<SecurityFinding>               findings_;
    uint64_t                                  next_finding_id_{1};

    static uint8_t score_for(const ActiveState& state) noexcept;
    static bool any_source_deterministic(const ActiveState& state) noexcept;
    static ThreatLevel level_for(uint8_t score) noexcept;
    void evict_oldest_locked();
};

} // namespace gcad::security
