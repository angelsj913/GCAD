#pragma once
#include "i_security_engine.hpp"
#include "security/security_pipeline.hpp"
#include <map>
#include <array>

namespace gcad {

class EngineManager {
    std::vector<std::unique_ptr<ISecurityEngine>> engines_;
    std::vector<ThreatEvent>                      event_log_;
    mutable std::shared_mutex                     log_mtx_;
    std::atomic<uint64_t>                         next_id_{1};
    std::function<void(const ThreatEvent&)>       global_cb_;
    std::unique_ptr<security::SecurityPipeline>   pipeline_;

public:
    EngineManager();
    ~EngineManager();

    ErrorCode start_all();
    ErrorCode stop_all();
    bool      all_running() const noexcept;            // true only if every engine is running
    std::vector<std::string> stopped_engines() const;  // names of engines not currently running

    void on_global_threat(std::function<void(const ThreatEvent&)> cb);
    void push_event(ThreatEvent ev);

    std::vector<EngineStatus> statuses() const;
    std::vector<ThreatEvent>  recent_events(size_t n = 50) const;
    size_t                    total_threats() const;
    ThreatLevel               current_threat_level() const;
    std::vector<security::SecurityFinding> recent_security_findings(size_t n = 50) const;
    std::vector<security::RemediationCandidate> recent_remediation_candidates(size_t n = 50) const;

    size_t                    engine_count() const noexcept { return engines_.size(); }
    uint64_t                  total_engine_events() const;          // sum of events_processed across engines
    std::array<size_t, 5>     severity_histogram() const;          // count per ThreatLevel over the event log
    std::vector<std::pair<ThreatCategory, size_t>> category_histogram() const; // sorted desc by count

    ISecurityEngine* engine(std::string_view name) const;
};

} // namespace gcad
