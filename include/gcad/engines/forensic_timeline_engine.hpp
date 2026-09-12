#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <deque>
#include <thread>
#include <mutex>

namespace gcad {

enum class KillChainStage : uint8_t {
    UNKNOWN          = 0,
    RECONNAISSANCE   = 1,
    WEAPONIZATION    = 2,
    DELIVERY         = 3,
    EXPLOITATION     = 4,
    INSTALLATION     = 5,
    COMMAND_CONTROL  = 6,
    ACTIONS_ON_OBJ   = 7,
};

enum class TimelineEventType : uint8_t {
    PROCESS     = 0,
    NETWORK     = 1,
    FILE_ACCESS = 2,
    REGISTRY    = 3,
    MEMORY      = 4,
    DNS         = 5,
    CREDENTIAL  = 6,
    EVASION     = 7,
};

struct TimelineEvent {
    uint64_t    id{0};
    std::chrono::system_clock::time_point timestamp{};
    TimelineEventType   type{TimelineEventType::PROCESS};
    KillChainStage      stage{KillChainStage::UNKNOWN};
    ThreatLevel         level{ThreatLevel::SAFE};
    ThreatCategory      category{ThreatCategory::NONE};

    uint32_t    process_id{0};
    std::string process_name;
    std::string file_path;
    std::string source_ip;
    std::string description;
    std::string evidence;

    uint64_t    causal_parent{0};
    double      confidence{0.0};
};

struct CausalChain {
    uint64_t                chain_id{0};
    std::vector<uint64_t>   event_ids;
    KillChainStage          max_stage{KillChainStage::UNKNOWN};
    ThreatLevel             max_level{ThreatLevel::SAFE};
    std::string             summary;
};

struct KillChainProgress {
    std::array<size_t, 8> stage_counts{};
    KillChainStage furthest{KillChainStage::UNKNOWN};
    size_t total_events{0};
    bool multi_stage_detected{false};
};

class ForensicTimelineEngine final : public ISecurityEngine {
public:
    ForensicTimelineEngine();
    ~ForensicTimelineEngine() override;

    std::string_view name() const noexcept override { return "ForensicTimeline"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    void ingest_threat(const ThreatEvent& ev);
    void ingest_observation(const security::SecurityObservation& obs);

    std::vector<TimelineEvent> query_timeline(size_t n = 100) const;
    std::vector<TimelineEvent> query_by_pid(uint32_t pid, size_t n = 50) const;
    std::vector<TimelineEvent> query_by_stage(KillChainStage stage, size_t n = 50) const;
    std::vector<TimelineEvent> query_time_range(
        std::chrono::system_clock::time_point from,
        std::chrono::system_clock::time_point to) const;

    std::vector<CausalChain> causal_chains(size_t n = 20) const;
    KillChainProgress kill_chain_progress() const;

    static KillChainStage map_category_to_stage(ThreatCategory cat);
    static KillChainStage map_observation_to_stage(security::ObservationKind kind);
    static TimelineEventType map_category_to_type(ThreatCategory cat);
    static TimelineEventType map_observation_to_type(security::ObservationKind kind);
    static const char* stage_name(KillChainStage stage);

    static constexpr size_t MAX_EVENTS = 5000;
    static constexpr size_t MAX_CHAINS = 200;

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};
    std::atomic<uint64_t> next_chain_id_{1};

    mutable std::mutex              mtx_;
    std::deque<TimelineEvent>       events_;
    std::deque<CausalChain>         chains_;

    std::thread monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void monitor_loop();
    void link_causal(TimelineEvent& ev);
    void update_chains(const TimelineEvent& ev);
    void detect_multi_stage();
};

} // namespace gcad
