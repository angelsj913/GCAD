#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>

namespace gcad {

struct BehaviorFeatures {
    double api_call_entropy{0.0};
    double memory_rwx_ratio{0.0};
    double network_rate{0.0};
    double file_write_rate{0.0};
    double registry_write_rate{0.0};
    double child_spawn_rate{0.0};
    double dll_load_count{0.0};
    double privilege_escalation{0.0};
    double injection_indicators{0.0};
    double evasion_indicators{0.0};
    double persistence_indicators{0.0};
    double encryption_indicators{0.0};
    static constexpr size_t FEATURE_COUNT = 12;

    double at(size_t i) const;
    void set(size_t i, double val);
};

struct ScoringResult {
    uint64_t    id{0};
    uint32_t    pid{0};
    std::string process_name;
    BehaviorFeatures features;
    double      risk_score{0.0};
    ThreatLevel level{ThreatLevel::SAFE};
    std::string explanation;
    std::chrono::system_clock::time_point scored_at{};
};

struct ModelWeights {
    double weights[BehaviorFeatures::FEATURE_COUNT]{};
    double bias{0.0};
    double threshold_suspicious{0.40};
    double threshold_malicious{0.75};
};

class BehaviorScorer final : public ISecurityEngine {
public:
    BehaviorScorer();
    ~BehaviorScorer() override;

    std::string_view name() const noexcept override { return "BehaviorML"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    ScoringResult score(uint32_t pid, const std::string& name, const BehaviorFeatures& features);
    std::vector<ScoringResult> recent_scores(size_t n = 50) const;
    const ModelWeights& model() const;
    void set_model(const ModelWeights& w);

    static double sigmoid(double x);
    static double compute_risk(const BehaviorFeatures& features, const ModelWeights& weights);
    static ThreatLevel classify(double risk, const ModelWeights& weights);
    static std::string explain(const BehaviorFeatures& features, const ModelWeights& weights);
    static BehaviorFeatures normalize(const BehaviorFeatures& raw);

    static ModelWeights default_model();
    static constexpr size_t MAX_SCORES = 1000;

    static const char* feature_name(size_t i);

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};

    mutable std::mutex              mtx_;
    ModelWeights                    model_;
    std::deque<ScoringResult>       score_log_;

    std::thread                     monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void monitor_loop();
};

} // namespace gcad
