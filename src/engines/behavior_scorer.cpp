#include "gcad/engines/behavior_scorer.hpp"
#include <cmath>
#include <sstream>
#include <algorithm>

namespace gcad {

static const char* s_feature_names[] = {
    "api_call_entropy",
    "memory_rwx_ratio",
    "network_rate",
    "file_write_rate",
    "registry_write_rate",
    "child_spawn_rate",
    "dll_load_count",
    "privilege_escalation",
    "injection_indicators",
    "evasion_indicators",
    "persistence_indicators",
    "encryption_indicators",
};

double BehaviorFeatures::at(size_t i) const {
    switch (i) {
        case 0:  return api_call_entropy;
        case 1:  return memory_rwx_ratio;
        case 2:  return network_rate;
        case 3:  return file_write_rate;
        case 4:  return registry_write_rate;
        case 5:  return child_spawn_rate;
        case 6:  return dll_load_count;
        case 7:  return privilege_escalation;
        case 8:  return injection_indicators;
        case 9:  return evasion_indicators;
        case 10: return persistence_indicators;
        case 11: return encryption_indicators;
        default: return 0.0;
    }
}

void BehaviorFeatures::set(size_t i, double val) {
    switch (i) {
        case 0:  api_call_entropy = val; break;
        case 1:  memory_rwx_ratio = val; break;
        case 2:  network_rate = val; break;
        case 3:  file_write_rate = val; break;
        case 4:  registry_write_rate = val; break;
        case 5:  child_spawn_rate = val; break;
        case 6:  dll_load_count = val; break;
        case 7:  privilege_escalation = val; break;
        case 8:  injection_indicators = val; break;
        case 9:  evasion_indicators = val; break;
        case 10: persistence_indicators = val; break;
        case 11: encryption_indicators = val; break;
        default: break;
    }
}

const char* BehaviorScorer::feature_name(size_t i) {
    if (i < BehaviorFeatures::FEATURE_COUNT) return s_feature_names[i];
    return "unknown";
}

BehaviorScorer::BehaviorScorer() : model_(default_model()) {}
BehaviorScorer::~BehaviorScorer() { stop(); }

ErrorCode BehaviorScorer::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&BehaviorScorer::monitor_loop, this);
    GCAD_LOG(INFO, "BehaviorML scoring engine started");
    return ErrorCode::OK;
}

ErrorCode BehaviorScorer::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus BehaviorScorer::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void BehaviorScorer::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void BehaviorScorer::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

ModelWeights BehaviorScorer::default_model() {
    ModelWeights w{};
    w.weights[0]  = 0.8;   // api_call_entropy
    w.weights[1]  = 2.5;   // memory_rwx_ratio
    w.weights[2]  = 1.2;   // network_rate
    w.weights[3]  = 0.9;   // file_write_rate
    w.weights[4]  = 1.5;   // registry_write_rate
    w.weights[5]  = 1.0;   // child_spawn_rate
    w.weights[6]  = 0.6;   // dll_load_count
    w.weights[7]  = 3.0;   // privilege_escalation
    w.weights[8]  = 3.5;   // injection_indicators
    w.weights[9]  = 2.8;   // evasion_indicators
    w.weights[10] = 2.0;   // persistence_indicators
    w.weights[11] = 2.5;   // encryption_indicators
    w.bias = -2.0;
    w.threshold_suspicious = 0.40;
    w.threshold_malicious = 0.75;
    return w;
}

double BehaviorScorer::sigmoid(double x) {
    if (x >= 0) {
        double z = std::exp(-x);
        return 1.0 / (1.0 + z);
    }
    double z = std::exp(x);
    return z / (1.0 + z);
}

double BehaviorScorer::compute_risk(const BehaviorFeatures& features, const ModelWeights& weights) {
    double logit = weights.bias;
    for (size_t i = 0; i < BehaviorFeatures::FEATURE_COUNT; ++i)
        logit += features.at(i) * weights.weights[i];
    return sigmoid(logit);
}

ThreatLevel BehaviorScorer::classify(double risk, const ModelWeights& weights) {
    if (risk >= weights.threshold_malicious) return ThreatLevel::HIGH;
    if (risk >= weights.threshold_suspicious) return ThreatLevel::MEDIUM;
    if (risk >= 0.20) return ThreatLevel::LOW;
    return ThreatLevel::SAFE;
}

BehaviorFeatures BehaviorScorer::normalize(const BehaviorFeatures& raw) {
    BehaviorFeatures n;
    n.api_call_entropy = std::clamp(raw.api_call_entropy / 8.0, 0.0, 1.0);
    n.memory_rwx_ratio = std::clamp(raw.memory_rwx_ratio, 0.0, 1.0);
    n.network_rate = std::clamp(raw.network_rate / 100.0, 0.0, 1.0);
    n.file_write_rate = std::clamp(raw.file_write_rate / 50.0, 0.0, 1.0);
    n.registry_write_rate = std::clamp(raw.registry_write_rate / 20.0, 0.0, 1.0);
    n.child_spawn_rate = std::clamp(raw.child_spawn_rate / 10.0, 0.0, 1.0);
    n.dll_load_count = std::clamp(raw.dll_load_count / 50.0, 0.0, 1.0);
    n.privilege_escalation = std::clamp(raw.privilege_escalation, 0.0, 1.0);
    n.injection_indicators = std::clamp(raw.injection_indicators, 0.0, 1.0);
    n.evasion_indicators = std::clamp(raw.evasion_indicators, 0.0, 1.0);
    n.persistence_indicators = std::clamp(raw.persistence_indicators, 0.0, 1.0);
    n.encryption_indicators = std::clamp(raw.encryption_indicators, 0.0, 1.0);
    return n;
}

std::string BehaviorScorer::explain(const BehaviorFeatures& features, const ModelWeights& weights) {
    struct Contribution { size_t idx; double value; };
    std::vector<Contribution> contribs;
    for (size_t i = 0; i < BehaviorFeatures::FEATURE_COUNT; ++i) {
        double c = features.at(i) * weights.weights[i];
        if (std::abs(c) > 0.01)
            contribs.push_back({i, c});
    }

    std::sort(contribs.begin(), contribs.end(),
              [](auto& a, auto& b) { return std::abs(a.value) > std::abs(b.value); });

    std::ostringstream o;
    o << "Risk factors: ";
    size_t shown = 0;
    for (auto& c : contribs) {
        if (shown >= 5) break;
        if (shown > 0) o << ", ";
        o << s_feature_names[c.idx] << "=" << std::fixed;
        o.precision(2);
        o << features.at(c.idx) << " (w=" << c.value << ")";
        ++shown;
    }
    if (shown == 0) o << "none significant";
    return o.str();
}

ScoringResult BehaviorScorer::score(uint32_t pid, const std::string& proc_name,
                                     const BehaviorFeatures& features) {
    auto normalized = normalize(features);
    ModelWeights w;
    {
        std::lock_guard lk(mtx_);
        w = model_;
    }

    double risk = compute_risk(normalized, w);
    auto level = classify(risk, w);
    auto explanation = explain(normalized, w);

    ScoringResult result;
    result.id = next_id_.fetch_add(1);
    result.pid = pid;
    result.process_name = proc_name;
    result.features = normalized;
    result.risk_score = risk;
    result.level = level;
    result.explanation = explanation;
    result.scored_at = std::chrono::system_clock::now();

    events_processed_.fetch_add(1);

    {
        std::lock_guard lk(mtx_);
        score_log_.push_back(result);
        while (score_log_.size() > MAX_SCORES) score_log_.pop_front();
    }

    if (level >= ThreatLevel::HIGH) {
        threats_detected_.fetch_add(1);
        std::function<void(ThreatEvent)> cb;
        {
            std::lock_guard lk(mtx_);
            cb = threat_cb_;
        }
        if (cb) {
            ThreatEvent ev{};
            ev.level = level;
            ev.category = ThreatCategory::SUSPICIOUS_BINARY;
            ev.description = "BehaviorML: " + proc_name + " risk=" +
                             std::to_string(static_cast<int>(risk * 100)) + "% — " + explanation;
            ev.process_name = proc_name;
            ev.process_id = pid;
            ev.timestamp = std::chrono::system_clock::now();
            cb(std::move(ev));
        }
    }

    if (level >= ThreatLevel::MEDIUM) {
        std::function<void(security::SecurityObservation)> obs_cb;
        {
            std::lock_guard lk(mtx_);
            obs_cb = observation_cb_;
        }
        if (obs_cb) {
            security::SecurityObservation obs{};
            obs.source_id = "behavior-ml";
            obs.kind = security::ObservationKind::PROCESS_MEMORY;
            obs.timestamp = std::chrono::system_clock::now();
            obs.suggested_level = level;
            obs.confidence = risk;
            obs.deterministic = false;
            obs.process_id = pid;
            obs.process_name = proc_name;
            obs.evidence = explanation;
            obs_cb(std::move(obs));
        }
    }

    return result;
}

std::vector<ScoringResult> BehaviorScorer::recent_scores(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, score_log_.size());
    return {score_log_.end() - static_cast<ptrdiff_t>(count), score_log_.end()};
}

const ModelWeights& BehaviorScorer::model() const {
    return model_;
}

void BehaviorScorer::set_model(const ModelWeights& w) {
    std::lock_guard lk(mtx_);
    model_ = w;
}

void BehaviorScorer::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 5000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        events_processed_.fetch_add(1);
    }
}

} // namespace gcad
