#include "gcad/engines/behavior_scorer.hpp"
#include <cmath>

extern void register_test(const char* name, std::function<bool()> fn);

void register_behavior_scorer_tests() {
    register_test("bml_sigmoid_zero", [] {
        return std::abs(gcad::BehaviorScorer::sigmoid(0.0) - 0.5) < 0.001;
    });

    register_test("bml_sigmoid_large_positive", [] {
        return gcad::BehaviorScorer::sigmoid(10.0) > 0.999;
    });

    register_test("bml_sigmoid_large_negative", [] {
        return gcad::BehaviorScorer::sigmoid(-10.0) < 0.001;
    });

    register_test("bml_sigmoid_symmetry", [] {
        double a = gcad::BehaviorScorer::sigmoid(2.0);
        double b = gcad::BehaviorScorer::sigmoid(-2.0);
        return std::abs(a + b - 1.0) < 0.001;
    });

    register_test("bml_clean_process_low_risk", [] {
        gcad::BehaviorFeatures f;
        f.dll_load_count = 10;
        f.file_write_rate = 2;
        auto w = gcad::BehaviorScorer::default_model();
        auto norm = gcad::BehaviorScorer::normalize(f);
        double risk = gcad::BehaviorScorer::compute_risk(norm, w);
        return risk < 0.40;
    });

    register_test("bml_malicious_process_high_risk", [] {
        gcad::BehaviorFeatures f;
        f.injection_indicators = 1.0;
        f.evasion_indicators = 1.0;
        f.privilege_escalation = 1.0;
        f.memory_rwx_ratio = 0.8;
        f.encryption_indicators = 1.0;
        auto w = gcad::BehaviorScorer::default_model();
        auto norm = gcad::BehaviorScorer::normalize(f);
        double risk = gcad::BehaviorScorer::compute_risk(norm, w);
        return risk >= 0.75;
    });

    register_test("bml_classify_safe", [] {
        auto w = gcad::BehaviorScorer::default_model();
        return gcad::BehaviorScorer::classify(0.10, w) == gcad::ThreatLevel::SAFE;
    });

    register_test("bml_classify_low", [] {
        auto w = gcad::BehaviorScorer::default_model();
        return gcad::BehaviorScorer::classify(0.25, w) == gcad::ThreatLevel::LOW;
    });

    register_test("bml_classify_medium", [] {
        auto w = gcad::BehaviorScorer::default_model();
        return gcad::BehaviorScorer::classify(0.50, w) == gcad::ThreatLevel::MEDIUM;
    });

    register_test("bml_classify_high", [] {
        auto w = gcad::BehaviorScorer::default_model();
        return gcad::BehaviorScorer::classify(0.80, w) == gcad::ThreatLevel::HIGH;
    });

    register_test("bml_normalize_clamp", [] {
        gcad::BehaviorFeatures raw;
        raw.api_call_entropy = 100.0;
        raw.network_rate = 9999.0;
        raw.memory_rwx_ratio = 5.0;
        auto n = gcad::BehaviorScorer::normalize(raw);
        return n.api_call_entropy <= 1.0 && n.network_rate <= 1.0 && n.memory_rwx_ratio <= 1.0;
    });

    register_test("bml_normalize_preserves_small", [] {
        gcad::BehaviorFeatures raw;
        raw.api_call_entropy = 4.0;
        auto n = gcad::BehaviorScorer::normalize(raw);
        return std::abs(n.api_call_entropy - 0.5) < 0.001;
    });

    register_test("bml_explain_identifies_top_factors", [] {
        gcad::BehaviorFeatures f;
        f.injection_indicators = 1.0;
        f.privilege_escalation = 1.0;
        auto w = gcad::BehaviorScorer::default_model();
        auto s = gcad::BehaviorScorer::explain(f, w);
        return s.find("injection") != std::string::npos
            && s.find("privilege") != std::string::npos;
    });

    register_test("bml_explain_clean_shows_none", [] {
        gcad::BehaviorFeatures f;
        auto w = gcad::BehaviorScorer::default_model();
        auto s = gcad::BehaviorScorer::explain(f, w);
        return s.find("none significant") != std::string::npos;
    });

    register_test("bml_feature_accessor_roundtrip", [] {
        gcad::BehaviorFeatures f;
        for (size_t i = 0; i < gcad::BehaviorFeatures::FEATURE_COUNT; ++i)
            f.set(i, static_cast<double>(i + 1));
        for (size_t i = 0; i < gcad::BehaviorFeatures::FEATURE_COUNT; ++i)
            if (std::abs(f.at(i) - static_cast<double>(i + 1)) > 0.001) return false;
        return true;
    });

    register_test("bml_feature_names_valid", [] {
        for (size_t i = 0; i < gcad::BehaviorFeatures::FEATURE_COUNT; ++i) {
            auto name = gcad::BehaviorScorer::feature_name(i);
            if (!name || std::string(name).empty()) return false;
        }
        return std::string(gcad::BehaviorScorer::feature_name(999)) == "unknown";
    });

    register_test("bml_score_records_result", [] {
        gcad::BehaviorScorer bs;
        gcad::BehaviorFeatures f;
        f.file_write_rate = 5;
        bs.score(1234, "test.exe", f);
        auto recent = bs.recent_scores();
        return recent.size() == 1 && recent[0].pid == 1234;
    });

    register_test("bml_score_malicious_fires_threat", [] {
        gcad::BehaviorScorer bs;
        bool fired = false;
        bs.on_threat([&](gcad::ThreatEvent) { fired = true; });
        gcad::BehaviorFeatures f;
        f.injection_indicators = 1.0;
        f.evasion_indicators = 1.0;
        f.privilege_escalation = 1.0;
        f.encryption_indicators = 1.0;
        f.memory_rwx_ratio = 0.9;
        bs.score(999, "evil.exe", f);
        return fired;
    });

    register_test("bml_set_model_changes_weights", [] {
        gcad::BehaviorScorer bs;
        auto w = gcad::BehaviorScorer::default_model();
        w.bias = 5.0;
        bs.set_model(w);
        return std::abs(bs.model().bias - 5.0) < 0.001;
    });

    register_test("bml_start_stop", [] {
        gcad::BehaviorScorer bs;
        if (bs.running()) return false;
        bs.start();
        if (!bs.running()) return false;
        auto s = bs.status();
        if (s.name != "BehaviorML") return false;
        bs.stop();
        return !bs.running();
    });

    register_test("bml_score_id_unique", [] {
        gcad::BehaviorScorer bs;
        gcad::BehaviorFeatures f;
        auto r1 = bs.score(1, "a.exe", f);
        auto r2 = bs.score(2, "b.exe", f);
        return r1.id != r2.id;
    });

    register_test("bml_default_model_sane", [] {
        auto w = gcad::BehaviorScorer::default_model();
        if (w.bias >= 0) return false;
        if (w.threshold_suspicious >= w.threshold_malicious) return false;
        for (size_t i = 0; i < gcad::BehaviorFeatures::FEATURE_COUNT; ++i)
            if (w.weights[i] <= 0) return false;
        return true;
    });
}
