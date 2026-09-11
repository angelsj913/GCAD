#include "gcad/common.hpp"
#include "gcad/security/observation.hpp"
#include "gcad/security/correlation_engine.hpp"
#include "gcad/security/security_pipeline.hpp"
#include "gcad/security/policy.hpp"
#include "gcad/security/telemetry_bus.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

gcad::security::SecurityObservation fixture_observation() {
    gcad::security::SecurityObservation observation{};
    observation.source_id = "unit-test";
    observation.kind = gcad::security::ObservationKind::ARTIFACT_SIGNATURE;
    observation.suggested_level = gcad::ThreatLevel::HIGH;
    observation.confidence = 0.8;
    observation.evidence = "controlled test observation";
    observation.process_id = 4242;
    observation.process_name = "fixture.exe";
    observation.file_path = "C:/Temp/fixture.exe";
    return observation;
}

gcad::security::SecurityFinding critical_signature_finding(std::string file_path) {
    gcad::security::SecurityFinding finding{};
    finding.id = 1;
    finding.level = gcad::ThreatLevel::CRITICAL;
    finding.risk_score = 100;
    finding.deterministic_signature = true;
    finding.file_path = std::move(file_path);
    finding.rationale = "controlled critical signature";
    return finding;
}

gcad::security::SecurityObservation observation_from(std::string source_id, double confidence) {
    auto observation = fixture_observation();
    observation.source_id = std::move(source_id);
    observation.confidence = confidence;
    return observation;
}

std::chrono::system_clock::time_point fixed_time() {
    return std::chrono::system_clock::time_point{std::chrono::seconds{1'000}};
}

} // namespace

void register_security_pipeline_tests() {
    register_test("security_observation_rejects_invalid_confidence", [] {
        auto observation = fixture_observation();
        observation.confidence = 1.01;
        return !observation.valid();
    });

    register_test("telemetry_bus_drops_when_capacity_is_reached", [] {
        gcad::security::TelemetryBus bus(1);
        if (bus.publish(fixture_observation()) != gcad::security::PublishResult::ACCEPTED)
            return false;
        if (bus.publish(fixture_observation()) != gcad::security::PublishResult::DROPPED_FULL)
            return false;
        return bus.metrics().dropped_full == 1;
    });

    register_test("telemetry_bus_rejects_publish_after_close", [] {
        gcad::security::TelemetryBus bus(1);
        bus.close();
        return bus.publish(fixture_observation()) == gcad::security::PublishResult::CLOSED;
    });

    register_test("policy_only_candidates_critical_deterministic_signatures", [] {
        gcad::security::PolicyEngine policy;
        const auto finding = critical_signature_finding("C:/Temp/sample.exe");
        if (policy.decide(finding, {}) != gcad::security::ResponseAction::QUARANTINE_CANDIDATE)
            return false;
        return policy.candidate_for(finding, {}).has_value();
    });

    register_test("policy_keeps_protected_target_report_only", [] {
        gcad::security::PolicyEngine policy;
        const auto finding = critical_signature_finding("C:/Windows/System32/notepad.exe");
        if (policy.decide(finding, {}) != gcad::security::ResponseAction::REPORT_ONLY)
            return false;
        return !policy.candidate_for(finding, {}).has_value();
    });

    register_test("correlation_suppresses_same_source_duplicate", [] {
        gcad::security::CorrelationEngine engine({});
        const auto first = engine.ingest(observation_from("artifact", 0.60), fixed_time());
        const auto duplicate = engine.ingest(
            observation_from("artifact", 0.60), fixed_time() + std::chrono::seconds{10});
        return first.has_value() && !duplicate.has_value();
    });

    register_test("correlation_raises_finding_for_independent_sources", [] {
        gcad::security::CorrelationEngine engine({});
        engine.ingest(observation_from("artifact", 0.60), fixed_time());
        const auto correlated = engine.ingest(
            observation_from("process", 0.65), fixed_time() + std::chrono::seconds{1});
        return correlated.has_value() && correlated->contributing_sources.size() == 2 &&
               correlated->risk_score > 60;
    });

    register_test("correlation_finding_marks_deterministic_when_any_source_is", [] {
        gcad::security::CorrelationEngine engine({});
        auto observation = observation_from("syscall-guard", 0.90);
        observation.deterministic = true;
        const auto finding = engine.ingest(observation, fixed_time());
        return finding.has_value() && finding->deterministic_signature;
    });

    register_test("correlation_finding_stays_non_deterministic_without_deterministic_source", [] {
        gcad::security::CorrelationEngine engine({});
        auto observation = observation_from("etg-ri", 0.60);
        observation.deterministic = false;
        const auto finding = engine.ingest(observation, fixed_time());
        return finding.has_value() && !finding->deterministic_signature;
    });

    register_test("correlation_finding_stays_deterministic_once_any_source_was", [] {
        gcad::security::CorrelationEngine engine({});
        auto first = observation_from("etg-ri", 0.60);
        first.deterministic = false;
        engine.ingest(first, fixed_time());

        auto second = observation_from("syscall-guard", 0.90);
        second.deterministic = true;
        const auto finding = engine.ingest(second, fixed_time() + std::chrono::seconds{1});
        return finding.has_value() && finding->deterministic_signature;
    });

    register_test("pipeline_drains_accepted_observation_on_stop", [] {
        gcad::security::SecurityPipeline pipeline(8, {});
        if (pipeline.start() != gcad::ErrorCode::OK) return false;
        if (pipeline.publish(fixture_observation()) != gcad::security::PublishResult::ACCEPTED)
            return false;
        if (pipeline.stop() != gcad::ErrorCode::OK) return false;
        return !pipeline.recent_findings(1).empty();
    });
}
