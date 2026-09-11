#include "gcad/common.hpp"
#include "gcad/security/observation.hpp"
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
}
