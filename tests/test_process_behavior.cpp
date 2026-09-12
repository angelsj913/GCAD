#include "gcad/common.hpp"
#include "gcad/security/process_behavior_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

bool has_high_confidence_injection_claim(
    const std::vector<gcad::security::SecurityObservation>& observations) {
    return std::any_of(observations.begin(), observations.end(), [](const auto& observation) {
        return observation.kind == gcad::security::ObservationKind::PROCESS_MEMORY &&
               observation.confidence >= 0.8;
    });
}

} // namespace

void register_process_behavior_tests() {
    register_test("process_behavior_does_not_flag_current_process_without_concrete_signal", [] {
#ifdef GCAD_PLATFORM_WINDOWS
        gcad::security::ProcessBehaviorEngine engine;
        const auto observations = engine.inspect_pid(GetCurrentProcessId());
        return !has_high_confidence_injection_claim(observations);
#else
        return true;
#endif
    });

    register_test("process_behavior_returns_empty_for_nonexistent_pid", [] {
        gcad::security::ProcessBehaviorEngine engine;
        const auto observations = engine.inspect_pid(0xFFFFFFFF);
        return observations.empty();
    });

    register_test("process_behavior_observations_have_valid_fields", [] {
#ifdef GCAD_PLATFORM_WINDOWS
        gcad::security::ProcessBehaviorEngine engine;
        const auto observations = engine.inspect_pid(GetCurrentProcessId());
        for (auto& obs : observations) {
            if (obs.source_id.empty()) return false;
            if (obs.evidence.empty()) return false;
            if (obs.confidence < 0.0 || obs.confidence > 1.0) return false;
        }
        return true;
#else
        return true;
#endif
    });

    register_test("process_behavior_inspect_pid_4", [] {
#ifdef GCAD_PLATFORM_WINDOWS
        gcad::security::ProcessBehaviorEngine engine;
        const auto observations = engine.inspect_pid(4);
        return true;
#else
        return true;
#endif
    });

    register_test("process_behavior_engine_stateless", [] {
        gcad::security::ProcessBehaviorEngine e1;
        gcad::security::ProcessBehaviorEngine e2;
#ifdef GCAD_PLATFORM_WINDOWS
        const auto obs1 = e1.inspect_pid(GetCurrentProcessId());
        const auto obs2 = e2.inspect_pid(GetCurrentProcessId());
        return obs1.size() == obs2.size();
#else
        return true;
#endif
    });
}
