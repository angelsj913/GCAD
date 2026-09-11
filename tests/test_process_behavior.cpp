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
}
