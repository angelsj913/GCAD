#include "gcad/common.hpp"
#include "gcad/security/etw_kernel_process_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

// FILETIME-shaped synthetic ticks. Real values come from GetProcessTimes/ETW
// CreateTime fields; only relative order matters for this pure comparison.
constexpr uint64_t EARLIER = 100'000'000ull;
constexpr uint64_t LATER   = 200'000'000ull;

} // namespace

void register_etw_kernel_process_tests() {
    register_test("etw_kernel_process_flags_parent_created_after_child", [] {
        return gcad::security::EtwKernelProcessEngine::is_impossible_parent_order(EARLIER, LATER);
    });

    register_test("etw_kernel_process_allows_parent_created_before_child", [] {
        return !gcad::security::EtwKernelProcessEngine::is_impossible_parent_order(LATER, EARLIER);
    });

    register_test("etw_kernel_process_allows_unknown_timestamps", [] {
        if (gcad::security::EtwKernelProcessEngine::is_impossible_parent_order(0, LATER)) return false;
        if (gcad::security::EtwKernelProcessEngine::is_impossible_parent_order(EARLIER, 0)) return false;
        return !gcad::security::EtwKernelProcessEngine::is_impossible_parent_order(0, 0);
    });

    register_test("etw_kernel_process_lineage_observation_is_valid_and_scoped", [] {
        const auto observation = gcad::security::EtwKernelProcessEngine::make_lineage_observation(
            4321, 9999, "C:/Windows/System32/spoofed.exe");
        if (!observation.valid()) return false;
        if (observation.kind != gcad::security::ObservationKind::PROCESS_LINEAGE) return false;
        if (observation.process_id != 4321) return false;
        if (observation.source_id != "etw-kernel-process") return false;
        if (observation.suggested_level != gcad::ThreatLevel::HIGH) return false;
        return observation.confidence >= 0.8 && observation.confidence <= 1.0;
    });

    register_test("etw_kernel_process_engine_lifecycle_never_fabricates_or_hangs", [] {
        gcad::security::EtwKernelProcessEngine engine;
        bool observed_anything = false;
        engine.on_observation([&](const gcad::security::SecurityObservation&) {
            observed_anything = true;
        });

        const auto rc = engine.start();
        if (rc != gcad::ErrorCode::OK) {
            // No real-time ETW session privilege in this environment: must report
            // reality honestly rather than pretend to run.
            return !engine.running();
        }
        // Started for real: must be idempotent and must stop cleanly without a
        // fabricated observation appearing from lifecycle alone.
        const auto rc2 = engine.start();
        if (rc2 != gcad::ErrorCode::OK) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return !observed_anything;
    });
}
