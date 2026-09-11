#include "gcad/common.hpp"
#include "gcad/security/etw_kernel_process_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

// FILETIME-shaped synthetic ticks. Real values come from GetProcessTimes/ETW
// CreateTime fields; only relative order matters for this pure comparison.
constexpr uint64_t EARLIER = 100'000'000ull;
constexpr uint64_t LATER   = 200'000'000ull;

// Builds a synthetic Kernel-Process ProcessStart UserData buffer matching the
// documented manifest field order decode_process_start() assumes -- exercises
// the decoder's own logic against a known-shape buffer; it does not itself
// prove the assumed layout matches a real ETW session's bytes.
std::vector<uint8_t> build_process_start_buffer(uint32_t pid, uint64_t create_time, uint32_t parent_pid,
                                                const std::u16string& image_name) {
    std::vector<uint8_t> buf(40, 0);
    std::memcpy(buf.data() + 0, &pid, sizeof(pid));
    std::memcpy(buf.data() + 12, &create_time, sizeof(create_time));
    std::memcpy(buf.data() + 20, &parent_pid, sizeof(parent_pid));

    for (char16_t c : image_name) {
        buf.push_back(static_cast<uint8_t>(c & 0xFF));
        buf.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    buf.push_back(0);
    buf.push_back(0); // NUL terminator
    return buf;
}

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
        if (!observation.deterministic) return false; // CreateTime order is an exact proof, not a guess
        return observation.confidence >= 0.8 && observation.confidence <= 1.0;
    });

    register_test("etw_kernel_process_decode_process_start_reads_fixed_fields", [] {
        const auto buf = build_process_start_buffer(4242, EARLIER, 9999, u"C:\\Temp\\evil.exe");
        const auto decoded = gcad::security::EtwKernelProcessEngine::decode_process_start(buf.data(), buf.size());
        if (!decoded) return false;
        return decoded->pid == 4242 && decoded->parent_pid == 9999 &&
               decoded->create_time_filetime == EARLIER && decoded->image_name == "C:\\Temp\\evil.exe";
    });

    register_test("etw_kernel_process_decode_process_start_rejects_short_buffer", [] {
        std::vector<uint8_t> too_short(39, 0);
        return !gcad::security::EtwKernelProcessEngine::decode_process_start(
            too_short.data(), too_short.size()).has_value();
    });

    register_test("etw_kernel_process_decode_process_start_rejects_zero_pid", [] {
        const auto buf = build_process_start_buffer(0, EARLIER, 9999, u"");
        return !gcad::security::EtwKernelProcessEngine::decode_process_start(buf.data(), buf.size()).has_value();
    });

    register_test("etw_kernel_process_decode_process_start_handles_missing_image_name", [] {
        std::vector<uint8_t> buf(40, 0);
        const uint32_t pid = 111;
        std::memcpy(buf.data(), &pid, sizeof(pid));
        const auto decoded = gcad::security::EtwKernelProcessEngine::decode_process_start(buf.data(), buf.size());
        return decoded.has_value() && decoded->pid == 111 && decoded->image_name.empty();
    });

    register_test("etw_kernel_process_decode_process_stop_pid_reads_first_field", [] {
        std::vector<uint8_t> buf(4, 0);
        const uint32_t pid = 777;
        std::memcpy(buf.data(), &pid, sizeof(pid));
        const auto decoded = gcad::security::EtwKernelProcessEngine::decode_process_stop_pid(buf.data(), buf.size());
        return decoded.has_value() && *decoded == 777;
    });

    register_test("etw_kernel_process_decode_process_stop_pid_rejects_short_buffer", [] {
        std::vector<uint8_t> too_short(3, 0);
        return !gcad::security::EtwKernelProcessEngine::decode_process_stop_pid(
            too_short.data(), too_short.size()).has_value();
    });

    register_test("etw_kernel_process_engine_lifecycle_never_fabricates_or_hangs", [] {
        gcad::security::EtwKernelProcessEngine engine;
        bool observed_anything = false;
        engine.on_observation([&](const gcad::security::SecurityObservation&) {
            observed_anything = true;
        });
        // Registered to prove it never crashes when wired, not to assert a
        // count: unrelated processes on the machine may legitimately start
        // during this test's short window, so any count would be flaky.
        engine.on_process_start([](uint32_t, std::string) {});

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
