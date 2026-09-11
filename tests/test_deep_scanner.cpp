#include "gcad/common.hpp"
#include "gcad/scanner/deep_scanner.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

std::filesystem::path make_temp_dir(const char* name) {
    auto dir = std::filesystem::temp_directory_path() / name;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    return dir;
}

// Same fixture shape as test_artifact_trust.cpp: an MZ header with an
// out-of-range e_lfanew, which DeepScanner's own check_pe_header() does not
// flag at all (it just fails the offset bounds check silently) but
// ArtifactTrustEngine::inspect() reports as INVALID_PE.
void write_invalid_pe_fixture(const std::filesystem::path& path) {
    std::array<uint8_t, 64> data{};
    data[0] = 'M';
    data[1] = 'Z';
    const uint32_t invalid_offset = 0xFFFF'FFF0u;
    std::memcpy(data.data() + 60, &invalid_offset, sizeof(invalid_offset));
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

bool wait_for_scan_to_finish(gcad::DeepScanner& scanner) {
    for (int i = 0; i < 100 && scanner.is_scanning(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return !scanner.is_scanning();
}

} // namespace

void register_deep_scanner_tests() {
    register_test("deep_scanner_escalates_invalid_pe_to_artifact_trust_observation", [] {
        const auto dir = make_temp_dir("gcad-deepscan-artifacttrust");
        write_invalid_pe_fixture(dir / "sample.exe");

        gcad::DeepScanner scanner;
        std::mutex observed_mtx;
        std::vector<gcad::security::SecurityObservation> observed;
        scanner.on_observation([&](gcad::security::SecurityObservation obs) {
            std::lock_guard lk(observed_mtx);
            observed.push_back(std::move(obs));
        });

        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        const bool finished = wait_for_scan_to_finish(scanner);

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        if (!finished) return false;

        std::lock_guard lk(observed_mtx);
        return std::any_of(observed.begin(), observed.end(), [](const auto& o) {
            return o.kind == gcad::security::ObservationKind::INVALID_PE;
        });
    });

    register_test("deep_scanner_skips_artifact_trust_escalation_without_observation_callback", [] {
        // No on_observation() registered: scanning an executable must not
        // crash just because there is nowhere to send the observation.
        const auto dir = make_temp_dir("gcad-deepscan-noobserver");
        write_invalid_pe_fixture(dir / "sample.exe");

        gcad::DeepScanner scanner;
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        const bool finished = wait_for_scan_to_finish(scanner);

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        return finished;
    });
}
