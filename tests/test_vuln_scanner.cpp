#include "gcad/engines/vuln_scanner_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_vuln_scanner_tests() {
    register_test("vuln_parse_version_simple", [] {
        auto v = gcad::VulnScannerEngine::parse_version("1.2.3");
        return v.size() == 3 && v[0] == 1 && v[1] == 2 && v[2] == 3;
    });

    register_test("vuln_parse_version_long", [] {
        auto v = gcad::VulnScannerEngine::parse_version("123.0.6312.86");
        return v.size() == 4 && v[0] == 123 && v[3] == 86;
    });

    register_test("vuln_parse_version_empty", [] {
        auto v = gcad::VulnScannerEngine::parse_version("");
        return v.empty();
    });

    register_test("vuln_version_less_true", [] {
        return gcad::VulnScannerEngine::version_less_than("1.2.3", "1.2.4");
    });

    register_test("vuln_version_less_false_equal", [] {
        return !gcad::VulnScannerEngine::version_less_than("1.2.3", "1.2.3");
    });

    register_test("vuln_version_less_false_greater", [] {
        return !gcad::VulnScannerEngine::version_less_than("2.0.0", "1.9.9");
    });

    register_test("vuln_version_less_major", [] {
        return gcad::VulnScannerEngine::version_less_than("1.9.9", "2.0.0");
    });

    register_test("vuln_version_less_unequal_length", [] {
        return gcad::VulnScannerEngine::version_less_than("1.2", "1.2.1");
    });

    register_test("vuln_severity_critical", [] {
        return gcad::VulnScannerEngine::severity_to_level("CRITICAL", 9.8) == gcad::ThreatLevel::CRITICAL;
    });

    register_test("vuln_severity_high", [] {
        return gcad::VulnScannerEngine::severity_to_level("HIGH", 7.5) == gcad::ThreatLevel::HIGH;
    });

    register_test("vuln_severity_medium", [] {
        return gcad::VulnScannerEngine::severity_to_level("MEDIUM", 5.5) == gcad::ThreatLevel::MEDIUM;
    });

    register_test("vuln_severity_low", [] {
        return gcad::VulnScannerEngine::severity_to_level("LOW", 2.0) == gcad::ThreatLevel::LOW;
    });

    register_test("vuln_severity_by_cvss_only", [] {
        return gcad::VulnScannerEngine::severity_to_level("", 9.5) == gcad::ThreatLevel::CRITICAL;
    });

    register_test("vuln_default_db_not_empty", [] {
        gcad::VulnScannerEngine vs;
        return vs.vuln_db_size() >= 10;
    });

    register_test("vuln_add_vuln", [] {
        gcad::VulnScannerEngine vs;
        auto before = vs.vuln_db_size();
        gcad::VulnEntry v{"TEST-001", "TestApp", "1.0.0", "LOW", 2.0, "test", "update"};
        vs.add_vuln(v);
        return vs.vuln_db_size() == before + 1;
    });

    register_test("vuln_scan_finds_match", [] {
        gcad::VulnScannerEngine vs;
        std::vector<gcad::SoftwareInfo> sw;
        sw.push_back({"OpenSSL 3.0.10", "OpenSSL", "3.0.10", "C:\\OpenSSL", "test"});
        auto results = vs.scan(sw);
        return results.size() == 1 && results[0].vuln.vuln_id == "GCAD-2024-0001";
    });

    register_test("vuln_scan_no_match_current", [] {
        gcad::VulnScannerEngine vs;
        std::vector<gcad::SoftwareInfo> sw;
        sw.push_back({"OpenSSL 3.1.0", "OpenSSL", "3.1.0", "C:\\OpenSSL", "test"});
        auto results = vs.scan(sw);
        return results.empty();
    });

    register_test("vuln_scan_fires_threat", [] {
        gcad::VulnScannerEngine vs;
        bool fired = false;
        vs.on_threat([&](gcad::ThreatEvent) { fired = true; });
        std::vector<gcad::SoftwareInfo> sw;
        sw.push_back({"Git for Windows", "Git", "2.40.0", "C:\\Git", "test"});
        vs.scan(sw);
        return fired;
    });

    register_test("vuln_recent_matches", [] {
        gcad::VulnScannerEngine vs;
        std::vector<gcad::SoftwareInfo> sw;
        sw.push_back({"curl 8.5.0", "curl", "8.5.0", "", "test"});
        vs.scan(sw);
        auto recent = vs.recent_matches();
        return recent.size() == 1;
    });

    register_test("vuln_db_roundtrip", [] {
        auto path = std::filesystem::temp_directory_path() / "gcad_test_vulndb.txt";
        {
            gcad::VulnScannerEngine vs;
            vs.save_vuln_db(path);
        }
        gcad::VulnScannerEngine vs2;
        auto before = vs2.vuln_db_size();
        vs2.load_vuln_db(path);
        std::filesystem::remove(path);
        return vs2.vuln_db_size() > before;
    });

    register_test("vuln_case_insensitive_match", [] {
        gcad::VulnScannerEngine vs;
        std::vector<gcad::SoftwareInfo> sw;
        sw.push_back({"OPENSSL Library", "OpenSSL", "3.0.10", "", "test"});
        auto results = vs.scan(sw);
        return results.size() == 1;
    });

    register_test("vuln_match_ids_unique", [] {
        gcad::VulnScannerEngine vs;
        std::vector<gcad::SoftwareInfo> sw;
        sw.push_back({"OpenSSL 3.0.10", "OpenSSL", "3.0.10", "", "test"});
        sw.push_back({"curl 8.5.0", "curl", "8.5.0", "", "test"});
        auto results = vs.scan(sw);
        if (results.size() < 2) return false;
        return results[0].id != results[1].id;
    });

    register_test("vuln_start_stop", [] {
        gcad::VulnScannerEngine vs;
        if (vs.running()) return false;
        vs.start();
        if (!vs.running()) return false;
        auto s = vs.status();
        if (s.name != "VulnScanner") return false;
        vs.stop();
        return !vs.running();
    });
}
