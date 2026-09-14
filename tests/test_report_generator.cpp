#include "gcad/report/report_generator.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/alert/alert_manager.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_report_generator_tests() {
    register_test("report_collect_basic", [] {
        gcad::EngineManager em;
        auto data = gcad::report::ReportGenerator::collect(em, nullptr, 3661);
        if (data.gcad_version.empty()) return false;
        if (data.generated_at.empty()) return false;
        if (data.uptime_seconds != 3661) return false;
        if (data.engines.empty()) return false;
        return true;
    });

    register_test("report_collect_with_alert_manager", [] {
        gcad::EngineManager em;
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        gcad::ThreatEvent ev;
        ev.level = gcad::ThreatLevel::HIGH;
        ev.category = gcad::ThreatCategory::YARA_RULE_MATCH;
        ev.description = "test";
        ev.timestamp = std::chrono::system_clock::now();
        am.push(ev);
        auto data = gcad::report::ReportGenerator::collect(em, &am);
        if (data.total_alerts != 1) return false;
        if (data.unacknowledged_alerts != 1) return false;
        return true;
    });

    register_test("report_generate_html_contains_structure", [] {
        gcad::report::ReportData data;
        data.generated_at = "2026-01-01 00:00:00";
        data.gcad_version = "1.0.0";
        data.uptime_seconds = 7200;
        data.engines.push_back({"TestEngine", true, 100, 5});
        data.total_events = 100;
        data.total_threats = 5;

        auto html = gcad::report::ReportGenerator::generate_html(data);
        if (html.find("<!DOCTYPE html>") == std::string::npos) return false;
        if (html.find("GCAD Security Report") == std::string::npos) return false;
        if (html.find("TestEngine") == std::string::npos) return false;
        if (html.find("ACTIVE") == std::string::npos) return false;
        if (html.find("2026-01-01") == std::string::npos) return false;
        return true;
    });

    register_test("report_generate_html_escapes_html", [] {
        gcad::report::ReportData data;
        data.generated_at = "2026-01-01";
        data.gcad_version = "1.0.0";
        data.engines.push_back({"<script>alert(1)</script>", true, 0, 0});

        auto html = gcad::report::ReportGenerator::generate_html(data);
        if (html.find("<script>alert(1)</script>") != std::string::npos) return false;
        if (html.find("&lt;script&gt;") == std::string::npos) return false;
        return true;
    });

    register_test("report_generate_text_contains_sections", [] {
        gcad::report::ReportData data;
        data.generated_at = "2026-01-01 00:00:00";
        data.gcad_version = "1.0.0";
        data.uptime_seconds = 3600;
        data.engines.push_back({"PMSR", true, 50, 2});
        data.engines.push_back({"FIM", false, 10, 0});
        data.total_events = 60;
        data.total_threats = 2;

        auto text = gcad::report::ReportGenerator::generate_text(data);
        if (text.find("GCAD Security Report") == std::string::npos) return false;
        if (text.find("SUMMARY") == std::string::npos) return false;
        if (text.find("ENGINE STATUS") == std::string::npos) return false;
        if (text.find("PMSR: ACTIVE") == std::string::npos) return false;
        if (text.find("FIM: STOPPED") == std::string::npos) return false;
        if (text.find("End of GCAD Report") == std::string::npos) return false;
        return true;
    });

    register_test("report_generate_text_with_events", [] {
        gcad::report::ReportData data;
        data.generated_at = "2026-01-01";
        data.gcad_version = "1.0.0";

        gcad::ThreatEvent ev;
        ev.level = gcad::ThreatLevel::HIGH;
        ev.category = gcad::ThreatCategory::DNS_TUNNEL;
        ev.description = "Suspicious DNS activity";
        ev.timestamp = std::chrono::system_clock::now();
        data.recent_events.push_back(ev);

        auto text = gcad::report::ReportGenerator::generate_text(data);
        if (text.find("DETECTION TIMELINE") == std::string::npos) return false;
        if (text.find("Suspicious DNS activity") == std::string::npos) return false;
        return true;
    });

    register_test("report_save_to_file", [] {
        auto path = std::filesystem::temp_directory_path() / "gcad_report_test.html";
        std::string content = "<html><body>test</body></html>";
        bool ok = gcad::report::ReportGenerator::save_to_file(content, path);
        if (!ok) return false;

        std::ifstream f(path);
        std::string read_back((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return read_back == content;
    });

    register_test("report_save_to_file_nonexistent_dir", [] {
        auto path = std::filesystem::temp_directory_path() / "gcad_report_subdir" / "report.html";
        bool ok = gcad::report::ReportGenerator::save_to_file("test", path);
        std::error_code ec;
        std::filesystem::remove_all(path.parent_path(), ec);
        return ok;
    });

    register_test("report_category_label_all_valid", [] {
        using C = gcad::ThreatCategory;
        C cats[] = {C::NONE, C::MEMORY_INJECTION, C::PROCESS_HOLLOW, C::DNS_TUNNEL,
                    C::REGISTRY_TAMPER, C::YARA_RULE_MATCH, C::FILE_INTEGRITY_VIOLATION,
                    C::DGA_DOMAIN, C::RANSOMWARE, C::DIRECT_SYSCALL};
        for (auto cat : cats) {
            auto* label = gcad::report::ReportGenerator::category_label(cat);
            if (!label || std::string(label).empty()) return false;
        }
        return true;
    });

    register_test("report_level_label_all_valid", [] {
        using L = gcad::ThreatLevel;
        L levels[] = {L::SAFE, L::LOW, L::MEDIUM, L::HIGH, L::CRITICAL};
        for (auto lvl : levels) {
            auto* label = gcad::report::ReportGenerator::level_label(lvl);
            if (!label || std::string(label).empty()) return false;
        }
        return true;
    });

    register_test("report_html_with_findings", [] {
        gcad::report::ReportData data;
        data.generated_at = "2026-01-01";
        data.gcad_version = "1.0.0";

        gcad::security::SecurityFinding f;
        f.level = gcad::ThreatLevel::HIGH;
        f.risk_score = 85;
        f.rationale = "Suspicious registry modification detected";
        data.findings.push_back(f);

        auto html = gcad::report::ReportGenerator::generate_html(data);
        if (html.find("Security Findings") == std::string::npos) return false;
        if (html.find("Suspicious registry modification") == std::string::npos) return false;
        return true;
    });

    register_test("report_empty_data_no_crash", [] {
        gcad::report::ReportData data;
        data.generated_at = "2026-01-01";
        data.gcad_version = "1.0.0";
        auto html = gcad::report::ReportGenerator::generate_html(data);
        auto text = gcad::report::ReportGenerator::generate_text(data);
        return !html.empty() && !text.empty();
    });

    register_test("report_mitre_ttp_mapping_coverage", [] {
        using gcad::ThreatCategory;
        using gcad::report::ReportGenerator;
        auto ttp_hollow = ReportGenerator::mitre_ttp_for_category(ThreatCategory::PROCESS_HOLLOW);
        auto ttp_ransom = ReportGenerator::mitre_ttp_for_category(ThreatCategory::RANSOMWARE);
        auto ttp_lsass = ReportGenerator::mitre_ttp_for_category(ThreatCategory::CREDENTIAL_DUMP);
        auto ttp_amsi = ReportGenerator::mitre_ttp_for_category(ThreatCategory::EVASION_AMSI);
        auto ttp_byovd = ReportGenerator::mitre_ttp_for_category(ThreatCategory::KERNEL_ATTACK);

        return std::string(ttp_hollow.technique_id) == "T1055.012" &&
               std::string(ttp_ransom.technique_id) == "T1486" &&
               std::string(ttp_lsass.technique_id) == "T1003.001" &&
               std::string(ttp_amsi.technique_id) == "T1562.001" &&
               std::string(ttp_byovd.technique_id) == "T1068";
    });

    register_test("report_html_and_text_contain_mitre_attack_breakdown", [] {
        using gcad::ThreatCategory;
        using gcad::report::ReportGenerator;
        gcad::report::ReportData data;
        data.generated_at = "2026-01-01 12:00:00";
        data.gcad_version = "1.0.0";
        data.category_histogram.push_back({ThreatCategory::PROCESS_HOLLOW, 3});
        data.category_histogram.push_back({ThreatCategory::RANSOMWARE, 1});

        auto html = ReportGenerator::generate_html(data);
        auto text = ReportGenerator::generate_text(data);

        return html.find("MITRE ATT&amp;CK") != std::string::npos &&
               html.find("T1055.012") != std::string::npos &&
               html.find("T1486") != std::string::npos &&
               text.find("MITRE ATT&CK MAPPING") != std::string::npos &&
               text.find("[T1055.012]") != std::string::npos &&
               text.find("[T1486]") != std::string::npos;
    });
}
