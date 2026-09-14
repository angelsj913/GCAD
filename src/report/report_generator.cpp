#include "gcad/report/report_generator.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/alert/alert_manager.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>

namespace gcad::report {

namespace {

std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef GCAD_PLATFORM_WINDOWS
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

std::string format_event_time(std::chrono::system_clock::time_point tp) {
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
#ifdef GCAD_PLATFORM_WINDOWS
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            default:   out += c;
        }
    }
    return out;
}

const char* level_color(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::SAFE:     return "#39d353";
        case ThreatLevel::LOW:      return "#58a6ff";
        case ThreatLevel::MEDIUM:   return "#d29922";
        case ThreatLevel::HIGH:     return "#f0883e";
        case ThreatLevel::CRITICAL: return "#f85149";
        default:                    return "#8b949e";
    }
}

} // namespace

const char* ReportGenerator::level_label(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::SAFE:     return "SAFE";
        case ThreatLevel::LOW:      return "LOW";
        case ThreatLevel::MEDIUM:   return "MEDIUM";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default:                    return "UNKNOWN";
    }
}

const char* ReportGenerator::category_label(ThreatCategory cat) {
    switch (cat) {
        case ThreatCategory::NONE:                   return "None";
        case ThreatCategory::MEMORY_INJECTION:       return "Memory Injection";
        case ThreatCategory::PROCESS_HOLLOW:         return "Process Hollowing";
        case ThreatCategory::DLL_INJECTION:          return "DLL Injection";
        case ThreatCategory::APC_INJECTION:          return "APC Injection";
        case ThreatCategory::REFLECTIVE_LOAD:        return "Reflective Loading";
        case ThreatCategory::SHELLCODE:              return "Shellcode";
        case ThreatCategory::NETWORK_SCAN:           return "Network Scan";
        case ThreatCategory::SYN_FLOOD:              return "SYN Flood";
        case ThreatCategory::UDP_FLOOD:              return "UDP Flood";
        case ThreatCategory::DNS_TUNNEL:             return "DNS Tunnel";
        case ThreatCategory::ARP_POISON:             return "ARP Poisoning";
        case ThreatCategory::ICMP_COVERT:            return "ICMP Covert Channel";
        case ThreatCategory::RAW_SOCKET_PROBE:       return "Raw Socket Probe";
        case ThreatCategory::RANSOMWARE:             return "Ransomware";
        case ThreatCategory::FILE_ENCRYPT:           return "File Encryption";
        case ThreatCategory::REGISTRY_TAMPER:        return "Registry Tamper";
        case ThreatCategory::BACKDOOR_ACCOUNT:       return "Backdoor Account";
        case ThreatCategory::EVASION_AMSI:           return "AMSI Evasion";
        case ThreatCategory::EVASION_ETW:            return "ETW Evasion";
        case ThreatCategory::EVASION_UNHOOK:         return "Unhooking";
        case ThreatCategory::DIRECT_SYSCALL:         return "Direct Syscall";
        case ThreatCategory::PPID_SPOOF:             return "PPID Spoofing";
        case ThreatCategory::KERBEROS_ATTACK:        return "Kerberos Attack";
        case ThreatCategory::NTLM_COERCE:            return "NTLM Coerce";
        case ThreatCategory::CREDENTIAL_DUMP:        return "Credential Dump";
        case ThreatCategory::ENTROPY_ANOMALY:        return "Entropy Anomaly";
        case ThreatCategory::SUSPICIOUS_BINARY:      return "Suspicious Binary";
        case ThreatCategory::FILELESS_EXEC:          return "Fileless Execution";
        case ThreatCategory::ANTI_FORENSIC:          return "Anti-Forensic";
        case ThreatCategory::DGA_DOMAIN:             return "DGA Domain";
        case ThreatCategory::FILE_INTEGRITY_VIOLATION: return "File Integrity Violation";
        case ThreatCategory::YARA_RULE_MATCH:        return "YARA Rule Match";
        case ThreatCategory::KERNEL_ATTACK:          return "Kernel / BYOVD Attack";
        default:                                     return "Unknown";
    }
}

MitreTtpInfo ReportGenerator::mitre_ttp_for_category(ThreatCategory cat) {
    switch (cat) {
        case ThreatCategory::MEMORY_INJECTION:
            return {"Defense Evasion", "T1055", "Process Injection"};
        case ThreatCategory::PROCESS_HOLLOW:
            return {"Defense Evasion", "T1055.012", "Process Hollowing"};
        case ThreatCategory::DLL_INJECTION:
            return {"Defense Evasion", "T1055.001", "Dynamic-link Library Injection"};
        case ThreatCategory::APC_INJECTION:
            return {"Defense Evasion", "T1055.004", "Asynchronous Procedure Call"};
        case ThreatCategory::REFLECTIVE_LOAD:
            return {"Defense Evasion", "T1620", "Reflective Code Loading"};
        case ThreatCategory::SHELLCODE:
            return {"Execution", "T1059", "Command and Scripting Interpreter"};
        case ThreatCategory::NETWORK_SCAN:
            return {"Discovery", "T1046", "Network Service Discovery"};
        case ThreatCategory::SYN_FLOOD:
            return {"Impact", "T1498.001", "Direct Network Flood (SYN)"};
        case ThreatCategory::UDP_FLOOD:
            return {"Impact", "T1498.001", "Direct Network Flood (UDP)"};
        case ThreatCategory::DNS_TUNNEL:
            return {"Command and Control", "T1071.004", "DNS Communication"};
        case ThreatCategory::ARP_POISON:
            return {"Credential Access", "T1557.002", "ARP Spoofing"};
        case ThreatCategory::ICMP_COVERT:
            return {"Command and Control", "T1095", "Non-Application Layer Protocol"};
        case ThreatCategory::RAW_SOCKET_PROBE:
            return {"Discovery", "T1046", "Raw Socket Network Discovery"};
        case ThreatCategory::RANSOMWARE:
        case ThreatCategory::FILE_ENCRYPT:
            return {"Impact", "T1486", "Data Encrypted for Impact"};
        case ThreatCategory::REGISTRY_TAMPER:
            return {"Defense Evasion", "T1112", "Modify Registry"};
        case ThreatCategory::BACKDOOR_ACCOUNT:
            return {"Persistence", "T1136", "Create Account"};
        case ThreatCategory::EVASION_AMSI:
            return {"Defense Evasion", "T1562.001", "Disable or Modify Tools: AMSI"};
        case ThreatCategory::EVASION_ETW:
            return {"Defense Evasion", "T1562.006", "Indicator Blocking: ETW Bypass"};
        case ThreatCategory::EVASION_UNHOOK:
            return {"Defense Evasion", "T1562.001", "Unhooking Native APIs"};
        case ThreatCategory::DIRECT_SYSCALL:
            return {"Defense Evasion", "T1106", "Native API Direct Syscall"};
        case ThreatCategory::PPID_SPOOF:
            return {"Defense Evasion", "T1134.004", "Parent PID Spoofing"};
        case ThreatCategory::KERBEROS_ATTACK:
            return {"Credential Access", "T1558", "Steal or Forge Kerberos Tickets"};
        case ThreatCategory::NTLM_COERCE:
            return {"Credential Access", "T1187", "Forced Authentication"};
        case ThreatCategory::CREDENTIAL_DUMP:
            return {"Credential Access", "T1003.001", "LSASS Memory Dump"};
        case ThreatCategory::ENTROPY_ANOMALY:
            return {"Defense Evasion", "T1027.002", "Software Packing (High Entropy)"};
        case ThreatCategory::SUSPICIOUS_BINARY:
            return {"Execution", "T1204", "User Execution: Malicious File"};
        case ThreatCategory::FILELESS_EXEC:
            return {"Execution", "T1059.001", "PowerShell Fileless Execution"};
        case ThreatCategory::ANTI_FORENSIC:
            return {"Defense Evasion", "T1070", "Indicator Removal"};
        case ThreatCategory::DGA_DOMAIN:
            return {"Command and Control", "T1568.002", "Domain Generation Algorithms"};
        case ThreatCategory::FILE_INTEGRITY_VIOLATION:
            return {"Impact", "T1565.001", "Stored Data Manipulation"};
        case ThreatCategory::YARA_RULE_MATCH:
            return {"Execution", "T1204.002", "Malicious File Signature Match"};
        case ThreatCategory::KERNEL_ATTACK:
            return {"Privilege Escalation", "T1068", "Exploitation for Privilege Escalation (BYOVD)"};
        default:
            return {"General", "T1000", "Unclassified Anomaly"};
    }
}

ReportData ReportGenerator::collect(const EngineManager& em,
                                     const AlertManager* am,
                                     int64_t uptime_seconds) {
    ReportData d;
    d.generated_at    = now_iso();
    d.gcad_version    = std::string(VERSION);
    d.uptime_seconds  = uptime_seconds;

    for (auto& s : em.statuses())
        d.engines.push_back({s.name, s.running, s.events_processed, s.threats_detected});

    d.total_events        = em.total_engine_events();
    d.total_threats       = em.total_threats();
    d.severity_histogram  = em.severity_histogram();
    d.category_histogram  = em.category_histogram();
    d.recent_events       = em.recent_events(100);
    d.findings            = em.recent_security_findings(50);

    if (am) {
        d.total_alerts          = am->total_count();
        d.unacknowledged_alerts = am->unacknowledged_count();
    }

    return d;
}

std::string ReportGenerator::generate_html(const ReportData& data) {
    std::ostringstream o;

    o << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GCAD Security Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif;padding:24px;max-width:1000px;margin:auto}
h1{font-size:24px;margin-bottom:4px}
h2{font-size:18px;color:#58a6ff;margin:24px 0 12px;border-bottom:1px solid #30363d;padding-bottom:6px}
.subtitle{color:#8b949e;margin-bottom:20px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card .label{color:#8b949e;font-size:13px}
.card .value{font-size:28px;font-weight:600;margin-top:4px}
table{width:100%;border-collapse:collapse;margin-bottom:16px}
th{text-align:left;color:#8b949e;font-size:13px;padding:8px;border-bottom:1px solid #30363d}
td{padding:8px;border-bottom:1px solid #21262d;font-size:14px}
tr:hover{background:#161b22}
.level{font-weight:600;font-size:12px;padding:2px 8px;border-radius:3px}
.bar-row{display:flex;align-items:center;gap:8px;margin:4px 0}
.bar-label{width:70px;color:#8b949e;font-size:13px}
.bar{height:16px;border-radius:3px}
.bar-value{color:#8b949e;font-size:13px}
.safe{color:#39d353} .low{color:#58a6ff} .medium{color:#d29922} .high{color:#f0883e} .critical{color:#f85149}
.footer{margin-top:32px;color:#484f58;font-size:12px;text-align:center;border-top:1px solid #21262d;padding-top:12px}
</style>
</head>
<body>
<h1>GCAD Security Report</h1>
<p class="subtitle">Generated: )" << html_escape(data.generated_at)
     << " &mdash; GCAD v" << html_escape(data.gcad_version) << "</p>\n";

    // Summary cards
    auto uptime_min = data.uptime_seconds / 60;
    auto uptime_hr  = uptime_min / 60;
    o << "<div class=\"summary\">\n";
    o << "<div class=\"card\"><div class=\"label\">Engines Online</div><div class=\"value\">";
    size_t running = 0;
    for (auto& e : data.engines) if (e.running) ++running;
    o << running << " / " << data.engines.size() << "</div></div>\n";
    o << "<div class=\"card\"><div class=\"label\">Total Events</div><div class=\"value\">"
      << data.total_events << "</div></div>\n";
    o << "<div class=\"card\"><div class=\"label\">Threats Detected</div><div class=\"value\">"
      << data.total_threats << "</div></div>\n";
    o << "<div class=\"card\"><div class=\"label\">Uptime</div><div class=\"value\">"
      << uptime_hr << "h " << (uptime_min % 60) << "m</div></div>\n";
    if (data.total_alerts > 0) {
        o << "<div class=\"card\"><div class=\"label\">Alerts</div><div class=\"value\">"
          << data.total_alerts << " (" << data.unacknowledged_alerts << " unread)</div></div>\n";
    }
    o << "</div>\n";

    // Engine status table
    o << "<h2>Engine Status</h2>\n<table><tr><th>Engine</th><th>Status</th>"
         "<th>Events</th><th>Threats</th></tr>\n";
    for (auto& e : data.engines) {
        o << "<tr><td>" << html_escape(e.name) << "</td><td class=\""
          << (e.running ? "safe" : "critical") << "\">"
          << (e.running ? "ACTIVE" : "STOPPED") << "</td><td>"
          << e.events_processed << "</td><td>" << e.threats_detected << "</td></tr>\n";
    }
    o << "</table>\n";

    // Severity distribution
    size_t max_sev = 1;
    for (auto v : data.severity_histogram) max_sev = std::max(max_sev, v);
    const char* sev_labels[] = {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    const char* sev_colors[] = {"#39d353", "#58a6ff", "#d29922", "#f0883e", "#f85149"};

    o << "<h2>Severity Distribution</h2>\n";
    for (int i = 0; i < 5; ++i) {
        int pct = static_cast<int>(data.severity_histogram[i] * 100 / max_sev);
        o << "<div class=\"bar-row\"><span class=\"bar-label\">" << sev_labels[i]
          << "</span><div class=\"bar\" style=\"width:" << std::max(pct, 1)
          << "%;background:" << sev_colors[i] << "\"></div><span class=\"bar-value\">"
          << data.severity_histogram[i] << "</span></div>\n";
    }

    // Category breakdown
    if (!data.category_histogram.empty()) {
        o << "<h2>Threat Categories</h2>\n<table><tr><th>Category</th><th>Count</th></tr>\n";
        for (auto& [cat, cnt] : data.category_histogram) {
            o << "<tr><td>" << category_label(cat) << "</td><td>" << cnt << "</td></tr>\n";
        }
        o << "</table>\n";
    }

    // Recent events
    if (!data.recent_events.empty()) {
        o << "<h2>Detection Timeline (last " << data.recent_events.size() << ")</h2>\n"
             "<table><tr><th>Time</th><th>Level</th><th>Category</th><th>Description</th></tr>\n";
        for (auto it = data.recent_events.rbegin(); it != data.recent_events.rend(); ++it) {
            o << "<tr><td>" << format_event_time(it->timestamp) << "</td>"
              << "<td><span class=\"level\" style=\"color:"
              << level_color(it->level) << "\">" << level_label(it->level) << "</span></td>"
              << "<td>" << category_label(it->category) << "</td>"
              << "<td>" << html_escape(it->description) << "</td></tr>\n";
        }
        o << "</table>\n";
    }

    // Security findings
    if (!data.findings.empty()) {
        o << "<h2>Security Findings (" << data.findings.size() << ")</h2>\n"
             "<table><tr><th>Level</th><th>Risk</th><th>Rationale</th></tr>\n";
        for (auto it = data.findings.rbegin(); it != data.findings.rend(); ++it) {
            o << "<tr><td><span class=\"level\" style=\"color:"
              << level_color(it->level) << "\">" << level_label(it->level) << "</span></td>"
              << "<td>" << it->risk_score << "</td>"
              << "<td>" << html_escape(it->rationale) << "</td></tr>\n";
        }
        o << "</table>\n";
    }

    // MITRE ATT&CK Enterprise Matrix Mapping
    o << "<h2>MITRE ATT&amp;CK&reg; Enterprise Matrix Mapping</h2>\n"
         "<table><tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th><th>GCAD Category</th><th>Detections</th></tr>\n";
    if (!data.category_histogram.empty()) {
        for (const auto& [cat, cnt] : data.category_histogram) {
            const auto ttp = mitre_ttp_for_category(cat);
            o << "<tr><td><span class=\"badge\" style=\"background:#21262d;color:#58a6ff;padding:2px 6px;border-radius:4px;\">"
              << html_escape(ttp.tactic) << "</span></td>"
              << "<td><strong>" << html_escape(ttp.technique_id) << "</strong></td>"
              << "<td>" << html_escape(ttp.technique_name) << "</td>"
              << "<td>" << html_escape(category_label(cat)) << "</td>"
              << "<td>" << cnt << "</td></tr>\n";
        }
    } else {
        o << "<tr><td colspan=\"5\" style=\"color:#8b949e;text-align:center;\">No active threats detected in this session.</td></tr>\n";
    }
    o << "</table>\n";

    o << "<div class=\"footer\">GCAD v" << html_escape(data.gcad_version)
      << " &mdash; Galoisconnection Antivirus &amp; Defense &mdash; "
      << html_escape(data.generated_at) << "</div>\n";
    o << "</body>\n</html>\n";

    return o.str();
}

std::string ReportGenerator::generate_text(const ReportData& data) {
    std::ostringstream o;

    o << "GCAD Security Report\n"
      << "====================\n"
      << "Generated: " << data.generated_at << "\n"
      << "Version:   " << data.gcad_version << "\n";
    if (data.uptime_seconds > 0)
        o << "Uptime:    " << (data.uptime_seconds / 3600) << "h "
          << ((data.uptime_seconds / 60) % 60) << "m\n";
    o << "\n";

    // Summary
    size_t running = 0;
    for (auto& e : data.engines) if (e.running) ++running;
    o << "SUMMARY\n"
      << "  Engines:  " << running << " / " << data.engines.size() << "\n"
      << "  Events:   " << data.total_events << "\n"
      << "  Threats:  " << data.total_threats << "\n";
    if (data.total_alerts > 0)
        o << "  Alerts:   " << data.total_alerts << " (" << data.unacknowledged_alerts << " unread)\n";
    o << "\n";

    // Engine status
    o << "ENGINE STATUS\n";
    for (auto& e : data.engines) {
        o << "  " << e.name << ": " << (e.running ? "ACTIVE" : "STOPPED")
          << "  events=" << e.events_processed << " threats=" << e.threats_detected << "\n";
    }
    o << "\n";

    // Severity
    const char* sev[] = {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    o << "SEVERITY DISTRIBUTION\n";
    for (int i = 0; i < 5; ++i)
        o << "  " << sev[i] << ": " << data.severity_histogram[i] << "\n";
    o << "\n";

    // Categories
    if (!data.category_histogram.empty()) {
        o << "THREAT CATEGORIES\n";
        for (auto& [cat, cnt] : data.category_histogram)
            o << "  " << category_label(cat) << ": " << cnt << "\n";
        o << "\n";

        o << "MITRE ATT&CK MAPPING\n";
        for (auto& [cat, cnt] : data.category_histogram) {
            const auto ttp = mitre_ttp_for_category(cat);
            o << "  [" << ttp.technique_id << "] " << ttp.tactic << " - "
              << ttp.technique_name << " (" << category_label(cat) << "): " << cnt << " detections\n";
        }
        o << "\n";
    }

    // Recent events
    if (!data.recent_events.empty()) {
        o << "DETECTION TIMELINE (last " << data.recent_events.size() << ")\n";
        for (auto it = data.recent_events.rbegin(); it != data.recent_events.rend(); ++it) {
            o << "  [" << level_label(it->level) << "] "
              << format_event_time(it->timestamp) << " "
              << it->description << "\n";
        }
        o << "\n";
    }

    // Findings
    if (!data.findings.empty()) {
        o << "SECURITY FINDINGS (" << data.findings.size() << ")\n";
        for (auto it = data.findings.rbegin(); it != data.findings.rend(); ++it) {
            o << "  [" << level_label(it->level) << " risk:" << it->risk_score << "] "
              << it->rationale << "\n";
        }
        o << "\n";
    }

    o << "--- End of GCAD Report ---\n";
    return o.str();
}

bool ReportGenerator::save_to_file(const std::string& content,
                                    const std::filesystem::path& path) {
    std::error_code ec;
    auto parent = path.parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, ec);

    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << content;
    return f.good();
}

} // namespace gcad::report
