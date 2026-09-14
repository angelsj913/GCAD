#include "gcad/ui/views/settings_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/report/report_generator.hpp"
#include "gcad/alert/alert_manager.hpp"
#include "imgui.h"

namespace gcad::ui::views {

void SettingsView::render(EngineManager& em, AlertManager* am) {
    load_preferences();
    ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_INFO), "CONTROL STUDIO");
    ImGui::PopFont();
    ImGui::SameLine();
    ImGui::TextDisabled("Granular engine lifecycle, policy thresholds and report generation");
    ImGui::Separator();
    ImGui::Spacing();

    const float nav_w = 210.0f;
    const float gap = 12.0f;

    // --- Left Master Navigation ---
    ImGui::BeginChild("##settings_nav", {nav_w, 0.0f}, true);
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "CONTROL DOMAINS");
    ImGui::Separator();
    ImGui::Spacing();

    struct DomainTab {
        const char* tag;
        const char* label;
    };
    static const DomainTab tabs[] = {
        {"ALL", "Master Overview"},
        {"KM",  "Kernel & Memory"},
        {"SF",  "Script & Fileless"},
        {"RD",  "Ransomware & FIM"},
        {"NC",  "Network & C2"},
        {"IR",  "Intel & Reports"},
        {"GP",  "General & Policy"},
    };

    for (int i = 0; i < 7; ++i) {
        const bool active = (selected_category_ == i);
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::BUTTON_HOV));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(ThemeColors::BORDER_LGT));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_INFO));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::BUTTON));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(ThemeColors::BUTTON_HOV));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT_DIM));
        }

        char label_buf[64];
        std::snprintf(label_buf, sizeof(label_buf), "[%s] %s", tabs[i].tag, tabs[i].label);
        if (ImGui::Button(label_buf, {-1.0f, 32.0f})) selected_category_ = i;
        ImGui::PopStyleColor(3);
        ImGui::Spacing();
    }

    ImGui::EndChild();

    ImGui::SameLine(0.0f, gap);

    // --- Right Detail Panel ---
    ImGui::BeginChild("##settings_detail", ImGui::GetContentRegionAvail(), true);

    auto render_engine_row = [&em](const std::string& name, const char* desc) {
        auto* eng = em.engine(name);
        const bool running = eng ? eng->running() : false;
        const ImU32 accent = running ? ThemeColors::ACCENT_SAFE : ThemeColors::ACCENT_CRIT;

        ImGui::PushID(name.c_str());
        const ImVec2 origin = ImGui::GetCursorScreenPos();
        const float card_w = ImGui::GetContentRegionAvail().x;
        const float card_h = ImGui::GetTextLineHeight() * 2.8f;
        auto* dl = ImGui::GetWindowDrawList();

        dl->AddRectFilled(origin, {origin.x + card_w, origin.y + card_h}, ThemeColors::BG_CHILD, 4.0f);
        dl->AddRect(origin, {origin.x + card_w, origin.y + card_h}, ThemeColors::BORDER, 4.0f);
        dl->AddRectFilled(origin, {origin.x + 3.0f, origin.y + card_h}, accent, 4.0f, ImDrawFlags_RoundCornersLeft);

        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + 6.0f});
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "%s", name.c_str());
        ImGui::SameLine();
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(accent), "[%s]", running ? "ONLINE" : "STOPPED");

        ImGui::SameLine(card_w - 90.0f);
        if (eng) {
            if (running) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::BUTTON));
                if (ImGui::SmallButton("Stop")) eng->stop();
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_SAFE));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0, 0, 0, 1));
                if (ImGui::SmallButton("Start")) eng->start();
                ImGui::PopStyleColor(2);
            }
        }

        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + ImGui::GetTextLineHeight() + 10.0f});
        ImGui::TextDisabled("%s", desc);

        ImGui::SetCursorScreenPos({origin.x, origin.y + card_h + 6.0f});
        ImGui::PopID();
    };

    switch (selected_category_) {
        case 0: { // Master Overview
            ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "GLOBAL ENGINE CONTROL");
            ImGui::PopFont();
            ImGui::TextDisabled("Simultaneously activate or safely suspend all 31 core protection engines");
            ImGui::Separator();
            ImGui::Spacing();

            if (ImGui::Button("START ALL ENGINES", {180.0f, 34.0f})) em.start_all();
            ImGui::SameLine();
            if (ImGui::Button("STOP ALL ENGINES", {180.0f, 34.0f})) em.stop_all();

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            render_engine_controls(em);
            break;
        }
        case 1: { // Kernel & Memory
            ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "KERNEL & MEMORY DEFENSE DOMAIN");
            ImGui::PopFont();
            ImGui::TextDisabled("Direct syscall validation, kernel SSDT integrity and anti-injection defenses");
            ImGui::Separator();
            ImGui::Spacing();

            render_engine_row("PMSR", "Process Memory Space Inspector - Shellcode and page permission anomaly detection");
            render_engine_row("SyscallGuard", "Validates NT direct syscall transitions to stop EDR bypass hooks");
            render_engine_row("KernelMon", "Inspects SSDT and IDT kernel structures against rootkit tampering");
            render_engine_row("DriverGuard", "Monitors and blocks known BYOVD vulnerable third-party driver loads");
            render_engine_row("ReflectiveInjection", "Detects reflective DLL loading and process hollowing in memory spaces");

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "DOMAIN HEURISTIC THRESHOLDS");
            ImGui::SliderFloat("PMSR Analysis Sensitivity", &pmsr_sensitivity_, 0.1f, 1.0f, "%.2f");
            break;
        }
        case 2: { // Script & Fileless
            ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "SCRIPT & FILELESS DEFENSE DOMAIN");
            ImGui::PopFont();
            ImGui::TextDisabled("AMSI memory protection, WMI persistence and weaponized living-off-the-land binaries");
            ImGui::Separator();
            ImGui::Spacing();

            render_engine_row("AmsiGuard", "AMSI memory buffer inspection and patch bypass tampering detection");
            render_engine_row("WmiBits", "Monitors WMI active script event consumers and suspicious BITS download jobs");
            render_engine_row("FilelessAstGuard", "Abstract Syntax Tree engine deobfuscating remote PowerShell execution cradles");
            render_engine_row("LolbinsGuard", "Analyzes weaponized CertUtil, MSHTA, Regsvr32 and malicious LNK files");
            render_engine_row("PeStaticAnalysis", "PE structural parser detecting W^X section violations and UPX/Themida packers");

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "DOMAIN HEURISTIC THRESHOLDS");
            ImGui::SliderFloat("PE Shannon Entropy Packing Threshold", &pe_entropy_thresh_, 6.0f, 8.0f, "%.2f");
            ImGui::SliderFloat("AMSI Script Threat Sensitivity", &amsi_script_thresh_, 20.0f, 80.0f, "%.1f");
            ImGui::Checkbox("AMSI In-Memory Auto-Heal Patches", &amsi_auto_heal_);
            break;
        }
        case 3: { // Ransomware & FIM
            ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "RANSOMWARE & DATA INTEGRITY DOMAIN");
            ImGui::PopFont();
            ImGui::TextDisabled("I/O entropy honeypot canary, file integrity monitoring, LSASS dump & device control");
            ImGui::Separator();
            ImGui::Spacing();

            render_engine_row("RansomwareShield", "Rapid encryption trap monitoring high-entropy I/O bursts and honeypot canary files");
            render_engine_row("FIM", "File Integrity Monitor maintaining SHA-256 baseline hashes of protected system binaries");
            render_engine_row("CredentialGuard", "Guards LSASS process memory against Mimikatz credential dumping");
            render_engine_row("DeviceControl", "Enforces access control policies on newly inserted USB storage media");
            render_engine_row("ARHS", "Automated Remediation & Honeypot System performing rolling backup snapshots");
            render_engine_row("ZRGP", "Zero-Day Response & Generic Protection heuristically scoring unknown behaviors");

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "DOMAIN HEURISTIC THRESHOLDS");
            ImGui::SliderFloat("ARHS Snapshot Interval (seconds)", &arhs_backup_interval_, 1.0f, 30.0f, "%.1f");
            ImGui::Checkbox("Auto-Quarantine on High Detection", &auto_quarantine_);
            ImGui::Checkbox("Auto-Rollback on Ransomware Trigger", &auto_rollback_);
            break;
        }
        case 4: { // Network & C2
            ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "NETWORK & PERIMETER C2 DOMAIN");
            ImGui::PopFont();
            ImGui::TextDisabled("Outbound exfiltration gating, DNS tunneling, L3/L4 filtering and C2 pipe scanner");
            ImGui::Separator();
            ImGui::Spacing();

            render_engine_row("ETG-RI", "Entropy Traffic Gate analyzing anomalous outbound payload entropy");
            render_engine_row("Firewall", "Native L3/L4 stateful packet filter blocking malicious remote hosts");
            render_engine_row("DnsMon", "Inspects local DNS requests for DGA domains and DNS exfiltration tunneling");
            render_engine_row("NetworkDPI", "Deep packet inspector flagging Cobalt Strike and Metasploit beacon profiles");
            render_engine_row("NamedPipe", "Monitors local Named Pipe creation for known adversary C2 transport names");

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            render_network_settings();
            break;
        }
        case 5: { // Intel & Reports
            ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "INTELLIGENCE & REPORTING DOMAIN");
            ImGui::PopFont();
            ImGui::TextDisabled("Threat intelligence, YARA matching, sandbox emulation, and incident report exports");
            ImGui::Separator();
            ImGui::Spacing();

            render_engine_row("YARA", "Compiled pattern matching engine scanning files and payloads against YARA rules");
            render_engine_row("Sandbox", "Isolated execution harness for dynamic behavioral observation");
            render_engine_row("ThreatIntel", "Feeds real-time IOC indicators and malicious IP/domain reputations");
            render_engine_row("VulnScanner", "Audits system configurations for known common vulnerabilities and exposures");
            render_engine_row("BehaviorML", "Behavioral event scorer calculating cumulative process risk ratings");
            render_engine_row("ForensicTimeline", "Records causal process graph histories for timeline forensic analysis");
            render_engine_row("Webhook", "Dispatches security alerts to remote Discord, Slack, Splunk and Syslog endpoints");

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            render_report_settings(em, am);
            break;
        }
        case 6: { // General & Policy
            ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "GENERAL & SYSTEM PREFERENCES");
            ImGui::PopFont();
            ImGui::TextDisabled("System tray behavior and persistent policy management");
            ImGui::Separator();
            ImGui::Spacing();

            render_general_settings();
            break;
        }
    }

    ImGui::EndChild();
}

void SettingsView::render_engine_controls(EngineManager& em) {
    auto stats = em.statuses();
    for (auto& s : stats) {
        ImGui::PushID(s.name.c_str());
        bool running = s.running;
        push_threat_color(running ? 0 : 4);
        ImGui::Text("%s: %s", s.name.c_str(), running ? "ONLINE" : "STOPPED");
        pop_threat_color();
        ImGui::SameLine(180.0f);
        auto* eng = em.engine(s.name);
        if (eng) {
            if (running) {
                if (ImGui::SmallButton("Stop")) eng->stop();
            } else {
                if (ImGui::SmallButton("Start")) eng->start();
            }
        }
        ImGui::PopID();
    }
}

void SettingsView::render_scan_settings() {
    ImGui::SliderFloat("ARHS Backup Interval (s)", &arhs_backup_interval_, 1.0f, 30.0f, "%.1f");
    ImGui::Checkbox("Auto-Quarantine on Detection", &auto_quarantine_);
    ImGui::TextDisabled("This preference does not enable automatic quarantine actions.");
    ImGui::Checkbox("Auto-Rollback on Ransomware", &auto_rollback_);
    ImGui::Checkbox("AMSI In-Memory Auto-Heal", &amsi_auto_heal_);
    ImGui::SliderFloat("AMSI Script Threat Sensitivity", &amsi_script_thresh_, 20.0f, 80.0f, "%.1f");
    ImGui::SliderFloat("PE Shannon Entropy Threshold", &pe_entropy_thresh_, 6.0f, 8.0f, "%.2f");
    ImGui::TextDisabled("Applies to: ARHS rollback buffer, AMSI memory patch repair, and PE packer detection.");
}

void SettingsView::render_network_settings() {
    ImGui::SliderFloat("ETG Entropy Threshold", &etg_entropy_thresh_, 5.0f, 8.0f, "%.2f");
    ImGui::SliderInt("ZRGP Max Honey Ports", &zrgp_max_ports_, 4, 64);
    ImGui::SliderFloat("WMI Persistence Audit Interval (s)", &wmi_audit_interval_, 2.0f, 60.0f, "%.1f");
    ImGui::SliderFloat("Named Pipe C2 Scan Interval (s)", &named_pipe_scan_interval_, 1.0f, 30.0f, "%.1f");
    ImGui::TextDisabled("Applies to: ETG-RI anomaly gate, ZRGP honeypots, WMI persistence, and C2 pipe scanner.");
}

void SettingsView::render_report_settings(EngineManager& em, AlertManager* am) {
    const char* formats[] = {"HTML", "Plain Text"};
    ImGui::Combo("Format", &report_format_, formats, 2);

    if (ImGui::Button("Generate Report", {160, 28})) {
        auto data = report::ReportGenerator::collect(em, am);
        std::string content;
        std::string ext;
        if (report_format_ == 0) {
            content = report::ReportGenerator::generate_html(data);
            ext = ".html";
        } else {
            content = report::ReportGenerator::generate_text(data);
            ext = ".txt";
        }

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
        localtime_s(&tm_buf, &t);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm_buf);

        auto path = std::filesystem::current_path() / ("gcad_report_" + std::string(ts) + ext);
        if (report::ReportGenerator::save_to_file(content, path))
            report_status_ = "Saved: " + path.filename().string();
        else
            report_status_ = "Failed to save report";
    }

    if (!report_status_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored({0.4f, 0.9f, 0.4f, 1.0f}, "%s", report_status_.c_str());
    }
}

void SettingsView::render_general_settings() {
    ImGui::Checkbox("Minimize to System Tray", &minimize_to_tray_);
    ImGui::SameLine();
    if (ImGui::Button("Save UI Preferences")) {
        UiPreferences preferences{};
        preferences.minimize_to_tray = minimize_to_tray_;
        preferences.report_format = report_format_;
        preferences_status_ = UiPreferencesStore::save(UiPreferencesStore::default_path(), preferences) == ErrorCode::OK
            ? "UI preferences saved"
            : "Failed to save UI preferences";
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload UI Preferences")) {
        preferences_loaded_ = false;
        load_preferences();
        preferences_status_ = "UI preferences reloaded";
    }
    if (!preferences_status_.empty())
        ImGui::TextDisabled("%s", preferences_status_.c_str());
    ImGui::Separator();
    ImGui::Text("GCAD v%s", std::string(VERSION).c_str());
    ImGui::Text("Build: C++20 | Platform: %s",
#ifdef GCAD_PLATFORM_WINDOWS
                "Windows (DX11)"
#else
                "Linux (OpenGL)"
#endif
    );
    ImGui::TextDisabled("Galoisconnection Antivirus & Defense");
}

void SettingsView::load_preferences() {
    if (preferences_loaded_) return;
    const auto preferences = UiPreferencesStore::load(UiPreferencesStore::default_path());
    minimize_to_tray_ = preferences.minimize_to_tray;
    report_format_ = preferences.report_format;
    preferences_loaded_ = true;
}

} // namespace gcad::ui::views
