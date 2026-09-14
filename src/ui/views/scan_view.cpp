#include "gcad/ui/views/scan_view.hpp"
#include "gcad/ui/theme.hpp"
#include "imgui.h"

namespace gcad::ui::views {

void ScanView::render(DeepScanner& scanner) {
    ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_INFO), "SCAN STUDIO");
    ImGui::PopFont();
    ImGui::SameLine();
    ImGui::TextDisabled("Targeted file, memory and directory deep static analysis");
    ImGui::Separator();
    ImGui::Spacing();

    const float total_w = ImGui::GetContentRegionAvail().x;
    const float gap = 12.0f;
    const float left_w = (total_w - gap) * 0.58f;
    const float right_w = total_w - gap - left_w;

    // --- Left Column: Scan Controls & Findings ---
    ImGui::BeginChild("##scan_ctrl_col", {left_w, 0.0f}, false);
    render_mode_selector(scanner);
    ImGui::Spacing();

    auto prog = scanner.progress();
    if (prog.files_total > 0 || prog.active) {
        render_progress(prog);
        ImGui::Spacing();
    }

    ImGui::Separator();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "FINDINGS & DETECTIONS");
    auto results = scanner.get_results();
    render_results(results);
    ImGui::EndChild();

    ImGui::SameLine(0.0f, gap);

    // --- Right Column: Presets & Benchmarks ---
    ImGui::BeginChild("##scan_info_col", {right_w, 0.0f}, true);

    // Scan Target Quick Presets
    ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "QUICK PRESETS");
    ImGui::PopFont();
    ImGui::TextDisabled("One-click targets for immediate security inspection");
    ImGui::Separator();
    ImGui::Spacing();

    auto set_custom_target = [this](const std::string& path) {
        selected_mode_ = 3; // Custom
        std::snprintf(custom_path_, sizeof(custom_path_), "%s", path.c_str());
    };

    if (ImGui::Button("Downloads Directory", {-1.0f, 32.0f})) {
        if (const char* p = std::getenv("USERPROFILE")) set_custom_target(std::string(p) + "\\Downloads");
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Scan recently downloaded user files");

    if (ImGui::Button("User Desktop Workspace", {-1.0f, 32.0f})) {
        if (const char* p = std::getenv("USERPROFILE")) set_custom_target(std::string(p) + "\\Desktop");
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Scan desktop files and weaponized shortcuts");

    if (ImGui::Button("Temp & AppData (%TEMP%)", {-1.0f, 32.0f})) {
        if (const char* p = std::getenv("TEMP")) set_custom_target(p);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("High-risk execution path for dropped malware payloads");

    if (ImGui::Button("Running Processes Memory Only", {-1.0f, 32.0f})) {
        selected_mode_ = 2; // Memory
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Enumerate process address spaces for injected shellcode");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Inspection Engines Active
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "ACTIVE STATIC DETECTORS");
    ImGui::TextDisabled("Integrated deep heuristic engines");
    ImGui::Spacing();
    ImGui::BulletText("PeStaticAnalysis (W^X violation, UPX/Themida, Entropy >= 7.2)");
    ImGui::BulletText("LolbinsGuard (CertUtil, MSHTA, Regsvr32, Weaponized LNK)");
    ImGui::BulletText("FilelessAST (PowerShell deobfuscation, WebClient cradle)");
    ImGui::BulletText("ArtifactTrust (Authenticode signature & revocation check)");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Cumulative Benchmarks
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "LIFETIME BENCHMARKS");
    ImGui::TextDisabled("Session and persistent engine metrics");
    ImGui::Spacing();

    ImGui::Text("Scans Completed:   %llu", static_cast<unsigned long long>(scanner.scans_completed()));
    ImGui::Text("Files Scanned:     %llu", static_cast<unsigned long long>(scanner.lifetime_scanned()));
    ImGui::Text("Threats Neutralized: %llu", static_cast<unsigned long long>(scanner.lifetime_threats()));
    ImGui::Text("Signatures Loaded: %zu rules", scanner.signature_count());

    ImGui::EndChild();
}

void ScanView::render_mode_selector(DeepScanner& scanner) {
    static constexpr const char* modes[] = {"Quick Scan", "Deep Scan", "Memory Scan", "Custom Path"};
    static constexpr const char* descriptions[] = {
        "Inspect common user paths (%USERPROFILE%\\Desktop, Downloads) and active execution indicators.",
        "Perform recursive deep inspection across all local storage drives and system folders.",
        "Scan readable executable memory spaces of running processes for shellcode and hollowed PE.",
        "Inspect a specific file, directory, or mounted USB storage device."
    };

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "SELECT SCAN MODE");
    ImGui::Spacing();

    for (int mode = 0; mode < 4; ++mode) {
        if (mode > 0) ImGui::SameLine();
        ImGui::PushID(mode);
        const bool active = (selected_mode_ == mode);
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::BUTTON_HOV));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_INFO));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::BUTTON));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT_DIM));
        }
        if (ImGui::Button(modes[mode], {110.0f, 30.0f})) selected_mode_ = mode;
        ImGui::PopStyleColor(2);
        ImGui::PopID();
    }

    ImGui::Spacing();
    ImGui::TextDisabled("%s", descriptions[selected_mode_]);
    ImGui::Spacing();

    // Dropzone / Target Path Box
    if (selected_mode_ == 3) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT), "TARGET PATH");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##custom_scan_path", "Enter target file or folder path (e.g. C:\\Tools)", custom_path_, sizeof(custom_path_));
        ImGui::Spacing();
    }

    const bool scanning = scanner.is_scanning();
    if (!scanning) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_INFO));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(ThemeColors::BORDER_LGT));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.04f, 0.09f, 0.13f, 1.0f));
        if (ImGui::Button("START DEEP SCAN", {200.0f, 36.0f})) {
            ScanMode mode = static_cast<ScanMode>(selected_mode_);
            std::filesystem::path path;
            if (selected_mode_ == 3 && custom_path_[0] != '\0')
                path = custom_path_;
            scanner.start_scan(mode, path);
        }
        ImGui::PopStyleColor(3);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_CRIT));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
        if (ImGui::Button("CANCEL SCAN", {180.0f, 36.0f})) {
            scanner.cancel_scan();
        }
        ImGui::PopStyleColor(2);
        ImGui::SameLine();
        ImGui::TextDisabled("Active worker threads will safely terminate.");
    }
}

void ScanView::render_progress(const ScanProgress& prog) {
    float pct = prog.files_total > 0 ?
        static_cast<float>(prog.files_scanned) / static_cast<float>(prog.files_total) : 0.0f;

    char overlay[128];
    snprintf(overlay, sizeof(overlay), "%llu / %llu files (%.0f%%)",
             static_cast<unsigned long long>(prog.files_scanned),
             static_cast<unsigned long long>(prog.files_total), pct * 100);
    ImGui::ProgressBar(pct, {-1, 24}, overlay);

    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_INFO),
                       "Threats found: %llu", static_cast<unsigned long long>(prog.threats_found));
    ImGui::SameLine();
    ImGui::TextDisabled("| Elapsed: %.1fs", prog.elapsed_seconds);
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextDisabled("Current: %s", prog.current_file.empty() ? "..." : prog.current_file.c_str());
    ImGui::PopTextWrapPos();
}

void ScanView::render_results(const std::vector<ScanResult>& results) {
    if (results.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled("No threats detected in the current workspace.");
        return;
    }

    if (ImGui::BeginTable("##results", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY, {0, 260})) {
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Level", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Details", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (auto& r : results) {
            if (r.level == ThreatLevel::SAFE) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", r.file_path.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%s", r.signature_name.empty() ? "Heuristic" : r.signature_name.c_str());
            ImGui::TableNextColumn();
            push_threat_color(static_cast<uint8_t>(r.level));
            ImGui::Text("%s", threat_level_label(static_cast<uint8_t>(r.level)));
            pop_threat_color();
            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", r.description.c_str());
        }
        ImGui::EndTable();
    }
}

} // namespace gcad::ui::views
