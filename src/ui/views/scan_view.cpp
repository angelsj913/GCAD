#include "gcad/ui/views/scan_view.hpp"
#include "gcad/ui/theme.hpp"
#include "imgui.h"

namespace gcad::ui::views {

void ScanView::render(DeepScanner& scanner) {
    ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
    ImGui::TextUnformatted("SCAN WORKSPACE");
    ImGui::PopFont();
    ImGui::TextDisabled("Choose a scan scope, then review results in one place.");
    ImGui::Spacing();

    render_mode_selector(scanner);
    ImGui::Separator();

    auto prog = scanner.progress();
    if (prog.files_total > 0 || prog.active) {
        render_progress(prog);
    }

    ImGui::Separator();
    ImGui::TextUnformatted("FINDINGS");
    auto results = scanner.get_results();
    render_results(results);
}

void ScanView::render_mode_selector(DeepScanner& scanner) {
    static constexpr const char* modes[] = {"Quick", "Deep", "Memory", "Custom"};
    static constexpr const char* descriptions[] = {
        "Common user locations and active threat indicators.",
        "Configured disk locations using the deep scanner.",
        "Readable executable memory regions in running processes.",
        "A path you explicitly provide below."
    };

    ImGui::TextUnformatted("SCAN SCOPE");
    for (int mode = 0; mode < 4; ++mode) {
        const float item_width = ImGui::CalcTextSize(modes[mode]).x + ImGui::GetStyle().FramePadding.x * 2.0f + 24.0f;
        if (mode > 0 && ImGui::GetCursorPosX() + item_width <= ImGui::GetWindowContentRegionMax().x)
            ImGui::SameLine();
        ImGui::RadioButton(modes[mode], &selected_mode_, mode);
    }
    ImGui::TextDisabled("%s", descriptions[selected_mode_]);

    if (selected_mode_ == 3) {
        ImGui::TextUnformatted("CUSTOM PATH");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##custom_scan_path", "Enter a folder or file path", custom_path_, sizeof(custom_path_));
    }

    bool scanning = scanner.is_scanning();
    if (!scanning) {
        if (ImGui::Button("Start Scan", {160, 32})) {
            ScanMode mode = static_cast<ScanMode>(selected_mode_);
            std::filesystem::path path;
            if (selected_mode_ == 3 && custom_path_[0] != '\0')
                path = custom_path_;
            scanner.start_scan(mode, path);
        }
    } else {
        if (ImGui::Button("Cancel Scan", {160, 32})) {
            scanner.cancel_scan();
        }
        ImGui::SameLine();
        ImGui::TextDisabled("The active scan will stop after its current work item.");
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

    ImGui::Text("Threats found: %llu | Elapsed: %.1fs",
                static_cast<unsigned long long>(prog.threats_found),
                prog.elapsed_seconds);
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextWrapped("Current: %s", prog.current_file.empty() ? "..." : prog.current_file.c_str());
    ImGui::PopTextWrapPos();
}

void ScanView::render_results(const std::vector<ScanResult>& results) {
    if (results.empty()) {
        ImGui::TextDisabled("No results yet.");
        return;
    }

    if (ImGui::BeginTable("##results", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY, {0, 300})) {
        ImGui::TableSetupColumn("File");
        ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("Level", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Description");
        ImGui::TableHeadersRow();

        for (auto& r : results) {
            if (r.level == ThreatLevel::SAFE) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", r.file_path.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%s", r.signature_name.empty() ? "heuristic" : r.signature_name.c_str());
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
