#include "gcad/ui/views/scan_view.hpp"
#include "gcad/ui/theme.hpp"
#include "imgui.h"
#include <cmath>

namespace gcad::ui::views {

void ScanView::render(DeepScanner& scanner) {
    render_mode_selector(scanner);
    ImGui::Separator();

    auto prog = scanner.progress();
    if (prog.files_total > 0 || prog.active) {
        render_progress(prog);
        ImGui::Separator();
        render_radar_effect(prog.files_total > 0 ?
            static_cast<float>(prog.files_scanned) / static_cast<float>(prog.files_total) : 0.0f);
    }

    ImGui::Separator();
    ImGui::Text("Results");
    auto results = scanner.get_results();
    render_results(results);
}

void ScanView::render_mode_selector(DeepScanner& scanner) {
    ImGui::Text("Scan Mode");
    ImGui::RadioButton("Quick Scan", &selected_mode_, 0); ImGui::SameLine();
    ImGui::RadioButton("Deep Scan",  &selected_mode_, 1); ImGui::SameLine();
    ImGui::RadioButton("Memory Scan", &selected_mode_, 2); ImGui::SameLine();
    ImGui::RadioButton("Custom Path", &selected_mode_, 3);

    if (selected_mode_ == 3) {
        ImGui::InputText("Path", custom_path_, sizeof(custom_path_));
    }

    bool scanning = scanner.is_scanning();
    if (!scanning) {
        if (ImGui::Button("Start Scan", {150, 30})) {
            ScanMode mode = static_cast<ScanMode>(selected_mode_);
            std::filesystem::path path;
            if (selected_mode_ == 3 && custom_path_[0] != '\0')
                path = custom_path_;
            scanner.start_scan(mode, path);
        }
    } else {
        if (ImGui::Button("Cancel", {150, 30})) {
            scanner.cancel_scan();
        }
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

    ImGui::Text("Threats found: %llu | Elapsed: %.1fs | Current: %s",
                static_cast<unsigned long long>(prog.threats_found),
                prog.elapsed_seconds,
                prog.current_file.empty() ? "..." : prog.current_file.c_str());
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

void ScanView::render_radar_effect(float progress) {
    scan_anim_ += ImGui::GetIO().DeltaTime * 2.0f;
    if (scan_anim_ > 6.2831853f) scan_anim_ -= 6.2831853f;

    auto* dl = ImGui::GetWindowDrawList();
    ImVec2 center = ImGui::GetCursorScreenPos();
    float r = 40.0f;
    center.x += ImGui::GetContentRegionAvail().x * 0.5f;
    center.y += r + 5;

    dl->AddCircle(center, r, 0xFF30363d, 48);
    float sweep = scan_anim_;
    float ex = center.x + cosf(sweep) * r;
    float ey = center.y + sinf(sweep) * r;
    dl->AddLine(center, {ex, ey}, 0xFF58a6ff, 2.0f);

    float arc = progress * 6.2831853f;
    for (float a = 0; a < arc; a += 0.1f) {
        float px = center.x + cosf(a) * r * 0.95f;
        float py = center.y + sinf(a) * r * 0.95f;
        dl->AddCircleFilled({px, py}, 2, 0x4039d353);
    }
    ImGui::Dummy({0, r * 2 + 15});
}

} // namespace gcad::ui::views
