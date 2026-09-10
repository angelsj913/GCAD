#include "gcad/ui/views/dashboard_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#include "imgui.h"
#include <cmath>

#ifdef GCAD_PLATFORM_WINDOWS
#include <psapi.h>
#endif

namespace gcad::ui::views {

void DashboardView::render(EngineManager& em) {
    render_header(em);
    ImGui::Separator();
    ImGui::Spacing();

    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##left", {w * 0.55f, 0}, true);
    render_engine_cards(em);
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##right", {0, 0}, true);
    render_threat_gauge();
    ImGui::Separator();
    render_resource_monitor();
    ImGui::Separator();
    render_radar_animation();
    ImGui::EndChild();
}

void DashboardView::render_header(EngineManager& em) {
    auto level = em.current_threat_level();
    push_threat_color(static_cast<uint8_t>(level));
    ImGui::Text("System Threat Level: %s", threat_level_label(static_cast<uint8_t>(level)));
    pop_threat_color();
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);
    ImGui::Text("Engines: %s", em.all_running() ? "ALL ACTIVE" : "PARTIAL");
    ImGui::SameLine();
    ImGui::Text("| Events: %zu", em.total_threats());
}

void DashboardView::render_threat_gauge() {
    auto level = static_cast<float>(target_gauge_);
    threat_gauge_ += (level - threat_gauge_) * 0.05f;

    ImGui::Text("Threat Gauge");
    ImGui::ProgressBar(threat_gauge_ / 4.0f, {-1, 20}, "");

    auto* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float width = ImGui::GetContentRegionAvail().x;
    float h = 8.0f;
    uint32_t colors[] = {0xFF39d353, 0xFF58a6ff, 0xFFd29922, 0xFFf0883e, 0xFFf85149};
    float seg = width / 5.0f;
    for (int i = 0; i < 5; i++) {
        dl->AddRectFilled({p.x + seg * i, p.y}, {p.x + seg * (i + 1) - 2, p.y + h}, colors[i], 2.0f);
    }
    float marker_x = p.x + (threat_gauge_ / 4.0f) * width;
    dl->AddTriangleFilled({marker_x - 5, p.y + h + 2}, {marker_x + 5, p.y + h + 2}, {marker_x, p.y + h - 1}, 0xFFe6edf3);
    ImGui::Dummy({0, h + 12});
}

void DashboardView::render_engine_cards(EngineManager& em) {
    ImGui::Text("Engine Status");
    ImGui::Separator();
    auto stats = em.statuses();
    const float card_h = ImGui::GetTextLineHeightWithSpacing() * 2.0f
                       + ImGui::GetStyle().WindowPadding.y * 2.0f
                       + ImGui::GetStyle().ItemSpacing.y;
    for (auto& s : stats) {
        ImGui::PushID(s.name.c_str());
        bool running = s.running;
        if (running) ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.05f, 0.15f, 0.05f, 1.0f));
        else         ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.15f, 0.05f, 0.05f, 1.0f));

        ImGui::BeginChild("##card", {ImGui::GetContentRegionAvail().x, card_h}, true);
        ImGui::Text("%s", s.name.c_str());
        {
            const char* st = running ? "ACTIVE" : "STOPPED";
            float off = ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(st).x;
            if (off > ImGui::GetCursorPosX()) ImGui::SameLine(off);
            else ImGui::SameLine();
            push_threat_color(running ? 0 : 4);
            ImGui::Text("%s", st);
            pop_threat_color();
        }
        ImGui::Text("Threats: %llu | Events: %llu",
                     static_cast<unsigned long long>(s.threats_detected),
                     static_cast<unsigned long long>(s.events_processed));
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::PopID();
        ImGui::Spacing();
    }

    ImGui::Separator();
    ImGui::Text("Recent Events");
    auto events = em.recent_events(20);
    float wrap_w = ImGui::GetContentRegionAvail().x;
    for (auto it = events.rbegin(); it != events.rend(); ++it) {
        push_threat_color(static_cast<uint8_t>(it->level));
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap_w);
        ImGui::TextWrapped("- [%s] %s", threat_level_label(static_cast<uint8_t>(it->level)),
                           it->description.c_str());
        ImGui::PopTextWrapPos();
        pop_threat_color();
    }
}

void DashboardView::render_resource_monitor() {
#ifdef GCAD_PLATFORM_WINDOWS
    PROCESS_MEMORY_COUNTERS pmc{};
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    float mem_mb = pmc.WorkingSetSize / (1024.0f * 1024.0f);
#else
    float mem_mb = 0.0f;
#endif

    cpu_history_[history_idx_ % 120] = 0.0f;
    mem_history_[history_idx_ % 120] = mem_mb;
    history_idx_++;

    ImGui::Text("Resource Monitor");
    ImGui::Text("Memory: %.1f MB", mem_mb);
    ImGui::PlotLines("MEM", mem_history_, 120, history_idx_ % 120, nullptr, 0.0f, 50.0f, {-1, 40});
}

void DashboardView::render_radar_animation() {
    radar_angle_ += ImGui::GetIO().DeltaTime * 1.5f;
    if (radar_angle_ > 6.2831853f) radar_angle_ -= 6.2831853f;

    auto* dl = ImGui::GetWindowDrawList();
    ImVec2 center = ImGui::GetCursorScreenPos();
    float radius = 50.0f;
    center.x += ImGui::GetContentRegionAvail().x * 0.5f;
    center.y += radius + 5;

    dl->AddCircle(center, radius, 0xFF30363d, 64);
    dl->AddCircle(center, radius * 0.66f, 0xFF21262d, 48);
    dl->AddCircle(center, radius * 0.33f, 0xFF21262d, 32);

    float ex = center.x + cosf(radar_angle_) * radius;
    float ey = center.y + sinf(radar_angle_) * radius;
    dl->AddLine(center, {ex, ey}, 0x8039d353, 2.0f);

    for (int i = 0; i < 8; i++) {
        float a = radar_angle_ - 0.05f * (i + 1);
        float ex2 = center.x + cosf(a) * radius;
        float ey2 = center.y + sinf(a) * radius;
        uint32_t alpha = static_cast<uint32_t>(180 - i * 20) << 24;
        dl->AddLine(center, {ex2, ey2}, alpha | 0x0039d353, 1.0f);
    }

    ImGui::Dummy({0, radius * 2 + 15});
}

} // namespace gcad::ui::views
