#include "gcad/ui/views/dashboard_view.hpp"

#include "gcad/engine_manager.hpp"
#include "gcad/ui/theme.hpp"
#include "imgui.h"

#include <algorithm>
#include <cstdio>

#ifdef GCAD_PLATFORM_WINDOWS
#include <psapi.h>
#endif

namespace gcad::ui::views {

namespace {

void section_title(const char* title) {
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT_DIM));
    ImGui::TextUnformatted(title);
    ImGui::PopStyleColor();
}

void metric_card(const char* label, const char* value, ImU32 accent, float width) {
    const ImVec2 start = ImGui::GetCursorScreenPos();
    const float height = ImGui::GetTextLineHeight() * 3.1f;
    auto* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(start, {start.x + width, start.y + height}, ThemeColors::BG_PANEL, 5.0f);
    draw_list->AddRect(start, {start.x + width, start.y + height}, ThemeColors::BORDER, 5.0f);
    draw_list->AddRectFilled(start, {start.x + 3.0f, start.y + height}, accent, 5.0f,
                             ImDrawFlags_RoundCornersLeft);
    draw_list->AddText({start.x + 12.0f, start.y + 8.0f}, ThemeColors::TEXT_DIM, label);
    draw_list->AddText({start.x + 12.0f, start.y + ImGui::GetTextLineHeight() + 12.0f},
                       ThemeColors::TEXT, value);
    ImGui::Dummy({width, height});
}

} // namespace

void DashboardView::render(EngineManager& em) {
    target_gauge_ = static_cast<float>(em.current_threat_level());
    update_eps(em);

    ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
    ImGui::TextUnformatted("OPERATIONS OVERVIEW");
    ImGui::PopFont();
    ImGui::SameLine();
    ImGui::TextDisabled("Live protection and incident telemetry");
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 100.0f);
    ImGui::TextDisabled("%.1f events/s", current_eps_);
    ImGui::Separator();
    ImGui::Spacing();

    render_kpi_cards(em);
    ImGui::Spacing();

    const float width = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##dashboard_primary", {width * 0.60f, 0.0f}, false);
    render_engine_heatmap(em);
    ImGui::Spacing();
    render_threat_timeline(em);
    ImGui::Spacing();
    render_security_findings(em);
    ImGui::Spacing();
    render_activity_feed(em);
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##dashboard_secondary", {0.0f, 0.0f}, false);
    render_threat_gauge(em);
    ImGui::Spacing();
    render_severity_histogram(em);
    ImGui::Spacing();
    render_resource_monitor();
    ImGui::EndChild();
}

void DashboardView::render_kpi_cards(EngineManager& em) {
    const auto statuses = em.statuses();
    const auto stopped = em.stopped_engines();
    const auto total_events = em.total_threats();

    char engines[32];
    char events[32];
    char coverage[32];
    std::snprintf(engines, sizeof(engines), "%zu / %zu", statuses.size() - stopped.size(), statuses.size());
    std::snprintf(events, sizeof(events), "%zu", total_events);
    std::snprintf(coverage, sizeof(coverage), "%s", stopped.empty() ? "NOMINAL" : "DEGRADED");

    const float gap = ImGui::GetStyle().ItemSpacing.x;
    const float card_width = std::max(120.0f, (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f);
    metric_card("ENGINES ONLINE", engines, stopped.empty() ? ThemeColors::ACCENT_SAFE : ThemeColors::ACCENT_WARN,
                card_width);
    ImGui::SameLine(0.0f, gap);
    metric_card("THREAT EVENTS", events, ThemeColors::ACCENT_CRIT, card_width);
    ImGui::SameLine(0.0f, gap);
    metric_card("PROTECTION STATE", coverage, stopped.empty() ? ThemeColors::ACCENT_INFO : ThemeColors::ACCENT_WARN,
                card_width);
}

void DashboardView::render_engine_cards(EngineManager& em) {
    section_title("SECURITY ENGINES");
    ImGui::Separator();

    for (const auto& status : em.statuses()) {
        ImGui::PushID(status.name.c_str());
        const ImVec2 origin = ImGui::GetCursorScreenPos();
        const float height = ImGui::GetTextLineHeight() * 2.6f;
        const float width = ImGui::GetContentRegionAvail().x;
        const ImU32 accent = status.running ? ThemeColors::ACCENT_SAFE : ThemeColors::ACCENT_CRIT;
        auto* draw_list = ImGui::GetWindowDrawList();
        draw_list->AddRectFilled(origin, {origin.x + width, origin.y + height}, ThemeColors::BG_PANEL, 5.0f);
        draw_list->AddRect(origin, {origin.x + width, origin.y + height}, ThemeColors::BORDER, 5.0f);
        draw_list->AddRectFilled(origin, {origin.x + 3.0f, origin.y + height}, accent, 5.0f,
                                 ImDrawFlags_RoundCornersLeft);
        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + 7.0f});
        ImGui::TextUnformatted(status.name.c_str());
        ImGui::SameLine(width - ImGui::CalcTextSize(status.running ? "ACTIVE" : "STOPPED").x - 10.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(accent));
        ImGui::TextUnformatted(status.running ? "ACTIVE" : "STOPPED");
        ImGui::PopStyleColor();
        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + ImGui::GetTextLineHeight() + 10.0f});
        ImGui::TextDisabled("Events %llu    Threats %llu",
                            static_cast<unsigned long long>(status.events_processed),
                            static_cast<unsigned long long>(status.threats_detected));
        ImGui::SetCursorScreenPos({origin.x, origin.y + height});
        ImGui::Dummy({width, 5.0f});
        ImGui::PopID();
    }
}

void DashboardView::render_threat_gauge(EngineManager& em) {
    threat_gauge_ += (target_gauge_ - threat_gauge_) * std::min(1.0f, ImGui::GetIO().DeltaTime * 8.0f);
    section_title("THREAT POSTURE");
    ImGui::Separator();

    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = ImGui::GetContentRegionAvail().x;
    constexpr ImU32 colors[] = {
        ThemeColors::ACCENT_SAFE, ThemeColors::ACCENT_INFO, ThemeColors::ACCENT_WARN,
        ThemeColors::ACCENT_HIGH, ThemeColors::ACCENT_CRIT,
    };
    auto* draw_list = ImGui::GetWindowDrawList();
    const float segment = width / 5.0f;
    for (int index = 0; index < 5; ++index)
        draw_list->AddRectFilled({origin.x + segment * index, origin.y},
                                 {origin.x + segment * (index + 1) - 2.0f, origin.y + 12.0f},
                                 colors[index], 3.0f);

    const float marker = origin.x + (threat_gauge_ / 4.0f) * width;
    draw_list->AddTriangleFilled({marker, origin.y + 24.0f}, {marker - 6.0f, origin.y + 15.0f},
                                 {marker + 6.0f, origin.y + 15.0f}, ThemeColors::TEXT);
    ImGui::Dummy({width, 32.0f});
    push_threat_color(static_cast<uint8_t>(em.current_threat_level()));
    ImGui::Text("Current level: %s", threat_level_label(static_cast<uint8_t>(em.current_threat_level())));
    pop_threat_color();
}

void DashboardView::render_resource_monitor() {
    section_title("SYSTEM RESOURCES");
    ImGui::Separator();

    float memory_mb = 0.0f;
#ifdef GCAD_PLATFORM_WINDOWS
    PROCESS_MEMORY_COUNTERS counters{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)))
        memory_mb = static_cast<float>(counters.WorkingSetSize) / (1024.0f * 1024.0f);
#endif

    update_cpu_usage();

    int idx = history_idx_ % static_cast<int>(std::size(mem_history_));
    mem_history_[idx] = memory_mb;
    ++history_idx_;

    float cpu_val = cpu_history_[(history_idx_ - 1) % std::size(cpu_history_)];
    ImGui::Text("CPU: %.0f%%", cpu_val);
    ImGui::PlotLines("##cpu", cpu_history_, static_cast<int>(std::size(cpu_history_)),
                     history_idx_ % static_cast<int>(std::size(cpu_history_)), nullptr, 0.0f, 100.0f,
                     {-1.0f, 60.0f});

    ImGui::Text("Memory: %.1f MB", memory_mb);
    ImGui::PlotLines("##mem", mem_history_, static_cast<int>(std::size(mem_history_)),
                     history_idx_ % static_cast<int>(std::size(mem_history_)), nullptr, 0.0f, 256.0f,
                     {-1.0f, 60.0f});

    ImGui::Text("Events/s:");
    ImGui::PlotLines("##eps", eps_history_, static_cast<int>(std::size(eps_history_)),
                     eps_idx_ % static_cast<int>(std::size(eps_history_)), nullptr, 0.0f, 100.0f,
                     {-1.0f, 40.0f});
}

void DashboardView::update_cpu_usage() {
#ifdef GCAD_PLATFORM_WINDOWS
    FILETIME idle_ft, kernel_ft, user_ft;
    if (GetSystemTimes(&idle_ft, &kernel_ft, &user_ft)) {
        auto to64 = [](FILETIME ft) -> uint64_t {
            return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        };
        uint64_t idle   = to64(idle_ft);
        uint64_t kernel = to64(kernel_ft);
        uint64_t user   = to64(user_ft);

        if (prev_kernel_ != 0 || prev_user_ != 0) {
            uint64_t total_diff = (kernel - prev_kernel_) + (user - prev_user_);
            uint64_t idle_diff  = idle - prev_idle_;
            float cpu_pct = 0.0f;
            if (total_diff > 0)
                cpu_pct = (1.0f - static_cast<float>(idle_diff) / static_cast<float>(total_diff)) * 100.0f;
            cpu_history_[(history_idx_) % std::size(cpu_history_)] = cpu_pct;
        }
        prev_idle_   = idle;
        prev_kernel_ = kernel;
        prev_user_   = user;
    }
#endif
}

void DashboardView::update_eps(EngineManager& em) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_eps_tick_).count();
    if (elapsed >= 1000) {
        uint64_t total = em.total_engine_events();
        if (prev_total_events_ > 0) {
            float secs = static_cast<float>(elapsed) / 1000.0f;
            current_eps_ = static_cast<float>(total - prev_total_events_) / secs;
        }
        prev_total_events_ = total;
        last_eps_tick_ = now;
        eps_history_[eps_idx_ % std::size(eps_history_)] = current_eps_;
        ++eps_idx_;
    }
}

void DashboardView::render_engine_heatmap(EngineManager& em) {
    section_title("ENGINE HEALTH MAP");
    ImGui::Separator();

    const auto statuses = em.statuses();
    const float avail = ImGui::GetContentRegionAvail().x;
    const int cols = std::max(3, static_cast<int>(avail / 90.0f));
    const float cell_w = (avail - ImGui::GetStyle().ItemSpacing.x * static_cast<float>(cols - 1)) / static_cast<float>(cols);
    const float cell_h = 36.0f;

    int col = 0;
    for (auto& s : statuses) {
        const ImVec2 origin = ImGui::GetCursorScreenPos();
        auto* dl = ImGui::GetWindowDrawList();

        ImU32 bg;
        if (!s.running) {
            bg = 0xFF2d1b1b;
        } else if (s.threats_detected > 10) {
            bg = 0xFF2d2b1b;
        } else {
            bg = 0xFF1b2d1b;
        }

        dl->AddRectFilled(origin, {origin.x + cell_w, origin.y + cell_h}, bg, 4.0f);
        dl->AddRect(origin, {origin.x + cell_w, origin.y + cell_h}, ThemeColors::BORDER, 4.0f);

        ImU32 dot_color = s.running ? ThemeColors::ACCENT_SAFE : ThemeColors::ACCENT_CRIT;
        dl->AddCircleFilled({origin.x + 10.0f, origin.y + cell_h / 2.0f}, 4.0f, dot_color);

        dl->AddText({origin.x + 20.0f, origin.y + 4.0f}, ThemeColors::TEXT, s.name.c_str());

        char info[32];
        std::snprintf(info, sizeof(info), "%llu/%llu",
                      static_cast<unsigned long long>(s.events_processed),
                      static_cast<unsigned long long>(s.threats_detected));
        dl->AddText({origin.x + 20.0f, origin.y + 18.0f}, ThemeColors::TEXT_DIM, info);

        ImGui::Dummy({cell_w, cell_h});
        ++col;
        if (col < cols && col < static_cast<int>(statuses.size()))
            ImGui::SameLine();
        else
            col = 0;
    }
    ImGui::Spacing();
}

void DashboardView::render_threat_timeline(EngineManager& em) {
    section_title("THREAT TIMELINE (60s)");
    ImGui::Separator();

    auto events = em.recent_events(200);
    auto now = std::chrono::system_clock::now();

    float buckets[60]{};
    for (auto& ev : events) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - ev.timestamp).count();
        if (age >= 0 && age < 60) {
            buckets[59 - age] += 1.0f;
        }
    }

    for (int i = 0; i < 60; ++i)
        threat_timeline_[i] = buckets[i];

    float max_val = 1.0f;
    for (float v : threat_timeline_) max_val = std::max(max_val, v);

    const float avail_w = ImGui::GetContentRegionAvail().x;
    const float bar_w = std::max(2.0f, avail_w / 60.0f - 1.0f);
    const float chart_h = 60.0f;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    auto* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(origin, {origin.x + avail_w, origin.y + chart_h}, ThemeColors::BG_PANEL, 4.0f);

    for (int i = 0; i < 60; ++i) {
        float ratio = threat_timeline_[i] / max_val;
        float h = ratio * (chart_h - 4.0f);
        float x = origin.x + static_cast<float>(i) * (bar_w + 1.0f);
        float y_bottom = origin.y + chart_h - 2.0f;

        ImU32 color = ThemeColors::ACCENT_INFO;
        if (threat_timeline_[i] >= 5.0f) color = ThemeColors::ACCENT_CRIT;
        else if (threat_timeline_[i] >= 2.0f) color = ThemeColors::ACCENT_WARN;

        if (h > 0.5f)
            dl->AddRectFilled({x, y_bottom - h}, {x + bar_w, y_bottom}, color, 1.0f);
    }

    ImGui::Dummy({avail_w, chart_h});
    ImGui::TextDisabled("60s ago                                    now");
}

void DashboardView::render_severity_histogram(EngineManager& em) {
    section_title("SEVERITY DISTRIBUTION");
    ImGui::Separator();

    const auto hist = em.severity_histogram();
    size_t max_val = 1;
    for (auto v : hist) max_val = std::max(max_val, v);

    const char* labels[] = {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    const ImU32 colors[] = {
        ThemeColors::ACCENT_SAFE, ThemeColors::ACCENT_INFO, ThemeColors::ACCENT_WARN,
        ThemeColors::ACCENT_HIGH, ThemeColors::ACCENT_CRIT,
    };

    const float bar_max_width = ImGui::GetContentRegionAvail().x - 110.0f;
    for (int i = 0; i < 5; ++i) {
        ImGui::TextDisabled("%-8s", labels[i]);
        ImGui::SameLine(90.0f);
        const float ratio = static_cast<float>(hist[i]) / static_cast<float>(max_val);
        const float bar_width = std::max(2.0f, ratio * bar_max_width);
        const ImVec2 origin = ImGui::GetCursorScreenPos();
        auto* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(origin, {origin.x + bar_width, origin.y + 14.0f}, colors[i], 3.0f);
        ImGui::Dummy({bar_max_width, 16.0f});
        ImGui::SameLine();
        ImGui::Text("%zu", hist[i]);
    }
}

void DashboardView::render_security_findings(EngineManager& em) {
    section_title("SECURITY FINDINGS");
    ImGui::Separator();

    const auto findings = em.recent_security_findings(20);
    if (findings.empty()) {
        ImGui::TextDisabled("No correlated security findings yet.");
        return;
    }

    for (auto it = findings.rbegin(); it != findings.rend(); ++it) {
        push_threat_color(static_cast<uint8_t>(it->level));
        ImGui::TextUnformatted(threat_level_label(static_cast<uint8_t>(it->level)));
        pop_threat_color();
        ImGui::SameLine();

        char score[16];
        std::snprintf(score, sizeof(score), "[risk:%u]", static_cast<unsigned>(it->risk_score));
        ImGui::TextDisabled("%s", score);
        ImGui::SameLine();

        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
        ImGui::TextWrapped("%s", it->rationale.c_str());
        ImGui::PopTextWrapPos();
    }
}

void DashboardView::render_activity_feed(EngineManager& em) {
    section_title("RECENT ACTIVITY");
    ImGui::Separator();
    ImGui::BeginChild("##activity_feed", {0.0f, 0.0f}, true);
    const auto events = em.recent_events(40);
    if (events.empty()) ImGui::TextDisabled("No detections recorded. Monitoring is active.");
    for (auto it = events.rbegin(); it != events.rend(); ++it) {
        push_threat_color(static_cast<uint8_t>(it->level));
        ImGui::TextUnformatted(threat_level_label(static_cast<uint8_t>(it->level)));
        pop_threat_color();
        ImGui::SameLine();
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
        ImGui::TextWrapped("%s", it->description.c_str());
        ImGui::PopTextWrapPos();
    }
    ImGui::EndChild();
}

} // namespace gcad::ui::views
