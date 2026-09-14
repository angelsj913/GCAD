#include "gcad/ui/views/dashboard_view.hpp"

#include "gcad/engine_manager.hpp"
#include "gcad/report/report_generator.hpp"
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
    const float height = ImGui::GetTextLineHeight() * 3.6f;
    auto* draw_list = ImGui::GetWindowDrawList();
    const ImVec2 end = {start.x + width, start.y + height};

    // Sleek glass panel with rounded corners and glowing border
    draw_list->AddRectFilled(start, end, ThemeColors::BG_PANEL, 8.0f);
    draw_list->AddRect(start, end, ThemeColors::BORDER, 8.0f, 0, 1.0f);

    // Accent indicator pill on the left
    draw_list->AddRectFilled(start, {start.x + 4.0f, end.y}, accent, 8.0f,
                             ImDrawFlags_RoundCornersLeft);

    // Subtle neon glow underneath the accent bar
    draw_list->AddRectFilled({start.x + 4.0f, start.y}, {start.x + 12.0f, end.y},
                             (accent & 0x00FFFFFF) | 0x18000000);

    draw_list->AddText({start.x + 16.0f, start.y + 10.0f}, ThemeColors::TEXT_DIM, label);
    draw_list->AddText({start.x + 16.0f, start.y + ImGui::GetTextLineHeight() + 14.0f},
                       ThemeColors::TEXT, value);
    ImGui::Dummy({width, height});
}

} // namespace

void DashboardView::render(EngineManager& em) {
    const auto status = em.current_threat_level();
    const bool is_safe = (status == ThreatLevel::SAFE);

    auto* dl = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    draw_status_dot(dl, {pos.x + 8.0f, pos.y + 14.0f}, is_safe, 5.0f);
    ImGui::SetCursorScreenPos({pos.x + 22.0f, pos.y});

    ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
    ImGui::TextUnformatted("PROTECTION OVERVIEW");
    ImGui::PopFont();
    const float header_width = ImGui::GetContentRegionAvail().x;
    if (header_width >= 440.0f) {
        ImGui::SameLine();
        ImGui::TextDisabled("Live protection and operator posture");
    }
    if (header_width >= 620.0f) {
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 150.0f);
        ImGui::TextDisabled("%llu engine events", static_cast<unsigned long long>(em.total_engine_events()));
    }
    ImGui::Separator();
    ImGui::Spacing();

    render_kpi_cards(em);
    ImGui::Spacing();

    const float width = ImGui::GetContentRegionAvail().x;
    const float gap = ImGui::GetStyle().ItemSpacing.x;
    const bool stacked = width < 860.0f;
    const float primary_width = stacked ? 0.0f : (width - gap) * 0.62f;
    const float primary_height = stacked ? ImGui::GetContentRegionAvail().y * 0.58f : 0.0f;
    ImGui::BeginChild("##dashboard_primary", {primary_width, primary_height}, false);
    render_engine_cards(em);
    ImGui::Spacing();
    render_category_health(em);
    ImGui::Spacing();
    render_severity_histogram(em);
    ImGui::Spacing();
    render_activity_feed(em);
    ImGui::EndChild();

    if (!stacked) ImGui::SameLine();
    else ImGui::Separator();

    ImGui::BeginChild("##dashboard_secondary", {0.0f, 0.0f}, false);
    render_threat_gauge(em);
    ImGui::Spacing();
    render_security_findings(em);
    ImGui::Spacing();
    if (ImGui::CollapsingHeader("Telemetry detail")) {
        render_threat_timeline(em);
        ImGui::Spacing();
        render_resource_monitor(em);
    }
    ImGui::EndChild();
}

void DashboardView::render_kpi_cards(EngineManager& em) {
    const auto statuses = em.statuses();
    const auto stopped = em.stopped_engines();
    const auto total_events = em.total_threats();

    char engines[32];
    char events[32];
    char engine_events[32];
    std::snprintf(engines, sizeof(engines), "%zu / %zu", statuses.size() - stopped.size(), statuses.size());
    std::snprintf(events, sizeof(events), "%zu", total_events);
    std::snprintf(engine_events, sizeof(engine_events), "%llu",
                  static_cast<unsigned long long>(em.total_engine_events()));

    const float gap = ImGui::GetStyle().ItemSpacing.x;
    const float card_width = std::max(120.0f, (ImGui::GetContentRegionAvail().x - gap * 2.0f) / 3.0f);
    const bool stack_cards = ImGui::GetContentRegionAvail().x < 440.0f;
    metric_card("ENGINES ONLINE", engines, stopped.empty() ? ThemeColors::ACCENT_SAFE : ThemeColors::ACCENT_WARN, card_width);
    if (!stack_cards) ImGui::SameLine(0.0f, gap);
    metric_card("ACTIVE THREATS", events, total_events == 0 ? ThemeColors::ACCENT_SAFE : ThemeColors::ACCENT_CRIT,
                card_width);
    if (!stack_cards) ImGui::SameLine(0.0f, gap);
    metric_card("ENGINE EVENTS", engine_events, ThemeColors::ACCENT_INFO,
                card_width);
}

void DashboardView::render_engine_cards(EngineManager& em) {
    section_title("DEFENSE DOMAIN MATRIX (31 ENGINES)");
    ImGui::Separator();
    ImGui::Spacing();

    struct DomainDef {
        const char* name;
        const char* desc;
        std::vector<std::string> engines;
    };

    static const DomainDef domains[] = {
        {"1. Kernel & Memory Defense", "Direct syscalls, kernel integrity, BYOVD drivers & memory injection",
         {"PMSR", "SyscallGuard", "KernelMon", "DriverGuard", "ReflectiveInjection"}},
        {"2. Script & Fileless Guard", "AMSI bypass patch, WMI persistence, PowerShell AST deobfuscation, weaponized LNK",
         {"AmsiGuard", "WmiBits", "FilelessAST", "Lolbins", "PeStaticAnalysis"}},
        {"3. Ransomware & Integrity", "I/O entropy honeypot canary, file integrity hash, LSASS dump & device control",
         {"RansomwareShield", "FIM", "CredentialGuard", "DeviceControl", "ARHS", "ZRGP"}},
        {"4. Perimeter & C2 Protection", "L3/L4 packet filtering, DGA/DNS tunnels, Cobalt Strike pipes & C2 DPI",
         {"ETG-RI", "Firewall", "DnsMon", "NetworkDPI", "NamedPipe"}},
        {"5. Intelligence & Forensics", "YARA rules, file sandbox, threat intel, vulnerability scanner & forensic timeline",
         {"YARA", "Sandbox", "ThreatIntel", "VulnScanner", "BehaviorML", "ForensicTimeline", "Webhook", "SelfDefense", "AutoUpdate"}},
    };

    const auto statuses = em.statuses();
    auto get_engine_status = [&statuses](const std::string& name) -> const EngineStatus* {
        for (const auto& s : statuses) {
            if (s.name == name) return &s;
        }
        return nullptr;
    };

    for (const auto& dom : domains) {
        size_t active_count = 0;
        uint64_t total_events = 0;
        uint64_t total_threats = 0;

        for (const auto& ename : dom.engines) {
            if (const auto* st = get_engine_status(ename)) {
                if (st->running) active_count++;
                total_events += st->events_processed;
                total_threats += st->threats_detected;
            }
        }

        const bool all_ok = (active_count == dom.engines.size());
        const ImU32 accent = all_ok ? ThemeColors::ACCENT_SAFE : ThemeColors::ACCENT_WARN;

        ImGui::PushID(dom.name);
        const ImVec2 origin = ImGui::GetCursorScreenPos();
        const float card_w = ImGui::GetContentRegionAvail().x;
        const float card_h = ImGui::GetTextLineHeight() * 3.8f;
        auto* dl = ImGui::GetWindowDrawList();

        // Card Panel Background
        dl->AddRectFilled(origin, {origin.x + card_w, origin.y + card_h}, ThemeColors::BG_PANEL, 6.0f);
        dl->AddRect(origin, {origin.x + card_w, origin.y + card_h}, ThemeColors::BORDER, 6.0f);
        dl->AddRectFilled(origin, {origin.x + 4.0f, origin.y + card_h}, accent, 6.0f, ImDrawFlags_RoundCornersLeft);

        // Header Row
        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + 6.0f});
        ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
        ImGui::TextUnformatted(dom.name);
        ImGui::PopFont();

        ImGui::SameLine(card_w - 140.0f);
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(accent), "%zu/%zu ONLINE", active_count, dom.engines.size());

        // Description
        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + ImGui::GetTextLineHeight() + 10.0f});
        ImGui::TextDisabled("%s", dom.desc);

        // Engine Chips row
        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + ImGui::GetTextLineHeight() * 2.2f + 12.0f});
        for (size_t i = 0; i < dom.engines.size(); ++i) {
            const auto& ename = dom.engines[i];
            const auto* st = get_engine_status(ename);
            const bool en_run = st ? st->running : false;
            ImGui::PushStyleColor(ImGuiCol_Button, en_run ? ImGui::ColorConvertU32ToFloat4(ThemeColors::BUTTON)
                                                         : ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_CRIT));
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(en_run ? ThemeColors::TEXT_DIM : ThemeColors::TEXT));
            ImGui::SmallButton(ename.c_str());
            if (st && ImGui::IsItemHovered()) {
                ImGui::SetTooltip("%s | Events: %llu, Threats: %llu", ename.c_str(),
                                  static_cast<unsigned long long>(st->events_processed),
                                  static_cast<unsigned long long>(st->threats_detected));
            }
            ImGui::PopStyleColor(2);
            if (i + 1 < dom.engines.size()) ImGui::SameLine(0.0f, 4.0f);
        }

        ImGui::SetCursorScreenPos({origin.x, origin.y + card_h + 8.0f});
        ImGui::PopID();
    }
}

void DashboardView::render_threat_gauge(EngineManager& em) {
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

    const float marker = origin.x + (static_cast<float>(em.current_threat_level()) / 4.0f) * width;
    draw_list->AddTriangleFilled({marker, origin.y + 24.0f}, {marker - 6.0f, origin.y + 15.0f},
                                 {marker + 6.0f, origin.y + 15.0f}, ThemeColors::TEXT);
    ImGui::Dummy({width, 32.0f});
    push_threat_color(static_cast<uint8_t>(em.current_threat_level()));
    ImGui::Text("Current level: %s", threat_level_label(static_cast<uint8_t>(em.current_threat_level())));
    pop_threat_color();
}

void DashboardView::render_resource_monitor(EngineManager& em) {
    section_title("SYSTEM RESOURCES");
    ImGui::Separator();

    float memory_mb = 0.0f;
#ifdef GCAD_PLATFORM_WINDOWS
    PROCESS_MEMORY_COUNTERS counters{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)))
        memory_mb = static_cast<float>(counters.WorkingSetSize) / (1024.0f * 1024.0f);
#endif

    ImGui::Text("GCAD working set: %.1f MB", memory_mb);
    ImGui::Text("Engine events processed: %llu", static_cast<unsigned long long>(em.total_engine_events()));
    ImGui::TextDisabled("Historical resource charts are omitted until sampled telemetry is available.");
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

    float max_val = 1.0f;
    for (float value : buckets) max_val = std::max(max_val, value);

    const float avail_w = ImGui::GetContentRegionAvail().x;
    const float bar_w = std::max(2.0f, avail_w / 60.0f - 1.0f);
    const float chart_h = 60.0f;
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    auto* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(origin, {origin.x + avail_w, origin.y + chart_h}, ThemeColors::BG_PANEL, 4.0f);

    for (int i = 0; i < 60; ++i) {
        float ratio = buckets[i] / max_val;
        float h = ratio * (chart_h - 4.0f);
        float x = origin.x + static_cast<float>(i) * (bar_w + 1.0f);
        float y_bottom = origin.y + chart_h - 2.0f;

        ImU32 color = ThemeColors::ACCENT_INFO;
        if (buckets[i] >= 5.0f) color = ThemeColors::ACCENT_CRIT;
        else if (buckets[i] >= 2.0f) color = ThemeColors::ACCENT_WARN;

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

void DashboardView::render_category_health(EngineManager& em) {
    section_title("CATEGORY HEALTH");
    ImGui::Separator();

    const auto categories = em.category_histogram();
    if (categories.empty()) {
        ImGui::TextDisabled("No categorized events recorded.");
        return;
    }

    const size_t max_count = std::max<size_t>(1, categories.front().second);
    const size_t visible_count = std::min<size_t>(5, categories.size());
    const float bar_max_width = std::max(40.0f, ImGui::GetContentRegionAvail().x - 150.0f);
    for (size_t index = 0; index < visible_count; ++index) {
        const auto [category, count] = categories[index];
        const char* label = category == ThreatCategory::C2_BEACON
                                ? "C2 Beacon"
                                : report::ReportGenerator::category_label(category);
        ImGui::TextDisabled("%-20s", label);
        ImGui::SameLine(145.0f);
        const float ratio = static_cast<float>(count) / static_cast<float>(max_count);
        const ImVec2 origin = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddRectFilled(
            origin, {origin.x + std::max(2.0f, ratio * bar_max_width), origin.y + 14.0f},
            ThemeColors::ACCENT_INFO, 3.0f);
        ImGui::Dummy({bar_max_width, 16.0f});
        ImGui::SameLine();
        ImGui::Text("%zu", count);
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
