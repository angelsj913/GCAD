#include "gcad/ui/views/dashboard_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/scanner/deep_scanner.hpp"
#include "imgui.h"
#include <cmath>
#include <cstdio>

#ifdef GCAD_PLATFORM_WINDOWS
#include <psapi.h>
#endif

namespace gcad::ui::views {

namespace {

void section_title(const char* t) {
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(0xFF8b98a5));
    ImGui::TextUnformatted(t);
    ImGui::PopStyleColor();
    ImGui::Spacing();
}

// A compact key/value tile drawn into the current cursor position.
void kpi_tile(const char* label, const std::string& value, unsigned int accent, float width) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetTextLineHeight() * 3.1f;
    auto* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, {p.x + width, p.y + h}, 0xFF161b22, 4.0f);
    dl->AddRect(p, {p.x + width, p.y + h}, 0xFF2a3038, 4.0f);
    dl->AddRectFilled(p, {p.x + 3, p.y + h}, accent, 4.0f, ImDrawFlags_RoundCornersLeft);

    dl->AddText({p.x + 12, p.y + 8}, 0xFF8b98a5, label);
    dl->AddText({p.x + 12, p.y + 8 + ImGui::GetTextLineHeight() + 4}, 0xFFe6edf3, value.c_str());
    ImGui::Dummy({width, h});
}

void hbar(const char* label, size_t count, size_t max_count, unsigned int color, float label_w) {
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(label);
    ImGui::SameLine(label_w);

    float avail = ImGui::GetContentRegionAvail().x - 52.0f;
    if (avail < 40.0f) avail = 40.0f;
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetTextLineHeight() + 2.0f;
    float frac = max_count > 0 ? static_cast<float>(count) / static_cast<float>(max_count) : 0.0f;
    auto* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, {p.x + avail, p.y + h}, 0xFF161b22, 3.0f);
    if (frac > 0.0f)
        dl->AddRectFilled(p, {p.x + avail * frac, p.y + h}, color, 3.0f);
    ImGui::Dummy({avail, h});
    ImGui::SameLine();
    ImGui::Text("%zu", count);
}

std::string human_uptime(std::chrono::steady_clock::duration d) {
    auto s = std::chrono::duration_cast<std::chrono::seconds>(d).count();
    long h = s / 3600, m = (s % 3600) / 60, sec = s % 60;
    char buf[32];
    if (h > 0) std::snprintf(buf, sizeof(buf), "%ldh %02ldm", h, m);
    else       std::snprintf(buf, sizeof(buf), "%ldm %02lds", m, sec);
    return buf;
}

std::string commaf(uint64_t v) {
    std::string s = std::to_string(v), out;
    int c = 0;
    for (auto it = s.rbegin(); it != s.rend(); ++it) {
        if (c && c % 3 == 0) out.push_back(',');
        out.push_back(*it);
        ++c;
    }
    return {out.rbegin(), out.rend()};
}

} // namespace

void DashboardView::sample_cpu() {
#ifdef GCAD_PLATFORM_WINDOWS
    FILETIME ftC, ftE, ftK, ftU;
    if (!GetProcessTimes(GetCurrentProcess(), &ftC, &ftE, &ftK, &ftU)) return;
    uint64_t k = (uint64_t(ftK.dwHighDateTime) << 32) | ftK.dwLowDateTime;
    uint64_t u = (uint64_t(ftU.dwHighDateTime) << 32) | ftU.dwLowDateTime;
    uint64_t ticks = k + u; // 100ns units
    auto now = std::chrono::steady_clock::now();
    if (last_cpu_ticks_ != 0) {
        double wall_ns = std::chrono::duration<double, std::nano>(now - last_cpu_sample_).count();
        double busy_ns = static_cast<double>(ticks - last_cpu_ticks_) * 100.0;
        int cores = static_cast<int>(std::thread::hardware_concurrency());
        if (cores < 1) cores = 1;
        if (wall_ns > 0.0)
            cpu_percent_ = static_cast<float>(busy_ns / wall_ns / cores * 100.0);
        if (cpu_percent_ < 0.0f) cpu_percent_ = 0.0f;
        if (cpu_percent_ > 100.0f) cpu_percent_ = 100.0f;
    }
    last_cpu_ticks_ = ticks;
    last_cpu_sample_ = now;
#endif
}

void DashboardView::render(EngineManager& em, DeepScanner& scanner) {
    render_quick_actions(em, scanner);
    ImGui::Separator();
    ImGui::Spacing();

    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##dash_left", {w * 0.56f, 0}, false);
    render_engine_cards(em);
    ImGui::Spacing();
    render_recent_events(em);
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##dash_right", {0, 0}, false);
    render_protection_summary(em, scanner);
    ImGui::Spacing();
    render_severity_breakdown(em);
    ImGui::Spacing();
    render_category_breakdown(em);
    ImGui::Spacing();
    render_resource_monitor();
    ImGui::Spacing();
    render_radar(em);
    ImGui::EndChild();
}

void DashboardView::render_quick_actions(EngineManager& em, DeepScanner& scanner) {
    auto lvl = em.current_threat_level();
    push_threat_color(static_cast<uint8_t>(lvl));
    ImGui::AlignTextToFramePadding();
    ImGui::Text("SHIELD: %s", threat_level_label(static_cast<uint8_t>(lvl)));
    pop_threat_color();
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();

    bool scanning = scanner.is_scanning();
    ImGui::BeginDisabled(scanning);
    if (ImGui::Button("Quick Scan"))  scanner.start_scan(ScanMode::QUICK);
    ImGui::SameLine();
    if (ImGui::Button("Memory Scan")) scanner.start_scan(ScanMode::MEMORY);
    ImGui::SameLine();
    if (ImGui::Button("Full Scan"))   scanner.start_scan(ScanMode::DEEP);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (scanning) {
        if (ImGui::Button("Cancel")) scanner.cancel_scan();
        ImGui::SameLine();
        auto pr = scanner.progress();
        float frac = pr.files_total > 0
            ? static_cast<float>(pr.files_scanned) / static_cast<float>(pr.files_total) : 0.0f;
        char ov[64];
        std::snprintf(ov, sizeof(ov), "scanning  %llu / %llu",
                      (unsigned long long)pr.files_scanned, (unsigned long long)pr.files_total);
        ImGui::SetNextItemWidth(240);
        ImGui::ProgressBar(frac, {240, 0}, ov);
    } else {
        ImGui::TextDisabled("idle");
    }
}

void DashboardView::render_engine_cards(EngineManager& em) {
    section_title("SECURITY ENGINES");
    auto stats = em.statuses();
    const float card_h = ImGui::GetTextLineHeightWithSpacing() * 2.0f
                       + ImGui::GetStyle().WindowPadding.y * 2.0f
                       + ImGui::GetStyle().ItemSpacing.y;

    for (auto& s : stats) {
        ImGui::PushID(s.name.c_str());
        bool running = s.running;
        ImGui::PushStyleColor(ImGuiCol_ChildBg,
            running ? ImVec4(0.05f, 0.13f, 0.06f, 1.0f) : ImVec4(0.14f, 0.05f, 0.05f, 1.0f));
        ImGui::BeginChild("##card", {ImGui::GetContentRegionAvail().x, card_h}, true);

        ImGui::TextUnformatted(s.name.c_str());
        const char* st = running ? "ACTIVE" : "STOPPED";
        float off = ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(st).x;
        if (off > ImGui::GetCursorPosX()) ImGui::SameLine(off); else ImGui::SameLine();
        push_threat_color(running ? 0 : 4);
        ImGui::TextUnformatted(st);
        pop_threat_color();

        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(0xFF9aa4af));
        ImGui::Text("threats %llu   events %llu",
                    (unsigned long long)s.threats_detected,
                    (unsigned long long)s.events_processed);
        ImGui::PopStyleColor();

        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::PopID();
        ImGui::Spacing();
    }
}

void DashboardView::render_recent_events(EngineManager& em) {
    section_title("RECENT DETECTIONS");
    ImGui::BeginChild("##recent", {0, 0}, true);
    auto events = em.recent_events(40);
    if (events.empty()) {
        ImGui::TextDisabled("No detections yet. Engines are monitoring.");
    }
    float wrap = ImGui::GetContentRegionAvail().x;
    for (auto it = events.rbegin(); it != events.rend(); ++it) {
        auto lv = static_cast<uint8_t>(it->level);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(threat_level_color(lv)));
        ImGui::TextUnformatted("*");
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap - 20.0f);
        ImGui::TextWrapped("[%s] %s", threat_category_label(static_cast<uint16_t>(it->category)),
                           it->description.c_str());
        ImGui::PopTextWrapPos();
    }
    ImGui::EndChild();
}

void DashboardView::render_protection_summary(EngineManager& em, DeepScanner& scanner) {
    section_title("PROTECTION SUMMARY");
    ImGui::BeginChild("##summary", {0, ImGui::GetTextLineHeight() * 7.4f}, true);

    float full = ImGui::GetContentRegionAvail().x;
    float gap = 8.0f;
    float tw = (full - gap) * 0.5f;

    auto stopped = em.stopped_engines();
    kpi_tile("ENGINES ONLINE",
             std::to_string(em.engine_count() - stopped.size()) + " / " + std::to_string(em.engine_count()),
             stopped.empty() ? 0xFF3fb950 : 0xFFd29922, tw);
    ImGui::SameLine(0.0f, gap);
    kpi_tile("THREAT EVENTS", commaf(em.total_threats()), 0xFFf85149, tw);

    kpi_tile("FILES SCANNED", commaf(scanner.lifetime_scanned()), 0xFF58a6ff, tw);
    ImGui::SameLine(0.0f, gap);
    kpi_tile("SCAN HITS", commaf(scanner.lifetime_threats()), 0xFFf0883e, tw);

    kpi_tile("SIGNATURES", commaf(scanner.signature_count()), 0xFFa371f7, tw);
    ImGui::SameLine(0.0f, gap);
    kpi_tile("UPTIME", human_uptime(std::chrono::steady_clock::now() - session_start_), 0xFF3fb950, tw);

    ImGui::EndChild();
}

void DashboardView::render_severity_breakdown(EngineManager& em) {
    section_title("DETECTIONS BY SEVERITY");
    ImGui::BeginChild("##sev", {0, ImGui::GetTextLineHeight() * 6.6f}, true);
    auto h = em.severity_histogram();
    size_t mx = 1;
    for (auto v : h) mx = std::max(mx, v);
    const char* names[5] = {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    float lw = ImGui::CalcTextSize("CRITICAL ").x + 8.0f;
    for (int i = 4; i >= 0; --i)
        hbar(names[i], h[i], mx, threat_level_color(static_cast<uint8_t>(i)), lw);
    ImGui::EndChild();
}

void DashboardView::render_category_breakdown(EngineManager& em) {
    section_title("TOP ATTACK CATEGORIES");
    ImGui::BeginChild("##cat", {0, ImGui::GetTextLineHeight() * 8.4f}, true);
    auto hist = em.category_histogram();
    if (hist.empty()) {
        ImGui::TextDisabled("No categorized detections yet.");
    } else {
        size_t mx = hist.front().second ? hist.front().second : 1;
        float lw = 168.0f;
        int shown = 0;
        for (auto& [cat, cnt] : hist) {
            if (shown++ >= 6) break;
            hbar(threat_category_label(static_cast<uint16_t>(cat)), cnt, mx, 0xFF58a6ff, lw);
        }
    }
    ImGui::EndChild();
}

void DashboardView::render_resource_monitor() {
    section_title("RESOURCE USAGE");
    ImGui::BeginChild("##res", {0, ImGui::GetTextLineHeight() * 8.2f}, true);

#ifdef GCAD_PLATFORM_WINDOWS
    PROCESS_MEMORY_COUNTERS pmc{};
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    float mem_mb = pmc.WorkingSetSize / (1024.0f * 1024.0f);
#else
    float mem_mb = 0.0f;
#endif
    sample_cpu();

    cpu_history_[history_idx_ % 120] = cpu_percent_;
    mem_history_[history_idx_ % 120] = mem_mb;
    history_idx_++;

    ImGui::Text("CPU  %.1f %%", cpu_percent_);
    ImGui::PlotLines("##cpu", cpu_history_, 120, history_idx_ % 120, nullptr, 0.0f, 25.0f, {-1, 46});
    ImGui::Text("RAM  %.1f MB", mem_mb);
    ImGui::PlotLines("##mem", mem_history_, 120, history_idx_ % 120, nullptr, 0.0f, 64.0f, {-1, 46});

    ImGui::EndChild();
}

void DashboardView::render_radar(EngineManager& em) {
    auto lvl = static_cast<float>(em.current_threat_level());
    threat_gauge_ += (lvl - threat_gauge_) * 0.06f;

    section_title("LIVE THREAT RADAR");
    ImGui::BeginChild("##radar", {0, 190}, true);

    radar_angle_ += ImGui::GetIO().DeltaTime * 1.6f;
    if (radar_angle_ > 6.2831853f) radar_angle_ -= 6.2831853f;

    auto* dl = ImGui::GetWindowDrawList();
    ImVec2 c = ImGui::GetCursorScreenPos();
    ImVec2 avail = ImGui::GetContentRegionAvail();
    c.x += avail.x * 0.5f;
    c.y += 80.0f;
    float R = 74.0f;

    for (int i = 1; i <= 3; ++i)
        dl->AddCircle(c, R * i / 3.0f, 0xFF243040, 64, 1.0f);
    dl->AddLine({c.x - R, c.y}, {c.x + R, c.y}, 0xFF243040);
    dl->AddLine({c.x, c.y - R}, {c.x, c.y + R}, 0xFF243040);

    unsigned int sweep_col = threat_level_color(static_cast<uint8_t>(em.current_threat_level()));
    for (int i = 0; i < 24; ++i) {
        float a = radar_angle_ - 0.045f * i;
        float alpha = (1.0f - i / 24.0f);
        ImU32 cc = (static_cast<ImU32>(alpha * 150) << 24) | (sweep_col & 0x00FFFFFF);
        dl->AddLine(c, {c.x + cosf(a) * R, c.y + sinf(a) * R}, cc, 2.0f);
    }

    // Blips: one per recent high/critical detection, angle by pid hash, radius by recency.
    auto evs = em.recent_events(40);
    int k = 0;
    for (auto it = evs.rbegin(); it != evs.rend() && k < 16; ++it, ++k) {
        if (static_cast<uint8_t>(it->level) < 3) continue;
        float a = (it->process_id % 360) * 3.14159265f / 180.0f;
        float rr = R * (0.25f + 0.7f * (k / 16.0f));
        ImVec2 bp{c.x + cosf(a) * rr, c.y + sinf(a) * rr};
        dl->AddCircleFilled(bp, 3.0f, threat_level_color(static_cast<uint8_t>(it->level)));
    }

    ImGui::Dummy({avail.x, 168.0f});
    ImGui::EndChild();
}

} // namespace gcad::ui::views
