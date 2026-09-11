#include "gcad/ui/views/forensics_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui.h"
#include "imgui_internal.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <map>

namespace gcad::ui::views {

namespace {

constexpr float CARD_W = 196.0f;
constexpr float CARD_H = 60.0f;
constexpr float COL_W  = 252.0f;
constexpr float ROW_H  = 88.0f;

std::string rel_time(std::chrono::system_clock::time_point tp) {
    if (tp.time_since_epoch().count() == 0) return "--";
    auto s = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now() - tp).count();
    char b[32];
    if (s < 0) s = 0;
    if (s < 60)        std::snprintf(b, sizeof(b), "%llds ago", (long long)s);
    else if (s < 3600) std::snprintf(b, sizeof(b), "%lldm ago", (long long)(s / 60));
    else               std::snprintf(b, sizeof(b), "%lldh ago", (long long)(s / 3600));
    return b;
}

std::string truncate_to(const std::string& s, float max_w) {
    if (ImGui::CalcTextSize(s.c_str()).x <= max_w) return s;
    std::string out = s;
    while (!out.empty() && ImGui::CalcTextSize((out + "...").c_str()).x > max_w)
        out.pop_back();
    return out + "...";
}

void level_badge(uint8_t lv) {
    ImU32 c = threat_level_color(lv);
    ImVec2 p = ImGui::GetCursorScreenPos();
    const char* t = threat_level_label(lv);
    ImVec2 ts = ImGui::CalcTextSize(t);
    float pad = 6.0f, h = ts.y + 4.0f;
    auto* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, {p.x + ts.x + pad * 2, p.y + h}, (c & 0x00FFFFFF) | 0x33000000, 3.0f);
    dl->AddRect(p, {p.x + ts.x + pad * 2, p.y + h}, c, 3.0f);
    dl->AddText({p.x + pad, p.y + 2.0f}, c, t);
    ImGui::Dummy({ts.x + pad * 2, h});
}

} // namespace

int ForensicsView::node_index_for_pid(uint32_t pid) const {
    for (size_t i = 0; i < nodes_.size(); ++i)
        if (nodes_[i].pid == pid) return static_cast<int>(i);
    return -1;
}

void ForensicsView::render(EngineManager& em) {
    auto events = em.recent_events(250);
    if (events.size() != last_event_count_) {
        last_event_count_ = events.size();
        timeline_ = events;
        rebuild(events);
    }

    draw_toolbar();
    ImGui::Separator();

    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##fx_graph", {w * 0.62f, 0}, true);
    draw_graph();
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##fx_side", {0, 0}, false);
    ImGui::BeginChild("##fx_detail", {0, ImGui::GetContentRegionAvail().y * 0.52f}, true);
    draw_detail_panel();
    ImGui::EndChild();
    ImGui::Spacing();
    ImGui::BeginChild("##fx_timeline", {0, 0}, true);
    draw_timeline();
    ImGui::EndChild();
    ImGui::EndChild();
}

void ForensicsView::rebuild(const std::vector<ThreatEvent>& events) {
    nodes_.clear();
    std::map<uint32_t, size_t> idx;

    for (auto& ev : events) {
        if (ev.process_id == 0) continue;
        auto it = idx.find(ev.process_id);
        size_t ni;
        if (it == idx.end()) {
            DagNode n;
            n.pid = ev.process_id;
            n.label = ev.process_name.empty() ? ("PID " + std::to_string(ev.process_id))
                                              : ev.process_name;
            n.first_seen = ev.timestamp;
            ni = nodes_.size();
            idx[ev.process_id] = ni;
            nodes_.push_back(std::move(n));
        } else {
            ni = it->second;
            if (!ev.process_name.empty() && nodes_[ni].label.rfind("PID ", 0) == 0)
                nodes_[ni].label = ev.process_name;
        }
        auto& n = nodes_[ni];
        n.events++;
        n.level = std::max<uint8_t>(n.level, static_cast<uint8_t>(ev.level));
    }

    // Edges: an event followed shortly by an event from a different process implies
    // a causal link (spawn / injection / lateral action).
    for (size_t i = 0; i + 1 < events.size(); ++i) {
        uint32_t a = events[i].process_id, b = events[i + 1].process_id;
        if (a == 0 || b == 0 || a == b) continue;
        auto ia = idx.find(a), ib = idx.find(b);
        if (ia == idx.end() || ib == idx.end()) continue;
        auto& kids = nodes_[ia->second].children;
        if (std::find(kids.begin(), kids.end(), ib->second) == kids.end()) {
            kids.push_back(ib->second);
            nodes_[ib->second].parents.push_back(ia->second);
        }
    }
    layout();
}

void ForensicsView::layout() {
    if (nodes_.empty()) return;

    // Longest-path ranking (stable under the cycle cap).
    for (auto& n : nodes_) n.rank = 0;
    for (size_t iter = 0; iter < nodes_.size(); ++iter) {
        bool changed = false;
        for (size_t i = 0; i < nodes_.size(); ++i)
            for (size_t c : nodes_[i].children)
                if (nodes_[c].rank < nodes_[i].rank + 1) {
                    nodes_[c].rank = std::min<int>(nodes_[i].rank + 1, 24);
                    changed = true;
                }
        if (!changed) break;
    }

    std::map<int, std::vector<size_t>> by_rank;
    for (size_t i = 0; i < nodes_.size(); ++i) by_rank[nodes_[i].rank].push_back(i);

    for (auto& [rank, group] : by_rank) {
        std::sort(group.begin(), group.end(), [&](size_t a, size_t b) {
            if (nodes_[a].level != nodes_[b].level) return nodes_[a].level > nodes_[b].level;
            return nodes_[a].pid < nodes_[b].pid;
        });
        for (size_t k = 0; k < group.size(); ++k) {
            nodes_[group[k]].x = 30.0f + rank * COL_W;
            nodes_[group[k]].y = 24.0f + k * ROW_H;
        }
    }
}

void ForensicsView::draw_toolbar() {
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("ATTACK GRAPH");
    ImGui::SameLine();
    ImGui::TextDisabled("%zu processes | %zu events", nodes_.size(), timeline_.size());
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 320.0f);
    if (ImGui::SmallButton("Reset view")) { pan_x_ = pan_y_ = 0.0f; zoom_ = 1.0f; }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::SliderFloat("##zoom", &zoom_, 0.35f, 2.5f, "zoom %.0f%%", ImGuiSliderFlags_Logarithmic);
    ImGui::SameLine();
    // Legend
    const char* names[5] = {"safe", "low", "med", "high", "crit"};
    for (int i = 1; i < 5; ++i) {
        ImGui::SameLine();
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddCircleFilled({p.x + 5, p.y + ImGui::GetTextLineHeight() * 0.5f + 2},
                                                    4.0f, threat_level_color(static_cast<uint8_t>(i)));
        ImGui::Dummy({12, 0}); ImGui::SameLine();
        ImGui::TextDisabled("%s", names[i]);
    }
}

void ForensicsView::draw_graph() {
    ImVec2 canvas_p = ImGui::GetCursorScreenPos();
    ImVec2 canvas_sz = ImGui::GetContentRegionAvail();
    if (canvas_sz.x < 50) canvas_sz.x = 50;
    if (canvas_sz.y < 50) canvas_sz.y = 50;
    auto* dl = ImGui::GetWindowDrawList();

    dl->AddRectFilled(canvas_p, canvas_p + canvas_sz, 0xFF0b0f14);

    ImGui::InvisibleButton("##fx_canvas", canvas_sz,
                           ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    bool hovered = ImGui::IsItemHovered();
    ImGuiIO& io = ImGui::GetIO();
    if (hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        pan_x_ += io.MouseDelta.x;
        pan_y_ += io.MouseDelta.y;
    }
    if (hovered && io.MouseWheel != 0.0f) {
        float old = zoom_;
        zoom_ = std::clamp(zoom_ * (1.0f + io.MouseWheel * 0.12f), 0.35f, 2.5f);
        // zoom toward cursor
        ImVec2 m = io.MousePos - canvas_p;
        pan_x_ = m.x - (m.x - pan_x_) * (zoom_ / old);
        pan_y_ = m.y - (m.y - pan_y_) * (zoom_ / old);
    }

    dl->PushClipRect(canvas_p, canvas_p + canvas_sz, true);

    auto to_screen = [&](float gx, float gy) {
        return ImVec2(canvas_p.x + pan_x_ + gx * zoom_, canvas_p.y + pan_y_ + gy * zoom_);
    };

    // grid
    float step = 40.0f * zoom_;
    if (step > 6.0f) {
        for (float gx = fmodf(pan_x_, step); gx < canvas_sz.x; gx += step)
            dl->AddLine({canvas_p.x + gx, canvas_p.y}, {canvas_p.x + gx, canvas_p.y + canvas_sz.y}, 0xFF12171e);
        for (float gy = fmodf(pan_y_, step); gy < canvas_sz.y; gy += step)
            dl->AddLine({canvas_p.x, canvas_p.y + gy}, {canvas_p.x + canvas_sz.x, canvas_p.y + gy}, 0xFF12171e);
    }

    if (nodes_.empty()) {
        const char* msg = "No process-linked detections yet.";
        const char* sub = "Detections carrying a PID will appear here as a causal attack graph.";
        ImVec2 t1 = ImGui::CalcTextSize(msg), t2 = ImGui::CalcTextSize(sub);
        dl->AddText({canvas_p.x + (canvas_sz.x - t1.x) / 2, canvas_p.y + canvas_sz.y / 2 - 16}, 0xFF8b98a5, msg);
        dl->AddText({canvas_p.x + (canvas_sz.x - t2.x) / 2, canvas_p.y + canvas_sz.y / 2 + 6}, 0xFF5a6570, sub);
        dl->PopClipRect();
        return;
    }

    // hit-test for hover
    hover_node_ = -1;
    ImVec2 mouse = io.MousePos;
    for (size_t i = 0; i < nodes_.size(); ++i) {
        ImVec2 a = to_screen(nodes_[i].x, nodes_[i].y);
        ImVec2 b = {a.x + CARD_W * zoom_, a.y + CARD_H * zoom_};
        if (hovered && mouse.x >= a.x && mouse.x <= b.x && mouse.y >= a.y && mouse.y <= b.y)
            hover_node_ = static_cast<int>(i);
    }
    if (hover_node_ >= 0 && ImGui::IsItemClicked(ImGuiMouseButton_Left))
        selected_pid_ = nodes_[hover_node_].pid;

    int sel_idx = node_index_for_pid(selected_pid_);

    auto related = [&](int ni) {
        if (sel_idx < 0 && hover_node_ < 0) return true;
        int ref = hover_node_ >= 0 ? hover_node_ : sel_idx;
        if (ni == ref) return true;
        for (size_t c : nodes_[ref].children) if ((int)c == ni) return true;
        for (size_t p : nodes_[ref].parents)  if ((int)p == ni) return true;
        return false;
    };

    // edges
    for (size_t i = 0; i < nodes_.size(); ++i) {
        for (size_t c : nodes_[i].children) {
            ImVec2 from = to_screen(nodes_[i].x + CARD_W, nodes_[i].y + CARD_H * 0.5f);
            ImVec2 to   = to_screen(nodes_[c].x, nodes_[c].y + CARD_H * 0.5f);
            float dx = std::max(40.0f, (to.x - from.x) * 0.5f);
            bool lit = related((int)i) && related((int)c);
            ImU32 ecol = threat_level_color(nodes_[c].level);
            ecol = (ecol & 0x00FFFFFF) | (lit ? 0xE0000000 : 0x3C000000);
            dl->AddBezierCubic(from, {from.x + dx, from.y}, {to.x - dx, to.y}, to, ecol, lit ? 2.4f : 1.4f);
            // arrowhead
            ImVec2 d{to.x - (to.x - dx) , 0};
            (void)d;
            float ah = 6.0f;
            dl->AddTriangleFilled({to.x, to.y}, {to.x - ah, to.y - ah * 0.7f},
                                  {to.x - ah, to.y + ah * 0.7f}, ecol);
        }
    }

    // nodes
    for (size_t i = 0; i < nodes_.size(); ++i) {
        auto& n = nodes_[i];
        ImVec2 a = to_screen(n.x, n.y);
        ImVec2 b = {a.x + CARD_W * zoom_, a.y + CARD_H * zoom_};
        bool lit = related((int)i);
        bool is_sel = ((int)i == sel_idx);
        bool is_hov = ((int)i == hover_node_);
        ImU32 lc = threat_level_color(n.level);

        ImU32 bg = lit ? 0xFF161c24 : 0xFF10151b;
        dl->AddRectFilled(a, b, bg, 6.0f);
        dl->AddRectFilled(a, {a.x + 4.0f, b.y}, (lc & 0x00FFFFFF) | (lit ? 0xFF000000 : 0x66000000),
                          6.0f, ImDrawFlags_RoundCornersLeft);
        ImU32 border = is_sel ? 0xFFe6edf3 : (is_hov ? 0xFF8b98a5 : 0xFF2a3038);
        dl->AddRect(a, b, border, 6.0f, 0, is_sel ? 2.0f : 1.0f);

        if (zoom_ > 0.5f) {
            float pad = 12.0f;
            ImU32 tcol = lit ? 0xFFe6edf3 : 0xFF6b7580;
            std::string title = truncate_to(n.label, (CARD_W - pad * 2) * 1.0f);
            dl->AddText({a.x + pad, a.y + 8}, tcol, title.c_str());
            char sub[64];
            std::snprintf(sub, sizeof(sub), "PID %u | %zu events", n.pid, n.events);
            dl->AddText({a.x + pad, a.y + 8 + ImGui::GetTextLineHeight() + 3}, lit ? 0xFF9aa4af : 0xFF565f6a, sub);
            dl->AddCircleFilled({b.x - 12, a.y + 12}, 4.0f, lc);
        }
    }

    dl->PopClipRect();
}

void ForensicsView::draw_detail_panel() {
    int i = node_index_for_pid(selected_pid_);
    if (i < 0) {
        ImGui::TextDisabled("Select a process node to inspect its activity.");
        return;
    }
    auto& n = nodes_[i];

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(0xFFe6edf3));
    ImGui::TextUnformatted(n.label.c_str());
    ImGui::PopStyleColor();
    ImGui::SameLine();
    level_badge(n.level);

    ImGui::TextDisabled("PID %u | first seen %s", n.pid, rel_time(n.first_seen).c_str());
    ImGui::Text("Events: %zu     Upstream: %zu     Downstream: %zu",
                n.events, n.parents.size(), n.children.size());
    ImGui::Separator();

    // category breakdown for this pid
    std::map<uint16_t, size_t> cats;
    for (auto& ev : timeline_)
        if (ev.process_id == n.pid) ++cats[static_cast<uint16_t>(ev.category)];
    if (!cats.empty()) {
        ImGui::TextDisabled("TECHNIQUES");
        for (auto& [c, cnt] : cats)
            ImGui::BulletText("%s  (%zu)", threat_category_label(c), cnt);
        ImGui::Separator();
    }

    ImGui::TextDisabled("EVENT LOG");
    ImGui::BeginChild("##fx_pidlog", {0, 0}, false);
    float wrap = ImGui::GetContentRegionAvail().x;
    for (auto it = timeline_.rbegin(); it != timeline_.rend(); ++it) {
        if (it->process_id != n.pid) continue;
        auto lv = static_cast<uint8_t>(it->level);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(threat_level_color(lv)));
        ImGui::Text("%s", threat_level_label(lv));
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::TextDisabled("%s", rel_time(it->timestamp).c_str());
        ImGui::PushTextWrapPos(wrap);
        ImGui::TextWrapped("%s", it->description.c_str());
        ImGui::PopTextWrapPos();
        ImGui::Spacing();
    }
    ImGui::EndChild();
}

void ForensicsView::draw_timeline() {
    ImGui::TextDisabled("GLOBAL TIMELINE  (newest first)");
    ImGui::Separator();
    float wrap = ImGui::GetContentRegionAvail().x;
    for (auto it = timeline_.rbegin(); it != timeline_.rend(); ++it) {
        auto lv = static_cast<uint8_t>(it->level);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(threat_level_color(lv)));
        ImGui::TextUnformatted("*");
        ImGui::PopStyleColor();
        ImGui::SameLine();

        bool clicked = false;
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap - 24.0f);
        std::string line = "[" + std::string(threat_category_label(static_cast<uint16_t>(it->category))) + "] "
                         + it->description;
        if (it->process_id) line += "  (PID " + std::to_string(it->process_id) + ")";
        ImGui::TextWrapped("%s", line.c_str());
        ImGui::PopTextWrapPos();
        if (ImGui::IsItemClicked() && it->process_id) clicked = true;
        if (clicked) selected_pid_ = it->process_id;
    }
}

} // namespace gcad::ui::views
