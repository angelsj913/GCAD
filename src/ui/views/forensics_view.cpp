#include "gcad/ui/views/forensics_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#include "imgui.h"
#include <cmath>
#include <algorithm>
#include <map>

namespace gcad::ui::views {

void ForensicsView::render(EngineManager& em) {
    auto events = em.recent_events(200);
    if (events.size() != timeline_.size()) {
        timeline_ = events;
        rebuild_dag(events);
    }

    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##dag", {w * 0.65f, 0}, true);
    render_dag_canvas();
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##timeline", {0, 0}, true);
    render_timeline_list();
    ImGui::Separator();
    render_node_detail();
    ImGui::EndChild();
}

void ForensicsView::rebuild_dag(const std::vector<ThreatEvent>& events) {
    nodes_.clear();
    std::map<uint32_t, size_t> pid_to_node;

    for (auto& ev : events) {
        uint32_t pid = ev.process_id;
        if (pid == 0) continue;
        if (pid_to_node.find(pid) == pid_to_node.end()) {
            DAGNode node;
            node.id = nodes_.size();
            node.pid = pid;
            node.label = ev.process_name.empty() ?
                "PID " + std::to_string(pid) : ev.process_name;
            node.color = threat_level_color(static_cast<uint8_t>(ev.level));
            pid_to_node[pid] = nodes_.size();
            nodes_.push_back(node);
        } else {
            auto& existing = nodes_[pid_to_node[pid]];
            if (static_cast<uint8_t>(ev.level) > 0) {
                uint32_t new_c = threat_level_color(static_cast<uint8_t>(ev.level));
                existing.color = new_c;
            }
        }
    }

    for (size_t i = 0; i + 1 < events.size(); i++) {
        uint32_t a_pid = events[i].process_id;
        uint32_t b_pid = events[i + 1].process_id;
        if (a_pid == 0 || b_pid == 0 || a_pid == b_pid) continue;
        auto it_a = pid_to_node.find(a_pid);
        auto it_b = pid_to_node.find(b_pid);
        if (it_a != pid_to_node.end() && it_b != pid_to_node.end()) {
            auto& children = nodes_[it_a->second].children;
            if (std::find(children.begin(), children.end(), it_b->second) == children.end())
                children.push_back(it_b->second);
        }
    }
    layout_dag();
}

void ForensicsView::layout_dag() {
    float x = 50.0f, y = 30.0f;
    for (size_t i = 0; i < nodes_.size(); i++) {
        nodes_[i].x = x + static_cast<float>(i % 6) * 130.0f;
        nodes_[i].y = y + static_cast<float>(i / 6) * 90.0f;
    }
}

void ForensicsView::render_dag_canvas() {
    ImGui::Text("Attack Graph (DAG)");
    ImGui::Text("Zoom: %.0f%% | Drag to pan | Click to select", zoom_ * 100);
    ImGui::Separator();

    auto* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetCursorScreenPos();
    ImVec2 avail = ImGui::GetContentRegionAvail();
    dl->AddRectFilled(origin, {origin.x + avail.x, origin.y + avail.y}, 0xFF0d1117);

    ImGuiIO& io = ImGui::GetIO();
    ImGui::InvisibleButton("##canvas", avail);
    if (ImGui::IsItemActive() && ImGui::IsMouseDragging(0)) {
        scroll_x_ += io.MouseDelta.x;
        scroll_y_ += io.MouseDelta.y;
    }
    if (ImGui::IsItemHovered()) {
        zoom_ += io.MouseWheel * 0.1f;
        if (zoom_ < 0.3f) zoom_ = 0.3f;
        if (zoom_ > 3.0f) zoom_ = 3.0f;
    }

    for (auto& node : nodes_) {
        for (auto child_id : node.children) {
            if (child_id < nodes_.size()) {
                auto& child = nodes_[child_id];
                ImVec2 from = {origin.x + scroll_x_ + node.x * zoom_,
                               origin.y + scroll_y_ + node.y * zoom_};
                ImVec2 to = {origin.x + scroll_x_ + child.x * zoom_,
                             origin.y + scroll_y_ + child.y * zoom_};
                dl->AddLine(from, to, 0xFF484f58, 1.5f);
                float dx = to.x - from.x, dy = to.y - from.y;
                float len = sqrtf(dx * dx + dy * dy);
                if (len > 0) {
                    dx /= len; dy /= len;
                    ImVec2 tip = to;
                    ImVec2 l = {tip.x - dx * 8 - dy * 4, tip.y - dy * 8 + dx * 4};
                    ImVec2 r = {tip.x - dx * 8 + dy * 4, tip.y - dy * 8 - dx * 4};
                    dl->AddTriangleFilled(tip, l, r, 0xFF484f58);
                }
            }
        }
    }

    for (size_t i = 0; i < nodes_.size(); i++) {
        auto& node = nodes_[i];
        ImVec2 pos = {origin.x + scroll_x_ + node.x * zoom_,
                      origin.y + scroll_y_ + node.y * zoom_};
        float r = 20.0f * zoom_;
        bool selected = (static_cast<int>(i) == selected_node_);
        dl->AddCircleFilled(pos, r, node.color, 24);
        if (selected) dl->AddCircle(pos, r + 3, 0xFFe6edf3, 24, 2.0f);

        auto ts = ImGui::CalcTextSize(node.label.c_str());
        dl->AddText({pos.x - ts.x * 0.5f, pos.y + r + 2}, 0xFFe6edf3, node.label.c_str());

        if (ImGui::IsMouseClicked(0)) {
            ImVec2 mp = io.MousePos;
            float ddx = mp.x - pos.x, ddy = mp.y - pos.y;
            if (ddx * ddx + ddy * ddy < r * r) selected_node_ = static_cast<int>(i);
        }
    }
}

void ForensicsView::render_timeline_list() {
    ImGui::Text("Event Timeline (%zu events)", timeline_.size());
    ImGui::Separator();
    ImGui::BeginChild("##evlist", {0, 200}, false);
    for (auto it = timeline_.rbegin(); it != timeline_.rend(); ++it) {
        push_threat_color(static_cast<uint8_t>(it->level));
        ImGui::BulletText("[%s] %s (PID %u)",
                          threat_level_label(static_cast<uint8_t>(it->level)),
                          it->description.c_str(),
                          it->process_id);
        pop_threat_color();
    }
    ImGui::EndChild();
}

void ForensicsView::render_node_detail() {
    if (selected_node_ < 0 || selected_node_ >= static_cast<int>(nodes_.size())) {
        ImGui::TextDisabled("Click a node for details.");
        return;
    }
    auto& node = nodes_[selected_node_];
    ImGui::Text("Node: %s", node.label.c_str());
    ImGui::Text("PID: %u", node.pid);
    ImGui::Text("Connections: %zu", node.children.size());

    size_t threat_count = 0;
    for (auto& ev : timeline_) {
        if (ev.process_id == node.pid) threat_count++;
    }
    ImGui::Text("Related events: %zu", threat_count);
}

} // namespace gcad::ui::views
