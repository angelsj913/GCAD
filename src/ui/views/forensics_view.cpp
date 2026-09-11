#include "gcad/ui/views/forensics_view.hpp"

#include "gcad/engine_manager.hpp"
#include "gcad/ui/theme.hpp"
#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui.h"
#include "imgui_internal.h"

#include <algorithm>
#include <cstdio>
#include <map>

namespace gcad::ui::views {

namespace {

constexpr float kCardWidth = 208.0f;
constexpr float kCardHeight = 68.0f;
constexpr float kColumnWidth = 260.0f;
constexpr float kRowHeight = 92.0f;

std::string relative_time(std::chrono::system_clock::time_point value) {
    if (value.time_since_epoch().count() == 0) return "--";
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - value).count();
    seconds = std::max<int64_t>(0, seconds);
    char text[32];
    if (seconds < 60) std::snprintf(text, sizeof(text), "%llds ago", static_cast<long long>(seconds));
    else if (seconds < 3600) std::snprintf(text, sizeof(text), "%lldm ago", static_cast<long long>(seconds / 60));
    else std::snprintf(text, sizeof(text), "%lldh ago", static_cast<long long>(seconds / 3600));
    return text;
}

std::string truncate_label(const std::string& label, float max_width) {
    if (ImGui::CalcTextSize(label.c_str()).x <= max_width) return label;
    std::string result = label;
    while (!result.empty() && ImGui::CalcTextSize((result + "...").c_str()).x > max_width)
        result.pop_back();
    return result + "...";
}

uint64_t fingerprint_of(std::span<const ThreatEvent> events) {
    uint64_t fingerprint = events.size();
    for (const auto& event : events) {
        fingerprint ^= event.id + 0x9e3779b97f4a7c15ULL + (fingerprint << 6U) + (fingerprint >> 2U);
        fingerprint ^= static_cast<uint64_t>(event.process_id) << 17U;
        fingerprint ^= static_cast<uint64_t>(event.level) << 9U;
        fingerprint ^= std::hash<std::string>{}(event.description);
    }
    return fingerprint;
}

} // namespace

void ForensicsView::render(EngineManager& em) {
    auto events = em.recent_events(250);
    if (fingerprint_of(events) != snapshot_fingerprint_) refresh(std::move(events));

    render_toolbar();
    ImGui::Separator();

    const float width = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##forensics_graph", {width * 0.64f, 0.0f}, true);
    render_graph_canvas();
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##forensics_detail", {0.0f, 0.0f}, false);
    const float detail_height = ImGui::GetContentRegionAvail().y * 0.48f;
    ImGui::BeginChild("##forensics_selection", {0.0f, detail_height}, true);
    render_node_detail();
    ImGui::EndChild();
    ImGui::Spacing();
    ImGui::BeginChild("##forensics_timeline", {0.0f, 0.0f}, true);
    render_timeline();
    ImGui::EndChild();
    ImGui::EndChild();
}

void ForensicsView::refresh(std::vector<ThreatEvent> events) {
    timeline_ = std::move(events);
    snapshot_fingerprint_ = fingerprint_of(timeline_);
    graph_ = build_forensic_graph(timeline_);
    if (node_index_for_pid(selected_pid_) < 0) selected_pid_ = 0;
    layout_graph();
}

void ForensicsView::layout_graph() {
    ranks_.assign(graph_.nodes.size(), 0);
    positions_.assign(graph_.nodes.size(), {});
    for (size_t pass = 0; pass < graph_.nodes.size(); ++pass) {
        bool changed = false;
        for (size_t index = 0; index < graph_.nodes.size(); ++index) {
            for (size_t child : graph_.nodes[index].children) {
                if (child >= ranks_.size()) continue;
                const int rank = std::min(24, ranks_[index] + 1);
                if (ranks_[child] < rank) {
                    ranks_[child] = rank;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }

    std::map<int, std::vector<size_t>> by_rank;
    for (size_t index = 0; index < ranks_.size(); ++index) by_rank[ranks_[index]].push_back(index);
    for (auto& [rank, indices] : by_rank) {
        std::sort(indices.begin(), indices.end(), [this](size_t left, size_t right) {
            const auto& lhs = graph_.nodes[left];
            const auto& rhs = graph_.nodes[right];
            if (lhs.level != rhs.level) return lhs.level > rhs.level;
            return lhs.pid < rhs.pid;
        });
        for (size_t row = 0; row < indices.size(); ++row)
            positions_[indices[row]] = {30.0f + rank * kColumnWidth, 28.0f + row * kRowHeight};
    }
}

void ForensicsView::render_toolbar() {
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("ATTACK GRAPH");
    ImGui::SameLine();
    ImGui::TextDisabled("%zu processes | %zu event records", graph_.nodes.size(), timeline_.size());
    ImGui::SameLine(std::max(ImGui::GetCursorPosX() + 12.0f, ImGui::GetContentRegionAvail().x - 230.0f));
    if (ImGui::SmallButton("Reset view")) { pan_x_ = 0.0f; pan_y_ = 0.0f; zoom_ = 1.0f; }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110.0f);
    ImGui::SliderFloat("##forensics_zoom", &zoom_, 0.35f, 2.5f, "%.0f%%", ImGuiSliderFlags_Logarithmic);
}

void ForensicsView::render_graph_canvas() {
    const ImVec2 canvas = ImGui::GetCursorScreenPos();
    ImVec2 size = ImGui::GetContentRegionAvail();
    size.x = std::max(50.0f, size.x);
    size.y = std::max(50.0f, size.y);
    auto* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas, canvas + size, ThemeColors::BG_MAIN, 4.0f);

    ImGui::InvisibleButton("##forensics_canvas", size,
                           ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    const bool hovered = ImGui::IsItemHovered();
    ImGuiIO& io = ImGui::GetIO();
    if (hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        pan_x_ += io.MouseDelta.x;
        pan_y_ += io.MouseDelta.y;
    }
    if (hovered && io.MouseWheel != 0.0f) {
        const float before = zoom_;
        zoom_ = std::clamp(zoom_ * (1.0f + io.MouseWheel * 0.12f), 0.35f, 2.5f);
        const ImVec2 cursor = io.MousePos - canvas;
        pan_x_ = cursor.x - (cursor.x - pan_x_) * (zoom_ / before);
        pan_y_ = cursor.y - (cursor.y - pan_y_) * (zoom_ / before);
    }

    draw_list->PushClipRect(canvas, canvas + size, true);
    const auto to_screen = [&](const GraphPoint& position) {
        return ImVec2(canvas.x + pan_x_ + position.x * zoom_, canvas.y + pan_y_ + position.y * zoom_);
    };

    const float grid = 40.0f * zoom_;
    if (grid > 8.0f) {
        for (float x = std::fmod(pan_x_, grid); x < size.x; x += grid)
            draw_list->AddLine({canvas.x + x, canvas.y}, {canvas.x + x, canvas.y + size.y}, 0xFF12171e);
        for (float y = std::fmod(pan_y_, grid); y < size.y; y += grid)
            draw_list->AddLine({canvas.x, canvas.y + y}, {canvas.x + size.x, canvas.y + y}, 0xFF12171e);
    }

    if (graph_.nodes.empty()) {
        const char* message = "No process-linked detections yet.";
        const ImVec2 text_size = ImGui::CalcTextSize(message);
        draw_list->AddText({canvas.x + (size.x - text_size.x) * 0.5f, canvas.y + size.y * 0.5f},
                           ThemeColors::TEXT_DIM, message);
        draw_list->PopClipRect();
        return;
    }

    hovered_node_ = -1;
    for (size_t index = 0; index < graph_.nodes.size(); ++index) {
        const ImVec2 origin = to_screen(positions_[index]);
        const ImVec2 end = {origin.x + kCardWidth * zoom_, origin.y + kCardHeight * zoom_};
        if (hovered && io.MousePos.x >= origin.x && io.MousePos.x <= end.x &&
            io.MousePos.y >= origin.y && io.MousePos.y <= end.y)
            hovered_node_ = static_cast<int>(index);
    }
    if (hovered_node_ >= 0 && ImGui::IsItemClicked(ImGuiMouseButton_Left))
        selected_pid_ = graph_.nodes[hovered_node_].pid;

    const int selected = node_index_for_pid(selected_pid_);
    const auto related = [&](int index) {
        if (selected < 0 && hovered_node_ < 0) return true;
        const int focus = hovered_node_ >= 0 ? hovered_node_ : selected;
        if (index == focus) return true;
        const auto& node = graph_.nodes[focus];
        return std::find(node.children.begin(), node.children.end(), static_cast<size_t>(index)) != node.children.end() ||
               std::find(node.parents.begin(), node.parents.end(), static_cast<size_t>(index)) != node.parents.end();
    };

    for (size_t index = 0; index < graph_.nodes.size(); ++index) {
        const auto& node = graph_.nodes[index];
        for (size_t child : node.children) {
            if (child >= positions_.size()) continue;
            ImVec2 from = to_screen({positions_[index].x + kCardWidth, positions_[index].y + kCardHeight * 0.5f});
            ImVec2 to = to_screen({positions_[child].x, positions_[child].y + kCardHeight * 0.5f});
            const bool lit = related(static_cast<int>(index)) && related(static_cast<int>(child));
            ImU32 color = threat_level_color(static_cast<uint8_t>(graph_.nodes[child].level));
            color = (color & 0x00FFFFFFU) | (lit ? 0xD0000000U : 0x35000000U);
            const float control = std::max(35.0f, (to.x - from.x) * 0.5f);
            draw_list->AddBezierCubic(from, {from.x + control, from.y}, {to.x - control, to.y}, to, color,
                                      lit ? 2.2f : 1.2f);
            draw_list->AddTriangleFilled(to, {to.x - 7.0f, to.y - 4.0f}, {to.x - 7.0f, to.y + 4.0f}, color);
        }
    }

    for (size_t index = 0; index < graph_.nodes.size(); ++index) {
        const auto& node = graph_.nodes[index];
        const ImVec2 origin = to_screen(positions_[index]);
        const ImVec2 end = {origin.x + kCardWidth * zoom_, origin.y + kCardHeight * zoom_};
        const bool lit = related(static_cast<int>(index));
        const bool is_selected = static_cast<int>(index) == selected;
        const bool is_hovered = static_cast<int>(index) == hovered_node_;
        const ImU32 severity = threat_level_color(static_cast<uint8_t>(node.level));
        const ImU32 background = lit ? ThemeColors::BG_PANEL : 0xFF10151b;
        const ImU32 border = is_selected ? ThemeColors::TEXT : (is_hovered ? ThemeColors::TEXT_DIM : ThemeColors::BORDER);

        draw_list->AddRectFilled(origin, end, background, 6.0f);
        draw_list->AddRectFilled(origin, {origin.x + 4.0f, end.y}, severity, 6.0f, ImDrawFlags_RoundCornersLeft);
        draw_list->AddRect(origin, end, border, 6.0f, 0, is_selected ? 2.0f : 1.0f);
        if (zoom_ > 0.5f) {
            const std::string title = truncate_label(node.label, (kCardWidth - 34.0f) * zoom_);
            draw_list->AddText({origin.x + 12.0f, origin.y + 9.0f}, lit ? ThemeColors::TEXT : ThemeColors::TEXT_DIM,
                               title.c_str());
            char subtitle[72];
            std::snprintf(subtitle, sizeof(subtitle), "PID %u | %zu event%s", node.pid, node.event_count,
                          node.event_count == 1 ? "" : "s");
            draw_list->AddText({origin.x + 12.0f, origin.y + 33.0f}, ThemeColors::TEXT_DIM, subtitle);
            draw_status_dot(draw_list, {end.x - 13.0f, origin.y + 13.0f}, node.level <= ThreatLevel::MEDIUM, 4.0f);
        }
    }
    draw_list->PopClipRect();
}

void ForensicsView::render_node_detail() {
    const int index = node_index_for_pid(selected_pid_);
    if (index < 0) {
        ImGui::TextDisabled("Select a process card to inspect related events.");
        return;
    }

    const auto& node = graph_.nodes[index];
    ImGui::TextUnformatted(node.label.c_str());
    ImGui::SameLine();
    push_threat_color(static_cast<uint8_t>(node.level));
    ImGui::TextUnformatted(threat_level_label(static_cast<uint8_t>(node.level)));
    pop_threat_color();
    ImGui::TextDisabled("PID %u | first seen %s", node.pid, relative_time(node.first_seen).c_str());
    ImGui::Text("Events %zu | upstream %zu | downstream %zu", node.event_count, node.parents.size(), node.children.size());
    ImGui::Separator();

    for (auto it = timeline_.rbegin(); it != timeline_.rend(); ++it) {
        if (it->process_id != node.pid) continue;
        push_threat_color(static_cast<uint8_t>(it->level));
        ImGui::TextUnformatted(threat_level_label(static_cast<uint8_t>(it->level)));
        pop_threat_color();
        ImGui::SameLine();
        ImGui::TextDisabled("%s", relative_time(it->timestamp).c_str());
        ImGui::TextWrapped("%s", it->description.c_str());
        ImGui::Spacing();
    }
}

void ForensicsView::render_timeline() {
    ImGui::TextDisabled("EVENT TIMELINE (newest first)");
    ImGui::Separator();
    for (auto it = timeline_.rbegin(); it != timeline_.rend(); ++it) {
        push_threat_color(static_cast<uint8_t>(it->level));
        ImGui::TextUnformatted("•");
        pop_threat_color();
        ImGui::SameLine();
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - 20.0f);
        ImGui::TextWrapped("%s", it->description.c_str());
        ImGui::PopTextWrapPos();
        if (ImGui::IsItemClicked() && it->process_id != 0) selected_pid_ = it->process_id;
    }
}

int ForensicsView::node_index_for_pid(uint32_t pid) const {
    for (size_t index = 0; index < graph_.nodes.size(); ++index)
        if (graph_.nodes[index].pid == pid) return static_cast<int>(index);
    return -1;
}

} // namespace gcad::ui::views
