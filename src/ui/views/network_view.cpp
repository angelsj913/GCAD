#include "gcad/ui/views/network_view.hpp"
#include "gcad/ui/theme.hpp"
#include "imgui.h"
#include <cstdio>

namespace gcad::ui::views {

static std::string ip_to_string(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return buf;
}

void NetworkView::render(ETGRIEngine* engine) {
    if (!engine) {
        ImGui::TextDisabled("ETG-RI engine not available.");
        return;
    }

    ImGui::Checkbox("Show Blocked IPs", &show_blocked_);
    ImGui::Separator();

    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##netgraph", {w, 200}, true);
    render_entropy_graph();
    ImGui::EndChild();

    ImGui::BeginChild("##netlog", {0, 0}, true);
    if (show_blocked_) render_blocked_ips(engine);
    else               render_packet_log(engine);
    ImGui::EndChild();
}

void NetworkView::render_entropy_graph() {
    ImGui::Text("Network Entropy (sliding window)");
    ImGui::PlotLines("##entropy", entropy_history_, 256, entropy_idx_ % 256,
                     nullptr, 0.0f, 8.0f, {-1, 140});
}

void NetworkView::render_packet_log(ETGRIEngine* engine) {
    ImGui::Text("Recent Packets (captured: %llu)", static_cast<unsigned long long>(engine->packets_captured()));
    ImGui::Separator();

    if (ImGui::BeginTable("##pkts", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Src IP");
        ImGui::TableSetupColumn("Dst IP");
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Payload", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Entropy", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableHeadersRow();

        auto recent = engine->recent_packets(100);
        for (auto it = recent.rbegin(); it != recent.rend(); ++it) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%s", ip_to_string(it->src_ip).c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%s", ip_to_string(it->dst_ip).c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%u", it->protocol);
            ImGui::TableNextColumn();
            ImGui::Text("%zu", it->payload_len);
            ImGui::TableNextColumn();
            float ent = static_cast<float>(it->shannon_entropy);
            if (ent > 7.5f) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.97f, 0.32f, 0.29f, 1));
            ImGui::Text("%.2f", ent);
            if (ent > 7.5f) ImGui::PopStyleColor();

            entropy_history_[entropy_idx_ % 256] = ent;
            entropy_idx_++;
        }
        ImGui::EndTable();
    }
}

void NetworkView::render_blocked_ips(ETGRIEngine* engine) {
    ImGui::Text("Blocked IP Addresses");
    auto blocked = engine->get_blocked_ips();
    if (blocked.empty()) {
        ImGui::TextDisabled("No blocked IPs.");
        return;
    }
    for (auto ip : blocked) {
        auto s = ip_to_string(ip);
        ImGui::BulletText("%s", s.c_str());
    }
}

} // namespace gcad::ui::views
