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

void NetworkView::render(ETGRIEngine* engine, FirewallEngine* firewall) {
    ImGui::PushFont(g_font_heading ? g_font_heading : ImGui::GetFont());
    ImGui::TextUnformatted("NETWORK OPERATIONS");
    ImGui::PopFont();
    ImGui::TextDisabled("Review packet telemetry and firewall decisions from local snapshots.");
    ImGui::Spacing();

    if (ImGui::Button("Traffic", {100, 30})) net_tab_ = 0;
    ImGui::SameLine();
    if (ImGui::Button("Firewall", {100, 30})) net_tab_ = 1;
    ImGui::Separator();

    if (net_tab_ == 0) {
        if (!engine) {
            ImGui::TextDisabled("ETG-RI engine not available.");
            return;
        }

        ImGui::Checkbox("Show Blocked IPs", &show_blocked_);
        ImGui::SameLine();
        ImGui::TextDisabled(show_blocked_ ? "Review addresses blocked by ETG-RI." : "Review recent packet snapshots.");
        ImGui::Spacing();
        ImGui::BeginChild("##network_traffic", {0, 0}, true);
        if (show_blocked_) render_blocked_ips(engine);
        else               render_packet_log(engine);
        ImGui::EndChild();
        return;
    }

    render_firewall(firewall);
}

void NetworkView::render_packet_log(ETGRIEngine* engine) {
    ImGui::Text("Recent Packets (captured: %llu)", static_cast<unsigned long long>(engine->packets_captured()));
    ImGui::Separator();

    auto recent = engine->recent_packets(100);

    if (ImGui::BeginTable("##pkts", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Src IP");
        ImGui::TableSetupColumn("Dst IP");
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Payload", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Entropy", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableHeadersRow();

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

void NetworkView::render_firewall(FirewallEngine* fw) {
    if (!fw) {
        ImGui::TextDisabled("Firewall engine not available.");
        return;
    }

    ImGui::Text("Allowed: %zu  |  Denied: %zu", fw->total_allowed(), fw->total_denied());
    ImGui::Separator();

    if (ImGui::Button("Rules", {100, 28})) net_tab_ = 1;
    ImGui::SameLine();
    if (ImGui::Button("Connections", {110, 28})) net_tab_ = 2;
    ImGui::SameLine();
    if (ImGui::Button("Suspicious", {100, 28})) net_tab_ = 3;
    ImGui::Separator();

    if (net_tab_ == 1)
        render_firewall_rules(fw);
    else if (net_tab_ == 2)
        render_firewall_log(fw);
    else if (net_tab_ == 3)
        render_firewall_suspects(fw);
}

void NetworkView::render_firewall_rules(FirewallEngine* fw) {
    auto rules = fw->rules();
    if (rules.empty()) {
        ImGui::TextDisabled("No rules configured.");
        return;
    }

    if (ImGui::BeginTable("##fwrules", 7,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
            {0, 200})) {
        ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableSetupColumn("Label");
        ImGui::TableSetupColumn("Dir", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Ports", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableHeadersRow();

        for (auto& r : rules) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%u", r.id);
            ImGui::TableNextColumn(); ImGui::Text("%s", r.label.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%s", r.direction == FirewallDirection::INBOUND ? "IN" : "OUT");
            ImGui::TableNextColumn();
            if (r.action == FirewallAction::DENY)
                ImGui::TextColored({0.97f, 0.32f, 0.29f, 1.0f}, "DENY");
            else
                ImGui::TextColored({0.22f, 0.83f, 0.33f, 1.0f}, "ALLOW");
            ImGui::TableNextColumn();
            const char* proto_str = "ANY";
            if (r.protocol == FirewallProto::TCP) proto_str = "TCP";
            else if (r.protocol == FirewallProto::UDP) proto_str = "UDP";
            else if (r.protocol == FirewallProto::ICMP) proto_str = "ICMP";
            ImGui::Text("%s", proto_str);
            ImGui::TableNextColumn();
            if (r.port_min == 0 && r.port_max == 65535)
                ImGui::Text("*");
            else if (r.port_min == r.port_max)
                ImGui::Text("%u", r.port_min);
            else
                ImGui::Text("%u-%u", r.port_min, r.port_max);
            ImGui::TableNextColumn();
            ImGui::Text("%s", r.enabled ? "Y" : "N");
        }
        ImGui::EndTable();
    }
}

void NetworkView::render_firewall_log(FirewallEngine* fw) {
    auto conns = fw->recent_connections(200);
    if (conns.empty()) {
        ImGui::TextDisabled("No connections logged.");
        return;
    }

    if (ImGui::BeginTable("##fwlog", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
            {0, 250})) {
        ImGui::TableSetupColumn("Src IP");
        ImGui::TableSetupColumn("Dst IP");
        ImGui::TableSetupColumn("Dst Port", ImGuiTableColumnFlags_WidthFixed, 55);
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Dir", ImGuiTableColumnFlags_WidthFixed, 35);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableHeadersRow();

        for (auto it = conns.rbegin(); it != conns.rend(); ++it) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", ip_to_string(it->src_ip).c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", ip_to_string(it->dst_ip).c_str());
            ImGui::TableNextColumn(); ImGui::Text("%u", it->dst_port);
            ImGui::TableNextColumn();
            if (it->protocol == FirewallProto::TCP) ImGui::Text("TCP");
            else if (it->protocol == FirewallProto::UDP) ImGui::Text("UDP");
            else ImGui::Text("?");
            ImGui::TableNextColumn();
            ImGui::Text("%s", it->direction == FirewallDirection::INBOUND ? "IN" : "OUT");
            ImGui::TableNextColumn();
            if (it->action_taken == FirewallAction::DENY)
                ImGui::TextColored({0.97f, 0.32f, 0.29f, 1.0f}, "DENY");
            else
                ImGui::TextColored({0.22f, 0.83f, 0.33f, 1.0f}, "OK");
        }
        ImGui::EndTable();
    }
}

void NetworkView::render_firewall_suspects(FirewallEngine* fw) {
    auto suspects = fw->suspicious_candidates();
    if (suspects.empty()) {
        ImGui::TextDisabled("No suspicious traffic detected.");
        return;
    }

    for (auto& s : suspects) {
        push_threat_color(3);
        ImGui::BulletText("%s — %s (conns: %zu, denied: %zu)",
                          ip_to_string(s.ip).c_str(), s.reason.c_str(),
                          s.connection_count, s.denied_count);
        pop_threat_color();
    }
}

} // namespace gcad::ui::views
