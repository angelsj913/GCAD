#include "gcad/ui/views/alert_view.hpp"
#include "gcad/alert/alert_manager.hpp"
#include "gcad/ui/theme.hpp"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <ctime>

namespace gcad::ui::views {

namespace {

void format_time(char* buf, size_t len, std::chrono::system_clock::time_point tp) {
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
#ifdef GCAD_PLATFORM_WINDOWS
    localtime_s(&tm_buf, &tt);
#else
    localtime_r(&tt, &tm_buf);
#endif
    std::strftime(buf, len, "%H:%M:%S", &tm_buf);
}

} // namespace

void AlertView::render(AlertManager& am) {
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::TEXT_DIM));
    ImGui::TextUnformatted("ALERT HISTORY");
    ImGui::PopStyleColor();
    ImGui::SameLine();

    size_t unacked = am.unacknowledged_count();
    if (unacked > 0) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_CRIT));
        char badge[32];
        std::snprintf(badge, sizeof(badge), "(%zu unread)", unacked);
        ImGui::TextUnformatted(badge);
        ImGui::PopStyleColor();
    }
    ImGui::Separator();

    // Controls row
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Severity:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110.0f);
    const char* levels[] = {"All", "LOW+", "MEDIUM+", "HIGH+", "CRITICAL"};
    ImGui::Combo("##alert_filter", &filter_level_, levels, 5);

    ImGui::SameLine();
    ImGui::TextDisabled("Source:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f);
    const char* sources[] = {
        "All Sources", "AmsiGuard", "WmiBits", "NamedPipe",
        "SelfDefense", "SyscallGuard", "RansomwareShield", "NetworkDPI", "CredentialGuard",
        "PeStaticAnalysis", "LolbinsGuard", "FilelessAstGuard"
    };
    ImGui::Combo("##source_filter", &filter_source_, sources, IM_ARRAYSIZE(sources));

    ImGui::SameLine();
    if (ImGui::Button("Acknowledge All"))
        am.acknowledge_all();

    ImGui::SameLine();
    if (ImGui::Button("Clear History"))
        am.clear();

    ImGui::SameLine();
    {
        bool snd = am.sound_enabled();
        if (ImGui::Checkbox("Sound", &snd)) am.set_sound_enabled(snd);
    }
    ImGui::SameLine();
    {
        bool toast = am.toast_enabled();
        if (ImGui::Checkbox("Toast", &toast)) am.set_toast_enabled(toast);
    }

    ImGui::Spacing();

    // Alert list
    auto alerts = am.recent(200);

    ImGui::BeginChild("##alert_list", {0.0f, 0.0f}, true);

    if (alerts.empty()) {
        ImGui::TextDisabled("No alerts recorded. Monitoring is active.");
        ImGui::EndChild();
        return;
    }

    for (auto it = alerts.rbegin(); it != alerts.rend(); ++it) {
        if (static_cast<int>(it->level) < filter_level_) continue;
        if (filter_source_ > 0 && it->source != sources[filter_source_]) continue;

        ImGui::PushID(static_cast<int>(it->id));

        const ImVec2 origin = ImGui::GetCursorScreenPos();
        const float row_height = ImGui::GetTextLineHeight() * 2.8f;
        const float width = ImGui::GetContentRegionAvail().x;
        auto* dl = ImGui::GetWindowDrawList();

        ImU32 bg = it->acknowledged ? ThemeColors::BG_PANEL : 0xFF1a2233;
        dl->AddRectFilled(origin, {origin.x + width, origin.y + row_height}, bg, 4.0f);
        dl->AddRect(origin, {origin.x + width, origin.y + row_height}, ThemeColors::BORDER, 4.0f);

        ImU32 accent = threat_level_color(static_cast<uint8_t>(it->level));
        dl->AddRectFilled(origin, {origin.x + 3.0f, origin.y + row_height}, accent, 4.0f,
                          ImDrawFlags_RoundCornersLeft);

        // Row 1: [LEVEL] [TIME] [SOURCE]  description
        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + 6.0f});
        push_threat_color(static_cast<uint8_t>(it->level));
        ImGui::TextUnformatted(threat_level_label(static_cast<uint8_t>(it->level)));
        pop_threat_color();

        ImGui::SameLine();
        char time_str[24];
        format_time(time_str, sizeof(time_str), it->timestamp);
        ImGui::TextDisabled("%s", time_str);

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColors::ACCENT_INFO));
        ImGui::TextUnformatted(it->source.c_str());
        ImGui::PopStyleColor();

        if (!it->acknowledged) {
            ImGui::SameLine(width - 70.0f);
            if (ImGui::SmallButton("Ack")) am.acknowledge(it->id);
        }

        // Row 2: description + process info
        ImGui::SetCursorScreenPos({origin.x + 12.0f, origin.y + ImGui::GetTextLineHeight() + 10.0f});
        ImGui::PushTextWrapPos(origin.x + width - 10.0f);
        if (!it->process_name.empty()) {
            char detail[512];
            std::snprintf(detail, sizeof(detail), "%s  [%s PID:%u]",
                          it->description.c_str(), it->process_name.c_str(), it->process_id);
            ImGui::TextWrapped("%s", detail);
        } else {
            ImGui::TextWrapped("%s", it->description.c_str());
        }
        ImGui::PopTextWrapPos();

        ImGui::SetCursorScreenPos({origin.x, origin.y + row_height});
        ImGui::Dummy({width, 4.0f});
        ImGui::PopID();
    }

    ImGui::EndChild();
}

} // namespace gcad::ui::views
