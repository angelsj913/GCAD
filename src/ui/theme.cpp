#include "gcad/ui/theme.hpp"
#include "imgui.h"
#include <cmath>

namespace gcad::ui {

ImFont* g_font_body    = nullptr;
ImFont* g_font_heading = nullptr;
ImFont* g_font_large   = nullptr;

void apply_dark_theme() {
    auto& style = ImGui::GetStyle();
    auto* colors = style.Colors;

    style.WindowRounding    = 6.0f;
    style.FrameRounding     = 4.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.ChildRounding     = 4.0f;
    style.PopupRounding     = 4.0f;
    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 0.0f;
    style.ChildBorderSize   = 1.0f;
    style.WindowPadding     = {12, 12};
    style.FramePadding      = {10, 5};
    style.ItemSpacing       = {8, 6};
    style.ItemInnerSpacing  = {6, 4};
    style.ScrollbarSize     = 10.0f;
    style.IndentSpacing     = 20.0f;

    auto from_hex = [](unsigned int hex) -> ImVec4 {
        return ImVec4(
            ((hex >> 16) & 0xFF) / 255.0f,
            ((hex >>  8) & 0xFF) / 255.0f,
            ((hex      ) & 0xFF) / 255.0f,
            ((hex >> 24) & 0xFF) / 255.0f
        );
    };

    colors[ImGuiCol_WindowBg]             = from_hex(0xFF0d1117);
    colors[ImGuiCol_ChildBg]              = from_hex(0xFF161b22);
    colors[ImGuiCol_PopupBg]              = from_hex(0xF0161b22);
    colors[ImGuiCol_Border]               = from_hex(0xFF30363d);
    colors[ImGuiCol_BorderShadow]         = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_FrameBg]              = from_hex(0xFF1a1f26);
    colors[ImGuiCol_FrameBgHovered]       = from_hex(0xFF252b33);
    colors[ImGuiCol_FrameBgActive]        = from_hex(0xFF303840);
    colors[ImGuiCol_TitleBg]              = from_hex(0xFF0d1117);
    colors[ImGuiCol_TitleBgActive]        = from_hex(0xFF161b22);
    colors[ImGuiCol_TitleBgCollapsed]     = from_hex(0xFF0d1117);
    colors[ImGuiCol_MenuBarBg]            = from_hex(0xFF161b22);
    colors[ImGuiCol_ScrollbarBg]          = from_hex(0xFF0d1117);
    colors[ImGuiCol_ScrollbarGrab]        = from_hex(0xFF30363d);
    colors[ImGuiCol_ScrollbarGrabHovered] = from_hex(0xFF484f58);
    colors[ImGuiCol_ScrollbarGrabActive]  = from_hex(0xFF6e7681);
    colors[ImGuiCol_CheckMark]            = from_hex(0xFF39d353);
    colors[ImGuiCol_SliderGrab]           = from_hex(0xFF39d353);
    colors[ImGuiCol_SliderGrabActive]     = from_hex(0xFF2ea043);
    colors[ImGuiCol_Button]               = from_hex(0xFF21262d);
    colors[ImGuiCol_ButtonHovered]        = from_hex(0xFF30363d);
    colors[ImGuiCol_ButtonActive]         = from_hex(0xFF484f58);
    colors[ImGuiCol_Header]               = from_hex(0xFF161b22);
    colors[ImGuiCol_HeaderHovered]        = from_hex(0xFF1f242c);
    colors[ImGuiCol_HeaderActive]         = from_hex(0xFF252b33);
    colors[ImGuiCol_Separator]            = from_hex(0xFF30363d);
    colors[ImGuiCol_SeparatorHovered]     = from_hex(0xFF484f58);
    colors[ImGuiCol_SeparatorActive]      = from_hex(0xFF6e7681);
    colors[ImGuiCol_Tab]                  = from_hex(0xFF0d1117);
    colors[ImGuiCol_TabHovered]           = from_hex(0xFF1f242c);
    colors[ImGuiCol_TabSelected]          = from_hex(0xFF161b22);
    colors[ImGuiCol_Text]                 = from_hex(0xFFe6edf3);
    colors[ImGuiCol_TextDisabled]         = from_hex(0xFF484f58);
    colors[ImGuiCol_PlotLines]            = from_hex(0xFF58a6ff);
    colors[ImGuiCol_PlotLinesHovered]     = from_hex(0xFF79c0ff);
    colors[ImGuiCol_PlotHistogram]        = from_hex(0xFF39d353);
    colors[ImGuiCol_PlotHistogramHovered] = from_hex(0xFF2ea043);
    colors[ImGuiCol_TableHeaderBg]        = from_hex(0xFF161b22);
    colors[ImGuiCol_TableBorderStrong]    = from_hex(0xFF30363d);
    colors[ImGuiCol_TableBorderLight]     = from_hex(0xFF21262d);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_TableRowBgAlt]        = from_hex(0x08FFFFFF);
    colors[ImGuiCol_NavHighlight]         = from_hex(0xFF58a6ff);
    colors[ImGuiCol_TextSelectedBg]       = from_hex(0x4058a6ff);
    colors[ImGuiCol_ModalWindowDimBg]     = from_hex(0x80000000);
}

unsigned int threat_level_color(uint8_t level) {
    switch (level) {
        case 0: return 0xFF39d353;
        case 1: return 0xFF58a6ff;
        case 2: return 0xFFd29922;
        case 3: return 0xFFf0883e;
        case 4: return 0xFFf85149;
        default: return 0xFFe6edf3;
    }
}

const char* threat_level_label(uint8_t level) {
    switch (level) {
        case 0: return "SAFE";
        case 1: return "LOW";
        case 2: return "MEDIUM";
        case 3: return "HIGH";
        case 4: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

void push_threat_color(uint8_t level) {
    auto c = threat_level_color(level);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(c));
}

void pop_threat_color() {
    ImGui::PopStyleColor();
}

void draw_status_dot(ImDrawList* dl, ImVec2 center, bool active, float radius) {
    if (active) {
        dl->AddCircleFilled(center, radius + 2.0f, 0x2039d353, 16);
        dl->AddCircleFilled(center, radius, 0xFF39d353, 16);
    } else {
        dl->AddCircleFilled(center, radius, 0xFF484f58, 16);
    }
}

void draw_bezier_arrow(ImDrawList* dl, ImVec2 p0, ImVec2 p1, unsigned int color, float thickness) {
    float mid_y = (p0.y + p1.y) * 0.5f;
    ImVec2 cp0 = {p0.x, mid_y};
    ImVec2 cp1 = {p1.x, mid_y};
    dl->AddBezierCubic(p0, cp0, cp1, p1, color, thickness);

    float tx = p1.x - cp1.x, ty = p1.y - cp1.y;
    float tlen = sqrtf(tx * tx + ty * ty);
    if (tlen > 1.0f) {
        tx /= tlen; ty /= tlen;
        float as = 8.0f;
        ImVec2 l = {p1.x - tx * as - ty * as * 0.5f, p1.y - ty * as + tx * as * 0.5f};
        ImVec2 r = {p1.x - tx * as + ty * as * 0.5f, p1.y - ty * as - tx * as * 0.5f};
        dl->AddTriangleFilled(p1, l, r, color);
    }
}

} // namespace gcad::ui
