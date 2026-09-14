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

    style.WindowRounding    = 10.0f;
    style.FrameRounding     = 6.0f;
    style.GrabRounding      = 6.0f;
    style.TabRounding       = 8.0f;
    style.ScrollbarRounding = 8.0f;
    style.ChildRounding     = 8.0f;
    style.PopupRounding     = 8.0f;
    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.WindowPadding     = {16, 16};
    style.FramePadding      = {12, 6};
    style.ItemSpacing       = {10, 8};
    style.ItemInnerSpacing  = {8, 6};
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

    // Next-Gen Cyber Sleek Dark Obsidian Palette
    colors[ImGuiCol_WindowBg]             = from_hex(0xFF090d16); // Deep Obsidian
    colors[ImGuiCol_ChildBg]              = from_hex(0xFF0f172a); // Elevated Slate Panel
    colors[ImGuiCol_PopupBg]              = from_hex(0xF40f172a); // Translucent Frosted Glass
    colors[ImGuiCol_Border]               = from_hex(0xFF1e293b); // Subtle Slate Border
    colors[ImGuiCol_BorderShadow]         = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_FrameBg]              = from_hex(0xFF131d31); // Dark Card Frame
    colors[ImGuiCol_FrameBgHovered]       = from_hex(0xFF1c2c47); // Lighter Card Hover
    colors[ImGuiCol_FrameBgActive]        = from_hex(0xFF233658); // Accent Active
    colors[ImGuiCol_TitleBg]              = from_hex(0xFF090d16);
    colors[ImGuiCol_TitleBgActive]        = from_hex(0xFF0f172a);
    colors[ImGuiCol_TitleBgCollapsed]     = from_hex(0xFF090d16);
    colors[ImGuiCol_MenuBarBg]            = from_hex(0xFF0d1322); // Sleek Top Bar
    colors[ImGuiCol_ScrollbarBg]          = from_hex(0xFF090d16);
    colors[ImGuiCol_ScrollbarGrab]        = from_hex(0xFF1e293b);
    colors[ImGuiCol_ScrollbarGrabHovered] = from_hex(0xFF334155);
    colors[ImGuiCol_ScrollbarGrabActive]  = from_hex(0xFF00d2ff); // Neon Cyan Grab
    colors[ImGuiCol_CheckMark]            = from_hex(0xFF00d2ff); // Neon Cyan Checkmark
    colors[ImGuiCol_SliderGrab]           = from_hex(0xFF00d2ff); // Neon Cyan Slider
    colors[ImGuiCol_SliderGrabActive]     = from_hex(0xFF38bdf8);
    colors[ImGuiCol_Button]               = from_hex(0xFF1e293b); // Slate Button
    colors[ImGuiCol_ButtonHovered]        = from_hex(0xFF28384f); // Glow Hover
    colors[ImGuiCol_ButtonActive]         = from_hex(0xFF0284c7); // Cyan Blue Active
    colors[ImGuiCol_Header]               = from_hex(0xFF162238);
    colors[ImGuiCol_HeaderHovered]        = from_hex(0xFF1f3050);
    colors[ImGuiCol_HeaderActive]         = from_hex(0xFF283e66);
    colors[ImGuiCol_Separator]            = from_hex(0xFF1e293b);
    colors[ImGuiCol_SeparatorHovered]     = from_hex(0xFF00d2ff);
    colors[ImGuiCol_SeparatorActive]      = from_hex(0xFF38bdf8);
    colors[ImGuiCol_Tab]                  = from_hex(0xFF0d1322);
    colors[ImGuiCol_TabHovered]           = from_hex(0xFF1a263c);
    colors[ImGuiCol_TabSelected]          = from_hex(0xFF1e293b); // Active tab pill
    colors[ImGuiCol_Text]                 = from_hex(0xFFf8fafc); // Crisp Platinum White
    colors[ImGuiCol_TextDisabled]         = from_hex(0xFF64748b); // Muted Slate
    colors[ImGuiCol_PlotLines]            = from_hex(0xFF00d2ff); // Electric Cyan
    colors[ImGuiCol_PlotLinesHovered]     = from_hex(0xFF38bdf8);
    colors[ImGuiCol_PlotHistogram]        = from_hex(0xFF10b981); // Emerald Green
    colors[ImGuiCol_PlotHistogramHovered] = from_hex(0xFF34d399);
    colors[ImGuiCol_TableHeaderBg]        = from_hex(0xFF111c30);
    colors[ImGuiCol_TableBorderStrong]    = from_hex(0xFF1e293b);
    colors[ImGuiCol_TableBorderLight]     = from_hex(0xFF141e33);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_TableRowBgAlt]        = from_hex(0x06FFFFFF);
    colors[ImGuiCol_NavHighlight]         = from_hex(0xFF00d2ff);
    colors[ImGuiCol_TextSelectedBg]       = from_hex(0x4000d2ff);
    colors[ImGuiCol_ModalWindowDimBg]     = from_hex(0xB0000000);
}

unsigned int threat_level_color(uint8_t level) {
    switch (level) {
        case 0: return 0xFF10b981; // Emerald Green
        case 1: return 0xFF00d2ff; // Cyber Cyan
        case 2: return 0xFFf59e0b; // Amber Warning
        case 3: return 0xFFf97316; // Vivid Orange
        case 4: return 0xFFef4444; // Neon Crimson
        default: return 0xFFf8fafc;
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
        dl->AddCircleFilled(center, radius + 3.0f, 0x3010b981, 16);
        dl->AddCircleFilled(center, radius, 0xFF10b981, 16);
    } else {
        dl->AddCircleFilled(center, radius, 0xFF64748b, 16);
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
