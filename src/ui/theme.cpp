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

    auto to_vec4 = [](unsigned int col) -> ImVec4 {
        return ImGui::ColorConvertU32ToFloat4(col);
    };

    // Deep Obsidian & Neon High-Tech Palette
    colors[ImGuiCol_WindowBg]             = to_vec4(ThemeColors::BG_CANVAS);
    colors[ImGuiCol_ChildBg]              = to_vec4(ThemeColors::BG_PANEL);
    colors[ImGuiCol_PopupBg]              = to_vec4(ThemeColors::BG_PANEL);
    colors[ImGuiCol_Border]               = to_vec4(ThemeColors::BORDER);
    colors[ImGuiCol_BorderShadow]         = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_FrameBg]              = to_vec4(ThemeColors::BG_CHILD);
    colors[ImGuiCol_FrameBgHovered]       = to_vec4(ThemeColors::BUTTON_HOV);
    colors[ImGuiCol_FrameBgActive]        = to_vec4(ThemeColors::BORDER_LGT);
    colors[ImGuiCol_TitleBg]              = to_vec4(ThemeColors::BG_CANVAS);
    colors[ImGuiCol_TitleBgActive]        = to_vec4(ThemeColors::BG_PANEL);
    colors[ImGuiCol_TitleBgCollapsed]     = to_vec4(ThemeColors::BG_CANVAS);
    colors[ImGuiCol_MenuBarBg]            = to_vec4(ThemeColors::BG_CANVAS);
    colors[ImGuiCol_ScrollbarBg]          = to_vec4(ThemeColors::BG_CANVAS);
    colors[ImGuiCol_ScrollbarGrab]        = to_vec4(ThemeColors::BORDER);
    colors[ImGuiCol_ScrollbarGrabHovered] = to_vec4(ThemeColors::BORDER_LGT);
    colors[ImGuiCol_ScrollbarGrabActive]  = to_vec4(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_CheckMark]            = to_vec4(ThemeColors::ACCENT_SAFE);
    colors[ImGuiCol_SliderGrab]           = to_vec4(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_SliderGrabActive]     = to_vec4(ThemeColors::ACCENT_SAFE);
    colors[ImGuiCol_Button]               = to_vec4(ThemeColors::BUTTON);
    colors[ImGuiCol_ButtonHovered]        = to_vec4(ThemeColors::BUTTON_HOV);
    colors[ImGuiCol_ButtonActive]         = to_vec4(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_Header]               = to_vec4(ThemeColors::HEADER);
    colors[ImGuiCol_HeaderHovered]        = to_vec4(ThemeColors::HEADER_HOV);
    colors[ImGuiCol_HeaderActive]         = to_vec4(ThemeColors::BUTTON_HOV);
    colors[ImGuiCol_Separator]            = to_vec4(ThemeColors::BORDER);
    colors[ImGuiCol_SeparatorHovered]     = to_vec4(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_SeparatorActive]      = to_vec4(ThemeColors::ACCENT_SAFE);
    colors[ImGuiCol_Tab]                  = to_vec4(ThemeColors::HEADER);
    colors[ImGuiCol_TabHovered]           = to_vec4(ThemeColors::HEADER_HOV);
    colors[ImGuiCol_TabSelected]          = to_vec4(ThemeColors::BUTTON);
    colors[ImGuiCol_Text]                 = to_vec4(ThemeColors::TEXT);
    colors[ImGuiCol_TextDisabled]         = to_vec4(ThemeColors::TEXT_MUTED);
    colors[ImGuiCol_PlotLines]            = to_vec4(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_PlotLinesHovered]     = to_vec4(ThemeColors::ACCENT_SAFE);
    colors[ImGuiCol_PlotHistogram]        = to_vec4(ThemeColors::ACCENT_SAFE);
    colors[ImGuiCol_PlotHistogramHovered] = to_vec4(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_TableHeaderBg]        = to_vec4(ThemeColors::HEADER);
    colors[ImGuiCol_TableBorderStrong]    = to_vec4(ThemeColors::BORDER);
    colors[ImGuiCol_TableBorderLight]     = to_vec4(ThemeColors::BG_CHILD);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_TableRowBgAlt]        = to_vec4(GCAD_COLOR(255, 255, 255, 6));
    colors[ImGuiCol_NavHighlight]         = to_vec4(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_TextSelectedBg]       = to_vec4(GCAD_COLOR(0, 180, 216, 64));
    colors[ImGuiCol_ModalWindowDimBg]     = to_vec4(GCAD_COLOR(0, 0, 0, 180));
}

unsigned int threat_level_color(uint8_t level) {
    switch (level) {
        case 0: return ThemeColors::ACCENT_SAFE;
        case 1: return ThemeColors::ACCENT_INFO;
        case 2: return ThemeColors::ACCENT_WARN;
        case 3: return ThemeColors::ACCENT_HIGH;
        case 4: return ThemeColors::ACCENT_CRIT;
        default: return ThemeColors::TEXT;
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
