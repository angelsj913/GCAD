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

    colors[ImGuiCol_WindowBg]             = from_hex(ThemeColors::BG_MAIN);
    colors[ImGuiCol_ChildBg]              = from_hex(ThemeColors::BG_CHILD);
    colors[ImGuiCol_PopupBg]              = from_hex(0xF0111C2E);
    colors[ImGuiCol_Border]               = from_hex(ThemeColors::BORDER);
    colors[ImGuiCol_BorderShadow]         = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_FrameBg]              = from_hex(ThemeColors::BUTTON);
    colors[ImGuiCol_FrameBgHovered]       = from_hex(ThemeColors::BUTTON_HOV);
    colors[ImGuiCol_FrameBgActive]        = from_hex(0xFF28506B);
    colors[ImGuiCol_TitleBg]              = from_hex(ThemeColors::BG_MAIN);
    colors[ImGuiCol_TitleBgActive]        = from_hex(ThemeColors::BG_PANEL);
    colors[ImGuiCol_TitleBgCollapsed]     = from_hex(ThemeColors::BG_MAIN);
    colors[ImGuiCol_MenuBarBg]            = from_hex(ThemeColors::BG_PANEL);
    colors[ImGuiCol_ScrollbarBg]          = from_hex(ThemeColors::SCROLLBAR);
    colors[ImGuiCol_ScrollbarGrab]        = from_hex(ThemeColors::BORDER);
    colors[ImGuiCol_ScrollbarGrabHovered] = from_hex(ThemeColors::BUTTON_HOV);
    colors[ImGuiCol_ScrollbarGrabActive]  = from_hex(0xFF315879);
    colors[ImGuiCol_CheckMark]            = from_hex(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_SliderGrab]           = from_hex(ThemeColors::SLIDER);
    colors[ImGuiCol_SliderGrabActive]     = from_hex(0xFF67E8F9);
    colors[ImGuiCol_Button]               = from_hex(ThemeColors::BUTTON);
    colors[ImGuiCol_ButtonHovered]        = from_hex(ThemeColors::BUTTON_HOV);
    colors[ImGuiCol_ButtonActive]         = from_hex(0xFF28506B);
    colors[ImGuiCol_Header]               = from_hex(ThemeColors::HEADER);
    colors[ImGuiCol_HeaderHovered]        = from_hex(ThemeColors::HEADER_HOV);
    colors[ImGuiCol_HeaderActive]         = from_hex(0xFF203552);
    colors[ImGuiCol_Separator]            = from_hex(ThemeColors::BORDER);
    colors[ImGuiCol_SeparatorHovered]     = from_hex(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_SeparatorActive]      = from_hex(0xFF67E8F9);
    colors[ImGuiCol_Tab]                  = from_hex(ThemeColors::BG_MAIN);
    colors[ImGuiCol_TabHovered]           = from_hex(ThemeColors::HEADER_HOV);
    colors[ImGuiCol_TabSelected]          = from_hex(ThemeColors::BG_PANEL);
    colors[ImGuiCol_Text]                 = from_hex(ThemeColors::TEXT);
    colors[ImGuiCol_TextDisabled]         = from_hex(ThemeColors::TEXT_DIM);
    colors[ImGuiCol_PlotLines]            = from_hex(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_PlotLinesHovered]     = from_hex(0xFF67E8F9);
    colors[ImGuiCol_PlotHistogram]        = from_hex(ThemeColors::ACCENT_SAFE);
    colors[ImGuiCol_PlotHistogramHovered] = from_hex(0xFF6EE7B7);
    colors[ImGuiCol_TableHeaderBg]        = from_hex(ThemeColors::BG_PANEL);
    colors[ImGuiCol_TableBorderStrong]    = from_hex(ThemeColors::BORDER);
    colors[ImGuiCol_TableBorderLight]     = from_hex(ThemeColors::BUTTON);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_TableRowBgAlt]        = from_hex(0x08FFFFFF);
    colors[ImGuiCol_NavHighlight]         = from_hex(ThemeColors::ACCENT_INFO);
    colors[ImGuiCol_TextSelectedBg]       = from_hex(0x4022D3EE);
    colors[ImGuiCol_ModalWindowDimBg]     = from_hex(0x80000000);
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
        dl->AddCircleFilled(center, radius + 2.0f, 0x2034D399, 16);
        dl->AddCircleFilled(center, radius, ThemeColors::ACCENT_SAFE, 16);
    } else {
        dl->AddCircleFilled(center, radius, ThemeColors::TEXT_DIM, 16);
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
