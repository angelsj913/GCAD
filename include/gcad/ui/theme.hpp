#pragma once
#include <cstdint>

struct ImFont;
struct ImDrawList;
struct ImVec2;

namespace gcad::ui {

struct ThemeColors {
    static constexpr unsigned int BG_MAIN     = 0xFF090d16;
    static constexpr unsigned int BG_PANEL    = 0xFF0f172a;
    static constexpr unsigned int BG_CHILD    = 0xFF131d31;
    static constexpr unsigned int BORDER      = 0xFF1e293b;
    static constexpr unsigned int TEXT        = 0xFFf8fafc;
    static constexpr unsigned int TEXT_DIM    = 0xFF94a3b8;
    static constexpr unsigned int ACCENT_SAFE = 0xFF10b981;
    static constexpr unsigned int ACCENT_INFO = 0xFF00d2ff;
    static constexpr unsigned int ACCENT_WARN = 0xFFf59e0b;
    static constexpr unsigned int ACCENT_HIGH = 0xFFf97316;
    static constexpr unsigned int ACCENT_CRIT = 0xFFef4444;
    static constexpr unsigned int HEADER      = 0xFF111c30;
    static constexpr unsigned int HEADER_HOV  = 0xFF1f3050;
    static constexpr unsigned int BUTTON      = 0xFF1e293b;
    static constexpr unsigned int BUTTON_HOV  = 0xFF28384f;
    static constexpr unsigned int SCROLLBAR   = 0xFF090d16;
    static constexpr unsigned int SLIDER      = 0xFF00d2ff;
};

extern ImFont* g_font_body;
extern ImFont* g_font_heading;
extern ImFont* g_font_large;

void apply_dark_theme();
void push_threat_color(uint8_t level);
void pop_threat_color();
unsigned int threat_level_color(uint8_t level);
const char*  threat_level_label(uint8_t level);

void draw_status_dot(ImDrawList* dl, ImVec2 center, bool active, float radius = 5.0f);
void draw_bezier_arrow(ImDrawList* dl, ImVec2 p0, ImVec2 p1, unsigned int color, float thickness = 1.5f);

} // namespace gcad::ui
