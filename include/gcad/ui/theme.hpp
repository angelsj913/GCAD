#pragma once
#include <cstdint>

struct ImFont;
struct ImDrawList;
struct ImVec2;

namespace gcad::ui {

struct ThemeColors {
    static constexpr unsigned int BG_MAIN     = 0xFF0d1117;
    static constexpr unsigned int BG_PANEL    = 0xFF161b22;
    static constexpr unsigned int BG_CHILD    = 0xFF161b22;
    static constexpr unsigned int BORDER      = 0xFF30363d;
    static constexpr unsigned int TEXT        = 0xFFe6edf3;
    static constexpr unsigned int TEXT_DIM    = 0xFF8b949e;
    static constexpr unsigned int ACCENT_SAFE = 0xFF39d353;
    static constexpr unsigned int ACCENT_INFO = 0xFF58a6ff;
    static constexpr unsigned int ACCENT_WARN = 0xFFd29922;
    static constexpr unsigned int ACCENT_HIGH = 0xFFf0883e;
    static constexpr unsigned int ACCENT_CRIT = 0xFFf85149;
    static constexpr unsigned int HEADER      = 0xFF161b22;
    static constexpr unsigned int HEADER_HOV  = 0xFF1f242c;
    static constexpr unsigned int BUTTON      = 0xFF21262d;
    static constexpr unsigned int BUTTON_HOV  = 0xFF30363d;
    static constexpr unsigned int SCROLLBAR   = 0xFF0d1117;
    static constexpr unsigned int SLIDER      = 0xFF39d353;
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
