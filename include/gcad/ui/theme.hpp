#pragma once
#include <cstdint>

struct ImFont;
struct ImDrawList;
struct ImVec2;

namespace gcad::ui {

#define GCAD_COLOR(r, g, b, a) (((unsigned int)(a) << 24) | ((unsigned int)(b) << 16) | ((unsigned int)(g) << 8) | ((unsigned int)(r)))

struct ThemeColors {
    // True Deep Charcoal & Obsidian Navy Palette
    static constexpr unsigned int BG_CANVAS   = GCAD_COLOR(11, 14, 20, 255);   // #0B0E14 Canvas
    static constexpr unsigned int BG_MAIN     = GCAD_COLOR(15, 20, 30, 255);   // #0F141E Main View
    static constexpr unsigned int BG_PANEL    = GCAD_COLOR(18, 24, 38, 255);   // #121826 Elevated Panel
    static constexpr unsigned int BG_CHILD    = GCAD_COLOR(22, 30, 48, 255);   // #161E30 Card Surface
    static constexpr unsigned int BORDER      = GCAD_COLOR(34, 46, 70, 255);   // #222E46 Subtle Slate Border
    static constexpr unsigned int BORDER_LGT  = GCAD_COLOR(48, 64, 96, 255);   // #304060 Active Border
    static constexpr unsigned int TEXT        = GCAD_COLOR(248, 250, 252, 255); // #F8FAFC Pure Text
    static constexpr unsigned int TEXT_DIM    = GCAD_COLOR(148, 163, 184, 255); // #94A3B8 Secondary Text
    static constexpr unsigned int TEXT_MUTED  = GCAD_COLOR(100, 116, 139, 255); // #64748B Muted Meta

    // Threat & Status Accents
    static constexpr unsigned int ACCENT_SAFE = GCAD_COLOR(0, 229, 153, 255);   // #00E599 High-Tech Emerald
    static constexpr unsigned int ACCENT_INFO = GCAD_COLOR(0, 180, 216, 255);   // #00B4D8 Cyan Blue
    static constexpr unsigned int ACCENT_WARN = GCAD_COLOR(245, 158, 11, 255);  // #F59E0B Amber
    static constexpr unsigned int ACCENT_HIGH = GCAD_COLOR(249, 115, 22, 255);  // #F97316 Vivid Orange
    static constexpr unsigned int ACCENT_CRIT = GCAD_COLOR(239, 68, 68, 255);   // #EF4444 Crimson Red

    // Control Elements
    static constexpr unsigned int HEADER      = GCAD_COLOR(20, 28, 44, 255);
    static constexpr unsigned int HEADER_HOV  = GCAD_COLOR(30, 42, 66, 255);
    static constexpr unsigned int BUTTON      = GCAD_COLOR(26, 36, 56, 255);
    static constexpr unsigned int BUTTON_HOV  = GCAD_COLOR(38, 52, 82, 255);
    static constexpr unsigned int SCROLLBAR   = GCAD_COLOR(11, 14, 20, 255);
    static constexpr unsigned int SLIDER      = GCAD_COLOR(0, 180, 216, 255);
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
