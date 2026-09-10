#pragma once
#include <cstdint>

struct ImVec4;

namespace gcad::ui {

struct ThemeColors {
    static constexpr unsigned int BG_MAIN     = 0xFF17110D;
    static constexpr unsigned int BG_PANEL    = 0xFF221B16;
    static constexpr unsigned int BG_CHILD    = 0xFF1A1510;
    static constexpr unsigned int BORDER      = 0xFF3D3630;
    static constexpr unsigned int TEXT        = 0xFFE6E1DC;
    static constexpr unsigned int TEXT_DIM    = 0xFF8B8680;
    static constexpr unsigned int ACCENT_SAFE = 0xFF53D339;
    static constexpr unsigned int ACCENT_INFO = 0xFFFFA658;
    static constexpr unsigned int ACCENT_WARN = 0xFF2299D2;
    static constexpr unsigned int ACCENT_CRIT = 0xFF4951F8;
    static constexpr unsigned int HEADER      = 0xFF2A2520;
    static constexpr unsigned int HEADER_HOV  = 0xFF353025;
    static constexpr unsigned int BUTTON      = 0xFF2A2520;
    static constexpr unsigned int BUTTON_HOV  = 0xFF353025;
    static constexpr unsigned int SCROLLBAR   = 0xFF252015;
    static constexpr unsigned int SLIDER      = 0xFF53D339;
};

void apply_dark_theme();
void push_threat_color(uint8_t level);
void pop_threat_color();

unsigned int threat_level_color(uint8_t level);
const char*  threat_level_label(uint8_t level);

} // namespace gcad::ui
