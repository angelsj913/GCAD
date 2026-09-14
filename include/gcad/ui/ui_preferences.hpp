#pragma once

#include "../common.hpp"

namespace gcad::ui {

// Presentation-only choices. These values never start or stop an engine and
// are intentionally separate from security::LocalSecurityPolicy.
struct UiPreferences {
    bool minimize_to_tray{true};
    int  report_format{0}; // 0: HTML, 1: plain text
};

class UiPreferencesStore final {
public:
    static std::filesystem::path default_path();
    static UiPreferences load(const std::filesystem::path& path);
    static ErrorCode save(const std::filesystem::path& path,
                          const UiPreferences& preferences);
};

} // namespace gcad::ui
