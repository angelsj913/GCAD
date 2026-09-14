#include "gcad/common.hpp"
#include "gcad/ui/ui_preferences.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

std::filesystem::path temp_preferences_path(const char* name) {
    return std::filesystem::temp_directory_path() / name;
}

} // namespace

void register_ui_preferences_tests() {
    register_test("ui_preferences_missing_file_uses_safe_defaults", [] {
        const auto path = temp_preferences_path("gcad-ui-preferences-missing.txt");
        std::error_code ec;
        std::filesystem::remove(path, ec);

        const auto loaded = gcad::ui::UiPreferencesStore::load(path);
        const gcad::ui::UiPreferences defaults{};
        return loaded.minimize_to_tray == defaults.minimize_to_tray &&
               loaded.report_format == defaults.report_format;
    });

    register_test("ui_preferences_round_trip_only_ui_values", [] {
        const auto path = temp_preferences_path("gcad-ui-preferences-roundtrip.txt");
        gcad::ui::UiPreferences preferences{};
        preferences.minimize_to_tray = false;
        preferences.report_format = 1;

        if (gcad::ui::UiPreferencesStore::save(path, preferences) != gcad::ErrorCode::OK)
            return false;
        const auto loaded = gcad::ui::UiPreferencesStore::load(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);

        return !loaded.minimize_to_tray && loaded.report_format == 1;
    });

    register_test("ui_preferences_rejects_corrupt_or_out_of_range_values", [] {
        const auto path = temp_preferences_path("gcad-ui-preferences-corrupt.txt");
        std::ofstream out(path, std::ios::trunc);
        out << "minimize_to_tray=not-a-bool\n";
        out << "report_format=99\n";
        out.close();

        const auto loaded = gcad::ui::UiPreferencesStore::load(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);

        const gcad::ui::UiPreferences defaults{};
        return loaded.minimize_to_tray == defaults.minimize_to_tray &&
               loaded.report_format == defaults.report_format;
    });
}
