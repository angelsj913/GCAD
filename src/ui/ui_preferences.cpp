#include "gcad/ui/ui_preferences.hpp"

#include <cstdlib>

namespace gcad::ui {

namespace {

bool parse_bool(const std::string& value, bool& out) {
    if (value == "0") { out = false; return true; }
    if (value == "1") { out = true; return true; }
    return false;
}

bool parse_report_format(const std::string& value, int& out) {
    try {
        size_t consumed = 0;
        const int parsed = std::stoi(value, &consumed);
        if (consumed != value.size() || parsed < 0 || parsed > 1) return false;
        out = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

std::filesystem::path UiPreferencesStore::default_path() {
#ifdef GCAD_PLATFORM_WINDOWS
    if (const char* appdata = std::getenv("APPDATA"); appdata && *appdata)
        return std::filesystem::path(appdata) / "GCAD" / "ui_preferences.txt";
#else
    if (const char* config_home = std::getenv("XDG_CONFIG_HOME"); config_home && *config_home)
        return std::filesystem::path(config_home) / "gcad" / "ui_preferences.txt";
#endif
    return std::filesystem::current_path() / "gcad_ui_preferences.txt";
}

UiPreferences UiPreferencesStore::load(const std::filesystem::path& path) {
    UiPreferences preferences{};
    std::ifstream in(path);
    if (!in) return preferences;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto equals = line.find('=');
        if (equals == std::string::npos || equals == 0) continue;

        const std::string key = line.substr(0, equals);
        const std::string value = line.substr(equals + 1);
        if (key == "minimize_to_tray") {
            bool parsed = preferences.minimize_to_tray;
            if (parse_bool(value, parsed)) preferences.minimize_to_tray = parsed;
        } else if (key == "report_format") {
            int parsed = preferences.report_format;
            if (parse_report_format(value, parsed)) preferences.report_format = parsed;
        }
    }
    return preferences;
}

ErrorCode UiPreferencesStore::save(const std::filesystem::path& path,
                                   const UiPreferences& preferences) {
    if (preferences.report_format < 0 || preferences.report_format > 1)
        return ErrorCode::ERR_SCAN_IO;

    std::error_code ec;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) return ErrorCode::ERR_SCAN_IO;

    auto temporary = path;
    temporary += ".tmp";
    std::filesystem::remove(temporary, ec);
    ec.clear();
    {
        std::ofstream out(temporary, std::ios::trunc);
        if (!out) return ErrorCode::ERR_SCAN_IO;
        out << "minimize_to_tray=" << (preferences.minimize_to_tray ? 1 : 0) << '\n';
        out << "report_format=" << preferences.report_format << '\n';
        if (!out.good()) {
            out.close();
            std::filesystem::remove(temporary, ec);
            return ErrorCode::ERR_SCAN_IO;
        }
    }

#ifdef GCAD_PLATFORM_WINDOWS
    if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(temporary, ec);
        return ErrorCode::ERR_SCAN_IO;
    }
#else
    std::filesystem::rename(temporary, path, ec);
    if (ec) {
        std::filesystem::remove(temporary, ec);
        return ErrorCode::ERR_SCAN_IO;
    }
#endif
    return ErrorCode::OK;
}

} // namespace gcad::ui
