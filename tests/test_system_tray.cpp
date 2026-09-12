#include "gcad/ui/system_tray.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_system_tray_tests() {
    register_test("tray_color_safe", [] {
        return gcad::SystemTrayManager::threat_color_rgb(gcad::ThreatLevel::SAFE) == 0x00C800;
    });

    register_test("tray_color_low", [] {
        return gcad::SystemTrayManager::threat_color_rgb(gcad::ThreatLevel::LOW) == 0x88CC00;
    });

    register_test("tray_color_medium", [] {
        return gcad::SystemTrayManager::threat_color_rgb(gcad::ThreatLevel::MEDIUM) == 0xFFAA00;
    });

    register_test("tray_color_high", [] {
        return gcad::SystemTrayManager::threat_color_rgb(gcad::ThreatLevel::HIGH) == 0xFF4400;
    });

    register_test("tray_color_critical", [] {
        return gcad::SystemTrayManager::threat_color_rgb(gcad::ThreatLevel::CRITICAL) == 0xFF0000;
    });

    register_test("tray_map_menu_restore", [] {
        return gcad::SystemTrayManager::map_menu_id(gcad::SystemTrayManager::MENU_RESTORE)
               == gcad::TrayAction::RESTORE_WINDOW;
    });

    register_test("tray_map_menu_dashboard", [] {
        return gcad::SystemTrayManager::map_menu_id(gcad::SystemTrayManager::MENU_DASHBOARD)
               == gcad::TrayAction::OPEN_DASHBOARD;
    });

    register_test("tray_map_menu_alerts", [] {
        return gcad::SystemTrayManager::map_menu_id(gcad::SystemTrayManager::MENU_ALERTS)
               == gcad::TrayAction::OPEN_ALERTS;
    });

    register_test("tray_map_menu_settings", [] {
        return gcad::SystemTrayManager::map_menu_id(gcad::SystemTrayManager::MENU_SETTINGS)
               == gcad::TrayAction::OPEN_SETTINGS;
    });

    register_test("tray_map_menu_toggle", [] {
        return gcad::SystemTrayManager::map_menu_id(gcad::SystemTrayManager::MENU_TOGGLE)
               == gcad::TrayAction::TOGGLE_PROTECTION;
    });

    register_test("tray_map_menu_exit", [] {
        return gcad::SystemTrayManager::map_menu_id(gcad::SystemTrayManager::MENU_EXIT)
               == gcad::TrayAction::EXIT;
    });

    register_test("tray_map_menu_unknown", [] {
        return gcad::SystemTrayManager::map_menu_id(9999) == gcad::TrayAction::NONE;
    });

    register_test("tray_default_state", [] {
        gcad::SystemTrayManager mgr;
        if (mgr.window_hidden()) return false;
        if (mgr.poll_action() != gcad::TrayAction::NONE) return false;
        return true;
    });

    register_test("tray_action_enum_values", [] {
        return static_cast<int>(gcad::TrayAction::NONE) == 0
            && static_cast<int>(gcad::TrayAction::EXIT) == 6;
    });
}
