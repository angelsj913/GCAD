#pragma once
#include "../common.hpp"
#include <atomic>
#include <memory>
#include <functional>
#include <string>

namespace gcad {

struct AlertRecord;
class EngineManager;
class AlertManager;

enum class TrayAction : uint8_t {
    NONE = 0,
    RESTORE_WINDOW,
    OPEN_DASHBOARD,
    OPEN_ALERTS,
    OPEN_SETTINGS,
    TOGGLE_PROTECTION,
    EXIT,
};

class SystemTrayManager {
public:
    SystemTrayManager();
    ~SystemTrayManager();

    bool init(void* main_hwnd, EngineManager* em, AlertManager* am);
    void cleanup();
    void update_icon(ThreatLevel level);
    void show_notification(const std::string& title, const std::string& msg, ThreatLevel level);
    void on_minimize();
    void restore_window();
    bool window_hidden() const noexcept { return window_hidden_.load(); }
    TrayAction poll_action();

    static uint32_t threat_color_rgb(ThreatLevel level);
    static TrayAction map_menu_id(int id);

    static constexpr int MENU_RESTORE   = 1001;
    static constexpr int MENU_DASHBOARD = 1002;
    static constexpr int MENU_ALERTS    = 1003;
    static constexpr int MENU_SETTINGS  = 1004;
    static constexpr int MENU_TOGGLE    = 1005;
    static constexpr int MENU_EXIT      = 1006;

#ifdef GCAD_PLATFORM_WINDOWS
    void show_context_menu();
    void handle_menu_command(int id);
#endif

private:
    std::atomic<bool> window_hidden_{false};
    std::atomic<int>  pending_action_{0};
    void* main_hwnd_{nullptr};
    EngineManager* engine_mgr_{nullptr};
    AlertManager*  alert_mgr_{nullptr};

#ifdef GCAD_PLATFORM_WINDOWS
    struct Impl;
    std::unique_ptr<Impl> impl_;
#endif
};

} // namespace gcad
