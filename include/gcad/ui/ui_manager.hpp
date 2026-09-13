#pragma once
#include "../common.hpp"
#include "navigation.hpp"
#include "system_tray.hpp"

namespace gcad {
class EngineManager;
class DeepScanner;
class AlertManager;
}

namespace gcad::ui {

class UIManager {
    bool                initialized_{false};
    bool                should_close_{false};
    EngineManager*      engine_mgr_{nullptr};
    DeepScanner*        scanner_{nullptr};
    AlertManager*       alert_mgr_{nullptr};
    PrimaryView         active_view_{PrimaryView::OVERVIEW};
    IncidentPane        incident_pane_{IncidentPane::ALERTS};
    std::chrono::steady_clock::time_point start_time_{};
    SystemTrayManager   tray_mgr_;

#ifdef GCAD_PLATFORM_WINDOWS
    struct DX11State;
    std::unique_ptr<DX11State> dx_;
#endif

    void render_menubar();
    void render_statusbar();
    void render_navigation_rail();
    void render_top_header();
    void render_active_view();
    void render_dashboard();
    void render_scan();
    void render_network();
    void render_quarantine();
    void render_forensics();
    void render_alerts();
    void render_settings();

public:
    UIManager();
    ~UIManager();

    ErrorCode init(EngineManager* em, DeepScanner* sc, AlertManager* am = nullptr);
    void      shutdown();
    bool      should_close() const noexcept { return should_close_; }
    void      run_frame();
    void      main_loop();
    void      set_active_tab(int tab);
    SystemTrayManager* tray_manager() { return &tray_mgr_; }
};

} // namespace gcad::ui
