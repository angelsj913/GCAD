#pragma once
#include "../../common.hpp"

namespace gcad {
class EngineManager;
class AlertManager;
}

namespace gcad::ui::views {

class SettingsView {
    float pmsr_sensitivity_{0.8f};
    float etg_entropy_thresh_{7.5f};
    float arhs_backup_interval_{5.0f};
    int   zrgp_max_ports_{32};
    bool  self_defense_enabled_{true};
    bool  syscall_guard_enabled_{true};
    bool  minimize_to_tray_{true};
    bool  auto_quarantine_{true};
    bool  auto_rollback_{false};
    int   report_format_{0};
    std::string report_status_;

public:
    void render(EngineManager& em, AlertManager* am = nullptr);

private:
    void render_engine_controls(EngineManager& em);
    void render_scan_settings();
    void render_network_settings();
    void render_report_settings(EngineManager& em, AlertManager* am);
    void render_general_settings();
};

} // namespace gcad::ui::views
