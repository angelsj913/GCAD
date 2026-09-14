#pragma once
#include "../../common.hpp"
#include "../ui_preferences.hpp"

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
    bool  amsi_guard_enabled_{true};
    bool  amsi_auto_heal_{true};
    float amsi_script_thresh_{50.0f};
    bool  wmi_bits_enabled_{true};
    float wmi_audit_interval_{10.0f};
    bool  named_pipe_enabled_{true};
    float named_pipe_scan_interval_{5.0f};
    bool  pe_static_enabled_{true};
    float pe_entropy_thresh_{7.2f};
    bool  lolbins_guard_enabled_{true};
    bool  fileless_ast_enabled_{true};
    bool  minimize_to_tray_{true};
    bool  auto_quarantine_{true};
    bool  auto_rollback_{false};
    int   report_format_{0};
    std::string report_status_;
    bool preferences_loaded_{false};
    std::string preferences_status_;

public:
    void render(EngineManager& em, AlertManager* am = nullptr);
    bool minimize_to_tray() const noexcept { return minimize_to_tray_; }

private:
    void render_engine_controls(EngineManager& em);
    void render_scan_settings();
    void render_network_settings();
    void render_report_settings(EngineManager& em, AlertManager* am);
    void render_general_settings();
    void load_preferences();
};

} // namespace gcad::ui::views
