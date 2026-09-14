#pragma once
#include "../../engines/arhs_engine.hpp"
#include "../incident_actions.hpp"

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

class QuarantineView {
    int selected_item_{-1};
    int selected_record_{-1};
    IncidentActionGate action_gate_;

    enum class FileVaultAction { NONE, RESTORE, SHRED };
    FileVaultAction pending_file_action_{FileVaultAction::NONE};
    uint64_t        pending_record_id_{0};
    std::string     pending_record_path_;

public:
    void render(ARHSEngine* engine);
    void render(EngineManager* engine_mgr, ARHSEngine* engine);

private:
    void render_vault_tab(EngineManager* engine_mgr);
    void render_sandboxed_tab(ARHSEngine* engine);
    void render_sandboxed_list(const std::vector<SandboxedProcess>& sandboxed);
    void render_detail_panel(const SandboxedProcess& proc);
    void render_action_buttons(const SandboxedProcess& proc);
    void render_confirmation_modal(ARHSEngine& engine);
    void render_vault_modal(EngineManager& engine_mgr);
    void execute_pending_action(ARHSEngine& engine, const PendingIncidentAction& pending);
};

} // namespace gcad::ui::views
