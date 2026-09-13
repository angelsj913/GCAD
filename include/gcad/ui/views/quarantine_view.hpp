#pragma once
#include "../../engines/arhs_engine.hpp"
#include "../incident_actions.hpp"

namespace gcad::ui::views {

class QuarantineView {
    int selected_item_{-1};
    IncidentActionGate action_gate_;

public:
    void render(ARHSEngine* engine);

private:
    void render_sandboxed_list(const std::vector<SandboxedProcess>& sandboxed);
    void render_detail_panel(const SandboxedProcess& proc);
    void render_action_buttons(const SandboxedProcess& proc);
    void render_confirmation_modal(ARHSEngine& engine);
    void execute_pending_action(ARHSEngine& engine, const PendingIncidentAction& pending);
};

} // namespace gcad::ui::views
