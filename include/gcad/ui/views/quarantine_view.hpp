#pragma once
#include "../../engines/arhs_engine.hpp"
#include "../incident_actions.hpp"

#include <optional>

namespace gcad::ui::views {

class QuarantineView {
    struct PendingIncidentAction {
        IncidentAction action{IncidentAction::NONE};
        uint32_t pid{0};
        uint64_t creation_time{0};
        std::string process_name;
    };

    int selected_item_{-1};
    std::optional<PendingIncidentAction> pending_action_;

public:
    void render(ARHSEngine* engine);

private:
    void render_sandboxed_list(const std::vector<SandboxedProcess>& sandboxed);
    void render_detail_panel(const SandboxedProcess& proc);
    void render_action_buttons(const SandboxedProcess& proc);
    void render_confirmation_modal(ARHSEngine& engine);
    void execute_pending_action(ARHSEngine& engine);
};

} // namespace gcad::ui::views
