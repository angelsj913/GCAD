#pragma once
#include "../../engines/arhs_engine.hpp"

namespace gcad::ui::views {

class QuarantineView {
    int selected_item_{-1};

public:
    void render(ARHSEngine* engine);

private:
    void render_sandboxed_list(ARHSEngine* engine);
    void render_detail_panel(const SandboxedProcess& proc);
    void render_action_buttons(ARHSEngine* engine, uint32_t pid);
};

} // namespace gcad::ui::views
