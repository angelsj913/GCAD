#pragma once

namespace gcad {
class AlertManager;
}

namespace gcad::ui::views {

class AlertView {
    int filter_level_{0};

public:
    void render(AlertManager& am);
};

} // namespace gcad::ui::views
