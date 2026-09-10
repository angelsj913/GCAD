#pragma once

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

class DashboardView {
    float threat_gauge_{0.0f};
    float target_gauge_{0.0f};
    float radar_angle_{0.0f};
    float cpu_history_[120]{};
    float mem_history_[120]{};
    int   history_idx_{0};

public:
    void render(EngineManager& em);

private:
    void render_header(EngineManager& em);
    void render_threat_gauge();
    void render_engine_cards(EngineManager& em);
    void render_resource_monitor();
    void render_radar_animation();
};

} // namespace gcad::ui::views
