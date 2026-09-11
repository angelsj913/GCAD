#pragma once

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

class DashboardView {
    float threat_gauge_{0.0f};
    float target_gauge_{0.0f};
    float mem_history_[120]{};
    int   history_idx_{0};

public:
    void render(EngineManager& em);

private:
    void render_kpi_cards(EngineManager& em);
    void render_engine_cards(EngineManager& em);
    void render_threat_gauge(EngineManager& em);
    void render_resource_monitor();
    void render_activity_feed(EngineManager& em);
};

} // namespace gcad::ui::views
