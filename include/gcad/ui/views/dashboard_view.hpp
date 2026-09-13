#pragma once
#include <chrono>

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

class DashboardView {
    uint64_t prev_total_events_{0};
    std::chrono::steady_clock::time_point last_eps_tick_{};
    float    current_eps_{0.0f};

public:
    void render(EngineManager& em);

private:
    void render_kpi_cards(EngineManager& em);
    void render_engine_cards(EngineManager& em);
    void render_threat_gauge(EngineManager& em);
    void render_threat_timeline(EngineManager& em);
    void render_severity_histogram(EngineManager& em);
    void render_security_findings(EngineManager& em);
    void render_resource_monitor();
    void render_activity_feed(EngineManager& em);
    void update_eps(EngineManager& em);
};

} // namespace gcad::ui::views
