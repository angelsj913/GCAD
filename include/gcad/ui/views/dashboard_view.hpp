#pragma once
namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

class DashboardView {
public:
    void render(EngineManager& em);

private:
    void render_kpi_cards(EngineManager& em);
    void render_engine_cards(EngineManager& em);
    void render_threat_gauge(EngineManager& em);
    void render_threat_timeline(EngineManager& em);
    void render_severity_histogram(EngineManager& em);
    void render_category_health(EngineManager& em);
    void render_security_findings(EngineManager& em);
    void render_resource_monitor(EngineManager& em);
    void render_activity_feed(EngineManager& em);
};

} // namespace gcad::ui::views
