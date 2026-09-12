#pragma once
#include <chrono>

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

class DashboardView {
    float threat_gauge_{0.0f};
    float target_gauge_{0.0f};
    float mem_history_[120]{};
    float cpu_history_[120]{};
    float eps_history_[60]{};
    float threat_timeline_[60]{};
    int   history_idx_{0};
    int   eps_idx_{0};

    uint64_t prev_total_events_{0};
    std::chrono::steady_clock::time_point last_eps_tick_{};
    float    current_eps_{0.0f};

#ifdef GCAD_PLATFORM_WINDOWS
    uint64_t prev_idle_{0};
    uint64_t prev_kernel_{0};
    uint64_t prev_user_{0};
#endif

public:
    void render(EngineManager& em);

private:
    void render_kpi_cards(EngineManager& em);
    void render_engine_heatmap(EngineManager& em);
    void render_engine_cards(EngineManager& em);
    void render_threat_gauge(EngineManager& em);
    void render_threat_timeline(EngineManager& em);
    void render_severity_histogram(EngineManager& em);
    void render_security_findings(EngineManager& em);
    void render_resource_monitor();
    void render_activity_feed(EngineManager& em);
    void update_cpu_usage();
    void update_eps(EngineManager& em);
};

} // namespace gcad::ui::views
