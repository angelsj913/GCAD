#pragma once
#include "../../common.hpp"

namespace gcad {
class EngineManager;
class DeepScanner;
}

namespace gcad::ui::views {

class DashboardView {
    float threat_gauge_{0.0f};
    float radar_angle_{0.0f};
    float cpu_history_[120]{};
    float mem_history_[120]{};
    int   history_idx_{0};

    std::chrono::steady_clock::time_point session_start_{std::chrono::steady_clock::now()};
    std::chrono::steady_clock::time_point last_cpu_sample_{};
    uint64_t                              last_cpu_ticks_{0};
    float                                 cpu_percent_{0.0f};

public:
    void render(EngineManager& em, DeepScanner& scanner);

private:
    void render_quick_actions(EngineManager& em, DeepScanner& scanner);
    void render_engine_cards(EngineManager& em);
    void render_recent_events(EngineManager& em);
    void render_protection_summary(EngineManager& em, DeepScanner& scanner);
    void render_severity_breakdown(EngineManager& em);
    void render_category_breakdown(EngineManager& em);
    void render_resource_monitor();
    void render_radar(EngineManager& em);
    void sample_cpu();
};

} // namespace gcad::ui::views
