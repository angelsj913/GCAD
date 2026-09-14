#pragma once

#include "../forensic_graph.hpp"

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

class ForensicsView {
    struct GraphPoint { float x{0.0f}; float y{0.0f}; };

    ForensicGraph                 graph_;
    std::vector<ThreatEvent>      timeline_;
    uint64_t                      snapshot_fingerprint_{0};
    std::vector<GraphPoint>       positions_;
    float                         pan_x_{0.0f};
    float                         pan_y_{0.0f};
    float                         zoom_{1.0f};
    uint32_t                      selected_pid_{0};
    int                           hovered_node_{-1};

public:
    void render(EngineManager& em);

private:
    void refresh(std::vector<ThreatEvent> events);
    void layout_graph();
    void render_toolbar();
    void render_graph_canvas();
    void render_node_detail();
    void render_timeline();
    int node_index_for_pid(uint32_t pid) const;
};

} // namespace gcad::ui::views
