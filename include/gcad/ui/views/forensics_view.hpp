#pragma once
#include "../../common.hpp"

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

struct DAGNode {
    uint64_t    id;
    uint32_t    pid;
    std::string label;
    float       x, y;
    uint32_t    color;
    std::vector<uint64_t> children;
};

class ForensicsView {
    std::vector<DAGNode>   nodes_;
    std::vector<ThreatEvent> timeline_;
    float                  scroll_x_{0.0f};
    float                  scroll_y_{0.0f};
    float                  zoom_{1.0f};
    int                    selected_node_{-1};

public:
    void render(EngineManager& em);
    void rebuild_dag(const std::vector<ThreatEvent>& events);

private:
    void render_dag_canvas();
    void render_timeline_list();
    void render_node_detail();
    void layout_dag();
};

} // namespace gcad::ui::views
