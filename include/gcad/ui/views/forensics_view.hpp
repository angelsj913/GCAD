#pragma once
#include "../../common.hpp"

namespace gcad {
class EngineManager;
}

namespace gcad::ui::views {

struct DagNode {
    uint32_t                pid{0};
    std::string             label;
    uint8_t                 level{0};       // max severity observed for this process
    size_t                  events{0};
    int                     rank{0};        // layout column
    float                   x{0.0f}, y{0.0f};
    std::vector<size_t>     children;
    std::vector<size_t>     parents;
    std::chrono::system_clock::time_point first_seen{};
};

class ForensicsView {
    std::vector<DagNode>     nodes_;
    std::vector<ThreatEvent> timeline_;
    size_t                   last_event_count_{static_cast<size_t>(-1)};

    float                    pan_x_{0.0f}, pan_y_{0.0f};
    float                    zoom_{1.0f};
    uint32_t                 selected_pid_{0};
    int                      hover_node_{-1};

public:
    void render(EngineManager& em);

private:
    void rebuild(const std::vector<ThreatEvent>& events);
    void layout();
    void draw_toolbar();
    void draw_graph();
    void draw_detail_panel();
    void draw_timeline();
    int  node_index_for_pid(uint32_t pid) const;
};

} // namespace gcad::ui::views
