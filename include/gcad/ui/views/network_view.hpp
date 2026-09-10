#pragma once
#include "../../engines/etg_ri_engine.hpp"

namespace gcad::ui::views {

class NetworkView {
    float entropy_history_[256]{};
    int   entropy_idx_{0};
    bool  show_blocked_{false};

public:
    void render(ETGRIEngine* engine);

private:
    void render_entropy_graph();
    void render_packet_log(ETGRIEngine* engine);
    void render_blocked_ips(ETGRIEngine* engine);
};

} // namespace gcad::ui::views
