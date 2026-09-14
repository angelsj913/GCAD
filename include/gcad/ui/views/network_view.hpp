#pragma once
#include "../../engines/etg_ri_engine.hpp"
#include "../../engines/firewall_engine.hpp"

namespace gcad::ui::views {

class NetworkView {
    bool  show_blocked_{false};
    int   net_tab_{0};

public:
    void render(ETGRIEngine* engine, FirewallEngine* firewall = nullptr);

private:
    void render_packet_log(ETGRIEngine* engine);
    void render_blocked_ips(ETGRIEngine* engine);
    void render_firewall(FirewallEngine* fw);
    void render_firewall_rules(FirewallEngine* fw);
    void render_firewall_log(FirewallEngine* fw);
    void render_firewall_suspects(FirewallEngine* fw);
};

} // namespace gcad::ui::views
