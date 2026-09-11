#include "gcad/common.hpp"
#include "gcad/ui/forensic_graph.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_forensic_graph_tests() {
    register_test("forensic_graph_groups_pid_events_and_keeps_highest_severity", [] {
        gcad::ThreatEvent first{};
        first.id = 1; first.level = gcad::ThreatLevel::MEDIUM; first.process_id = 42;
        first.process_name = "alpha.exe"; first.description = "first";
        gcad::ThreatEvent second{};
        second.id = 2; second.level = gcad::ThreatLevel::LOW; second.process_id = 7;
        second.process_name = "beta.exe"; second.description = "second";
        gcad::ThreatEvent third{};
        third.id = 3; third.level = gcad::ThreatLevel::CRITICAL; third.process_id = 42;
        third.process_name = "alpha.exe"; third.description = "third";
        gcad::ThreatEvent system_wide{};
        system_wide.id = 4; system_wide.level = gcad::ThreatLevel::HIGH;
        system_wide.description = "system-wide";
        const std::vector<gcad::ThreatEvent> events{first, second, third, system_wide};

        const auto graph = gcad::ui::build_forensic_graph(events);
        if (graph.nodes.size() != 2) return false;

        const auto alpha = std::find_if(graph.nodes.begin(), graph.nodes.end(),
            [](const auto& node) { return node.pid == 42; });
        if (alpha == graph.nodes.end()) return false;
        if (alpha->event_count != 2) return false;
        if (alpha->level != gcad::ThreatLevel::CRITICAL) return false;
        return alpha->label == "alpha.exe";
    });
}
