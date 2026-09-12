#include "gcad/common.hpp"
#include "gcad/ui/forensic_graph.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_forensic_graph_tests() {
    register_test("forensic_graph_empty_events", [] {
        const std::vector<gcad::ThreatEvent> events;
        const auto graph = gcad::ui::build_forensic_graph(events);
        return graph.nodes.empty();
    });

    register_test("forensic_graph_skips_zero_pid", [] {
        gcad::ThreatEvent ev{};
        ev.id = 1; ev.process_id = 0; ev.description = "no pid";
        const std::vector<gcad::ThreatEvent> events{ev};
        const auto graph = gcad::ui::build_forensic_graph(events);
        return graph.nodes.empty();
    });

    register_test("forensic_graph_single_event", [] {
        gcad::ThreatEvent ev{};
        ev.id = 1; ev.level = gcad::ThreatLevel::LOW; ev.process_id = 100;
        ev.process_name = "test.exe"; ev.description = "test event";
        const std::vector<gcad::ThreatEvent> events{ev};
        const auto graph = gcad::ui::build_forensic_graph(events);
        if (graph.nodes.size() != 1) return false;
        if (graph.nodes[0].pid != 100) return false;
        if (graph.nodes[0].event_count != 1) return false;
        return graph.nodes[0].label == "test.exe";
    });

    register_test("forensic_graph_pid_without_name_uses_fallback", [] {
        gcad::ThreatEvent ev{};
        ev.id = 1; ev.process_id = 77;
        const std::vector<gcad::ThreatEvent> events{ev};
        const auto graph = gcad::ui::build_forensic_graph(events);
        return graph.nodes.size() == 1 && graph.nodes[0].label == "PID 77";
    });

    register_test("forensic_graph_name_overrides_pid_fallback", [] {
        gcad::ThreatEvent first{};
        first.id = 1; first.process_id = 77;
        gcad::ThreatEvent second{};
        second.id = 2; second.process_id = 77; second.process_name = "real.exe";
        const std::vector<gcad::ThreatEvent> events{first, second};
        const auto graph = gcad::ui::build_forensic_graph(events);
        return graph.nodes.size() == 1 && graph.nodes[0].label == "real.exe";
    });

    register_test("forensic_graph_creates_edges_between_consecutive_pids", [] {
        gcad::ThreatEvent a{};
        a.id = 1; a.process_id = 10; a.process_name = "parent.exe";
        gcad::ThreatEvent b{};
        b.id = 2; b.process_id = 20; b.process_name = "child.exe";
        const std::vector<gcad::ThreatEvent> events{a, b};
        const auto graph = gcad::ui::build_forensic_graph(events);
        if (graph.nodes.size() != 2) return false;
        if (graph.nodes[0].children.empty()) return false;
        if (graph.nodes[1].parents.empty()) return false;
        return graph.nodes[0].children[0] == 1 && graph.nodes[1].parents[0] == 0;
    });

    register_test("forensic_graph_no_self_edges", [] {
        gcad::ThreatEvent a{};
        a.id = 1; a.process_id = 10;
        gcad::ThreatEvent b{};
        b.id = 2; b.process_id = 10;
        const std::vector<gcad::ThreatEvent> events{a, b};
        const auto graph = gcad::ui::build_forensic_graph(events);
        if (graph.nodes.size() != 1) return false;
        return graph.nodes[0].children.empty();
    });

    register_test("forensic_graph_no_duplicate_edges", [] {
        gcad::ThreatEvent a{};
        a.id = 1; a.process_id = 10;
        gcad::ThreatEvent b{};
        b.id = 2; b.process_id = 20;
        gcad::ThreatEvent c{};
        c.id = 3; c.process_id = 10;
        gcad::ThreatEvent d{};
        d.id = 4; d.process_id = 20;
        const std::vector<gcad::ThreatEvent> events{a, b, c, d};
        const auto graph = gcad::ui::build_forensic_graph(events);
        return graph.nodes[0].children.size() == 1;
    });

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
