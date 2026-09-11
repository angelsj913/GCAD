#pragma once

#include "../common.hpp"

namespace gcad::ui {

struct ForensicGraphNode {
    uint32_t                  pid{0};
    std::string               label;
    ThreatLevel               level{ThreatLevel::SAFE};
    size_t                    event_count{0};
    std::vector<size_t>       children;
    std::vector<size_t>       parents;
    std::chrono::system_clock::time_point first_seen{};
};

struct ForensicGraph {
    std::vector<ForensicGraphNode> nodes;
};

inline ForensicGraph build_forensic_graph(std::span<const ThreatEvent> events) {
    ForensicGraph graph;
    std::unordered_map<uint32_t, size_t> index_by_pid;

    for (const auto& event : events) {
        if (event.process_id == 0) continue;

        const auto [it, inserted] = index_by_pid.emplace(event.process_id, graph.nodes.size());
        if (inserted) {
            ForensicGraphNode node;
            node.pid = event.process_id;
            node.label = event.process_name.empty() ? "PID " + std::to_string(event.process_id) : event.process_name;
            node.level = event.level;
            node.event_count = 1;
            node.first_seen = event.timestamp;
            graph.nodes.push_back(std::move(node));
            continue;
        }

        auto& node = graph.nodes[it->second];
        ++node.event_count;
        node.level = std::max(node.level, event.level);
        if (node.label.rfind("PID ", 0) == 0 && !event.process_name.empty())
            node.label = event.process_name;
    }

    for (size_t i = 0; i + 1 < events.size(); ++i) {
        const auto source = index_by_pid.find(events[i].process_id);
        const auto target = index_by_pid.find(events[i + 1].process_id);
        if (source == index_by_pid.end() || target == index_by_pid.end() || source->second == target->second)
            continue;

        auto& children = graph.nodes[source->second].children;
        if (std::find(children.begin(), children.end(), target->second) == children.end()) {
            children.push_back(target->second);
            graph.nodes[target->second].parents.push_back(source->second);
        }
    }

    return graph;
}

} // namespace gcad::ui
