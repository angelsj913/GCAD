#include "gcad/engines/forensic_timeline_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

static gcad::ThreatEvent make_event(uint32_t pid, const std::string& proc,
                                    gcad::ThreatCategory cat, gcad::ThreatLevel lvl) {
    gcad::ThreatEvent ev{};
    ev.process_id = pid;
    ev.process_name = proc;
    ev.category = cat;
    ev.level = lvl;
    ev.description = "test event";
    ev.timestamp = std::chrono::system_clock::now();
    return ev;
}

void register_forensic_timeline_tests() {
    register_test("ftl_stage_name_all", [] {
        auto names = {
            gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::RECONNAISSANCE),
            gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::WEAPONIZATION),
            gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::DELIVERY),
            gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::EXPLOITATION),
            gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::INSTALLATION),
            gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::COMMAND_CONTROL),
            gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::ACTIONS_ON_OBJ),
        };
        for (auto n : names)
            if (!n || std::string(n).empty()) return false;
        return std::string(gcad::ForensicTimelineEngine::stage_name(gcad::KillChainStage::UNKNOWN)) == "Unknown";
    });

    register_test("ftl_map_recon", [] {
        return gcad::ForensicTimelineEngine::map_category_to_stage(gcad::ThreatCategory::NETWORK_SCAN) ==
               gcad::KillChainStage::RECONNAISSANCE;
    });

    register_test("ftl_map_exploitation", [] {
        return gcad::ForensicTimelineEngine::map_category_to_stage(gcad::ThreatCategory::MEMORY_INJECTION) ==
               gcad::KillChainStage::EXPLOITATION;
    });

    register_test("ftl_map_c2", [] {
        return gcad::ForensicTimelineEngine::map_category_to_stage(gcad::ThreatCategory::DNS_TUNNEL) ==
               gcad::KillChainStage::COMMAND_CONTROL;
    });

    register_test("ftl_map_actions", [] {
        return gcad::ForensicTimelineEngine::map_category_to_stage(gcad::ThreatCategory::RANSOMWARE) ==
               gcad::KillChainStage::ACTIONS_ON_OBJ;
    });

    register_test("ftl_map_installation", [] {
        return gcad::ForensicTimelineEngine::map_category_to_stage(gcad::ThreatCategory::BACKDOOR_ACCOUNT) ==
               gcad::KillChainStage::INSTALLATION;
    });

    register_test("ftl_map_delivery", [] {
        return gcad::ForensicTimelineEngine::map_category_to_stage(gcad::ThreatCategory::SYN_FLOOD) ==
               gcad::KillChainStage::DELIVERY;
    });

    register_test("ftl_map_obs_network", [] {
        return gcad::ForensicTimelineEngine::map_observation_to_stage(
                   gcad::security::ObservationKind::NETWORK_CONNECTION) ==
               gcad::KillChainStage::COMMAND_CONTROL;
    });

    register_test("ftl_map_obs_registry", [] {
        return gcad::ForensicTimelineEngine::map_observation_to_stage(
                   gcad::security::ObservationKind::REGISTRY_PERSISTENCE) ==
               gcad::KillChainStage::INSTALLATION;
    });

    register_test("ftl_type_memory", [] {
        return gcad::ForensicTimelineEngine::map_category_to_type(gcad::ThreatCategory::MEMORY_INJECTION) ==
               gcad::TimelineEventType::MEMORY;
    });

    register_test("ftl_type_dns", [] {
        return gcad::ForensicTimelineEngine::map_category_to_type(gcad::ThreatCategory::DNS_TUNNEL) ==
               gcad::TimelineEventType::DNS;
    });

    register_test("ftl_type_registry", [] {
        return gcad::ForensicTimelineEngine::map_category_to_type(gcad::ThreatCategory::REGISTRY_TAMPER) ==
               gcad::TimelineEventType::REGISTRY;
    });

    register_test("ftl_type_obs_file", [] {
        return gcad::ForensicTimelineEngine::map_observation_to_type(
                   gcad::security::ObservationKind::FILE_INTEGRITY) ==
               gcad::TimelineEventType::FILE_ACCESS;
    });

    register_test("ftl_ingest_threat", [] {
        gcad::ForensicTimelineEngine fte;
        auto ev = make_event(100, "test.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::MEDIUM);
        fte.ingest_threat(ev);
        auto tl = fte.query_timeline(10);
        return tl.size() == 1 && tl[0].process_id == 100 &&
               tl[0].stage == gcad::KillChainStage::RECONNAISSANCE;
    });

    register_test("ftl_ingest_observation", [] {
        gcad::ForensicTimelineEngine fte;
        gcad::security::SecurityObservation obs;
        obs.source_id = "test";
        obs.kind = gcad::security::ObservationKind::REGISTRY_PERSISTENCE;
        obs.suggested_level = gcad::ThreatLevel::HIGH;
        obs.confidence = 0.9;
        obs.process_id = 200;
        obs.process_name = "evil.exe";
        obs.evidence = "persistence detected";
        obs.timestamp = std::chrono::system_clock::now();
        fte.ingest_observation(obs);
        auto tl = fte.query_timeline(10);
        return tl.size() == 1 && tl[0].stage == gcad::KillChainStage::INSTALLATION;
    });

    register_test("ftl_query_by_pid", [] {
        gcad::ForensicTimelineEngine fte;
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::LOW));
        fte.ingest_threat(make_event(200, "b.exe", gcad::ThreatCategory::DNS_TUNNEL, gcad::ThreatLevel::HIGH));
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::RAW_SOCKET_PROBE, gcad::ThreatLevel::MEDIUM));
        auto result = fte.query_by_pid(100);
        return result.size() == 2;
    });

    register_test("ftl_query_by_stage", [] {
        gcad::ForensicTimelineEngine fte;
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::LOW));
        fte.ingest_threat(make_event(200, "b.exe", gcad::ThreatCategory::MEMORY_INJECTION, gcad::ThreatLevel::HIGH));
        auto recon = fte.query_by_stage(gcad::KillChainStage::RECONNAISSANCE);
        auto exploit = fte.query_by_stage(gcad::KillChainStage::EXPLOITATION);
        return recon.size() == 1 && exploit.size() == 1;
    });

    register_test("ftl_causal_linking", [] {
        gcad::ForensicTimelineEngine fte;
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::LOW));
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::MEMORY_INJECTION, gcad::ThreatLevel::HIGH));
        auto tl = fte.query_timeline(10);
        return tl.size() == 2 && tl[1].causal_parent == tl[0].id;
    });

    register_test("ftl_causal_chains", [] {
        gcad::ForensicTimelineEngine fte;
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::MEDIUM));
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::MEMORY_INJECTION, gcad::ThreatLevel::HIGH));
        auto chains = fte.causal_chains();
        return !chains.empty() && chains.back().event_ids.size() == 2;
    });

    register_test("ftl_kill_chain_progress", [] {
        gcad::ForensicTimelineEngine fte;
        fte.ingest_threat(make_event(1, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::LOW));
        fte.ingest_threat(make_event(2, "b.exe", gcad::ThreatCategory::MEMORY_INJECTION, gcad::ThreatLevel::HIGH));
        fte.ingest_threat(make_event(3, "c.exe", gcad::ThreatCategory::RANSOMWARE, gcad::ThreatLevel::CRITICAL));
        auto p = fte.kill_chain_progress();
        return p.total_events == 3 && p.furthest == gcad::KillChainStage::ACTIONS_ON_OBJ &&
               p.multi_stage_detected;
    });

    register_test("ftl_query_time_range", [] {
        gcad::ForensicTimelineEngine fte;
        auto now = std::chrono::system_clock::now();
        gcad::ThreatEvent ev = make_event(1, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::LOW);
        ev.timestamp = now - std::chrono::seconds(10);
        fte.ingest_threat(ev);
        ev.timestamp = now;
        fte.ingest_threat(ev);
        auto result = fte.query_time_range(now - std::chrono::seconds(5), now + std::chrono::seconds(1));
        return result.size() == 1;
    });

    register_test("ftl_start_stop", [] {
        gcad::ForensicTimelineEngine fte;
        if (fte.running()) return false;
        fte.start();
        if (!fte.running()) return false;
        auto s = fte.status();
        if (s.name != "ForensicTimeline") return false;
        fte.stop();
        return !fte.running();
    });

    register_test("ftl_event_ids_unique", [] {
        gcad::ForensicTimelineEngine fte;
        fte.ingest_threat(make_event(1, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::LOW));
        fte.ingest_threat(make_event(2, "b.exe", gcad::ThreatCategory::DNS_TUNNEL, gcad::ThreatLevel::HIGH));
        auto tl = fte.query_timeline(10);
        return tl.size() == 2 && tl[0].id != tl[1].id;
    });

    register_test("ftl_no_cross_pid_causal", [] {
        gcad::ForensicTimelineEngine fte;
        fte.ingest_threat(make_event(100, "a.exe", gcad::ThreatCategory::NETWORK_SCAN, gcad::ThreatLevel::LOW));
        fte.ingest_threat(make_event(200, "b.exe", gcad::ThreatCategory::DNS_TUNNEL, gcad::ThreatLevel::HIGH));
        auto tl = fte.query_timeline(10);
        return tl.size() == 2 && tl[1].causal_parent == 0;
    });
}
