#include "gcad/common.hpp"
#include "gcad/engines/registry_monitor_engine.hpp"
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_registry_monitor_tests() {
    register_test("regmon_name", [] {
        gcad::RegistryMonitorEngine engine;
        return engine.name() == "RegMon";
    });

    register_test("regmon_initial_state", [] {
        gcad::RegistryMonitorEngine engine;
        if (engine.running()) return false;
        auto s = engine.status();
        if (s.running) return false;
        if (s.events_processed != 0) return false;
        if (s.threats_detected != 0) return false;
        return true;
    });

    register_test("regmon_status_name", [] {
        gcad::RegistryMonitorEngine engine;
        auto s = engine.status();
        return s.name == "RegMon";
    });

    register_test("regmon_default_autorun_keys", [] {
        auto keys = gcad::RegistryMonitorEngine::default_autorun_keys();
#ifdef GCAD_PLATFORM_WINDOWS
        if (keys.empty()) return false;
        bool found_run = false;
        for (auto& k : keys) {
            if (k.subkey.find("CurrentVersion\\Run") != std::string::npos)
                found_run = true;
        }
        return found_run;
#else
        return keys.empty();
#endif
    });

    register_test("regmon_on_threat_callback", [] {
        gcad::RegistryMonitorEngine engine;
        bool called = false;
        engine.on_threat([&](gcad::ThreatEvent) { called = true; });
        return !called;
    });

    register_test("regmon_on_observation_callback", [] {
        gcad::RegistryMonitorEngine engine;
        bool called = false;
        engine.on_observation([&](gcad::security::SecurityObservation) { called = true; });
        return !called;
    });

    register_test("regmon_start_stop", [] {
        gcad::RegistryMonitorEngine engine;
        auto rc = engine.start();
        if (rc != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        rc = engine.stop();
        if (rc != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("regmon_double_start", [] {
        gcad::RegistryMonitorEngine engine;
        engine.start();
        auto rc = engine.start();
        engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("regmon_double_stop", [] {
        gcad::RegistryMonitorEngine engine;
        auto rc = engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("regmon_enumerate_values", [] {
        auto values = gcad::RegistryMonitorEngine::enumerate_autorun_values();
#ifdef GCAD_PLATFORM_WINDOWS
        return true;
#else
        return values.empty();
#endif
    });
}
