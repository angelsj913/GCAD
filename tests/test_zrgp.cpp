#include "gcad/common.hpp"
#include "gcad/engines/zrgp_engine.hpp"
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_zrgp_tests() {
    register_test("zrgp_name", [] {
        gcad::ZRGPEngine engine;
        return engine.name() == "ZRGP";
    });

    register_test("zrgp_initial_state", [] {
        gcad::ZRGPEngine engine;
        if (engine.running()) return false;
        return true;
    });

    register_test("zrgp_status", [] {
        gcad::ZRGPEngine engine;
        auto s = engine.status();
        if (s.name != "ZRGP") return false;
        if (s.running) return false;
        return true;
    });

    register_test("zrgp_threat_callback", [] {
        gcad::ZRGPEngine engine;
        std::atomic<int> count{0};
        engine.on_threat([&count](gcad::ThreatEvent) { count++; });
        return true;
    });

    register_test("zrgp_double_stop", [] {
        gcad::ZRGPEngine engine;
        auto rc = engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("zrgp_status_fields_initial", [] {
        gcad::ZRGPEngine engine;
        auto s = engine.status();
        if (s.events_processed != 0) return false;
        if (s.threats_detected != 0) return false;
        return true;
    });

    register_test("zrgp_total_fake_responses_initial", [] {
        gcad::ZRGPEngine engine;
        return engine.total_fake_responses() == 0;
    });

    register_test("zrgp_attacker_stats_empty", [] {
        gcad::ZRGPEngine engine;
        return engine.get_attacker_stats().empty();
    });

    register_test("zrgp_add_honey_port", [] {
        gcad::ZRGPEngine engine;
        engine.add_honey_port(31337, "honeypot");
        return true;
    });
}
