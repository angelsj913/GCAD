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
}
