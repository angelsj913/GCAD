#include "gcad/common.hpp"
#include "gcad/engines/pmsr_engine.hpp"
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_pmsr_tests() {
    register_test("pmsr_start_stop", [] {
        gcad::PMSREngine engine;
        auto rc = engine.start();
        if (rc != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        engine.stop();
        if (engine.running()) return false;
        return true;
    });

    register_test("pmsr_name", [] {
        gcad::PMSREngine engine;
        return engine.name() == "PMSR";
    });

    register_test("pmsr_status_fields", [] {
        gcad::PMSREngine engine;
        auto s = engine.status();
        if (s.name != "PMSR") return false;
        if (s.running) return false;
        return true;
    });

    register_test("pmsr_threat_callback", [] {
        gcad::PMSREngine engine;
        std::atomic<int> count{0};
        engine.on_threat([&count](gcad::ThreatEvent) { count++; });
        engine.start();
        std::this_thread::sleep_for(std::chrono::seconds(2));
        engine.stop();
        return true;
    });
}
