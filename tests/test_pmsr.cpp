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

    register_test("pmsr_double_start", [] {
        gcad::PMSREngine engine;
        engine.start();
        auto rc = engine.start();
        engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("pmsr_double_stop", [] {
        gcad::PMSREngine engine;
        auto rc = engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("pmsr_register_region", [] {
        gcad::PMSREngine engine;
        uint8_t buffer[64]{};
        engine.register_region(reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
        return true;
    });

    register_test("pmsr_inject_honey_iat", [] {
        gcad::PMSREngine engine;
        engine.inject_honey_iat(0xDEADBEEF, 0x12345678);
        return true;
    });

    register_test("pmsr_status_after_run", [] {
        gcad::PMSREngine engine;
        engine.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto s = engine.status();
        engine.stop();
        if (!s.running) return false;
        return s.name == "PMSR";
    });

    register_test("pmsr_events_processed_increases", [] {
        gcad::PMSREngine engine;
        engine.start();
        std::this_thread::sleep_for(std::chrono::seconds(2));
        auto s = engine.status();
        engine.stop();
        return s.events_processed > 0;
    });
}
