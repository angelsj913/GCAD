#include "gcad/engines/reflective_injection_engine.hpp"
#include <functional>
#include <cstring>
#include <vector>

extern void register_test(const char* name, std::function<bool()> fn);

void register_reflective_injection_tests() {
    register_test("reflective_injection_name_and_lifecycle", [] {
        gcad::ReflectiveInjectionEngine engine;
        if (engine.name() != "ReflectiveInjection") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("reflective_injection_detects_reflective_pe", [] {
        std::vector<uint8_t> pe_mock(512, 0);
        pe_mock[0] = 'M';
        pe_mock[1] = 'Z';
        uint32_t pe_offset = 0x80;
        std::memcpy(&pe_mock[0x3C], &pe_offset, sizeof(uint32_t));
        pe_mock[pe_offset] = 'P';
        pe_mock[pe_offset + 1] = 'E';
        pe_mock[pe_offset + 2] = '\0';
        pe_mock[pe_offset + 3] = '\0';

        return gcad::ReflectiveInjectionEngine::is_rwx_reflective_pe(pe_mock.data(), pe_mock.size());
    });

    register_test("reflective_injection_ignores_benign_memory", [] {
        std::vector<uint8_t> clean_mem(512, 0xCC);
        if (gcad::ReflectiveInjectionEngine::is_rwx_reflective_pe(clean_mem.data(), clean_mem.size())) return false;
        if (gcad::ReflectiveInjectionEngine::is_rwx_reflective_pe(nullptr, 0)) return false;
        return true;
    });

    register_test("reflective_injection_detects_hollowing", [] {
        if (!gcad::ReflectiveInjectionEngine::evaluate_hollowing_anomaly(true, true, 0x1000)) return false;
        if (!gcad::ReflectiveInjectionEngine::evaluate_hollowing_anomaly(true, false, 0)) return false;
        if (gcad::ReflectiveInjectionEngine::evaluate_hollowing_anomaly(false, true, 0x1000)) return false;
        if (gcad::ReflectiveInjectionEngine::evaluate_hollowing_anomaly(true, false, 0x00401000)) return false;
        return true;
    });

    register_test("reflective_injection_detects_early_bird_apc", [] {
        if (!gcad::ReflectiveInjectionEngine::evaluate_early_bird_apc(true, true, false)) return false;
        if (gcad::ReflectiveInjectionEngine::evaluate_early_bird_apc(true, true, true)) return false;
        if (gcad::ReflectiveInjectionEngine::evaluate_early_bird_apc(false, true, false)) return false;
        return true;
    });

    register_test("reflective_injection_fires_threat_callback", [] {
        gcad::ReflectiveInjectionEngine engine;
        bool threat_fired = false;
        engine.on_threat([&](const gcad::ThreatEvent& te) {
            if (te.category == gcad::ThreatCategory::MEMORY_INJECTION && te.process_id == 1234u) {
                threat_fired = true;
            }
        });

        std::vector<uint8_t> pe_mock(512, 0);
        pe_mock[0] = 'M';
        pe_mock[1] = 'Z';
        uint32_t pe_offset = 0x40;
        std::memcpy(&pe_mock[0x3C], &pe_offset, sizeof(uint32_t));
        pe_mock[pe_offset] = 'P';
        pe_mock[pe_offset + 1] = 'E';
        pe_mock[pe_offset + 2] = '\0';
        pe_mock[pe_offset + 3] = '\0';

        auto ev = engine.inspect_memory_region(1234, "svchost.exe", 0x7FFF0000, pe_mock.data(), pe_mock.size(), 0x40);
        return threat_fired && ev.technique == gcad::InjectionTechnique::REFLECTIVE_DLL;
    });
}
