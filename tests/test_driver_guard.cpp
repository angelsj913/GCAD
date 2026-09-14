#include "gcad/engines/driver_guard_engine.hpp"
#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_driver_guard_tests() {
    register_test("driver_guard_name_and_lifecycle", [] {
        gcad::DriverGuardEngine engine;
        if (engine.name() != "DriverGuard") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("driver_guard_detects_known_byovd_gdrv", [] {
        gcad::DriverGuardEngine engine;
        bool threat_fired = false;
        engine.on_threat([&](const gcad::ThreatEvent& te) {
            if (te.level == gcad::ThreatLevel::CRITICAL && te.category == gcad::ThreatCategory::KERNEL_ATTACK) {
                threat_fired = true;
            }
        });

        auto res = engine.evaluate_driver_load("gdrv.sys", "C:\\Drivers\\gdrv.sys", true);
        return res.is_vulnerable_byovd &&
               res.risk == gcad::DriverRiskLevel::VULNERABLE_KNOWN &&
               threat_fired;
    });

    register_test("driver_guard_detects_known_byovd_kprocesshacker", [] {
        if (!gcad::DriverGuardEngine::is_known_vulnerable_driver("kprocesshacker.sys")) return false;
        if (!gcad::DriverGuardEngine::is_known_vulnerable_driver("mhyprot2.sys")) return false;
        if (!gcad::DriverGuardEngine::is_known_vulnerable_driver("dbutil_2_3.sys")) return false;
        if (gcad::DriverGuardEngine::is_known_vulnerable_driver("fltmgr.sys")) return false;
        return true;
    });

    register_test("driver_guard_detects_unsigned_driver", [] {
        gcad::DriverGuardEngine engine;
        bool threat_fired = false;
        engine.on_threat([&](const gcad::ThreatEvent& te) {
            if (te.level == gcad::ThreatLevel::HIGH) {
                threat_fired = true;
            }
        });

        auto res = engine.evaluate_driver_load("custom_rootkit.sys", "C:\\Windows\\System32\\drivers\\custom_rootkit.sys", false);
        return !res.is_signed &&
               res.risk == gcad::DriverRiskLevel::MALICIOUS_UNSIGNED &&
               threat_fired;
    });

    register_test("driver_guard_detects_suspicious_temp_path", [] {
        gcad::DriverGuardEngine engine;
        bool threat_fired = false;
        engine.on_threat([&](const gcad::ThreatEvent& te) {
            if (te.level == gcad::ThreatLevel::MEDIUM) {
                threat_fired = true;
            }
        });

        auto res = engine.evaluate_driver_load("my_driver.sys", "C:\\Users\\victim\\AppData\\Local\\Temp\\my_driver.sys", true);
        return res.risk == gcad::DriverRiskLevel::SUSPICIOUS && threat_fired;
    });

    register_test("driver_guard_allows_legitimate_system32_driver", [] {
        gcad::DriverGuardEngine engine;
        bool threat_fired = false;
        engine.on_threat([&](const gcad::ThreatEvent&) {
            threat_fired = true;
        });

        auto res = engine.evaluate_driver_load("ntfs.sys", "C:\\Windows\\System32\\drivers\\ntfs.sys", true);
        return res.risk == gcad::DriverRiskLevel::BENIGN && !threat_fired;
    });
}
