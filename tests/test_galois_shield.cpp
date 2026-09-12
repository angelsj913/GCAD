#include "gcad/galois_shield.hpp"
#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_galois_shield_tests() {
    register_test("shield_version_string", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        auto vs = shield.version_string();
        return vs.find("GaloisShield Engine") != std::string::npos &&
               vs.find("1.0.0") != std::string::npos &&
               vs.find("Bastion") != std::string::npos &&
               vs.find("Galoisconnection") != std::string::npos;
    });

    register_test("shield_name_version_vendor", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        return shield.name() == "GaloisShield Engine" &&
               shield.version() == "1.0.0" &&
               shield.vendor() == "Galoisconnection" &&
               shield.codename() == "Bastion";
    });

    register_test("shield_engine_count", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        return shield.engine_count() == 22;
    });

    register_test("shield_health_before_start", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        auto h = shield.health();
        return h.engines_total == 22 &&
               h.engines_running == 0 &&
               h.engines_stopped == 22 &&
               h.overall_score == 0.0;
    });

    register_test("shield_health_after_start", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        shield.start();
        auto h = shield.health();
        shield.stop();
        return h.engines_total == 22 &&
               h.engines_running >= 1 &&
               h.overall_score > 0.0;
    });

    register_test("shield_categories_cover_all_engines", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        shield.start();
        auto cats = shield.categories();
        size_t total = 0;
        for (auto& c : cats) total += c.engine_names.size();
        shield.stop();
        return total == 22;
    });

    register_test("shield_categorize_pmsr", [] {
        return gcad::GaloisShield::categorize("PMSR") == gcad::EngineCategory::MEMORY_PROTECTION;
    });

    register_test("shield_categorize_firewall", [] {
        return gcad::GaloisShield::categorize("Firewall") == gcad::EngineCategory::NETWORK_SECURITY;
    });

    register_test("shield_categorize_ransomware", [] {
        return gcad::GaloisShield::categorize("RansomwareShield") == gcad::EngineCategory::FILE_PROTECTION;
    });

    register_test("shield_categorize_yara", [] {
        return gcad::GaloisShield::categorize("YARA") == gcad::EngineCategory::THREAT_ANALYSIS;
    });

    register_test("shield_category_labels", [] {
        return gcad::GaloisShield::category_label(gcad::EngineCategory::MEMORY_PROTECTION) == "Memory Protection" &&
               gcad::GaloisShield::category_label(gcad::EngineCategory::NETWORK_SECURITY) == "Network Security" &&
               gcad::GaloisShield::category_label(gcad::EngineCategory::SYSTEM_INTEGRITY) == "System Integrity";
    });

    register_test("shield_start_stop", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        auto rc1 = shield.start();
        auto h1 = shield.health();
        auto rc2 = shield.stop();
        auto h2 = shield.health();
        return rc1 == gcad::ErrorCode::OK && rc2 == gcad::ErrorCode::OK &&
               h1.engines_running > h2.engines_running;
    });

    register_test("shield_manager_ref", [] {
        gcad::EngineManager mgr;
        gcad::GaloisShield shield(mgr);
        return &shield.manager() == &mgr;
    });
}
