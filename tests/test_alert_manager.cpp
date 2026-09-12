#include "gcad/alert/alert_manager.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

gcad::ThreatEvent make_event(gcad::ThreatLevel level, gcad::ThreatCategory cat,
                              const std::string& desc) {
    gcad::ThreatEvent ev;
    ev.timestamp   = std::chrono::system_clock::now();
    ev.level       = level;
    ev.category    = cat;
    ev.description = desc;
    return ev;
}

} // namespace

void register_alert_manager_tests() {
    register_test("alert_manager_initial_state", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        if (am.total_count() != 0) return false;
        if (am.unacknowledged_count() != 0) return false;
        if (am.recent().size() != 0) return false;
        return true;
    });

    register_test("alert_manager_push_adds_to_history", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::MEDIUM, gcad::ThreatCategory::MEMORY_INJECTION,
                           "test injection"));
        if (am.total_count() != 1) return false;
        auto alerts = am.recent(10);
        if (alerts.size() != 1) return false;
        if (alerts[0].description != "test injection") return false;
        if (alerts[0].level != gcad::ThreatLevel::MEDIUM) return false;
        return true;
    });

    register_test("alert_manager_filters_below_min_level", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.set_min_level(gcad::ThreatLevel::HIGH);
        am.push(make_event(gcad::ThreatLevel::LOW, gcad::ThreatCategory::NONE, "low"));
        am.push(make_event(gcad::ThreatLevel::MEDIUM, gcad::ThreatCategory::NONE, "med"));
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "high"));
        if (am.total_count() != 1) return false;
        return am.recent(10)[0].description == "high";
    });

    register_test("alert_manager_recent_returns_limited", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        for (int i = 0; i < 10; ++i)
            am.push(make_event(gcad::ThreatLevel::MEDIUM, gcad::ThreatCategory::NONE,
                               "event_" + std::to_string(i)));
        auto r3 = am.recent(3);
        if (r3.size() != 3) return false;
        return r3[0].description == "event_7";
    });

    register_test("alert_manager_unacknowledged_count", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "a"));
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "b"));
        if (am.unacknowledged_count() != 2) return false;
        return true;
    });

    register_test("alert_manager_acknowledge_single", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "a"));
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "b"));
        auto alerts = am.recent(10);
        am.acknowledge(alerts[0].id);
        if (am.unacknowledged_count() != 1) return false;
        return true;
    });

    register_test("alert_manager_acknowledge_all", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "a"));
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "b"));
        am.acknowledge_all();
        if (am.unacknowledged_count() != 0) return false;
        return am.total_count() == 2;
    });

    register_test("alert_manager_clear", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "a"));
        am.clear();
        return am.total_count() == 0;
    });

    register_test("alert_manager_max_history_bounded", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        for (int i = 0; i < 510; ++i)
            am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE,
                               "e" + std::to_string(i)));
        return am.total_count() == 500;
    });

    register_test("alert_manager_category_source_mapping", [] {
        using C = gcad::ThreatCategory;
        if (std::string(gcad::AlertManager::category_source(C::MEMORY_INJECTION)) != "PMSR") return false;
        if (std::string(gcad::AlertManager::category_source(C::PROCESS_HOLLOW)) != "PMSR") return false;
        if (std::string(gcad::AlertManager::category_source(C::DNS_TUNNEL)) != "DnsMon") return false;
        if (std::string(gcad::AlertManager::category_source(C::RANSOMWARE)) != "ARHS") return false;
        if (std::string(gcad::AlertManager::category_source(C::NETWORK_SCAN)) != "ZRGP") return false;
        if (std::string(gcad::AlertManager::category_source(C::REGISTRY_TAMPER)) != "RegMon") return false;
        if (std::string(gcad::AlertManager::category_source(C::DIRECT_SYSCALL)) != "SyscallGuard") return false;
        if (std::string(gcad::AlertManager::category_source(C::FILE_INTEGRITY_VIOLATION)) != "FIM") return false;
        if (std::string(gcad::AlertManager::category_source(C::YARA_RULE_MATCH)) != "YARA") return false;
        if (std::string(gcad::AlertManager::category_source(C::DGA_DOMAIN)) != "DnsMon") return false;
        if (std::string(gcad::AlertManager::category_source(C::NONE)) != "GCAD") return false;
        return true;
    });

    register_test("alert_manager_source_field_populated", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::YARA_RULE_MATCH,
                           "yara match"));
        auto alerts = am.recent(1);
        return alerts.size() == 1 && alerts[0].source == "YARA";
    });

    register_test("alert_manager_settings_persist", [] {
        gcad::AlertManager am;
        am.set_sound_enabled(false);
        am.set_toast_enabled(false);
        am.set_min_level(gcad::ThreatLevel::CRITICAL);
        if (am.sound_enabled()) return false;
        if (am.toast_enabled()) return false;
        if (am.min_level() != gcad::ThreatLevel::CRITICAL) return false;
        return true;
    });

    register_test("alert_manager_default_min_level_is_low", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        if (am.min_level() != gcad::ThreatLevel::LOW) return false;
        am.push(make_event(gcad::ThreatLevel::SAFE, gcad::ThreatCategory::NONE, "safe"));
        return am.total_count() == 0;
    });

    register_test("alert_manager_concurrent_pushes", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        constexpr int N = 100;
        std::vector<std::thread> threads;
        threads.reserve(4);
        for (int t = 0; t < 4; ++t) {
            threads.emplace_back([&am, t] {
                for (int i = 0; i < N; ++i)
                    am.push(make_event(gcad::ThreatLevel::MEDIUM, gcad::ThreatCategory::NONE,
                                       "t" + std::to_string(t) + "_" + std::to_string(i)));
            });
        }
        for (auto& th : threads) th.join();
        return am.total_count() == 4 * N;
    });

    register_test("alert_manager_id_monotonic", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "a"));
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "b"));
        auto alerts = am.recent(10);
        if (alerts.size() != 2) return false;
        return alerts[1].id > alerts[0].id;
    });

    register_test("alert_manager_timestamp_populated", [] {
        gcad::AlertManager am;
        am.set_toast_enabled(false);
        am.set_sound_enabled(false);
        am.push(make_event(gcad::ThreatLevel::HIGH, gcad::ThreatCategory::NONE, "a"));
        auto alerts = am.recent(1);
        auto now = std::chrono::system_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - alerts[0].timestamp).count();
        return diff >= 0 && diff < 5;
    });
}
