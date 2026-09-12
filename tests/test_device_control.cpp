#include "gcad/engines/device_control_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_device_control_tests() {
    register_test("devctl_type_names", [] {
        for (int i = 0; i <= 7; ++i) {
            auto n = gcad::DeviceControlEngine::device_type_name(
                static_cast<gcad::DeviceType>(i));
            if (std::string(n) == "Unknown") return false;
        }
        return true;
    });

    register_test("devctl_action_names", [] {
        for (int i = 0; i <= 5; ++i) {
            auto n = gcad::DeviceControlEngine::action_name(
                static_cast<gcad::DeviceAction>(i));
            if (std::string(n) == "Unknown") return false;
        }
        return true;
    });

    register_test("devctl_policy_names", [] {
        for (int i = 0; i <= 3; ++i) {
            auto n = gcad::DeviceControlEngine::policy_name(
                static_cast<gcad::DevicePolicy>(i));
            if (std::string(n) == "Unknown") return false;
        }
        return true;
    });

    register_test("devctl_classify_hid", [] {
        return gcad::DeviceControlEngine::classify_device("046D", "C534")
               == gcad::DeviceType::DEV_USB_HID;
    });

    register_test("devctl_classify_network", [] {
        return gcad::DeviceControlEngine::classify_device("0BDA", "8153")
               == gcad::DeviceType::DEV_USB_NETWORK;
    });

    register_test("devctl_classify_storage_default", [] {
        return gcad::DeviceControlEngine::classify_device("ABCD", "1234")
               == gcad::DeviceType::DEV_USB_STORAGE;
    });

    register_test("devctl_classify_empty", [] {
        return gcad::DeviceControlEngine::classify_device("", "")
               == gcad::DeviceType::DEV_USB_OTHER;
    });

    register_test("devctl_default_policy_audit", [] {
        gcad::DeviceControlEngine engine;
        return engine.default_policy() == gcad::DevicePolicy::POL_AUDIT;
    });

    register_test("devctl_set_default_policy", [] {
        gcad::DeviceControlEngine engine;
        engine.set_default_policy(gcad::DevicePolicy::POL_BLOCK);
        return engine.default_policy() == gcad::DevicePolicy::POL_BLOCK;
    });

    register_test("devctl_evaluate_default", [] {
        gcad::DeviceControlEngine engine;
        gcad::DeviceInfo dev;
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        return engine.evaluate_policy(dev) == gcad::DevicePolicy::POL_AUDIT;
    });

    register_test("devctl_whitelist_overrides", [] {
        gcad::DeviceControlEngine engine;
        engine.set_default_policy(gcad::DevicePolicy::POL_BLOCK);
        engine.whitelist_device("SN12345");
        gcad::DeviceInfo dev;
        dev.serial_number = "SN12345";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        return engine.evaluate_policy(dev) == gcad::DevicePolicy::POL_ALLOW;
    });

    register_test("devctl_blacklist_overrides", [] {
        gcad::DeviceControlEngine engine;
        engine.set_default_policy(gcad::DevicePolicy::POL_ALLOW);
        engine.blacklist_device("SN99999");
        gcad::DeviceInfo dev;
        dev.serial_number = "SN99999";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        return engine.evaluate_policy(dev) == gcad::DevicePolicy::POL_BLOCK;
    });

    register_test("devctl_blacklist_removes_whitelist", [] {
        gcad::DeviceControlEngine engine;
        engine.whitelist_device("SN111");
        engine.blacklist_device("SN111");
        gcad::DeviceInfo dev;
        dev.serial_number = "SN111";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        return engine.evaluate_policy(dev) == gcad::DevicePolicy::POL_BLOCK;
    });

    register_test("devctl_rule_match", [] {
        gcad::DeviceControlEngine engine;
        gcad::DeviceRule rule;
        rule.rule_id = "R1";
        rule.device_type = gcad::DeviceType::DEV_USB_STORAGE;
        rule.policy = gcad::DevicePolicy::POL_READ_ONLY;
        engine.add_rule(rule);

        gcad::DeviceInfo dev;
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        return engine.evaluate_policy(dev) == gcad::DevicePolicy::POL_READ_ONLY;
    });

    register_test("devctl_rule_vendor_filter", [] {
        gcad::DeviceControlEngine engine;
        gcad::DeviceRule rule;
        rule.rule_id = "R2";
        rule.device_type = gcad::DeviceType::DEV_USB_STORAGE;
        rule.vendor_id = "EVIL";
        rule.policy = gcad::DevicePolicy::POL_BLOCK;
        engine.add_rule(rule);

        gcad::DeviceInfo good;
        good.type = gcad::DeviceType::DEV_USB_STORAGE;
        good.vendor_id = "GOOD";

        gcad::DeviceInfo bad;
        bad.type = gcad::DeviceType::DEV_USB_STORAGE;
        bad.vendor_id = "EVIL";

        return engine.evaluate_policy(good) == gcad::DevicePolicy::POL_AUDIT &&
               engine.evaluate_policy(bad) == gcad::DevicePolicy::POL_BLOCK;
    });

    register_test("devctl_remove_rule", [] {
        gcad::DeviceControlEngine engine;
        gcad::DeviceRule rule;
        rule.rule_id = "R3";
        rule.device_type = gcad::DeviceType::DEV_USB_STORAGE;
        rule.policy = gcad::DevicePolicy::POL_BLOCK;
        engine.add_rule(rule);
        engine.remove_rule("R3");
        return engine.rules().empty();
    });

    register_test("devctl_report_event_tracks", [] {
        gcad::DeviceControlEngine engine;
        gcad::DeviceInfo dev;
        dev.device_id = "USB001";
        dev.friendly_name = "SanDisk Ultra";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        engine.report_device_event(dev, gcad::DeviceAction::ACT_CONNECTED);
        auto events = engine.recent_events();
        return events.size() == 1 && events[0].device.device_id == "USB001";
    });

    register_test("devctl_connected_tracked", [] {
        gcad::DeviceControlEngine engine;
        gcad::DeviceInfo dev;
        dev.device_id = "USB002";
        dev.friendly_name = "Kingston";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        engine.report_device_event(dev, gcad::DeviceAction::ACT_CONNECTED);
        auto connected = engine.connected_devices();
        if (connected.size() != 1) return false;
        engine.report_device_event(dev, gcad::DeviceAction::ACT_DISCONNECTED);
        connected = engine.connected_devices();
        return connected.empty();
    });

    register_test("devctl_block_fires_threat", [] {
        gcad::DeviceControlEngine engine;
        engine.set_default_policy(gcad::DevicePolicy::POL_BLOCK);
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            fired = ev.level >= gcad::ThreatLevel::HIGH;
        });
        gcad::DeviceInfo dev;
        dev.device_id = "USB003";
        dev.friendly_name = "BadUSB";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        engine.report_device_event(dev, gcad::DeviceAction::ACT_CONNECTED);
        return fired;
    });

    register_test("devctl_readonly_blocks_write", [] {
        gcad::DeviceControlEngine engine;
        engine.set_default_policy(gcad::DevicePolicy::POL_READ_ONLY);
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent) { fired = true; });
        gcad::DeviceInfo dev;
        dev.device_id = "USB004";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        engine.report_device_event(dev, gcad::DeviceAction::ACT_WRITE, "secret.docx");
        return fired;
    });

    register_test("devctl_readonly_allows_read", [] {
        gcad::DeviceControlEngine engine;
        engine.set_default_policy(gcad::DevicePolicy::POL_READ_ONLY);
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent) { fired = true; });
        gcad::DeviceInfo dev;
        dev.device_id = "USB005";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        engine.report_device_event(dev, gcad::DeviceAction::ACT_READ, "readme.txt");
        return !fired;
    });

    register_test("devctl_audit_no_threat", [] {
        gcad::DeviceControlEngine engine;
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent) { fired = true; });
        gcad::DeviceInfo dev;
        dev.device_id = "USB006";
        dev.type = gcad::DeviceType::DEV_USB_STORAGE;
        engine.report_device_event(dev, gcad::DeviceAction::ACT_CONNECTED);
        return !fired;
    });

    register_test("devctl_event_ids_unique", [] {
        gcad::DeviceControlEngine engine;
        for (int i = 0; i < 5; ++i) {
            gcad::DeviceInfo dev;
            dev.device_id = "DEV" + std::to_string(i);
            dev.type = gcad::DeviceType::DEV_USB_STORAGE;
            engine.report_device_event(dev, gcad::DeviceAction::ACT_CONNECTED);
        }
        auto events = engine.recent_events();
        std::unordered_map<uint64_t, int> ids;
        for (const auto& ev : events) ++ids[ev.id];
        for (const auto& [id, count] : ids)
            if (count > 1) return false;
        return true;
    });

    register_test("devctl_start_stop", [] {
        gcad::DeviceControlEngine engine;
        if (engine.running()) return false;
        engine.start();
        if (!engine.running()) return false;
        auto s = engine.status();
        if (s.name != "DeviceControl") return false;
        engine.stop();
        return !engine.running();
    });
}
