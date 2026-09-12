#include "gcad/engines/firewall_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_firewall_engine_tests() {
    register_test("firewall_parse_ipv4_valid", [] {
        auto ip = gcad::FirewallEngine::parse_ipv4("192.168.1.100");
        return ip == ((192u << 24) | (168u << 16) | (1u << 8) | 100u);
    });

    register_test("firewall_parse_ipv4_zero", [] {
        return gcad::FirewallEngine::parse_ipv4("0.0.0.0") == 0;
    });

    register_test("firewall_parse_ipv4_max", [] {
        return gcad::FirewallEngine::parse_ipv4("255.255.255.255") == 0xFFFFFFFF;
    });

    register_test("firewall_parse_ipv4_invalid", [] {
        return gcad::FirewallEngine::parse_ipv4("999.1.2.3") == 0
            && gcad::FirewallEngine::parse_ipv4("abc") == 0
            && gcad::FirewallEngine::parse_ipv4("1.2.3") == 0;
    });

    register_test("firewall_ip_to_string", [] {
        auto s = gcad::FirewallEngine::ip_to_string((10u << 24) | (0u << 16) | (0u << 8) | 1u);
        return s == "10.0.0.1";
    });

    register_test("firewall_cidr_to_mask", [] {
        return gcad::FirewallEngine::cidr_to_mask(24) == 0xFFFFFF00
            && gcad::FirewallEngine::cidr_to_mask(32) == 0xFFFFFFFF
            && gcad::FirewallEngine::cidr_to_mask(0)  == 0
            && gcad::FirewallEngine::cidr_to_mask(16) == 0xFFFF0000;
    });

    register_test("firewall_add_remove_rule", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "test rule";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::TCP;
        r.port_min = 8080;
        r.port_max = 8080;
        auto id = fw.add_rule(r);
        if (id == 0) return false;
        auto rules = fw.rules();
        if (rules.empty()) return false;
        bool found = false;
        for (auto& rule : rules) if (rule.id == id) found = true;
        if (!found) return false;
        if (!fw.remove_rule(id)) return false;
        rules = fw.rules();
        for (auto& rule : rules) if (rule.id == id) return false;
        return true;
    });

    register_test("firewall_enable_disable_rule", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "toggle";
        r.action = gcad::FirewallAction::DENY;
        auto id = fw.add_rule(r);
        if (!fw.enable_rule(id, false)) return false;
        auto rules = fw.rules();
        for (auto& rule : rules) {
            if (rule.id == id && rule.enabled) return false;
        }
        if (!fw.enable_rule(id, true)) return false;
        return true;
    });

    register_test("firewall_evaluate_deny_port", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny 4444";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::TCP;
        r.port_min = 4444;
        r.port_max = 4444;
        fw.add_rule(r);

        auto result = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP,
                                   0x0A000001, 0xC0A80101, 12345, 4444);
        return result == gcad::FirewallAction::DENY;
    });

    register_test("firewall_evaluate_allow_no_match", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny 4444";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::TCP;
        r.port_min = 4444;
        r.port_max = 4444;
        fw.add_rule(r);

        auto result = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP,
                                   0x0A000001, 0xC0A80101, 12345, 80);
        return result == gcad::FirewallAction::ALLOW;
    });

    register_test("firewall_evaluate_ip_mask", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny 10.0.0.0/8 inbound";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::ANY;
        r.src_ip = gcad::FirewallEngine::parse_ipv4("10.0.0.0");
        r.src_mask = gcad::FirewallEngine::cidr_to_mask(8);
        fw.add_rule(r);

        auto deny = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP,
                                 gcad::FirewallEngine::parse_ipv4("10.1.2.3"), 0xC0A80101, 80, 443);
        auto allow = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP,
                                  gcad::FirewallEngine::parse_ipv4("192.168.1.1"), 0xC0A80101, 80, 443);
        return deny == gcad::FirewallAction::DENY && allow == gcad::FirewallAction::ALLOW;
    });

    register_test("firewall_evaluate_direction_mismatch", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny inbound only";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::TCP;
        r.port_min = 80;
        r.port_max = 80;
        fw.add_rule(r);

        auto result = fw.evaluate(gcad::FirewallDirection::OUTBOUND, gcad::FirewallProto::TCP,
                                   0x0A000001, 0xC0A80101, 80, 80);
        return result == gcad::FirewallAction::ALLOW;
    });

    register_test("firewall_evaluate_proto_mismatch", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny TCP 80";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::TCP;
        r.port_min = 80;
        r.port_max = 80;
        fw.add_rule(r);

        auto result = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::UDP,
                                   0x0A000001, 0xC0A80101, 12345, 80);
        return result == gcad::FirewallAction::ALLOW;
    });

    register_test("firewall_priority_ordering", [] {
        gcad::FirewallEngine fw;

        gcad::FirewallRule deny_all;
        deny_all.label = "deny all";
        deny_all.direction = gcad::FirewallDirection::INBOUND;
        deny_all.action = gcad::FirewallAction::DENY;
        deny_all.priority = 100;
        fw.add_rule(deny_all);

        gcad::FirewallRule allow_443;
        allow_443.label = "allow 443";
        allow_443.direction = gcad::FirewallDirection::INBOUND;
        allow_443.action = gcad::FirewallAction::ALLOW;
        allow_443.protocol = gcad::FirewallProto::TCP;
        allow_443.port_min = 443;
        allow_443.port_max = 443;
        allow_443.priority = 10;
        fw.add_rule(allow_443);

        auto r443 = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP,
                                 0x0A000001, 0xC0A80101, 12345, 443);
        auto r80 = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP,
                                0x0A000001, 0xC0A80101, 12345, 80);
        return r443 == gcad::FirewallAction::ALLOW && r80 == gcad::FirewallAction::DENY;
    });

    register_test("firewall_connection_log", [] {
        gcad::FirewallEngine fw;
        gcad::ConnectionLog c;
        c.src_ip = 0x0A000001;
        c.dst_ip = 0xC0A80101;
        c.src_port = 12345;
        c.dst_port = 80;
        c.protocol = gcad::FirewallProto::TCP;
        c.timestamp = std::chrono::system_clock::now();
        fw.log_connection(c);

        auto recent = fw.recent_connections(10);
        if (recent.size() != 1) return false;
        return recent[0].src_ip == 0x0A000001 && recent[0].dst_port == 80;
    });

    register_test("firewall_connection_log_bounded", [] {
        gcad::FirewallEngine fw;
        for (size_t i = 0; i < gcad::FirewallEngine::MAX_CONNECTION_LOG + 100; ++i) {
            gcad::ConnectionLog c;
            c.src_ip = static_cast<uint32_t>(i);
            c.timestamp = std::chrono::system_clock::now();
            fw.log_connection(c);
        }
        auto recent = fw.recent_connections(gcad::FirewallEngine::MAX_CONNECTION_LOG + 100);
        return recent.size() == gcad::FirewallEngine::MAX_CONNECTION_LOG;
    });

    register_test("firewall_suspicious_port_scan", [] {
        gcad::FirewallEngine fw;
        uint32_t attacker = gcad::FirewallEngine::parse_ipv4("10.0.0.99");
        for (uint16_t port = 1; port <= 25; ++port) {
            gcad::ConnectionLog c;
            c.src_ip = attacker;
            c.dst_ip = gcad::FirewallEngine::parse_ipv4("192.168.1.1");
            c.dst_port = port;
            c.direction = gcad::FirewallDirection::INBOUND;
            c.action_taken = gcad::FirewallAction::DENY;
            c.timestamp = std::chrono::system_clock::now();
            fw.log_connection(c);
        }
        auto suspects = fw.suspicious_candidates();
        if (suspects.empty()) return false;
        bool found = false;
        for (auto& s : suspects) {
            if (s.ip == attacker && s.suspected_category == gcad::ThreatCategory::NETWORK_SCAN)
                found = true;
        }
        return found;
    });

    register_test("firewall_suspicious_flood", [] {
        gcad::FirewallEngine fw;
        uint32_t attacker = gcad::FirewallEngine::parse_ipv4("10.0.0.50");
        for (size_t i = 0; i < gcad::FirewallEngine::FLOOD_THRESHOLD + 10; ++i) {
            gcad::ConnectionLog c;
            c.src_ip = attacker;
            c.dst_ip = gcad::FirewallEngine::parse_ipv4("192.168.1.1");
            c.dst_port = 80;
            c.direction = gcad::FirewallDirection::INBOUND;
            c.timestamp = std::chrono::system_clock::now();
            fw.log_connection(c);
        }
        auto suspects = fw.suspicious_candidates();
        bool found = false;
        for (auto& s : suspects) {
            if (s.ip == attacker && s.suspected_category == gcad::ThreatCategory::SYN_FLOOD)
                found = true;
        }
        return found;
    });

    register_test("firewall_counters", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny 4444";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::TCP;
        r.port_min = 4444;
        r.port_max = 4444;
        fw.add_rule(r);

        fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 4444);
        fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 80);
        fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 4444);

        return fw.total_denied() == 2 && fw.total_allowed() == 1;
    });

    register_test("firewall_disabled_rule_skipped", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny all";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        auto id = fw.add_rule(r);
        fw.enable_rule(id, false);

        auto result = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP,
                                   0, 0, 0, 80);
        return result == gcad::FirewallAction::ALLOW;
    });

    register_test("firewall_start_stop", [] {
        gcad::FirewallEngine fw;
        if (fw.running()) return false;
        fw.start();
        if (!fw.running()) return false;
        auto s = fw.status();
        if (s.name != "Firewall") return false;
        if (!s.running) return false;
        fw.stop();
        return !fw.running();
    });

    register_test("firewall_default_rules_installed", [] {
        gcad::FirewallEngine fw;
        fw.start();
        auto rules = fw.rules();
        fw.stop();
        return rules.size() >= 5;
    });

    register_test("firewall_threat_callback", [] {
        gcad::FirewallEngine fw;
        bool called = false;
        gcad::ThreatCategory received_cat{};
        fw.on_threat([&](gcad::ThreatEvent ev) {
            called = true;
            received_cat = ev.category;
        });

        uint32_t attacker = gcad::FirewallEngine::parse_ipv4("10.0.0.50");
        for (size_t i = 0; i < gcad::FirewallEngine::FLOOD_THRESHOLD + 10; ++i) {
            gcad::ConnectionLog c;
            c.src_ip = attacker;
            c.dst_port = 80;
            c.direction = gcad::FirewallDirection::INBOUND;
            c.timestamp = std::chrono::system_clock::now();
            fw.log_connection(c);
        }

        fw.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(6000));
        fw.stop();

        return called && received_cat == gcad::ThreatCategory::SYN_FLOOD;
    });

    register_test("firewall_remove_nonexistent", [] {
        gcad::FirewallEngine fw;
        return !fw.remove_rule(99999);
    });

    register_test("firewall_port_range", [] {
        gcad::FirewallEngine fw;
        gcad::FirewallRule r;
        r.label = "deny 8000-9000";
        r.direction = gcad::FirewallDirection::INBOUND;
        r.action = gcad::FirewallAction::DENY;
        r.protocol = gcad::FirewallProto::TCP;
        r.port_min = 8000;
        r.port_max = 9000;
        fw.add_rule(r);

        auto d1 = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 8500);
        auto d2 = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 8000);
        auto d3 = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 9000);
        auto a1 = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 7999);
        auto a2 = fw.evaluate(gcad::FirewallDirection::INBOUND, gcad::FirewallProto::TCP, 0, 0, 0, 9001);

        return d1 == gcad::FirewallAction::DENY && d2 == gcad::FirewallAction::DENY
            && d3 == gcad::FirewallAction::DENY && a1 == gcad::FirewallAction::ALLOW
            && a2 == gcad::FirewallAction::ALLOW;
    });
}
