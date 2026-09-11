#include "gcad/common.hpp"
#include "gcad/engines/dns_monitor_engine.hpp"
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_dns_monitor_tests() {
    register_test("dnsmon_name", [] {
        gcad::DnsMonitorEngine engine;
        return engine.name() == "DnsMon";
    });

    register_test("dnsmon_initial_state", [] {
        gcad::DnsMonitorEngine engine;
        if (engine.running()) return false;
        auto s = engine.status();
        if (s.running) return false;
        if (s.events_processed != 0) return false;
        if (s.threats_detected != 0) return false;
        return true;
    });

    register_test("dnsmon_status_name", [] {
        gcad::DnsMonitorEngine engine;
        auto s = engine.status();
        return s.name == "DnsMon";
    });

    register_test("dnsmon_blocklist_populated", [] {
        gcad::DnsMonitorEngine engine;
        return engine.blocklist().size() >= 10;
    });

    register_test("dnsmon_dga_score_normal", [] {
        double score = gcad::DnsMonitorEngine::dga_score("google.com");
        return score < 0.50;
    });

    register_test("dnsmon_dga_score_suspicious", [] {
        double score = gcad::DnsMonitorEngine::dga_score("xkrjfqpzblmw.com");
        return score >= 0.60;
    });

    register_test("dnsmon_dga_score_short_label", [] {
        double score = gcad::DnsMonitorEngine::dga_score("ab.com");
        return score == 0.0;
    });

    register_test("dnsmon_dga_score_numeric_heavy", [] {
        double score = gcad::DnsMonitorEngine::dga_score("a1b2c3d4e5f6g7h8.com");
        return score > 0.40;
    });

    register_test("dnsmon_parse_dns_query_valid", [] {
        uint8_t packet[] = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x06, 'g', 'o', 'o', 'g', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,
            0x00, 0x01, 0x00, 0x01
        };
        std::string domain;
        uint16_t qtype = 0;
        bool ok = gcad::DnsMonitorEngine::parse_dns_query(packet, sizeof(packet), domain, qtype);
        if (!ok) return false;
        if (domain != "google.com") return false;
        if (qtype != 1) return false;
        return true;
    });

    register_test("dnsmon_parse_dns_query_too_short", [] {
        uint8_t packet[8] = {};
        std::string domain;
        uint16_t qtype = 0;
        return !gcad::DnsMonitorEngine::parse_dns_query(packet, sizeof(packet), domain, qtype);
    });

    register_test("dnsmon_parse_dns_query_zero_qdcount", [] {
        uint8_t packet[12] = {};
        std::string domain;
        uint16_t qtype = 0;
        return !gcad::DnsMonitorEngine::parse_dns_query(packet, sizeof(packet), domain, qtype);
    });

    register_test("dnsmon_parse_dns_query_compressed", [] {
        uint8_t packet[] = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01
        };
        std::string domain;
        uint16_t qtype = 0;
        return !gcad::DnsMonitorEngine::parse_dns_query(packet, sizeof(packet), domain, qtype);
    });

    register_test("dnsmon_analyze_blocked_domain", [] {
        gcad::DnsMonitorEngine engine;
        bool threat_called = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            if (ev.category == gcad::ThreatCategory::DNS_TUNNEL) threat_called = true;
        });
        engine.analyze_domain("malware-c2.com");
        if (!threat_called) return false;
        auto queries = engine.recent_queries(10);
        if (queries.empty()) return false;
        if (!queries.back().blocked) return false;
        return true;
    });

    register_test("dnsmon_analyze_normal_domain", [] {
        gcad::DnsMonitorEngine engine;
        bool threat_called = false;
        engine.on_threat([&](gcad::ThreatEvent) { threat_called = true; });
        engine.analyze_domain("google.com");
        if (threat_called) return false;
        auto queries = engine.recent_queries(10);
        if (queries.empty()) return false;
        if (queries.back().blocked) return false;
        return true;
    });

    register_test("dnsmon_recent_queries_limit", [] {
        gcad::DnsMonitorEngine engine;
        for (int i = 0; i < 10; ++i)
            engine.analyze_domain("test" + std::to_string(i) + ".example.com");
        auto q5 = engine.recent_queries(5);
        return q5.size() == 5;
    });

    register_test("dnsmon_start_stop", [] {
        gcad::DnsMonitorEngine engine;
        auto rc = engine.start();
        if (rc != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        rc = engine.stop();
        if (rc != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("dnsmon_double_start", [] {
        gcad::DnsMonitorEngine engine;
        engine.start();
        auto rc = engine.start();
        engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("dnsmon_observation_callback", [] {
        gcad::DnsMonitorEngine engine;
        bool obs_called = false;
        engine.on_observation([&](gcad::security::SecurityObservation obs) {
            if (obs.kind == gcad::security::ObservationKind::DNS_ANOMALY) obs_called = true;
        });
        engine.analyze_domain("malware-c2.com");
        return obs_called;
    });
}
