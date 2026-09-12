#include "gcad/engines/network_dpi_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_network_dpi_tests() {
    register_test("dpi_classify_http", [] {
        return gcad::NetworkDpiEngine::classify_port(80) == gcad::DpiProtocol::PROTO_HTTP;
    });

    register_test("dpi_classify_https", [] {
        return gcad::NetworkDpiEngine::classify_port(443) == gcad::DpiProtocol::PROTO_HTTPS;
    });

    register_test("dpi_classify_dns", [] {
        return gcad::NetworkDpiEngine::classify_port(53) == gcad::DpiProtocol::PROTO_DNS;
    });

    register_test("dpi_classify_ssh", [] {
        return gcad::NetworkDpiEngine::classify_port(22) == gcad::DpiProtocol::PROTO_SSH;
    });

    register_test("dpi_classify_rdp", [] {
        return gcad::NetworkDpiEngine::classify_port(3389) == gcad::DpiProtocol::PROTO_RDP;
    });

    register_test("dpi_classify_smb", [] {
        return gcad::NetworkDpiEngine::classify_port(445) == gcad::DpiProtocol::PROTO_SMB;
    });

    register_test("dpi_classify_irc", [] {
        return gcad::NetworkDpiEngine::classify_port(6667) == gcad::DpiProtocol::PROTO_IRC;
    });

    register_test("dpi_classify_unknown", [] {
        return gcad::NetworkDpiEngine::classify_port(12345) == gcad::DpiProtocol::PROTO_UNKNOWN;
    });

    register_test("dpi_suspicious_ua_python", [] {
        return gcad::NetworkDpiEngine::is_suspicious_user_agent("python-requests/2.31.0");
    });

    register_test("dpi_suspicious_ua_cobalt", [] {
        return gcad::NetworkDpiEngine::is_suspicious_user_agent("Mozilla/5.0 cobalt strike beacon");
    });

    register_test("dpi_normal_ua", [] {
        return !gcad::NetworkDpiEngine::is_suspicious_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    });

    register_test("dpi_suspicious_ua_empty", [] {
        return !gcad::NetworkDpiEngine::is_suspicious_user_agent("");
    });

    register_test("dpi_suspicious_uri_cmd", [] {
        return gcad::NetworkDpiEngine::is_suspicious_uri("/api/shell?cmd=whoami");
    });

    register_test("dpi_suspicious_uri_traversal", [] {
        return gcad::NetworkDpiEngine::is_suspicious_uri("/files/..%2f..%2fetc/passwd");
    });

    register_test("dpi_normal_uri", [] {
        return !gcad::NetworkDpiEngine::is_suspicious_uri("/api/v1/users/123");
    });

    register_test("dpi_c2_port_4444", [] {
        return gcad::NetworkDpiEngine::is_known_c2_port(4444);
    });

    register_test("dpi_c2_port_31337", [] {
        return gcad::NetworkDpiEngine::is_known_c2_port(31337);
    });

    register_test("dpi_not_c2_port", [] {
        return !gcad::NetworkDpiEngine::is_known_c2_port(80) &&
               !gcad::NetworkDpiEngine::is_known_c2_port(443);
    });

    register_test("dpi_beacon_score_regular", [] {
        double score = gcad::NetworkDpiEngine::compute_beacon_score(60000.0, 100.0, 20);
        return score >= gcad::NetworkDpiEngine::BEACON_SCORE_THRESHOLD;
    });

    register_test("dpi_beacon_score_irregular", [] {
        double score = gcad::NetworkDpiEngine::compute_beacon_score(60000.0, 55000.0, 5);
        return score < gcad::NetworkDpiEngine::BEACON_SCORE_THRESHOLD;
    });

    register_test("dpi_beacon_score_too_few", [] {
        double score = gcad::NetworkDpiEngine::compute_beacon_score(60000.0, 100.0, 2);
        return score == 0.0;
    });

    register_test("dpi_inspect_c2_port_alert", [] {
        gcad::NetworkDpiEngine engine;
        gcad::PacketMeta pkt;
        pkt.src_ip = "192.168.1.100";
        pkt.dst_ip = "10.0.0.1";
        pkt.dst_port = 4444;
        pkt.timestamp = std::chrono::system_clock::now();
        engine.inspect_packet(pkt);
        auto alerts = engine.recent_alerts();
        return !alerts.empty() &&
               alerts.back().rule_name == "KNOWN_C2_PORT";
    });

    register_test("dpi_inspect_suspicious_ua", [] {
        gcad::NetworkDpiEngine engine;
        gcad::PacketMeta pkt;
        pkt.src_ip = "192.168.1.100";
        pkt.dst_ip = "evil.com";
        pkt.dst_port = 80;
        pkt.user_agent = "python-requests/2.31.0";
        pkt.timestamp = std::chrono::system_clock::now();
        engine.inspect_packet(pkt);
        auto alerts = engine.recent_alerts();
        bool found = false;
        for (const auto& a : alerts)
            if (a.rule_name == "SUSPICIOUS_USER_AGENT") found = true;
        return found;
    });

    register_test("dpi_inspect_tls_self_signed", [] {
        gcad::NetworkDpiEngine engine;
        gcad::PacketMeta pkt;
        pkt.dst_ip = "10.0.0.5";
        pkt.dst_port = 443;
        pkt.tls_self_signed = true;
        pkt.tls_subject = "CN=evil.local";
        pkt.timestamp = std::chrono::system_clock::now();
        engine.inspect_packet(pkt);
        auto alerts = engine.recent_alerts();
        bool found = false;
        for (const auto& a : alerts)
            if (a.rule_name == "TLS_SELF_SIGNED") found = true;
        return found;
    });

    register_test("dpi_inspect_fires_threat_on_high", [] {
        gcad::NetworkDpiEngine engine;
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent) { fired = true; });
        gcad::PacketMeta pkt;
        pkt.dst_ip = "10.0.0.1";
        pkt.dst_port = 80;
        pkt.uri = "/cgi-bin/shell?cmd=ls";
        pkt.timestamp = std::chrono::system_clock::now();
        engine.inspect_packet(pkt);
        return fired;
    });

    register_test("dpi_clean_packet_no_alert", [] {
        gcad::NetworkDpiEngine engine;
        gcad::PacketMeta pkt;
        pkt.src_ip = "192.168.1.100";
        pkt.dst_ip = "google.com";
        pkt.dst_port = 443;
        pkt.payload_size = 100;
        pkt.payload_entropy = 3.5;
        pkt.timestamp = std::chrono::system_clock::now();
        engine.inspect_packet(pkt);
        auto alerts = engine.recent_alerts();
        return alerts.empty();
    });

    register_test("dpi_alert_ids_unique", [] {
        gcad::NetworkDpiEngine engine;
        auto now = std::chrono::system_clock::now();
        for (int i = 0; i < 3; ++i) {
            gcad::PacketMeta pkt;
            pkt.dst_ip = "10.0.0." + std::to_string(i);
            pkt.dst_port = 4444;
            pkt.timestamp = now;
            engine.inspect_packet(pkt);
        }
        auto alerts = engine.recent_alerts();
        std::unordered_map<uint64_t, int> ids;
        for (const auto& a : alerts) ++ids[a.id];
        for (const auto& [id, count] : ids)
            if (count > 1) return false;
        return true;
    });

    register_test("dpi_irc_alert", [] {
        gcad::NetworkDpiEngine engine;
        gcad::PacketMeta pkt;
        pkt.dst_ip = "irc.evil.net";
        pkt.dst_port = 6667;
        pkt.protocol = gcad::DpiProtocol::PROTO_IRC;
        pkt.timestamp = std::chrono::system_clock::now();
        engine.inspect_packet(pkt);
        auto alerts = engine.recent_alerts();
        bool found = false;
        for (const auto& a : alerts)
            if (a.rule_name == "IRC_CONNECTION") found = true;
        return found;
    });

    register_test("dpi_dns_oversized", [] {
        gcad::NetworkDpiEngine engine;
        gcad::PacketMeta pkt;
        pkt.dst_ip = "8.8.8.8";
        pkt.dst_port = 53;
        pkt.protocol = gcad::DpiProtocol::PROTO_DNS;
        pkt.payload_size = 1024;
        pkt.timestamp = std::chrono::system_clock::now();
        engine.inspect_packet(pkt);
        auto alerts = engine.recent_alerts();
        bool found = false;
        for (const auto& a : alerts)
            if (a.rule_name == "DNS_LARGE_PAYLOAD") found = true;
        return found;
    });

    register_test("dpi_start_stop", [] {
        gcad::NetworkDpiEngine engine;
        if (engine.running()) return false;
        engine.start();
        if (!engine.running()) return false;
        auto s = engine.status();
        if (s.name != "NetworkDPI") return false;
        engine.stop();
        return !engine.running();
    });
}
