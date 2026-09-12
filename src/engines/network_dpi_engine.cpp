#include "gcad/engines/network_dpi_engine.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>

namespace gcad {

static const std::vector<std::string> suspicious_agents = {
    "python-requests", "go-http-client", "wget", "curl",
    "powershell", "certutil", "bitsadmin",
    "cobalt", "beacon", "meterpreter",
    "empire", "covenant", "sliver",
};

static const std::vector<std::string> suspicious_uri_patterns = {
    "/admin/upload", "/shell", "/cmd", "/exec",
    "/c2/", "/beacon/", "/implant/",
    "..%2f", "..%5c", "%00",
    "/wp-admin/admin-ajax.php?action=",
    ".php?cmd=", ".asp?exec=", ".jsp?cmd=",
    "/cgi-bin/", "eval(", "base64,",
};

static const std::vector<uint16_t> known_c2_ports = {
    4444, 5555, 8443, 8888, 9999,
    1337, 31337, 6666, 6667, 6668, 6669,
    4443, 2222, 3333, 7777,
    50050, 50051,
};

NetworkDpiEngine::NetworkDpiEngine() = default;
NetworkDpiEngine::~NetworkDpiEngine() { stop(); }

ErrorCode NetworkDpiEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&NetworkDpiEngine::monitor_loop, this);
    GCAD_LOG(INFO, "NetworkDPI engine started");
    return ErrorCode::OK;
}

ErrorCode NetworkDpiEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus NetworkDpiEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void NetworkDpiEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void NetworkDpiEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

DpiProtocol NetworkDpiEngine::classify_port(uint16_t port) {
    switch (port) {
        case 80:    return DpiProtocol::PROTO_HTTP;
        case 443:
        case 8443:  return DpiProtocol::PROTO_HTTPS;
        case 53:    return DpiProtocol::PROTO_DNS;
        case 25:
        case 587:
        case 465:   return DpiProtocol::PROTO_SMTP;
        case 21:    return DpiProtocol::PROTO_FTP;
        case 22:    return DpiProtocol::PROTO_SSH;
        case 3389:  return DpiProtocol::PROTO_RDP;
        case 445:
        case 139:   return DpiProtocol::PROTO_SMB;
        case 6667:
        case 6668:
        case 6669:  return DpiProtocol::PROTO_IRC;
        default:    return DpiProtocol::PROTO_UNKNOWN;
    }
}

bool NetworkDpiEngine::is_suspicious_user_agent(const std::string& ua) {
    if (ua.empty()) return false;
    std::string lower = ua;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return std::any_of(suspicious_agents.begin(), suspicious_agents.end(),
                       [&lower](const std::string& s) {
                           return lower.find(s) != std::string::npos;
                       });
}

bool NetworkDpiEngine::is_suspicious_uri(const std::string& uri) {
    if (uri.empty()) return false;
    std::string lower = uri;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return std::any_of(suspicious_uri_patterns.begin(), suspicious_uri_patterns.end(),
                       [&lower](const std::string& p) {
                           return lower.find(p) != std::string::npos;
                       });
}

bool NetworkDpiEngine::is_known_c2_port(uint16_t port) {
    return std::find(known_c2_ports.begin(), known_c2_ports.end(), port)
           != known_c2_ports.end();
}

double NetworkDpiEngine::compute_beacon_score(double interval_mean_ms,
                                               double interval_stddev_ms,
                                               size_t count) {
    if (count < BEACON_MIN_CONNECTIONS || interval_mean_ms <= 0.0)
        return 0.0;

    double jitter = (interval_mean_ms > 0.0)
                    ? interval_stddev_ms / interval_mean_ms
                    : 1.0;

    double regularity = std::max(0.0, 1.0 - jitter);
    double count_factor = std::min(1.0, static_cast<double>(count) / 20.0);

    return std::clamp(regularity * 0.7 + count_factor * 0.3, 0.0, 1.0);
}

void NetworkDpiEngine::inspect_packet(const PacketMeta& pkt) {
    events_processed_.fetch_add(1);

    {
        std::lock_guard lk(mtx_);
        PacketMeta stored = pkt;
        stored.id = next_id_.fetch_add(1);
        packets_.push_back(stored);
        while (packets_.size() > MAX_PACKETS) packets_.pop_front();

        auto key = conn_key(pkt.dst_ip, pkt.dst_port);
        auto& timeline = conn_timelines_[key];
        timeline.dst_ip = pkt.dst_ip;
        timeline.dst_port = pkt.dst_port;
        timeline.timestamps.push_back(pkt.timestamp);
        while (timeline.timestamps.size() > 200)
            timeline.timestamps.pop_front();
    }

    check_protocol_anomalies(pkt);
    check_tls_anomalies(pkt);

    if (pkt.payload_entropy >= HIGH_ENTROPY_THRESHOLD &&
        pkt.payload_size > 256) {
        add_alert(DpiVerdict::SUSPICIOUS, ThreatLevel::MEDIUM,
                  "HIGH_ENTROPY_PAYLOAD",
                  "High entropy payload (" +
                  std::to_string(static_cast<int>(pkt.payload_entropy * 100) / 100) +
                  " bits) to " + pkt.dst_ip + ":" + std::to_string(pkt.dst_port),
                  pkt);
    }

    if (is_known_c2_port(pkt.dst_port)) {
        add_alert(DpiVerdict::SUSPICIOUS, ThreatLevel::MEDIUM,
                  "KNOWN_C2_PORT",
                  "Connection to known C2 port " + pkt.dst_ip + ":" +
                  std::to_string(pkt.dst_port),
                  pkt);
    }
}

void NetworkDpiEngine::check_protocol_anomalies(const PacketMeta& pkt) {
    if (!pkt.user_agent.empty() && is_suspicious_user_agent(pkt.user_agent)) {
        add_alert(DpiVerdict::SUSPICIOUS, ThreatLevel::MEDIUM,
                  "SUSPICIOUS_USER_AGENT",
                  "Suspicious User-Agent: " + pkt.user_agent +
                  " connecting to " + pkt.dst_ip,
                  pkt);
    }

    if (!pkt.uri.empty() && is_suspicious_uri(pkt.uri)) {
        add_alert(DpiVerdict::MALICIOUS, ThreatLevel::HIGH,
                  "SUSPICIOUS_URI",
                  "Suspicious URI pattern: " + pkt.uri + " to " + pkt.dst_ip,
                  pkt);
    }

    if (pkt.protocol == DpiProtocol::PROTO_DNS && pkt.payload_size > 512) {
        add_alert(DpiVerdict::SUSPICIOUS, ThreatLevel::MEDIUM,
                  "DNS_LARGE_PAYLOAD",
                  "Oversized DNS payload (" + std::to_string(pkt.payload_size) +
                  " bytes) to " + pkt.dst_ip,
                  pkt);
    }

    if (pkt.protocol == DpiProtocol::PROTO_IRC) {
        add_alert(DpiVerdict::SUSPICIOUS, ThreatLevel::MEDIUM,
                  "IRC_CONNECTION",
                  "IRC connection to " + pkt.dst_ip + ":" +
                  std::to_string(pkt.dst_port) + " (common C2 channel)",
                  pkt);
    }
}

void NetworkDpiEngine::check_tls_anomalies(const PacketMeta& pkt) {
    if (pkt.tls_self_signed) {
        add_alert(DpiVerdict::SUSPICIOUS, ThreatLevel::MEDIUM,
                  "TLS_SELF_SIGNED",
                  "Self-signed TLS certificate from " + pkt.dst_ip +
                  " (subject: " + pkt.tls_subject + ")",
                  pkt);
    }

    if (pkt.tls_expired) {
        add_alert(DpiVerdict::SUSPICIOUS, ThreatLevel::LOW,
                  "TLS_EXPIRED",
                  "Expired TLS certificate from " + pkt.dst_ip +
                  " (issuer: " + pkt.tls_issuer + ")",
                  pkt);
    }
}

void NetworkDpiEngine::add_alert(DpiVerdict verdict, ThreatLevel level,
                                  const std::string& rule, const std::string& desc,
                                  const PacketMeta& pkt) {
    std::function<void(ThreatEvent)> threat_cb;
    std::function<void(security::SecurityObservation)> obs_cb;

    {
        std::lock_guard lk(mtx_);
        threat_cb = threat_cb_;
        obs_cb = observation_cb_;

        DpiAlert alert;
        alert.id = next_alert_id_.fetch_add(1);
        alert.verdict = verdict;
        alert.level = level;
        alert.rule_name = rule;
        alert.description = desc;
        alert.src_ip = pkt.src_ip;
        alert.dst_ip = pkt.dst_ip;
        alert.dst_port = pkt.dst_port;
        alert.protocol = pkt.protocol;
        alert.timestamp = std::chrono::system_clock::now();
        alerts_.push_back(std::move(alert));
        while (alerts_.size() > MAX_ALERTS) alerts_.pop_front();
    }

    if (level >= ThreatLevel::HIGH) {
        threats_detected_.fetch_add(1);
        if (threat_cb) {
            ThreatEvent ev{};
            ev.level = level;
            ev.category = ThreatCategory::NETWORK_SCAN;
            ev.source_ip = pkt.src_ip;
            ev.source_port = pkt.src_port;
            ev.description = "[" + rule + "] " + desc;
            ev.timestamp = std::chrono::system_clock::now();
            threat_cb(std::move(ev));
        }
    } else if (obs_cb) {
        security::SecurityObservation obs;
        obs.kind = security::ObservationKind::NETWORK_CONNECTION;
        obs.suggested_level = level;
        obs.confidence = (verdict == DpiVerdict::MALICIOUS) ? 0.9 : 0.6;
        obs.evidence = "[" + rule + "] " + desc;
        obs.source_id = "NetworkDPI";
        obs.timestamp = std::chrono::system_clock::now();
        obs_cb(std::move(obs));
    }
}

std::vector<DpiAlert> NetworkDpiEngine::recent_alerts(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, alerts_.size());
    return {alerts_.end() - static_cast<ptrdiff_t>(count), alerts_.end()};
}

std::vector<BeaconPattern> NetworkDpiEngine::detected_beacons(size_t n) const {
    std::lock_guard lk(mtx_);
    std::vector<BeaconPattern> result;

    for (const auto& [key, tl] : conn_timelines_) {
        if (tl.timestamps.size() < BEACON_MIN_CONNECTIONS) continue;

        std::vector<double> intervals;
        for (size_t i = 1; i < tl.timestamps.size(); ++i) {
            auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
                tl.timestamps[i] - tl.timestamps[i - 1]).count();
            intervals.push_back(static_cast<double>(diff));
        }
        if (intervals.empty()) continue;

        double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
        double mean = sum / static_cast<double>(intervals.size());

        double sq_sum = 0.0;
        for (double v : intervals) sq_sum += (v - mean) * (v - mean);
        double stddev = std::sqrt(sq_sum / static_cast<double>(intervals.size()));

        double score = compute_beacon_score(mean, stddev, tl.timestamps.size());
        if (score >= BEACON_SCORE_THRESHOLD) {
            BeaconPattern bp;
            bp.dst_ip = tl.dst_ip;
            bp.dst_port = tl.dst_port;
            bp.connection_count = tl.timestamps.size();
            bp.interval_mean_ms = mean;
            bp.interval_stddev_ms = stddev;
            bp.jitter_ratio = (mean > 0.0) ? stddev / mean : 0.0;
            bp.beacon_score = score;
            result.push_back(std::move(bp));
            if (result.size() >= n) break;
        }
    }

    std::sort(result.begin(), result.end(),
              [](const BeaconPattern& a, const BeaconPattern& b) {
                  return a.beacon_score > b.beacon_score;
              });
    return result;
}

void NetworkDpiEngine::analyze_beacons() {
    std::function<void(ThreatEvent)> cb;
    std::vector<ThreatEvent> deferred;

    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
        if (!cb) return;

        for (const auto& [key, tl] : conn_timelines_) {
            if (tl.timestamps.size() < BEACON_MIN_CONNECTIONS) continue;

            std::vector<double> intervals;
            for (size_t i = 1; i < tl.timestamps.size(); ++i) {
                auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
                    tl.timestamps[i] - tl.timestamps[i - 1]).count();
                intervals.push_back(static_cast<double>(diff));
            }
            if (intervals.empty()) continue;

            double sum = std::accumulate(intervals.begin(), intervals.end(), 0.0);
            double mean = sum / static_cast<double>(intervals.size());
            double sq_sum = 0.0;
            for (double v : intervals) sq_sum += (v - mean) * (v - mean);
            double stddev = std::sqrt(sq_sum / static_cast<double>(intervals.size()));

            double score = compute_beacon_score(mean, stddev, tl.timestamps.size());
            if (score >= BEACON_SCORE_THRESHOLD) {
                if (reported_beacons_.count(key)) continue;
                reported_beacons_.insert(key);
                threats_detected_.fetch_add(1);
                ThreatEvent ev{};
                ev.level = ThreatLevel::HIGH;
                ev.category = ThreatCategory::C2_BEACON;
                ev.source_ip = tl.dst_ip;
                ev.source_port = tl.dst_port;
                ev.description = "Beaconing detected to " + tl.dst_ip + ":" +
                                 std::to_string(tl.dst_port) +
                                 " — " + std::to_string(tl.timestamps.size()) +
                                 " connections, interval=" +
                                 std::to_string(static_cast<int>(mean)) +
                                 "ms, score=" +
                                 std::to_string(static_cast<int>(score * 100)) + "%";
                ev.timestamp = std::chrono::system_clock::now();
                deferred.push_back(std::move(ev));
            } else {
                reported_beacons_.erase(key);
            }
        }
    }

    for (auto& ev : deferred)
        cb(std::move(ev));
}

std::string NetworkDpiEngine::conn_key(const std::string& dst_ip,
                                        uint16_t dst_port) const {
    return dst_ip + ":" + std::to_string(dst_port);
}

void NetworkDpiEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 10000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        analyze_beacons();
    }
}

} // namespace gcad
