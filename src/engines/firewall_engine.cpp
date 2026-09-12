#include "gcad/engines/firewall_engine.hpp"
#include <algorithm>
#include <charconv>
#include <cstdio>
#include <unordered_map>

namespace gcad {

FirewallEngine::FirewallEngine() = default;
FirewallEngine::~FirewallEngine() { stop(); }

ErrorCode FirewallEngine::start() {
    if (running_.load()) return ErrorCode::OK;

    install_default_rules();
    running_.store(true);
    monitor_thread_ = std::thread(&FirewallEngine::monitor_loop, this);
    GCAD_LOG(INFO, "Firewall engine started, " + std::to_string(rules_.size()) + " rules loaded");
    return ErrorCode::OK;
}

ErrorCode FirewallEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus FirewallEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void FirewallEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void FirewallEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

uint32_t FirewallEngine::add_rule(FirewallRule rule) {
    std::lock_guard lk(mtx_);
    rule.id = next_rule_id_++;
    rules_.push_back(std::move(rule));
    std::stable_sort(rules_.begin(), rules_.end(),
                     [](auto& a, auto& b) { return a.priority < b.priority; });
    return rules_.back().id;
}

bool FirewallEngine::remove_rule(uint32_t rule_id) {
    std::lock_guard lk(mtx_);
    auto it = std::find_if(rules_.begin(), rules_.end(),
                           [rule_id](auto& r) { return r.id == rule_id; });
    if (it == rules_.end()) return false;
    rules_.erase(it);
    return true;
}

bool FirewallEngine::enable_rule(uint32_t rule_id, bool enabled) {
    std::lock_guard lk(mtx_);
    auto it = std::find_if(rules_.begin(), rules_.end(),
                           [rule_id](auto& r) { return r.id == rule_id; });
    if (it == rules_.end()) return false;
    it->enabled = enabled;
    return true;
}

std::vector<FirewallRule> FirewallEngine::rules() const {
    std::lock_guard lk(mtx_);
    return rules_;
}

FirewallAction FirewallEngine::evaluate(FirewallDirection dir, FirewallProto proto,
                                         uint32_t src_ip, uint32_t dst_ip,
                                         uint16_t src_port, uint16_t dst_port) {
    std::lock_guard lk(mtx_);
    events_processed_.fetch_add(1);

    for (auto& r : rules_) {
        if (!r.enabled) continue;
        if (r.direction != dir) continue;
        if (r.protocol != FirewallProto::ANY && r.protocol != proto) continue;

        if (r.src_ip != 0 && (src_ip & r.src_mask) != (r.src_ip & r.src_mask))
            continue;
        if (r.dst_ip != 0 && (dst_ip & r.dst_mask) != (r.dst_ip & r.dst_mask))
            continue;

        uint16_t check_port = (dir == FirewallDirection::INBOUND) ? dst_port : src_port;
        if (r.port_min != 0 || r.port_max != 65535) {
            if (check_port < r.port_min || check_port > r.port_max)
                continue;
        }

        if (r.action == FirewallAction::ALLOW) {
            total_allowed_.fetch_add(1);
        } else {
            total_denied_.fetch_add(1);
        }
        return r.action;
    }

    total_allowed_.fetch_add(1);
    return FirewallAction::ALLOW;
}

void FirewallEngine::log_connection(const ConnectionLog& entry) {
    std::lock_guard lk(mtx_);
    conn_log_.push_back(entry);
    while (conn_log_.size() > MAX_CONNECTION_LOG)
        conn_log_.pop_front();
}

std::vector<ConnectionLog> FirewallEngine::recent_connections(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, conn_log_.size());
    return {conn_log_.end() - static_cast<ptrdiff_t>(count), conn_log_.end()};
}

std::vector<SuspiciousTraffic> FirewallEngine::suspicious_candidates() const {
    std::lock_guard lk(mtx_);

    struct IpStats {
        size_t total{0};
        size_t denied{0};
        std::unordered_map<uint16_t, size_t> port_scatter;
    };
    std::unordered_map<uint32_t, IpStats> stats;

    for (auto& c : conn_log_) {
        uint32_t key = (c.direction == FirewallDirection::INBOUND) ? c.src_ip : c.dst_ip;
        auto& s = stats[key];
        s.total++;
        if (c.action_taken == FirewallAction::DENY) s.denied++;
        s.port_scatter[c.dst_port]++;
    }

    std::vector<SuspiciousTraffic> result;
    for (auto& [ip, s] : stats) {
        SuspiciousTraffic st;
        st.ip = ip;
        st.connection_count = s.total;
        st.denied_count = s.denied;

        bool suspicious = false;

        if (s.total >= FLOOD_THRESHOLD) {
            st.suspected_category = ThreatCategory::SYN_FLOOD;
            st.reason = "High connection volume (" + std::to_string(s.total) + " connections)";
            suspicious = true;
        } else if (s.denied >= DENY_RATIO_THRESH && s.denied * 2 > s.total) {
            st.suspected_category = ThreatCategory::NETWORK_SCAN;
            st.reason = "High deny ratio (" + std::to_string(s.denied) + "/" + std::to_string(s.total) + ")";
            suspicious = true;
        } else if (s.port_scatter.size() >= 20) {
            st.suspected_category = ThreatCategory::NETWORK_SCAN;
            st.reason = "Port scan detected (" + std::to_string(s.port_scatter.size()) + " unique ports)";
            suspicious = true;
        }

        if (suspicious)
            result.push_back(std::move(st));
    }

    std::sort(result.begin(), result.end(),
              [](auto& a, auto& b) { return a.connection_count > b.connection_count; });
    return result;
}

uint32_t FirewallEngine::parse_ipv4(std::string_view s) {
    uint32_t octets[4]{};
    size_t idx = 0;
    size_t start = 0;
    for (size_t i = 0; i <= s.size() && idx < 4; ++i) {
        if (i == s.size() || s[i] == '.') {
            auto sub = s.substr(start, i - start);
            uint32_t val = 0;
            auto [ptr, ec] = std::from_chars(sub.data(), sub.data() + sub.size(), val);
            if (ec != std::errc{} || val > 255) return 0;
            octets[idx++] = val;
            start = i + 1;
        }
    }
    if (idx != 4) return 0;
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
}

std::string FirewallEngine::ip_to_string(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return buf;
}

uint32_t FirewallEngine::cidr_to_mask(unsigned prefix_len) {
    if (prefix_len == 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFF;
    return ~((1u << (32 - prefix_len)) - 1);
}

void FirewallEngine::monitor_loop() {
    int poll_ms = 5000;
    int quiet_ticks = 0;

    while (running_.load()) {
        for (int slept = 0; slept < poll_ms && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;

        analyze_traffic();

        auto suspects = suspicious_candidates();
        if (!suspects.empty()) {
            poll_ms = 5000;
            quiet_ticks = 0;
            for (auto& s : suspects) {
                emit_threat(s.suspected_category, s.reason, s.ip, 0);
                emit_observation(security::ObservationKind::NETWORK_CONNECTION,
                                 ThreatLevel::HIGH, 0.8, s.reason);
            }
        } else if (++quiet_ticks >= 5 && poll_ms < 30000) {
            poll_ms = std::min(poll_ms * 2, 30000);
        }
    }
}

void FirewallEngine::analyze_traffic() {
    std::lock_guard lk(mtx_);

    auto now = std::chrono::system_clock::now();
    auto window_start = now - std::chrono::minutes(5);

    std::unordered_map<uint32_t, size_t> recent_counts;
    for (auto it = conn_log_.rbegin(); it != conn_log_.rend(); ++it) {
        if (it->timestamp < window_start) break;
        uint32_t key = (it->direction == FirewallDirection::INBOUND) ? it->src_ip : it->dst_ip;
        recent_counts[key]++;
    }

    for (auto& [ip, count] : recent_counts) {
        if (count >= FLOOD_THRESHOLD) {
            events_processed_.fetch_add(1);
        }
    }
}

void FirewallEngine::emit_threat(ThreatCategory cat, const std::string& desc,
                                  uint32_t src_ip, uint16_t port) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::HIGH;
        ev.category = cat;
        ev.description = desc;
        ev.source_ip = ip_to_string(src_ip);
        ev.source_port = port;
        ev.timestamp = std::chrono::system_clock::now();
        cb(std::move(ev));
    }
}

void FirewallEngine::emit_observation(security::ObservationKind kind, ThreatLevel level,
                                       double confidence, const std::string& evidence) {
    std::function<void(security::SecurityObservation)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = observation_cb_;
    }
    if (cb) {
        security::SecurityObservation obs{};
        obs.source_id = "firewall";
        obs.kind = kind;
        obs.timestamp = std::chrono::system_clock::now();
        obs.suggested_level = level;
        obs.confidence = confidence;
        obs.deterministic = true;
        obs.evidence = evidence;
        cb(std::move(obs));
    }
}

void FirewallEngine::install_default_rules() {
    std::lock_guard lk(mtx_);
    if (!rules_.empty()) return;

    auto add = [this](const char* label, FirewallDirection dir, FirewallAction act,
                      FirewallProto proto, uint16_t pmin, uint16_t pmax, int prio) {
        FirewallRule r;
        r.id = next_rule_id_++;
        r.label = label;
        r.direction = dir;
        r.action = act;
        r.protocol = proto;
        r.port_min = pmin;
        r.port_max = pmax;
        r.priority = prio;
        rules_.push_back(std::move(r));
    };

    add("Allow DNS out",      FirewallDirection::OUTBOUND, FirewallAction::ALLOW, FirewallProto::UDP, 53, 53, 10);
    add("Allow HTTP out",     FirewallDirection::OUTBOUND, FirewallAction::ALLOW, FirewallProto::TCP, 80, 80, 10);
    add("Allow HTTPS out",    FirewallDirection::OUTBOUND, FirewallAction::ALLOW, FirewallProto::TCP, 443, 443, 10);
    add("Allow DHCP out",     FirewallDirection::OUTBOUND, FirewallAction::ALLOW, FirewallProto::UDP, 67, 68, 10);
    add("Allow loopback in",  FirewallDirection::INBOUND,  FirewallAction::ALLOW, FirewallProto::ANY, 0, 65535, 5);
    add("Deny known bad ports in", FirewallDirection::INBOUND, FirewallAction::DENY, FirewallProto::TCP, 4444, 4444, 20);
    add("Deny Telnet in",     FirewallDirection::INBOUND,  FirewallAction::DENY, FirewallProto::TCP, 23, 23, 20);
    add("Deny RDP brute in",  FirewallDirection::INBOUND,  FirewallAction::DENY, FirewallProto::TCP, 3389, 3389, 30);

    std::stable_sort(rules_.begin(), rules_.end(),
                     [](auto& a, auto& b) { return a.priority < b.priority; });
}

} // namespace gcad
