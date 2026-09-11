#include "gcad/engines/dns_monitor_engine.hpp"

namespace gcad {

DnsMonitorEngine::DnsMonitorEngine() { init_blocklist(); }
DnsMonitorEngine::~DnsMonitorEngine() { stop(); }

void DnsMonitorEngine::init_blocklist() {
    static const char* const kMaliciousDomains[] = {
        "malware-c2.com", "evil-payload.net", "darkside-ransomware.net",
        "cobalt-strike-c2.com", "mimikatz-download.xyz", "emotet-dropper.club",
        "trickbot-panel.top", "ryuk-payment.onion.ws", "conti-leak.cc",
        "lockbit-blog.xyz", "blackcat-ransomware.net", "revil-payment.cc",
        "lazarus-apt.top", "apt28-implant.net", "apt29-beacon.xyz",
        "cobaltstrike.github.io.evil.com", "havoc-c2-framework.net",
        "sliver-implant.club", "bruteratel-c4.top", "nighthawk-c2.xyz",
    };
    for (auto* d : kMaliciousDomains) blocklist_.insert(d);
}

double DnsMonitorEngine::dga_score(std::string_view domain) {
    auto dot = domain.rfind('.');
    if (dot == std::string_view::npos) dot = domain.size();
    auto second_dot = domain.rfind('.', dot > 0 ? dot - 1 : 0);
    std::string_view label = (second_dot != std::string_view::npos)
        ? domain.substr(second_dot + 1, dot - second_dot - 1)
        : domain.substr(0, dot);

    if (label.size() < 4) return 0.0;

    double entropy = shannon_entropy(reinterpret_cast<const uint8_t*>(label.data()), label.size());
    double normalized_entropy = entropy / 4.7;

    size_t consonants = 0, vowels = 0, digits = 0;
    for (char c : label) {
        char lo = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        if (lo >= '0' && lo <= '9') { ++digits; continue; }
        if (lo == 'a' || lo == 'e' || lo == 'i' || lo == 'o' || lo == 'u') ++vowels;
        else if (lo >= 'a' && lo <= 'z') ++consonants;
    }
    double total_alpha = static_cast<double>(consonants + vowels);
    double consonant_ratio = total_alpha > 0 ? static_cast<double>(consonants) / total_alpha : 0.0;
    double digit_ratio = static_cast<double>(digits) / static_cast<double>(label.size());

    size_t max_consecutive = 0, current_run = 0;
    bool last_was_consonant = false;
    for (char c : label) {
        char lo = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        bool is_vowel = (lo == 'a' || lo == 'e' || lo == 'i' || lo == 'o' || lo == 'u');
        bool is_consonant = (lo >= 'a' && lo <= 'z') && !is_vowel;
        if (is_consonant) {
            if (last_was_consonant) ++current_run;
            else current_run = 1;
            if (current_run > max_consecutive) max_consecutive = current_run;
        } else {
            current_run = 0;
        }
        last_was_consonant = is_consonant;
    }

    double length_factor = label.size() > 15 ? 0.15 : 0.0;
    double consecutive_factor = max_consecutive >= 4 ? 0.15 : (max_consecutive >= 3 ? 0.05 : 0.0);

    double score = normalized_entropy * 0.35 +
                   consonant_ratio * 0.20 +
                   digit_ratio * 0.15 +
                   consecutive_factor +
                   length_factor;

    return std::min(1.0, std::max(0.0, score));
}

bool DnsMonitorEngine::parse_dns_query(const uint8_t* data, size_t len,
                                        std::string& out_domain, uint16_t& out_qtype) {
    if (len < 12) return false;
    uint16_t qdcount = (static_cast<uint16_t>(data[4]) << 8) | data[5];
    if (qdcount == 0) return false;

    size_t offset = 12;
    out_domain.clear();
    while (offset < len) {
        uint8_t label_len = data[offset++];
        if (label_len == 0) break;
        if ((label_len & 0xC0) == 0xC0) return false;
        if (offset + label_len > len) return false;
        if (!out_domain.empty()) out_domain += '.';
        out_domain.append(reinterpret_cast<const char*>(data + offset), label_len);
        offset += label_len;
    }

    if (offset + 4 > len) return false;
    out_qtype = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    return !out_domain.empty();
}

void DnsMonitorEngine::analyze_domain(const std::string& domain) {
    events_processed_.fetch_add(1);

    DnsQueryRecord record;
    record.domain = domain;
    record.timestamp = std::chrono::system_clock::now();
    record.dga_score = dga_score(domain);

    bool is_blocked = blocklist_.count(domain) > 0;
    record.blocked = is_blocked;

    {
        std::lock_guard lk(mtx_);
        query_log_.push_back(record);
        if (query_log_.size() > MAX_QUERY_LOG) query_log_.pop_front();
    }

    if (is_blocked) {
        emit_threat(ThreatCategory::DNS_TUNNEL, "Blocked malicious domain query: " + domain);
        emit_observation(security::ObservationKind::DNS_ANOMALY, ThreatLevel::CRITICAL,
                         0.95, "Query to known malicious domain: " + domain);
    } else if (record.dga_score >= DGA_THRESHOLD) {
        std::lock_guard lk(mtx_);
        if (seen_domains_.insert(domain).second) {
            emit_threat(ThreatCategory::DGA_DOMAIN,
                        "Suspected DGA domain (score=" + std::format("{:.2f}", record.dga_score) + "): " + domain);
            emit_observation(security::ObservationKind::DNS_ANOMALY, ThreatLevel::HIGH,
                             record.dga_score, "Suspected DGA domain: " + domain);
        }
    }
}

ErrorCode DnsMonitorEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&DnsMonitorEngine::monitor_loop, this);
    GCAD_LOG(INFO, "DnsMon engine started, blocklist: " + std::to_string(blocklist_.size()) + " domains");
    return ErrorCode::OK;
}

ErrorCode DnsMonitorEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus DnsMonitorEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void DnsMonitorEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void DnsMonitorEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

std::vector<DnsQueryRecord> DnsMonitorEngine::recent_queries(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t start = query_log_.size() > n ? query_log_.size() - n : 0;
    return {query_log_.begin() + static_cast<std::ptrdiff_t>(start), query_log_.end()};
}

void DnsMonitorEngine::monitor_loop() {
    while (running_.load()) {
        for (int i = 0; i < 50 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void DnsMonitorEngine::emit_threat(ThreatCategory cat, const std::string& desc) {
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
        cb(std::move(ev));
    }
}

void DnsMonitorEngine::emit_observation(security::ObservationKind kind, ThreatLevel level,
                                         double confidence, const std::string& evidence) {
    std::function<void(security::SecurityObservation)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = observation_cb_;
    }
    if (cb) {
        security::SecurityObservation obs{};
        obs.source_id = "dns-monitor";
        obs.kind = kind;
        obs.timestamp = std::chrono::system_clock::now();
        obs.suggested_level = level;
        obs.confidence = confidence;
        obs.deterministic = (kind == security::ObservationKind::DNS_ANOMALY && confidence > 0.9);
        obs.evidence = evidence;
        cb(std::move(obs));
    }
}

} // namespace gcad
