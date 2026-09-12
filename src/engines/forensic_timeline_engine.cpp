#include "gcad/engines/forensic_timeline_engine.hpp"
#include <algorithm>
#include <sstream>

namespace gcad {

ForensicTimelineEngine::ForensicTimelineEngine() = default;
ForensicTimelineEngine::~ForensicTimelineEngine() { stop(); }

ErrorCode ForensicTimelineEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&ForensicTimelineEngine::monitor_loop, this);
    GCAD_LOG(INFO, "ForensicTimeline engine started");
    return ErrorCode::OK;
}

ErrorCode ForensicTimelineEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus ForensicTimelineEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void ForensicTimelineEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void ForensicTimelineEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

const char* ForensicTimelineEngine::stage_name(KillChainStage stage) {
    switch (stage) {
        case KillChainStage::RECONNAISSANCE:  return "Reconnaissance";
        case KillChainStage::WEAPONIZATION:   return "Weaponization";
        case KillChainStage::DELIVERY:        return "Delivery";
        case KillChainStage::EXPLOITATION:    return "Exploitation";
        case KillChainStage::INSTALLATION:    return "Installation";
        case KillChainStage::COMMAND_CONTROL: return "Command & Control";
        case KillChainStage::ACTIONS_ON_OBJ:  return "Actions on Objectives";
        default:                              return "Unknown";
    }
}

KillChainStage ForensicTimelineEngine::map_category_to_stage(ThreatCategory cat) {
    switch (cat) {
        case ThreatCategory::NETWORK_SCAN:
        case ThreatCategory::RAW_SOCKET_PROBE:
            return KillChainStage::RECONNAISSANCE;

        case ThreatCategory::ENTROPY_ANOMALY:
        case ThreatCategory::SUSPICIOUS_BINARY:
            return KillChainStage::WEAPONIZATION;

        case ThreatCategory::SYN_FLOOD:
        case ThreatCategory::UDP_FLOOD:
        case ThreatCategory::ARP_POISON:
            return KillChainStage::DELIVERY;

        case ThreatCategory::MEMORY_INJECTION:
        case ThreatCategory::PROCESS_HOLLOW:
        case ThreatCategory::DLL_INJECTION:
        case ThreatCategory::APC_INJECTION:
        case ThreatCategory::SHELLCODE:
        case ThreatCategory::REFLECTIVE_LOAD:
        case ThreatCategory::DIRECT_SYSCALL:
        case ThreatCategory::KERBEROS_ATTACK:
        case ThreatCategory::NTLM_COERCE:
        case ThreatCategory::CREDENTIAL_DUMP:
            return KillChainStage::EXPLOITATION;

        case ThreatCategory::BACKDOOR_ACCOUNT:
        case ThreatCategory::REGISTRY_TAMPER:
        case ThreatCategory::FILELESS_EXEC:
        case ThreatCategory::YARA_RULE_MATCH:
            return KillChainStage::INSTALLATION;

        case ThreatCategory::DNS_TUNNEL:
        case ThreatCategory::ICMP_COVERT:
        case ThreatCategory::DGA_DOMAIN:
            return KillChainStage::COMMAND_CONTROL;

        case ThreatCategory::RANSOMWARE:
        case ThreatCategory::FILE_ENCRYPT:
        case ThreatCategory::ANTI_FORENSIC:
        case ThreatCategory::FILE_INTEGRITY_VIOLATION:
            return KillChainStage::ACTIONS_ON_OBJ;

        case ThreatCategory::EVASION_AMSI:
        case ThreatCategory::EVASION_ETW:
        case ThreatCategory::EVASION_UNHOOK:
        case ThreatCategory::PPID_SPOOF:
            return KillChainStage::EXPLOITATION;

        default:
            return KillChainStage::UNKNOWN;
    }
}

KillChainStage ForensicTimelineEngine::map_observation_to_stage(security::ObservationKind kind) {
    using K = security::ObservationKind;
    switch (kind) {
        case K::NETWORK_CONNECTION:
        case K::DNS_ANOMALY:
            return KillChainStage::COMMAND_CONTROL;
        case K::PROCESS_MEMORY:
        case K::PROCESS_LINEAGE:
            return KillChainStage::EXPLOITATION;
        case K::REGISTRY_PERSISTENCE:
            return KillChainStage::INSTALLATION;
        case K::FILE_INTEGRITY:
            return KillChainStage::ACTIONS_ON_OBJ;
        case K::ARTIFACT_SIGNATURE:
        case K::ARTIFACT_STRUCTURE:
        case K::ARTIFACT_TRUST:
        case K::INVALID_PE:
        case K::UNSIGNED_RISKY_LOCATION:
        case K::INVALID_SIGNATURE:
            return KillChainStage::WEAPONIZATION;
        case K::HIGH_ENTROPY:
            return KillChainStage::WEAPONIZATION;
        case K::YARA_MATCH:
            return KillChainStage::INSTALLATION;
        default:
            return KillChainStage::UNKNOWN;
    }
}

TimelineEventType ForensicTimelineEngine::map_category_to_type(ThreatCategory cat) {
    switch (cat) {
        case ThreatCategory::MEMORY_INJECTION:
        case ThreatCategory::PROCESS_HOLLOW:
        case ThreatCategory::DLL_INJECTION:
        case ThreatCategory::APC_INJECTION:
        case ThreatCategory::REFLECTIVE_LOAD:
        case ThreatCategory::SHELLCODE:
            return TimelineEventType::MEMORY;

        case ThreatCategory::NETWORK_SCAN:
        case ThreatCategory::SYN_FLOOD:
        case ThreatCategory::UDP_FLOOD:
        case ThreatCategory::ARP_POISON:
        case ThreatCategory::ICMP_COVERT:
        case ThreatCategory::RAW_SOCKET_PROBE:
            return TimelineEventType::NETWORK;

        case ThreatCategory::DNS_TUNNEL:
        case ThreatCategory::DGA_DOMAIN:
            return TimelineEventType::DNS;

        case ThreatCategory::REGISTRY_TAMPER:
        case ThreatCategory::BACKDOOR_ACCOUNT:
            return TimelineEventType::REGISTRY;

        case ThreatCategory::RANSOMWARE:
        case ThreatCategory::FILE_ENCRYPT:
        case ThreatCategory::FILE_INTEGRITY_VIOLATION:
        case ThreatCategory::ANTI_FORENSIC:
            return TimelineEventType::FILE_ACCESS;

        case ThreatCategory::KERBEROS_ATTACK:
        case ThreatCategory::NTLM_COERCE:
        case ThreatCategory::CREDENTIAL_DUMP:
            return TimelineEventType::CREDENTIAL;

        case ThreatCategory::EVASION_AMSI:
        case ThreatCategory::EVASION_ETW:
        case ThreatCategory::EVASION_UNHOOK:
        case ThreatCategory::PPID_SPOOF:
        case ThreatCategory::DIRECT_SYSCALL:
            return TimelineEventType::EVASION;

        default:
            return TimelineEventType::PROCESS;
    }
}

TimelineEventType ForensicTimelineEngine::map_observation_to_type(security::ObservationKind kind) {
    using K = security::ObservationKind;
    switch (kind) {
        case K::NETWORK_CONNECTION:  return TimelineEventType::NETWORK;
        case K::DNS_ANOMALY:         return TimelineEventType::DNS;
        case K::PROCESS_MEMORY:      return TimelineEventType::MEMORY;
        case K::PROCESS_LINEAGE:     return TimelineEventType::PROCESS;
        case K::REGISTRY_PERSISTENCE: return TimelineEventType::REGISTRY;
        case K::FILE_INTEGRITY:      return TimelineEventType::FILE_ACCESS;
        default:                     return TimelineEventType::PROCESS;
    }
}

void ForensicTimelineEngine::ingest_threat(const ThreatEvent& ev) {
    TimelineEvent te;
    te.id = next_id_.fetch_add(1);
    te.timestamp = ev.timestamp;
    te.type = map_category_to_type(ev.category);
    te.stage = map_category_to_stage(ev.category);
    te.level = ev.level;
    te.category = ev.category;
    te.process_id = ev.process_id;
    te.process_name = ev.process_name;
    te.file_path = ev.file_path;
    te.source_ip = ev.source_ip;
    te.description = ev.description;
    te.confidence = 1.0;

    link_causal(te);

    {
        std::lock_guard lk(mtx_);
        events_.push_back(te);
        while (events_.size() > MAX_EVENTS) events_.pop_front();
    }

    update_chains(te);
    events_processed_.fetch_add(1);

    if (te.level >= ThreatLevel::HIGH)
        threats_detected_.fetch_add(1);
}

void ForensicTimelineEngine::ingest_observation(const security::SecurityObservation& obs) {
    TimelineEvent te;
    te.id = next_id_.fetch_add(1);
    te.timestamp = obs.timestamp;
    te.type = map_observation_to_type(obs.kind);
    te.stage = map_observation_to_stage(obs.kind);
    te.level = obs.suggested_level;
    te.process_id = obs.process_id;
    te.process_name = obs.process_name;
    te.file_path = obs.file_path;
    te.description = obs.evidence;
    te.evidence = obs.source_id;
    te.confidence = obs.confidence;

    link_causal(te);

    {
        std::lock_guard lk(mtx_);
        events_.push_back(te);
        while (events_.size() > MAX_EVENTS) events_.pop_front();
    }

    update_chains(te);
    events_processed_.fetch_add(1);
}

void ForensicTimelineEngine::link_causal(TimelineEvent& ev) {
    std::lock_guard lk(mtx_);
    if (ev.process_id == 0) return;

    for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
        if (it->process_id == ev.process_id && it->id != ev.id) {
            ev.causal_parent = it->id;
            return;
        }
        auto age = std::chrono::duration_cast<std::chrono::seconds>(ev.timestamp - it->timestamp);
        if (age.count() > 300) break;
    }
}

void ForensicTimelineEngine::update_chains(const TimelineEvent& ev) {
    std::lock_guard lk(mtx_);

    if (ev.causal_parent != 0) {
        for (auto& chain : chains_) {
            for (uint64_t eid : chain.event_ids) {
                if (eid == ev.causal_parent) {
                    chain.event_ids.push_back(ev.id);
                    chain.max_stage = std::max(chain.max_stage, ev.stage);
                    chain.max_level = std::max(chain.max_level, ev.level);
                    return;
                }
            }
        }
    }

    if (ev.level >= ThreatLevel::MEDIUM || ev.stage != KillChainStage::UNKNOWN) {
        CausalChain chain;
        chain.chain_id = next_chain_id_.fetch_add(1);
        chain.event_ids.push_back(ev.id);
        chain.max_stage = ev.stage;
        chain.max_level = ev.level;
        chain.summary = std::string(stage_name(ev.stage)) + ": " + ev.description;
        chains_.push_back(std::move(chain));
        while (chains_.size() > MAX_CHAINS) chains_.pop_front();
    }
}

void ForensicTimelineEngine::detect_multi_stage() {
    std::vector<ThreatEvent> deferred_alerts;
    std::function<void(ThreatEvent)> cb;

    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
        if (!cb) return;

        for (auto& chain : chains_) {
            std::array<bool, 8> stages{};
            for (uint64_t eid : chain.event_ids) {
                for (const auto& ev : events_) {
                    if (ev.id == eid) {
                        stages[static_cast<size_t>(ev.stage)] = true;
                        break;
                    }
                }
            }
            int distinct = 0;
            for (size_t i = 1; i < 8; ++i)
                if (stages[i]) ++distinct;

            if (distinct >= 3 && chain.summary.find("[MULTI-STAGE]") == std::string::npos) {
                chain.summary = "[MULTI-STAGE] " + chain.summary;
                ThreatEvent alert{};
                alert.level = ThreatLevel::CRITICAL;
                alert.category = ThreatCategory::ANTI_FORENSIC;
                alert.description = "Multi-stage attack detected: " + std::to_string(distinct) +
                                    " kill chain stages observed across " +
                                    std::to_string(chain.event_ids.size()) + " events";
                alert.timestamp = std::chrono::system_clock::now();
                deferred_alerts.push_back(std::move(alert));
            }
        }
    }

    for (auto& alert : deferred_alerts)
        cb(std::move(alert));
}

std::vector<TimelineEvent> ForensicTimelineEngine::query_timeline(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, events_.size());
    return {events_.end() - static_cast<ptrdiff_t>(count), events_.end()};
}

std::vector<TimelineEvent> ForensicTimelineEngine::query_by_pid(uint32_t pid, size_t n) const {
    std::lock_guard lk(mtx_);
    std::vector<TimelineEvent> result;
    for (auto it = events_.rbegin(); it != events_.rend() && result.size() < n; ++it)
        if (it->process_id == pid)
            result.push_back(*it);
    std::reverse(result.begin(), result.end());
    return result;
}

std::vector<TimelineEvent> ForensicTimelineEngine::query_by_stage(KillChainStage stage, size_t n) const {
    std::lock_guard lk(mtx_);
    std::vector<TimelineEvent> result;
    for (auto it = events_.rbegin(); it != events_.rend() && result.size() < n; ++it)
        if (it->stage == stage)
            result.push_back(*it);
    std::reverse(result.begin(), result.end());
    return result;
}

std::vector<TimelineEvent> ForensicTimelineEngine::query_time_range(
    std::chrono::system_clock::time_point from,
    std::chrono::system_clock::time_point to) const {
    std::lock_guard lk(mtx_);
    std::vector<TimelineEvent> result;
    for (const auto& ev : events_)
        if (ev.timestamp >= from && ev.timestamp <= to)
            result.push_back(ev);
    return result;
}

std::vector<CausalChain> ForensicTimelineEngine::causal_chains(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, chains_.size());
    return {chains_.end() - static_cast<ptrdiff_t>(count), chains_.end()};
}

KillChainProgress ForensicTimelineEngine::kill_chain_progress() const {
    std::lock_guard lk(mtx_);
    KillChainProgress p{};
    p.total_events = events_.size();
    for (const auto& ev : events_) {
        auto idx = static_cast<size_t>(ev.stage);
        if (idx < p.stage_counts.size()) {
            ++p.stage_counts[idx];
            if (ev.stage > p.furthest) p.furthest = ev.stage;
        }
    }
    int distinct = 0;
    for (size_t i = 1; i < 8; ++i)
        if (p.stage_counts[i] > 0) ++distinct;
    p.multi_stage_detected = distinct >= 3;
    return p;
}

void ForensicTimelineEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 10000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        detect_multi_stage();
    }
}

} // namespace gcad
