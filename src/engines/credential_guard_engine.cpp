#include "gcad/engines/credential_guard_engine.hpp"
#include <algorithm>

namespace gcad {

static const std::vector<std::string> known_dump_tools = {
    "mimikatz", "procdump", "procdump64", "sqldumper",
    "comsvcs", "rundll32", "task_manager_dump",
    "processhacker", "processhacker2",
    "nanodump", "pypykatz", "lsassy",
    "secretsdump", "lazagne", "credentialfileview",
    "ntdsutil", "fgdump", "gsecdump",
    "wce", "pwdump", "samdump2",
};

CredentialGuardEngine::CredentialGuardEngine() = default;
CredentialGuardEngine::~CredentialGuardEngine() { stop(); }

ErrorCode CredentialGuardEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&CredentialGuardEngine::monitor_loop, this);
    GCAD_LOG(INFO, "CredentialGuard engine started");
    return ErrorCode::OK;
}

ErrorCode CredentialGuardEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus CredentialGuardEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void CredentialGuardEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void CredentialGuardEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

bool CredentialGuardEngine::is_known_dump_tool(const std::string& process_name) {
    if (process_name.empty()) return false;
    std::string lower = process_name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    auto stem = std::filesystem::path(lower).stem().string();

    return std::any_of(known_dump_tools.begin(), known_dump_tools.end(),
                       [&stem](const std::string& tool) { return stem == tool; });
}

bool CredentialGuardEngine::is_suspicious_lsass_access(uint32_t access_mask) {
    constexpr uint32_t suspicious_flags = MASK_VM_READ | MASK_VM_WRITE |
                                           MASK_VM_OPERATION;
    return (access_mask & suspicious_flags) != 0 || access_mask == MASK_ALL_ACCESS;
}

ThreatLevel CredentialGuardEngine::classify_attack(CredentialAttackType type) {
    switch (type) {
        case CredentialAttackType::ATK_GOLDEN_TICKET:
        case CredentialAttackType::ATK_DCSYNC:
        case CredentialAttackType::ATK_PASS_THE_HASH:
        case CredentialAttackType::ATK_PASS_THE_TICKET:
            return ThreatLevel::CRITICAL;
        case CredentialAttackType::ATK_LSASS_ACCESS:
        case CredentialAttackType::ATK_SAM_DUMP:
        case CredentialAttackType::ATK_KERBEROASTING:
            return ThreatLevel::HIGH;
        case CredentialAttackType::ATK_TOKEN_IMPERSONATE:
        case CredentialAttackType::ATK_TOKEN_DUPLICATE:
        case CredentialAttackType::ATK_SILVER_TICKET:
            return ThreatLevel::HIGH;
        default:
            return ThreatLevel::MEDIUM;
    }
}

ThreatCategory CredentialGuardEngine::map_to_category(CredentialAttackType type) {
    switch (type) {
        case CredentialAttackType::ATK_LSASS_ACCESS:
        case CredentialAttackType::ATK_SAM_DUMP:
        case CredentialAttackType::ATK_DCSYNC:
            return ThreatCategory::CREDENTIAL_DUMP;
        case CredentialAttackType::ATK_PASS_THE_HASH:
        case CredentialAttackType::ATK_GOLDEN_TICKET:
        case CredentialAttackType::ATK_SILVER_TICKET:
        case CredentialAttackType::ATK_KERBEROASTING:
        case CredentialAttackType::ATK_PASS_THE_TICKET:
            return ThreatCategory::KERBEROS_ATTACK;
        case CredentialAttackType::ATK_TOKEN_IMPERSONATE:
        case CredentialAttackType::ATK_TOKEN_DUPLICATE:
            return ThreatCategory::NTLM_COERCE;
        default:
            return ThreatCategory::CREDENTIAL_DUMP;
    }
}

double CredentialGuardEngine::score_indicator(const CredentialThreatIndicator& ind) {
    double score = 0.0;

    if (ind.known_tool) score += 0.50;

    if (ind.lsass_access_count >= 3) score += 0.25;
    else if (ind.lsass_access_count >= 1) score += 0.15;

    if (ind.token_manipulation_count >= 3) score += 0.20;
    else if (ind.token_manipulation_count >= 1) score += 0.10;

    if (ind.lateral_movement_count >= 1) score += 0.25;

    if (ind.sam_access_count >= 1) score += 0.20;

    return std::clamp(score, 0.0, 1.0);
}

const char* CredentialGuardEngine::attack_type_name(CredentialAttackType type) {
    switch (type) {
        case CredentialAttackType::ATK_LSASS_ACCESS:        return "LSASS Access";
        case CredentialAttackType::ATK_TOKEN_IMPERSONATE:  return "Token Impersonation";
        case CredentialAttackType::ATK_TOKEN_DUPLICATE:      return "Token Duplication";
        case CredentialAttackType::ATK_PASS_THE_HASH:        return "Pass-the-Hash";
        case CredentialAttackType::ATK_PASS_THE_TICKET:      return "Pass-the-Ticket";
        case CredentialAttackType::ATK_SAM_DUMP:             return "SAM Dump";
        case CredentialAttackType::ATK_DCSYNC:               return "DCSync";
        case CredentialAttackType::ATK_KERBEROASTING:        return "Kerberoasting";
        case CredentialAttackType::ATK_GOLDEN_TICKET:        return "Golden Ticket";
        case CredentialAttackType::ATK_SILVER_TICKET:        return "Silver Ticket";
        default:                                         return "Unknown";
    }
}

void CredentialGuardEngine::ingest(const CredentialAccessEvent& ev) {
    events_processed_.fetch_add(1);

    std::function<void(ThreatEvent)> threat_cb;
    std::function<void(security::SecurityObservation)> obs_cb;
    std::vector<ThreatEvent> deferred_threats;
    std::vector<security::SecurityObservation> deferred_obs;

    {
        std::lock_guard lk(mtx_);
        threat_cb = threat_cb_;
        obs_cb = observation_cb_;

        CredentialAccessEvent stored = ev;
        stored.id = next_id_.fetch_add(1);
        events_.push_back(stored);
        while (events_.size() > MAX_EVENTS) events_.pop_front();

        auto& ind = indicators_[ev.source_pid];
        if (ind.id == 0) {
            ind.id = next_indicator_id_.fetch_add(1);
            ind.pid = ev.source_pid;
            ind.process_name = ev.source_process;
            ind.first_seen = ev.timestamp;
            ind.known_tool = is_known_dump_tool(ev.source_process);
        }
        ind.last_seen = ev.timestamp;

        switch (ev.type) {
            case CredentialAttackType::ATK_LSASS_ACCESS:
                ++ind.lsass_access_count;
                break;
            case CredentialAttackType::ATK_TOKEN_IMPERSONATE:
            case CredentialAttackType::ATK_TOKEN_DUPLICATE:
                ++ind.token_manipulation_count;
                break;
            case CredentialAttackType::ATK_PASS_THE_HASH:
            case CredentialAttackType::ATK_PASS_THE_TICKET:
            case CredentialAttackType::ATK_DCSYNC:
            case CredentialAttackType::ATK_KERBEROASTING:
            case CredentialAttackType::ATK_GOLDEN_TICKET:
            case CredentialAttackType::ATK_SILVER_TICKET:
                ++ind.lateral_movement_count;
                break;
            case CredentialAttackType::ATK_SAM_DUMP:
                ++ind.sam_access_count;
                break;
        }

        ind.risk_score = score_indicator(ind);

        ThreatLevel attack_level = classify_attack(ev.type);
        ThreatCategory cat = map_to_category(ev.type);

        if (ind.risk_score >= RISK_THRESHOLD_MALICIOUS || ind.known_tool) {
            threats_detected_.fetch_add(1);
            if (threat_cb) {
                ThreatEvent te{};
                te.level = std::max(attack_level, ThreatLevel::HIGH);
                te.category = cat;
                te.process_id = ev.source_pid;
                te.process_name = ev.source_process;
                te.description = std::string(attack_type_name(ev.type)) +
                                 " by " + ev.source_process +
                                 " (PID " + std::to_string(ev.source_pid) + ")";
                if (!ev.detail.empty()) te.description += " — " + ev.detail;
                te.timestamp = std::chrono::system_clock::now();
                deferred_threats.push_back(std::move(te));
            }
        } else if (ind.risk_score >= RISK_THRESHOLD_SUSPICIOUS && obs_cb) {
            security::SecurityObservation obs;
            obs.kind = security::ObservationKind::PROCESS_MEMORY;
            obs.suggested_level = ThreatLevel::MEDIUM;
            obs.confidence = ind.risk_score;
            obs.process_id = ev.source_pid;
            obs.process_name = ev.source_process;
            obs.evidence = "Suspicious credential access: " +
                           std::string(attack_type_name(ev.type));
            obs.timestamp = std::chrono::system_clock::now();
            deferred_obs.push_back(std::move(obs));
        }
    }

    for (auto& te : deferred_threats)
        threat_cb(std::move(te));
    for (auto& obs : deferred_obs)
        obs_cb(std::move(obs));
}

void CredentialGuardEngine::report_lsass_access(uint32_t source_pid,
                                                 const std::string& source_process,
                                                 uint32_t access_mask) {
    if (!is_suspicious_lsass_access(access_mask)) return;

    CredentialAccessEvent ev;
    ev.type = CredentialAttackType::ATK_LSASS_ACCESS;
    ev.source_pid = source_pid;
    ev.source_process = source_process;
    ev.access_mask = access_mask;
    ev.detail = "access_mask=0x" + [&] {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%08X", access_mask);
        return std::string(buf);
    }();
    ev.timestamp = std::chrono::system_clock::now();
    ingest(ev);
}

void CredentialGuardEngine::report_token_manipulation(uint32_t pid,
                                                       const std::string& process_name,
                                                       CredentialAttackType type) {
    CredentialAccessEvent ev;
    ev.type = type;
    ev.source_pid = pid;
    ev.source_process = process_name;
    ev.timestamp = std::chrono::system_clock::now();
    ingest(ev);
}

void CredentialGuardEngine::report_sam_access(uint32_t pid,
                                               const std::string& process_name) {
    CredentialAccessEvent ev;
    ev.type = CredentialAttackType::ATK_SAM_DUMP;
    ev.source_pid = pid;
    ev.source_process = process_name;
    ev.detail = "SAM registry hive access detected";
    ev.timestamp = std::chrono::system_clock::now();
    ingest(ev);
}

std::vector<CredentialThreatIndicator> CredentialGuardEngine::active_indicators(size_t n) const {
    std::lock_guard lk(mtx_);
    std::vector<CredentialThreatIndicator> result;
    result.reserve(std::min(n, indicators_.size()));
    for (const auto& [pid, ind] : indicators_) {
        result.push_back(ind);
        if (result.size() >= n) break;
    }
    std::sort(result.begin(), result.end(),
              [](const CredentialThreatIndicator& a, const CredentialThreatIndicator& b) {
                  return a.risk_score > b.risk_score;
              });
    return result;
}

std::vector<CredentialAccessEvent> CredentialGuardEngine::recent_events(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, events_.size());
    return {events_.end() - static_cast<ptrdiff_t>(count), events_.end()};
}

void CredentialGuardEngine::decay_indicators() {
    std::lock_guard lk(mtx_);
    auto now = std::chrono::system_clock::now();
    for (auto it = indicators_.begin(); it != indicators_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::minutes>(
            now - it->second.last_seen).count();
        if (age > 30 && it->second.risk_score < RISK_THRESHOLD_SUSPICIOUS) {
            it = indicators_.erase(it);
        } else {
            ++it;
        }
    }
}

void CredentialGuardEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 10000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        decay_indicators();
    }
}

} // namespace gcad
