#include "gcad/engine_manager.hpp"
#include "gcad/engines/pmsr_engine.hpp"
#include "gcad/engines/etg_ri_engine.hpp"
#include "gcad/engines/arhs_engine.hpp"
#include "gcad/engines/zrgp_engine.hpp"
#include "gcad/engines/self_defense.hpp"
#include "gcad/engines/syscall_guard.hpp"
#include "gcad/engines/kernel_monitor_engine.hpp"
#include "gcad/engines/registry_monitor_engine.hpp"
#include "gcad/engines/file_integrity_engine.hpp"
#include "gcad/engines/dns_monitor_engine.hpp"
#include "gcad/engines/yara_engine.hpp"
#include "gcad/engines/firewall_engine.hpp"
#include "gcad/engines/sandbox_engine.hpp"
#include "gcad/engines/threat_intel_engine.hpp"
#include "gcad/engines/update_engine.hpp"
#include "gcad/engines/behavior_scorer.hpp"
#include "gcad/engines/forensic_timeline_engine.hpp"
#include "gcad/engines/vuln_scanner_engine.hpp"
#include "gcad/engines/ransomware_shield_engine.hpp"
#include "gcad/engines/credential_guard_engine.hpp"
#include "gcad/security/legacy_adapter.hpp"
#include "gcad/security/policy_store.hpp"
#include "gcad/security/process_behavior_engine.hpp"
#include "gcad/platform/platform_compat.hpp"
#include <unordered_set>

namespace gcad {

namespace {

// %PROGRAMDATA%\GCAD\policy.txt is writable without per-user or install-path
// permissions and is the conventional location for a Windows security
// product's machine-wide config. A missing PROGRAMDATA (or non-Windows build)
// falls back to a relative path so the Linux compatibility stub still builds
// and runs; PolicyStore::load() returns safe defaults either way if the file
// is absent.
std::filesystem::path default_policy_path() {
#ifdef GCAD_PLATFORM_WINDOWS
    char program_data[MAX_PATH]{};
    const DWORD len = GetEnvironmentVariableA("PROGRAMDATA", program_data, sizeof(program_data));
    if (len > 0 && len < sizeof(program_data))
        return std::filesystem::path(program_data) / "GCAD" / "policy.txt";
#endif
    return std::filesystem::path("gcad_policy.txt");
}

// Same reasoning as default_policy_path(): a machine-wide, permission-free
// location for the vault QuarantineExecutor moves approved files into.
std::filesystem::path default_quarantine_vault_path() {
#ifdef GCAD_PLATFORM_WINDOWS
    char program_data[MAX_PATH]{};
    const DWORD len = GetEnvironmentVariableA("PROGRAMDATA", program_data, sizeof(program_data));
    if (len > 0 && len < sizeof(program_data))
        return std::filesystem::path(program_data) / "GCAD" / "Quarantine";
#endif
    return std::filesystem::path("gcad_quarantine");
}

} // namespace

EngineManager::EngineManager()
    : quarantine_(default_quarantine_vault_path(), security::PolicyStore::load(default_policy_path())) {
    pipeline_ = std::make_unique<security::SecurityPipeline>(
        1024, security::PolicyStore::load(default_policy_path()));
    engines_.push_back(std::make_unique<PMSREngine>());
    engines_.push_back(std::make_unique<ETGRIEngine>());
    engines_.push_back(std::make_unique<ARHSEngine>());
    engines_.push_back(std::make_unique<ZRGPEngine>());
    engines_.push_back(std::make_unique<SelfDefenseEngine>());
    engines_.push_back(std::make_unique<SyscallGuardEngine>());
    engines_.push_back(std::make_unique<KernelMonitorEngine>());
    engines_.push_back(std::make_unique<RegistryMonitorEngine>());
    engines_.push_back(std::make_unique<FileIntegrityEngine>());
    engines_.push_back(std::make_unique<DnsMonitorEngine>());
    engines_.push_back(std::make_unique<YaraEngine>());
    engines_.push_back(std::make_unique<FirewallEngine>());
    engines_.push_back(std::make_unique<SandboxEngine>());
    engines_.push_back(std::make_unique<ThreatIntelEngine>());
    engines_.push_back(std::make_unique<UpdateEngine>());
    engines_.push_back(std::make_unique<BehaviorScorer>());
    engines_.push_back(std::make_unique<ForensicTimelineEngine>());
    engines_.push_back(std::make_unique<VulnScannerEngine>());
    engines_.push_back(std::make_unique<RansomwareShieldEngine>());
    engines_.push_back(std::make_unique<CredentialGuardEngine>());

    for (auto& e : engines_) {
        // Captured by value: adapt_legacy_event needs the emitting engine's
        // identity to tell an exact tamper check apart from a weak heuristic
        // that happens to share the same ThreatCategory in another engine.
        const std::string engine_name(e->name());
        e->on_threat([this, engine_name](ThreatEvent ev) { push_event(std::move(ev), engine_name); });
    }

    etw_process_engine_.on_observation([this](security::SecurityObservation observation) {
        if (pipeline_) pipeline_->publish(std::move(observation));
    });

    // Rides the ETW consumer's existing subscription instead of adding a new
    // polling loop: ProcessBehaviorEngine::inspect_pid() does a VirtualQueryEx
    // walk that can visit thousands of regions on an ordinary process, so it
    // runs on a small dedicated pool (never the ETW delivery thread, which
    // must stay free to keep draining the real-time buffer) and is sampled at
    // most once every 250ms rather than on every single process start, so a
    // burst of process creation cannot pile up unbounded background work.
    etw_process_engine_.on_process_start([this](uint32_t pid, std::string) {
        if (!pipeline_) return;
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (now_ms - last_process_inspection_ms_ < 250) return;
        last_process_inspection_ms_ = now_ms;

        process_inspection_pool_.enqueue([this, pid] {
            security::ProcessBehaviorEngine inspector;
            for (auto& observation : inspector.inspect_pid(pid))
                if (pipeline_) pipeline_->publish(std::move(observation));
        });
    });
}

EngineManager::~EngineManager() {
    stop_all();
}

ErrorCode EngineManager::start_all() {
    if (pipeline_ && pipeline_->start() != ErrorCode::OK)
        return ErrorCode::ERR_ENGINE_START;

    // A real-time ETW session needs administrator (or Performance Log Users)
    // privilege. Its absence is not fatal to the rest of GCAD: report reality
    // through etw_kernel_process_active() rather than failing start_all().
    const auto etw_rc = etw_process_engine_.start();
    etw_process_engine_running_.store(etw_rc == ErrorCode::OK && etw_process_engine_.running());
    if (etw_rc != ErrorCode::OK) {
        GCAD_LOG(WARN, "EtwKernelProcess sensor not running: insufficient privilege for a "
                       "real-time ETW session (admin or Performance Log Users required)");
        poll_running_.store(true);
        process_poll_thread_ = std::thread(&EngineManager::process_poll_loop, this);
        GCAD_LOG(INFO, "ProcessBehaviorEngine fallback: polling via enumerate_processes()");
    }

    for (auto& e : engines_) {
        try {
            auto rc = e->start();
            if (rc != ErrorCode::OK) {
                GCAD_LOG(ERR, std::string("Failed to start engine (non-fatal): ") + std::string(e->name()));
            } else {
                GCAD_LOG(INFO, std::string("Engine started: ") + std::string(e->name()));
            }
        } catch (const std::exception& ex) {
            GCAD_LOG(ERR, std::string("Engine threw exception: ") + std::string(e->name()) + " — " + ex.what());
        } catch (...) {
            GCAD_LOG(ERR, std::string("Engine threw unknown exception: ") + std::string(e->name()));
        }
    }
    // Resilient start: a single engine that cannot start (e.g. raw socket without
    // admin rights) must not take down the whole app. Report reality via
    // all_running()/stopped_engines() instead of failing here.
    auto stopped = stopped_engines();
    if (!stopped.empty()) {
        std::string names;
        for (auto& n : stopped) names += (names.empty() ? "" : ", ") + n;
        GCAD_LOG(WARN, "Engines not running after start_all: " + names);
    }
    return ErrorCode::OK;
}

ErrorCode EngineManager::stop_all() {
    poll_running_.store(false);
    if (process_poll_thread_.joinable()) process_poll_thread_.join();

    for (auto& e : engines_) {
        if (e->running()) {
            e->stop();
            GCAD_LOG(INFO, std::string("Engine stopped: ") + std::string(e->name()));
        }
    }
    etw_process_engine_.stop();
    etw_process_engine_running_.store(false);
    if (pipeline_) pipeline_->stop();
    return ErrorCode::OK;
}

bool EngineManager::all_running() const noexcept {
    for (auto& e : engines_)
        if (!e->running()) return false;
    return !engines_.empty();
}

std::vector<std::string> EngineManager::stopped_engines() const {
    std::vector<std::string> out;
    for (auto& e : engines_)
        if (!e->running()) out.emplace_back(e->name());
    return out;
}

void EngineManager::on_global_threat(std::function<void(const ThreatEvent&)> cb) {
    global_cb_ = std::move(cb);
}

void EngineManager::push_event(ThreatEvent ev, std::string_view engine_source) {
    ev.id = next_id_.fetch_add(1);
    ev.timestamp = std::chrono::system_clock::now();

    {
        std::unique_lock lk(log_mtx_);
        event_log_.push_back(ev);
        if (event_log_.size() > 10000)
            event_log_.erase(event_log_.begin(), event_log_.begin() + 5000);
    }

    if (global_cb_) global_cb_(ev);

    if (pipeline_) pipeline_->publish(security::adapt_legacy_event(ev, engine_source));

    GCAD_LOG(WARN, std::string("Threat: [") + std::to_string(static_cast<int>(ev.level)) +
             "] " + ev.description);
}

std::vector<EngineStatus> EngineManager::statuses() const {
    std::vector<EngineStatus> out;
    out.reserve(engines_.size());
    for (auto& e : engines_)
        out.push_back(e->status());
    return out;
}

std::vector<ThreatEvent> EngineManager::recent_events(size_t n) const {
    std::shared_lock lk(log_mtx_);
    size_t start = event_log_.size() > n ? event_log_.size() - n : 0;
    return {event_log_.begin() + start, event_log_.end()};
}

size_t EngineManager::total_threats() const {
    std::shared_lock lk(log_mtx_);
    return event_log_.size();
}

ThreatLevel EngineManager::current_threat_level() const {
    std::shared_lock lk(log_mtx_);
    if (event_log_.empty()) return ThreatLevel::SAFE;

    auto now = std::chrono::system_clock::now();
    ThreatLevel max_level = ThreatLevel::SAFE;
    for (auto it = event_log_.rbegin(); it != event_log_.rend(); ++it) {
        auto age = std::chrono::duration_cast<std::chrono::minutes>(now - it->timestamp);
        if (age.count() > 10) break;
        if (it->level > max_level) max_level = it->level;
    }
    return max_level;
}

void EngineManager::publish_observation(security::SecurityObservation observation) {
    if (pipeline_) pipeline_->publish(std::move(observation));
}

std::vector<security::SecurityFinding> EngineManager::recent_security_findings(size_t n) const {
    return pipeline_ ? pipeline_->recent_findings(n) : std::vector<security::SecurityFinding>{};
}

std::vector<security::RemediationCandidate> EngineManager::recent_remediation_candidates(size_t n) const {
    return pipeline_ ? pipeline_->recent_candidates(n) : std::vector<security::RemediationCandidate>{};
}

std::optional<security::RemediationCandidate> EngineManager::find_remediation_candidate(uint64_t finding_id) const {
    return pipeline_ ? pipeline_->find_candidate(finding_id) : std::nullopt;
}

ErrorCode EngineManager::approve_remediation(uint64_t finding_id) {
    return pipeline_ ? pipeline_->approve_candidate(finding_id) : ErrorCode::ERR_NOT_FOUND;
}

ErrorCode EngineManager::reject_remediation(uint64_t finding_id) {
    return pipeline_ ? pipeline_->reject_candidate(finding_id) : ErrorCode::ERR_NOT_FOUND;
}

ErrorCode EngineManager::execute_quarantine(uint64_t finding_id, security::QuarantineRecord& out) {
    if (!pipeline_) return ErrorCode::ERR_NOT_FOUND;
    const auto candidate = pipeline_->find_candidate(finding_id);
    if (!candidate) return ErrorCode::ERR_NOT_FOUND;
    // QuarantineExecutor itself refuses anything not APPROVED; this call site
    // does not shortcut that check, it just surfaces ERR_NOT_FOUND separately
    // from "found but not approved" for a caller that wants to tell the two
    // apart (e.g. to show "approve it first" versus "no such finding").
    return quarantine_.quarantine(*candidate, out);
}

ErrorCode EngineManager::restore_quarantine(uint64_t record_id) {
    return quarantine_.restore(record_id);
}

std::vector<security::QuarantineRecord> EngineManager::recent_quarantine_records(size_t n) const {
    return quarantine_.records(n);
}

uint64_t EngineManager::total_engine_events() const {
    uint64_t sum = 0;
    for (auto& e : engines_) sum += e->status().events_processed;
    return sum;
}

std::array<size_t, 5> EngineManager::severity_histogram() const {
    std::array<size_t, 5> h{};
    std::shared_lock lk(log_mtx_);
    for (auto& ev : event_log_) {
        auto i = static_cast<size_t>(ev.level);
        if (i < h.size()) ++h[i];
    }
    return h;
}

std::vector<std::pair<ThreatCategory, size_t>> EngineManager::category_histogram() const {
    std::map<ThreatCategory, size_t> counts;
    {
        std::shared_lock lk(log_mtx_);
        for (auto& ev : event_log_) ++counts[ev.category];
    }
    std::vector<std::pair<ThreatCategory, size_t>> out(counts.begin(), counts.end());
    std::sort(out.begin(), out.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    return out;
}

ISecurityEngine* EngineManager::engine(std::string_view name) const {
    for (auto& e : engines_)
        if (e->name() == name) return e.get();
    return nullptr;
}

void EngineManager::process_poll_loop() {
    std::unordered_set<uint32_t> known;
    for (auto& p : platform::enumerate_processes())
        known.insert(p.pid);

    while (poll_running_.load()) {
        for (int i = 0; i < 30 && poll_running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!poll_running_.load()) break;

        auto procs = platform::enumerate_processes();
        std::unordered_set<uint32_t> current;
        current.reserve(procs.size());
        for (auto& p : procs) current.insert(p.pid);

        for (uint32_t pid : current) {
            if (known.count(pid)) continue;
            const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            if (now_ms - last_process_inspection_ms_ < 250) continue;
            last_process_inspection_ms_ = now_ms;

            process_inspection_pool_.enqueue([this, pid] {
                security::ProcessBehaviorEngine inspector;
                for (auto& observation : inspector.inspect_pid(pid))
                    if (pipeline_) pipeline_->publish(std::move(observation));
            });
        }
        known = std::move(current);
    }
}

} // namespace gcad
