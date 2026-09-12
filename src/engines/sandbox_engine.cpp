#include "gcad/engines/sandbox_engine.hpp"
#include <algorithm>
#include <sstream>
#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#endif

namespace gcad {

SandboxEngine::SandboxEngine() = default;
SandboxEngine::~SandboxEngine() { stop(); }

ErrorCode SandboxEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    worker_thread_ = std::thread(&SandboxEngine::worker_loop, this);
    GCAD_LOG(INFO, "Sandbox engine started");
    return ErrorCode::OK;
}

ErrorCode SandboxEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (worker_thread_.joinable()) worker_thread_.join();
    return ErrorCode::OK;
}

EngineStatus SandboxEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void SandboxEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void SandboxEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

uint64_t SandboxEngine::submit(const std::string& file_path, int timeout_ms) {
    std::lock_guard lk(mtx_);
    uint64_t id = next_id_.fetch_add(1);

    SandboxAnalysis sa;
    sa.id = id;
    sa.file_path = file_path;
    sa.started_at = std::chrono::system_clock::now();
    analyses_.push_back(sa);
    while (analyses_.size() > MAX_ANALYSES) analyses_.pop_front();

    pending_queue_.push_back({file_path, timeout_ms});
    return id;
}

SandboxAnalysis SandboxEngine::get_analysis(uint64_t id) const {
    std::lock_guard lk(mtx_);
    for (auto& a : analyses_) {
        if (a.id == id) return a;
    }
    return {};
}

std::vector<SandboxAnalysis> SandboxEngine::recent_analyses(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, analyses_.size());
    return {analyses_.end() - static_cast<ptrdiff_t>(count), analyses_.end()};
}

SandboxVerdict SandboxEngine::classify(const SandboxBehavior& b, double& out_risk) {
    double risk = 0.0;

    if (b.attempted_sandbox_escape)       risk += 40.0;
    if (b.attempted_process_injection)    risk += 35.0;
    if (b.attempted_privilege_escalation) risk += 30.0;
    if (b.attempted_debug_api)            risk += 15.0;
    if (b.encrypted_files)                risk += 35.0;
    if (b.modified_startup_entries)       risk += 20.0;

    if (b.files_deleted > 20) risk += 15.0;
    else if (b.files_deleted > 5) risk += 5.0;

    if (b.registry_writes > 10) risk += 10.0;
    else if (b.registry_writes > 3) risk += 5.0;

    if (b.network_connections > 5) risk += 10.0;
    else if (b.network_connections > 0) risk += 3.0;

    if (b.child_processes > 5) risk += 10.0;
    else if (b.child_processes > 2) risk += 5.0;

    if (b.memory_allocations > 50) risk += 5.0;

    risk += static_cast<double>(b.suspicious_apis.size()) * 5.0;

    risk = std::min(risk, 100.0);
    out_risk = risk;

    if (risk >= 70.0) return SandboxVerdict::MALICIOUS;
    if (risk >= 30.0) return SandboxVerdict::SUSPICIOUS;
    return SandboxVerdict::CLEAN;
}

std::string SandboxEngine::generate_summary(const SandboxBehavior& b, SandboxVerdict verdict) {
    std::ostringstream o;

    const char* verdict_str = "CLEAN";
    if (verdict == SandboxVerdict::MALICIOUS)  verdict_str = "MALICIOUS";
    else if (verdict == SandboxVerdict::SUSPICIOUS) verdict_str = "SUSPICIOUS";
    else if (verdict == SandboxVerdict::ANALYSIS_ERROR) verdict_str = "ERROR";

    o << "Verdict: " << verdict_str << ". ";

    if (b.attempted_sandbox_escape)
        o << "Sandbox escape attempt detected. ";
    if (b.attempted_process_injection)
        o << "Process injection attempt. ";
    if (b.attempted_privilege_escalation)
        o << "Privilege escalation attempt. ";
    if (b.encrypted_files)
        o << "File encryption activity (possible ransomware). ";
    if (b.modified_startup_entries)
        o << "Modified startup/autorun entries. ";

    o << "Files: " << b.files_created << " created, "
      << b.files_modified << " modified, " << b.files_deleted << " deleted. ";
    o << "Registry: " << b.registry_writes << " writes. ";
    o << "Network: " << b.network_connections << " connections. ";
    o << "Children: " << b.child_processes << ". ";

    if (!b.suspicious_apis.empty()) {
        o << "Suspicious APIs: ";
        for (size_t i = 0; i < b.suspicious_apis.size() && i < 5; ++i) {
            if (i > 0) o << ", ";
            o << b.suspicious_apis[i];
        }
        if (b.suspicious_apis.size() > 5) o << " (+" << (b.suspicious_apis.size() - 5) << " more)";
        o << ". ";
    }

    return o.str();
}

bool SandboxEngine::detect_escape_attempt(const SandboxBehavior& b) {
    if (b.attempted_sandbox_escape) return true;
    if (b.attempted_process_injection && b.attempted_privilege_escalation) return true;
    if (b.attempted_debug_api && b.child_processes > 3) return true;
    return false;
}

void SandboxEngine::worker_loop() {
    while (running_.load()) {
        std::string file_path;
        int timeout = DEFAULT_TIMEOUT_MS;

        {
            std::lock_guard lk(mtx_);
            if (!pending_queue_.empty()) {
                auto [f, t] = pending_queue_.front();
                pending_queue_.pop_front();
                file_path = f;
                timeout = t;
            }
        }

        if (!file_path.empty()) {
            auto result = analyze_file(file_path, timeout);
            events_processed_.fetch_add(1);

            {
                std::lock_guard lk(mtx_);
                for (auto& a : analyses_) {
                    if (a.file_path == file_path && a.verdict == SandboxVerdict::PENDING) {
                        uint64_t saved_id = a.id;
                        a = result;
                        a.id = saved_id;
                        break;
                    }
                }
            }

            if (result.verdict == SandboxVerdict::MALICIOUS) {
                emit_threat(ThreatCategory::SUSPICIOUS_BINARY,
                            "Sandbox: " + result.summary, file_path);
                emit_observation(security::ObservationKind::ARTIFACT_STRUCTURE,
                                 ThreatLevel::HIGH, result.risk_score / 100.0,
                                 result.summary, file_path);
            } else if (result.verdict == SandboxVerdict::SUSPICIOUS) {
                emit_observation(security::ObservationKind::ARTIFACT_STRUCTURE,
                                 ThreatLevel::MEDIUM, result.risk_score / 100.0,
                                 result.summary, file_path);
            }
        }

        for (int slept = 0; slept < 500 && running_.load(); slept += 50)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

SandboxAnalysis SandboxEngine::analyze_file(const std::string& file_path, int timeout_ms) {
    SandboxAnalysis sa;
    sa.file_path = file_path;
    sa.started_at = std::chrono::system_clock::now();

    if (!std::filesystem::exists(file_path)) {
        sa.verdict = SandboxVerdict::ANALYSIS_ERROR;
        sa.summary = "File not found: " + file_path;
        sa.completed_at = std::chrono::system_clock::now();
        return sa;
    }

    (void)std::filesystem::file_size(file_path);
    SandboxBehavior behavior;

#ifdef GCAD_PLATFORM_WINDOWS
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    HANDLE job = CreateJobObjectA(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit = 5;
        limits.ProcessMemoryLimit = 256 * 1024 * 1024;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                &limits, sizeof(limits));

        std::string cmd = "\"" + file_path + "\"";
        DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
        if (CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                           flags, nullptr, nullptr, &si, &pi)) {
            AssignProcessToJobObject(job, pi.hProcess);
            ResumeThread(pi.hThread);

            behavior = monitor_process(pi.dwProcessId, timeout_ms);

            WaitForSingleObject(pi.hProcess, static_cast<DWORD>(timeout_ms));
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            behavior.suspicious_apis.push_back("CreateProcess_failed");
        }
        CloseHandle(job);
    }
#else
    (void)timeout_ms;
    (void)file_size;
#endif

    double risk = 0.0;
    sa.verdict = classify(behavior, risk);
    sa.risk_score = risk;
    sa.behavior = behavior;
    sa.threat_level = (sa.verdict == SandboxVerdict::MALICIOUS) ? ThreatLevel::HIGH
                    : (sa.verdict == SandboxVerdict::SUSPICIOUS) ? ThreatLevel::MEDIUM
                    : ThreatLevel::SAFE;
    sa.summary = generate_summary(behavior, sa.verdict);
    sa.completed_at = std::chrono::system_clock::now();
    sa.duration_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(sa.completed_at - sa.started_at).count());
    return sa;
}

SandboxBehavior SandboxEngine::monitor_process(uint32_t pid, int timeout_ms) {
    SandboxBehavior b;

#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) return b;

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(timeout_ms)) {
        DWORD exit_code = STILL_ACTIVE;
        GetExitCodeProcess(proc, &exit_code);
        if (exit_code != STILL_ACTIVE) break;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me{};
            me.dwSize = sizeof(me);
            size_t module_count = 0;
            if (Module32First(snap, &me)) {
                do { ++module_count; } while (Module32Next(snap, &me));
            }
            b.dll_loads = module_count;
            CloseHandle(snap);
        }

        HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (proc_snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe{};
            pe.dwSize = sizeof(pe);
            if (Process32First(proc_snap, &pe)) {
                do {
                    if (pe.th32ParentProcessID == pid)
                        b.child_processes++;
                } while (Process32Next(proc_snap, &pe));
            }
            CloseHandle(proc_snap);
        }

        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = 0;
        while (VirtualQueryEx(proc, reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE))
                b.memory_allocations++;
            addr += mbi.RegionSize;
            if (addr == 0) break;
        }

        if (b.memory_allocations > 10)
            b.attempted_process_injection = true;

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    CloseHandle(proc);
#else
    (void)pid;
    (void)timeout_ms;
#endif

    return b;
}

void SandboxEngine::emit_threat(ThreatCategory cat, const std::string& desc,
                                 const std::string& file) {
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
        ev.file_path = file;
        ev.timestamp = std::chrono::system_clock::now();
        cb(std::move(ev));
    }
}

void SandboxEngine::emit_observation(security::ObservationKind kind, ThreatLevel level,
                                      double confidence, const std::string& evidence,
                                      const std::string& file) {
    std::function<void(security::SecurityObservation)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = observation_cb_;
    }
    if (cb) {
        security::SecurityObservation obs{};
        obs.source_id = "sandbox";
        obs.kind = kind;
        obs.timestamp = std::chrono::system_clock::now();
        obs.suggested_level = level;
        obs.confidence = confidence;
        obs.deterministic = false;
        obs.file_path = file;
        obs.evidence = evidence;
        cb(std::move(obs));
    }
}

} // namespace gcad
