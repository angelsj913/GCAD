#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <unordered_map>
#include <vector>
#include <atomic>

namespace gcad {

enum class SandboxVerdict : uint8_t {
    PENDING = 0,
    CLEAN   = 1,
    SUSPICIOUS = 2,
    MALICIOUS  = 3,
    ANALYSIS_ERROR = 4
};

struct SandboxBehavior {
    size_t files_created{0};
    size_t files_modified{0};
    size_t files_deleted{0};
    size_t registry_writes{0};
    size_t network_connections{0};
    size_t child_processes{0};
    size_t dll_loads{0};
    size_t memory_allocations{0};
    bool   attempted_privilege_escalation{false};
    bool   attempted_debug_api{false};
    bool   attempted_process_injection{false};
    bool   attempted_sandbox_escape{false};
    bool   modified_startup_entries{false};
    bool   encrypted_files{false};
    std::vector<std::string> suspicious_apis;
    std::vector<std::string> network_destinations;
    std::vector<std::string> dropped_files;
};

struct SandboxAnalysis {
    uint64_t    id{0};
    std::string file_path;
    std::string file_hash;
    uint32_t    pid{0};
    SandboxVerdict verdict{SandboxVerdict::PENDING};
    ThreatLevel    threat_level{ThreatLevel::SAFE};
    double         risk_score{0.0};
    SandboxBehavior behavior;
    std::string    summary;
    std::chrono::system_clock::time_point started_at{};
    std::chrono::system_clock::time_point completed_at{};
    int            duration_ms{0};
};

class SandboxEngine final : public ISecurityEngine {
public:
    SandboxEngine();
    ~SandboxEngine() override;

    std::string_view name() const noexcept override { return "Sandbox"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    uint64_t submit(const std::string& file_path, int timeout_ms = 30000);
    SandboxAnalysis get_analysis(uint64_t id) const;
    std::vector<SandboxAnalysis> recent_analyses(size_t n = 50) const;

    static SandboxVerdict classify(const SandboxBehavior& behavior, double& out_risk);
    static std::string generate_summary(const SandboxBehavior& behavior, SandboxVerdict verdict);
    static bool detect_escape_attempt(const SandboxBehavior& behavior);

    static constexpr size_t MAX_ANALYSES = 500;
    static constexpr int    DEFAULT_TIMEOUT_MS = 30000;

private:
    std::atomic<bool>    running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};

    mutable std::mutex   mtx_;
    std::deque<SandboxAnalysis>  analyses_;
    std::deque<std::pair<std::string, int>> pending_queue_;
    std::thread          worker_thread_;

    std::function<void(ThreatEvent)> threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void worker_loop();
    SandboxAnalysis analyze_file(const std::string& file_path, int timeout_ms);
    SandboxBehavior monitor_process(uint32_t pid, int timeout_ms);
    void emit_threat(ThreatCategory cat, const std::string& desc, const std::string& file);
    void emit_observation(security::ObservationKind kind, ThreatLevel level,
                          double confidence, const std::string& evidence,
                          const std::string& file);
};

} // namespace gcad
