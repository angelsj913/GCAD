#pragma once
#include "../i_security_engine.hpp"

namespace gcad {

struct CowSnapshot {
    std::filesystem::path   path;
    std::vector<uint8_t>    original_data;
    uint64_t                original_size;
    std::string             sha256_hash;
    std::chrono::system_clock::time_point capture_time;
};

struct SandboxedProcess {
    uint32_t    pid;
    std::string name;
    ThreatCategory reason;
    std::chrono::system_clock::time_point suspended_at;
    std::vector<CowSnapshot> snapshots;
};

class ARHSEngine final : public ISecurityEngine {
    std::atomic<bool>                    running_{false};
    std::thread                          watch_thread_;
    std::function<void(ThreatEvent)>     threat_cb_;
    mutable std::mutex                   mtx_;

    std::vector<std::filesystem::path>   watch_dirs_;
    std::unordered_map<std::string, std::string> file_hashes_;
    std::vector<SandboxedProcess>        sandboxed_;
    std::vector<CowSnapshot>            snapshot_ring_;

    static constexpr size_t MAX_SNAPSHOTS = 4096;
    static constexpr size_t MAX_SNAPSHOT_FILE_SIZE = 64 * 1024 * 1024;
    static constexpr double RANSOMWARE_ENTROPY_THRESH = 7.8;
    static constexpr size_t RAPID_CHANGE_THRESH = 20;
    static constexpr auto   RAPID_CHANGE_WINDOW = std::chrono::seconds(5);

    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> rollbacks_performed_{0};

    struct ChangeRecord {
        std::filesystem::path path;
        std::chrono::steady_clock::time_point when;
    };
    std::vector<ChangeRecord> recent_changes_;

    void watch_loop();
    void scan_directory(const std::filesystem::path& dir);
    void take_snapshot_unlocked(const std::filesystem::path& path);
    bool detect_rapid_encryption();
    void emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid = 0, const std::string& path = "");

public:
    ARHSEngine();
    ~ARHSEngine() override;

    std::string_view name() const noexcept override { return "ARHS"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void add_watch_directory(const std::filesystem::path& dir);
    void take_snapshot(const std::filesystem::path& path);
    ErrorCode rollback_file(const std::filesystem::path& path);
    ErrorCode rollback_process(uint32_t pid);
    ErrorCode suspend_process(uint32_t pid, ThreatCategory reason);

    std::vector<SandboxedProcess> sandboxed_processes() const;
    uint64_t rollbacks_performed() const noexcept { return rollbacks_performed_.load(); }
};

} // namespace gcad
