#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <unordered_map>

namespace gcad {

struct FileIntegrityEntry {
    std::filesystem::path path;
    std::string           sha256;
    uint64_t              size{0};
    std::filesystem::file_time_type mtime{};
};

class FileIntegrityEngine final : public ISecurityEngine {
public:
    FileIntegrityEngine();
    ~FileIntegrityEngine() override;

    std::string_view name() const noexcept override { return "FIM"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void on_observation(std::function<void(security::SecurityObservation)> cb);
    void add_watch_path(const std::filesystem::path& path);

    static std::vector<std::filesystem::path> default_watch_paths();

    size_t baseline_size() const;

private:
    std::atomic<bool>                        running_{false};
    std::atomic<uint64_t>                    events_processed_{0};
    std::atomic<uint64_t>                    threats_detected_{0};
    std::thread                              monitor_thread_;
    mutable std::mutex                       mtx_;
    std::function<void(ThreatEvent)>         threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    std::vector<std::filesystem::path>       watch_paths_;
    std::unordered_map<std::string, FileIntegrityEntry> baseline_;

    void monitor_loop();
    void build_baseline();
    void check_integrity();
    void emit_threat(ThreatCategory cat, const std::string& desc, const std::string& file_path);
    void emit_observation(const std::string& evidence, const std::string& file_path, const std::string& sha256);
};

} // namespace gcad
