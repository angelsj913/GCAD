#pragma once
#include "../i_security_engine.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>

namespace gcad {

struct PipeInfo {
    std::string pipe_name;
    bool        is_suspicious{false};
    std::string matched_framework;
    std::string reason;
};

class NamedPipeEngine final : public ISecurityEngine {
    std::atomic<bool>                running_{false};
    std::thread                      monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    mutable std::mutex               mtx_;

    std::atomic<uint64_t>            events_processed_{0};
    std::atomic<uint64_t>            threats_detected_{0};

    std::unordered_set<std::string>  known_pipes_;

    void monitor_loop();
    void emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid = 0);

public:
    NamedPipeEngine();
    ~NamedPipeEngine() override;

    std::string_view name() const noexcept override { return "NamedPipe-Defense"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    std::vector<PipeInfo> scan_active_pipes();

    static bool is_c2_pipe(std::string_view pipe_name,
                           std::string& out_framework,
                           std::string& out_reason);
};

} // namespace gcad
