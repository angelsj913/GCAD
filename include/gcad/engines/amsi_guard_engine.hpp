#pragma once
#include "../i_security_engine.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

namespace gcad {

enum class ScriptRiskLevel : uint8_t {
    BENIGN     = 0,
    SUSPICIOUS = 1,
    MALICIOUS  = 2
};

struct ScriptScanResult {
    ScriptRiskLevel          risk{ScriptRiskLevel::BENIGN};
    int                      score{0};
    std::vector<std::string> matched_indicators;
};

class AmsiGuardEngine final : public ISecurityEngine {
    std::atomic<bool>                running_{false};
    std::thread                      monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    mutable std::mutex               mtx_;

    std::atomic<uint64_t>            events_processed_{0};
    std::atomic<uint64_t>            threats_detected_{0};

    std::vector<uint8_t>             original_prologue_;
    uintptr_t                        amsi_scan_buffer_addr_{0};
    bool                             amsi_available_{false};
    bool                             bypass_detected_{false};

    void monitor_loop();
    void emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid = 0);

public:
    AmsiGuardEngine();
    ~AmsiGuardEngine() override;

    std::string_view name() const noexcept override { return "AMSI-Guard"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    bool check_amsi_integrity();
    bool restore_amsi_prologue();
    ScriptScanResult scan_script_buffer(std::string_view script_content);

    static bool is_patch_bypass(const uint8_t* code_bytes, size_t len);
};

} // namespace gcad
