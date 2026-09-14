#pragma once
#include "../i_security_engine.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

namespace gcad {

enum class DriverRiskLevel : uint8_t {
    BENIGN = 0,
    SUSPICIOUS = 1,
    VULNERABLE_KNOWN = 2,
    MALICIOUS_UNSIGNED = 3
};

struct DriverInfo {
    std::string     driver_name;
    std::string     file_path;
    std::string     sha256;
    bool            is_signed{true};
    bool            is_vulnerable_byovd{false};
    DriverRiskLevel risk{DriverRiskLevel::BENIGN};
    std::string     threat_detail;
};

class DriverGuardEngine final : public ISecurityEngine {
    std::atomic<bool>                running_{false};
    std::thread                      monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    mutable std::mutex               mtx_;

    std::atomic<uint64_t>            events_processed_{0};
    std::atomic<uint64_t>            threats_detected_{0};

    void monitor_loop();
    void emit_threat(const DriverInfo& drv);

public:
    DriverGuardEngine();
    ~DriverGuardEngine() override;

    std::string_view name() const noexcept override { return "DriverGuard"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    // BYOVD and driver validation
    static bool is_known_vulnerable_driver(std::string_view driver_name);
    static bool is_suspicious_driver_path(std::string_view path);
    DriverInfo evaluate_driver_load(std::string_view driver_name, std::string_view path, bool is_signed);
};

} // namespace gcad
