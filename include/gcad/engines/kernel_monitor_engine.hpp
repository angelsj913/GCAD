#pragma once
#include "../i_security_engine.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include "../platform/win32_etw.hpp"
#else
#include "../platform/linux_ebpf.hpp"
#endif

namespace gcad {

// Bridges the platform kernel-telemetry monitor (ETW on Windows, fanotify/proc
// connector on Linux) into the EngineManager as a first-class security engine,
// translating its events into ThreatEvents.
class KernelMonitorEngine final : public ISecurityEngine {
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::mutex            mtx_;
    std::function<void(ThreatEvent)> threat_cb_;

#ifdef GCAD_PLATFORM_WINDOWS
    platform::Win32Etw monitor_;
#else
    platform::LinuxEbpf monitor_;
#endif

    void emit(ThreatLevel level, ThreatCategory cat, const std::string& desc, uint32_t pid);

public:
    KernelMonitorEngine() = default;
    ~KernelMonitorEngine() override { stop(); }

    std::string_view name() const noexcept override { return "KernelMon"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
};

} // namespace gcad
