#include "gcad/engines/kernel_monitor_engine.hpp"

namespace gcad {

void KernelMonitorEngine::emit(ThreatLevel level, ThreatCategory cat,
                               const std::string& desc, uint32_t pid) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.level = level;
        ev.category = cat;
        ev.process_id = pid;
        ev.description = desc;
        cb(std::move(ev));
    }
}

ErrorCode KernelMonitorEngine::start() {
    if (running_.load()) return ErrorCode::OK;

#ifdef GCAD_PLATFORM_WINDOWS
    monitor_.on_event([this](const platform::EtwEvent& e) {
        events_processed_.fetch_add(1);
        switch (e.event_id) {
            case 2:
                emit(ThreatLevel::CRITICAL, ThreatCategory::EVASION_AMSI, e.description, e.process_id);
                break;
            case 3:
                emit(ThreatLevel::HIGH, ThreatCategory::EVASION_ETW, e.description, e.process_id);
                break;
            case 1:
                emit(ThreatLevel::HIGH, ThreatCategory::PPID_SPOOF, e.description, e.process_id);
                break;
            default:
                break;
        }
    });
#else
    monitor_.on_process_event([this](const platform::ProcessEvent& e) {
        events_processed_.fetch_add(1);
        if (e.is_exec && (e.exe.rfind("/tmp/", 0) == 0 || e.exe.rfind("/dev/shm/", 0) == 0)) {
            emit(ThreatLevel::HIGH, ThreatCategory::SUSPICIOUS_BINARY,
                 "Process exec from volatile path: " + e.exe, e.pid);
        }
    });
    monitor_.on_file_event([this](const platform::FileEvent&) {
        events_processed_.fetch_add(1);
    });
#endif

    auto rc = monitor_.start();
    if (rc != ErrorCode::OK) return rc;
    running_.store(true);
    GCAD_LOG(INFO, "KernelMon engine started");
    return ErrorCode::OK;
}

ErrorCode KernelMonitorEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    monitor_.stop();
    return ErrorCode::OK;
}

EngineStatus KernelMonitorEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void KernelMonitorEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

} // namespace gcad
