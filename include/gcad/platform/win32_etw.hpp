#pragma once
#include "../common.hpp"

#ifdef GCAD_PLATFORM_WINDOWS

namespace gcad::platform {

struct EtwEvent {
    uint32_t    process_id;
    uint32_t    thread_id;
    uint16_t    event_id;
    std::string provider_name;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

class Win32Etw {
    std::atomic<bool> running_{false};
    std::thread       trace_thread_;
    mutable std::mutex mtx_;
    std::vector<EtwEvent> events_;
    std::function<void(const EtwEvent&)> callback_;

    void trace_loop();

public:
    Win32Etw();
    ~Win32Etw();

    ErrorCode start();
    ErrorCode stop();
    bool running() const noexcept { return running_.load(); }

    void on_event(std::function<void(const EtwEvent&)> cb);
    std::vector<EtwEvent> recent(size_t n = 50) const;

    bool check_amsi_tampering();
    bool check_etw_tampering();
    bool detect_memory_write(uint32_t pid, uintptr_t addr, size_t size);
    std::vector<uint32_t> find_suspicious_process_creation();
    bool detect_ppid_spoofing(uint32_t pid);
};

} // namespace gcad::platform

#endif
