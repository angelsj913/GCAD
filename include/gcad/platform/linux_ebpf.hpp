#pragma once
#include "../common.hpp"

#ifdef GCAD_PLATFORM_LINUX

namespace gcad::platform {

struct FileEvent {
    uint32_t    pid;
    std::string path;
    uint32_t    mask;
    std::chrono::system_clock::time_point timestamp;
};

struct ProcessEvent {
    uint32_t    pid;
    uint32_t    ppid;
    std::string comm;
    std::string exe;
    bool        is_exec;
    std::chrono::system_clock::time_point timestamp;
};

class LinuxEbpf {
    std::atomic<bool> running_{false};
    std::thread       fanotify_thread_;
    std::thread       proc_thread_;
    mutable std::mutex mtx_;

    int fanotify_fd_{-1};
    std::vector<FileEvent>    file_events_;
    std::vector<ProcessEvent> proc_events_;
    std::function<void(const FileEvent&)>    file_cb_;
    std::function<void(const ProcessEvent&)> proc_cb_;

    void fanotify_loop();
    void proc_connector_loop();

public:
    LinuxEbpf();
    ~LinuxEbpf();

    ErrorCode start();
    ErrorCode stop();
    bool running() const noexcept { return running_.load(); }

    void on_file_event(std::function<void(const FileEvent&)> cb);
    void on_process_event(std::function<void(const ProcessEvent&)> cb);
    void add_watch(const std::filesystem::path& path);

    std::vector<FileEvent>    recent_file_events(size_t n = 50) const;
    std::vector<ProcessEvent> recent_proc_events(size_t n = 50) const;
};

} // namespace gcad::platform

#endif
