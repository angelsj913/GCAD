#pragma once

#include "observation.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <evntcons.h>
#endif

namespace gcad::security {

// Consumes the manifested Microsoft-Windows-Kernel-Process ETW provider in real
// time via StartTrace/EnableTraceEx2/OpenTrace/ProcessTrace. This is a genuine
// ETW consumer: unlike platform::Win32Etw -- which polls process snapshots with
// CreateToolhelp32Snapshot and inspects this process's own AMSI/ETW entry points
// -- this engine subscribes to kernel-logged ProcessStart/ProcessStop events and
// reacts to each one as it is delivered.
//
// It emits a SecurityObservation only for the same documented, deterministic
// condition ProcessBehaviorEngine already reports on demand: a process whose
// claimed live parent was created strictly after it. Observing this through ETW
// removes the polling gap (a short-lived process can start and exit between two
// snapshot polls) rather than adding a new detection claim. It does not assert
// that ETW defeats every EPROCESS-level parent-spoofing technique; the parent
// field is whatever the kernel recorded at process-creation time, the same field
// CreateToolhelp32Snapshot reports.
//
// Starting a real-time ETW session requires administrator privileges (or
// membership in the "Performance Log Users" group). When the caller lacks that
// privilege, start() returns ErrorCode::ERR_ENGINE_START and running() stays
// false -- it never fabricates telemetry to appear active.
class EtwKernelProcessEngine final {
public:
    EtwKernelProcessEngine();
    ~EtwKernelProcessEngine();

    EtwKernelProcessEngine(const EtwKernelProcessEngine&) = delete;
    EtwKernelProcessEngine& operator=(const EtwKernelProcessEngine&) = delete;

    ErrorCode start();
    ErrorCode stop();
    bool running() const noexcept { return running_.load(); }

    void on_observation(std::function<void(SecurityObservation)> cb);

    // Pure decision/construction logic -- no Windows API calls, no live session
    // required. Directly unit-testable on every platform.
    static bool is_impossible_parent_order(uint64_t child_created_filetime,
                                           uint64_t parent_created_filetime) noexcept;
    static SecurityObservation make_lineage_observation(uint32_t pid, uint32_t parent_pid,
                                                        const std::string& image_name);

private:
    std::atomic<bool>                        running_{false};
    std::mutex                               cb_mtx_;
    std::function<void(SecurityObservation)> observation_cb_;

    void dispatch(SecurityObservation observation);

#ifdef GCAD_PLATFORM_WINDOWS
    struct Session;
    std::unique_ptr<Session> session_;
    std::thread              consumer_thread_;
    std::mutex               known_parents_mtx_;
    std::unordered_map<uint32_t, uint64_t> known_create_times_; // pid -> CreateTime (bounded)

    static void WINAPI trace_callback(PEVENT_RECORD record);
    void on_event_record(PEVENT_RECORD record);
    void handle_process_event(uint16_t event_id, uint32_t pid, uint32_t parent_pid,
                              uint64_t create_time_filetime, const std::string& image_name);
    ErrorCode open_session();
    void close_session();
#endif
};

} // namespace gcad::security
