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
//
// Event payloads are decoded directly from the raw UserData bytes against the
// provider's documented manifest field layout (decode_process_start()) rather
// than through TDH (TdhGetProperty/TdhFormatProperty), which would look the
// schema up and extract values on GCAD's behalf. The field layout itself is
// necessarily still a hardcoded assumption sourced from published
// documentation of this specific provider -- a manifest-based ETW event does
// not self-describe its own schema, so *some* external schema knowledge is
// unavoidable whether TDH or GCAD supplies it. That assumption has not been
// verified against a live capture in this environment (no administrator
// session was available to start a real-time trace and inspect real bytes);
// decode_process_start() fails closed (returns nullopt) rather than guess
// when the buffer does not fit the expected shape.
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

    // Fires once per ProcessStart event regardless of the lineage check
    // above -- unlike on_observation(), which only fires for the anomaly
    // case. A caller can use this to run its own inspection (e.g.
    // ProcessBehaviorEngine::inspect_pid) exactly once per new process,
    // riding this engine's existing ETW subscription instead of adding a
    // separate polling loop.
    void on_process_start(std::function<void(uint32_t pid, std::string image_name)> cb);

    // Pure decision/construction logic -- no Windows API calls, no live session
    // required. Directly unit-testable on every platform.
    static bool is_impossible_parent_order(uint64_t child_created_filetime,
                                           uint64_t parent_created_filetime) noexcept;
    static SecurityObservation make_lineage_observation(uint32_t pid, uint32_t parent_pid,
                                                        const std::string& image_name);

    struct DecodedProcessStart {
        uint32_t    pid;
        uint32_t    parent_pid;
        uint64_t    create_time_filetime;
        std::string image_name;
    };

    // Decodes a Kernel-Process ProcessStart (event ID 1) UserData buffer per
    // the manifest field order: ProcessID(UInt32), ProcessSequenceNumber
    // (UInt64, unused), CreateTime(FILETIME/UInt64), ParentProcessID(UInt32),
    // ParentProcessSequenceNumber(UInt64, unused), SessionID(UInt32, unused),
    // Flags(UInt32, unused), then ImageName as a NUL-terminated UTF-16LE
    // string running to the end of the buffer. Returns nullopt for a buffer
    // too short for the fixed 40-byte prefix, or a zero PID.
    static std::optional<DecodedProcessStart> decode_process_start(const uint8_t* data, size_t size);

    // Decodes a Kernel-Process ProcessStop (event ID 2) UserData buffer: only
    // ProcessID (the first UInt32) is read, since that is all this engine uses.
    static std::optional<uint32_t> decode_process_stop_pid(const uint8_t* data, size_t size) noexcept;

private:
    std::atomic<bool>                        running_{false};
    std::mutex                               cb_mtx_;
    std::function<void(SecurityObservation)> observation_cb_;
    std::function<void(uint32_t, std::string)> process_start_cb_;

    void dispatch(SecurityObservation observation);
    void dispatch_process_start(uint32_t pid, std::string image_name);

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
