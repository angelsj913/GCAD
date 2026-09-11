#include "gcad/security/etw_kernel_process_engine.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <evntrace.h>
#include <tdh.h>
#include <cwchar>

#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)-1)
#endif
#endif

namespace gcad::security {

namespace {

#ifdef GCAD_PLATFORM_WINDOWS
constexpr const wchar_t* kSessionName = L"GCAD-EtwKernelProcess";

// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
constexpr GUID kKernelProcessProviderGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

constexpr uint16_t kEventProcessStart = 1;
constexpr uint16_t kEventProcessStop  = 2;
constexpr size_t   MAX_KNOWN_CREATE_TIMES = 8192;

std::optional<uint32_t> get_uint32_property(PEVENT_RECORD record, PCWSTR name) {
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
    desc.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size < sizeof(uint32_t))
        return std::nullopt;
    std::vector<uint8_t> buffer(size);
    if (TdhGetProperty(record, 0, nullptr, 1, &desc, size, buffer.data()) != ERROR_SUCCESS)
        return std::nullopt;
    uint32_t value = 0;
    std::memcpy(&value, buffer.data(), sizeof(value));
    return value;
}

std::optional<uint64_t> get_uint64_property(PEVENT_RECORD record, PCWSTR name) {
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
    desc.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size < sizeof(uint64_t))
        return std::nullopt;
    std::vector<uint8_t> buffer(size);
    if (TdhGetProperty(record, 0, nullptr, 1, &desc, size, buffer.data()) != ERROR_SUCCESS)
        return std::nullopt;
    uint64_t value = 0;
    std::memcpy(&value, buffer.data(), sizeof(value));
    return value;
}

std::string get_wstring_property(PEVENT_RECORD record, PCWSTR name) {
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
    desc.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size == 0)
        return {};
    std::vector<uint8_t> buffer(size);
    if (TdhGetProperty(record, 0, nullptr, 1, &desc, size, buffer.data()) != ERROR_SUCCESS)
        return {};

    const auto* wide = reinterpret_cast<const wchar_t*>(buffer.data());
    size_t wlen = size / sizeof(wchar_t);
    while (wlen > 0 && wide[wlen - 1] == L'\0') --wlen;
    if (wlen == 0) return {};

    const int needed = WideCharToMultiByte(CP_UTF8, 0, wide, static_cast<int>(wlen), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, static_cast<int>(wlen), out.data(), needed, nullptr, nullptr);
    return out;
}
#endif // GCAD_PLATFORM_WINDOWS

} // namespace

#ifdef GCAD_PLATFORM_WINDOWS
struct EtwKernelProcessEngine::Session {
    std::vector<uint8_t> properties_buffer;
    TRACEHANDLE           trace_handle{0};
    TRACEHANDLE           consumer_handle{INVALID_PROCESSTRACE_HANDLE};
    bool                  session_started{false};
    bool                  consumer_opened{false};

    EVENT_TRACE_PROPERTIES* properties() {
        return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer.data());
    }
};
#endif

EtwKernelProcessEngine::EtwKernelProcessEngine() = default;
EtwKernelProcessEngine::~EtwKernelProcessEngine() { stop(); }

void EtwKernelProcessEngine::on_observation(std::function<void(SecurityObservation)> cb) {
    std::lock_guard lk(cb_mtx_);
    observation_cb_ = std::move(cb);
}

void EtwKernelProcessEngine::dispatch(SecurityObservation observation) {
    std::function<void(SecurityObservation)> cb;
    {
        std::lock_guard lk(cb_mtx_);
        cb = observation_cb_;
    }
    if (cb) cb(std::move(observation)); // invoked outside cb_mtx_
}

bool EtwKernelProcessEngine::is_impossible_parent_order(uint64_t child_created_filetime,
                                                        uint64_t parent_created_filetime) noexcept {
    return child_created_filetime != 0 && parent_created_filetime != 0 &&
           parent_created_filetime > child_created_filetime;
}

SecurityObservation EtwKernelProcessEngine::make_lineage_observation(
    uint32_t pid, uint32_t parent_pid, const std::string& image_name) {
    SecurityObservation observation{};
    observation.source_id = "etw-kernel-process";
    observation.kind = ObservationKind::PROCESS_LINEAGE;
    observation.timestamp = std::chrono::system_clock::now();
    observation.suggested_level = ThreatLevel::HIGH;
    observation.confidence = 0.90;
    observation.deterministic = true; // CreateTime ordering is an exact proof, not a guess
    observation.process_id = pid;
    observation.process_name = image_name;
    observation.file_path = image_name;
    observation.evidence = "Kernel-Process ETW reported live parent PID " + std::to_string(parent_pid) +
                           " created after this process (CreateTime order violation)";
    return observation;
}

#ifndef GCAD_PLATFORM_WINDOWS

ErrorCode EtwKernelProcessEngine::start() {
    // Real-time ETW session consumption is Windows-only. Linux keeps a
    // compile-safe stub that never reports running() so callers cannot mistake
    // this for active kernel telemetry.
    return ErrorCode::OK;
}

ErrorCode EtwKernelProcessEngine::stop() { return ErrorCode::OK; }

#else // GCAD_PLATFORM_WINDOWS

void EtwKernelProcessEngine::handle_process_event(uint16_t event_id, uint32_t pid, uint32_t parent_pid,
                                                  uint64_t create_time_filetime, const std::string& image_name) {
    if (event_id == kEventProcessStart) {
        {
            std::lock_guard lk(known_parents_mtx_);
            if (known_create_times_.size() >= MAX_KNOWN_CREATE_TIMES) known_create_times_.clear();
            known_create_times_[pid] = create_time_filetime;
        }

        if (parent_pid != 0 && parent_pid != pid) {
            uint64_t parent_created = 0;
            {
                std::lock_guard lk(known_parents_mtx_);
                auto it = known_create_times_.find(parent_pid);
                if (it != known_create_times_.end()) parent_created = it->second;
            }
            if (parent_created == 0) {
                // Parent existed before this engine started observing: ask the OS
                // directly for its live creation time (one documented query call).
                HANDLE parent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent_pid);
                if (parent) {
                    FILETIME created{}, exited{}, kernel{}, user{};
                    if (GetProcessTimes(parent, &created, &exited, &kernel, &user))
                        parent_created = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
                    CloseHandle(parent);
                }
            }
            if (is_impossible_parent_order(create_time_filetime, parent_created))
                dispatch(make_lineage_observation(pid, parent_pid, image_name));
        }
    } else if (event_id == kEventProcessStop) {
        std::lock_guard lk(known_parents_mtx_);
        known_create_times_.erase(pid);
    }
}

void EtwKernelProcessEngine::on_event_record(PEVENT_RECORD record) {
    if (!IsEqualGUID(record->EventHeader.ProviderId, kKernelProcessProviderGuid)) return;
    const uint16_t event_id = record->EventHeader.EventDescriptor.Id;
    if (event_id != kEventProcessStart && event_id != kEventProcessStop) return;

    const auto pid = get_uint32_property(record, L"ProcessID");
    const auto ppid = get_uint32_property(record, L"ParentProcessID");
    const auto create_time = get_uint64_property(record, L"CreateTime");
    if (!pid || !create_time) return; // insufficient documented evidence: never guess
    const std::string image = get_wstring_property(record, L"ImageName");

    handle_process_event(event_id, *pid, ppid.value_or(0), *create_time, image);
}

void WINAPI EtwKernelProcessEngine::trace_callback(PEVENT_RECORD record) {
    if (!record || !record->UserContext) return;
    static_cast<EtwKernelProcessEngine*>(record->UserContext)->on_event_record(record);
}

ErrorCode EtwKernelProcessEngine::open_session() {
    session_ = std::make_unique<Session>();
    const size_t name_bytes = (std::wcslen(kSessionName) + 1) * sizeof(wchar_t);
    const size_t total = sizeof(EVENT_TRACE_PROPERTIES) + name_bytes;
    session_->properties_buffer.assign(total, 0);

    auto init_properties = [&] {
        auto* props = session_->properties();
        std::memset(props, 0, sizeof(EVENT_TRACE_PROPERTIES));
        props->Wnode.BufferSize = static_cast<ULONG>(total);
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1; // QPC timer resolution
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    };
    init_properties();

    ULONG rc = StartTraceW(&session_->trace_handle, kSessionName, session_->properties());
    if (rc == ERROR_ALREADY_EXISTS) {
        // A prior run did not shut down cleanly (crash/kill). Stop the stale
        // session by name and retry once rather than failing permanently.
        ControlTraceW(0, kSessionName, session_->properties(), EVENT_TRACE_CONTROL_STOP);
        init_properties();
        rc = StartTraceW(&session_->trace_handle, kSessionName, session_->properties());
    }
    if (rc != ERROR_SUCCESS) {
        GCAD_LOG(WARN, "EtwKernelProcess: StartTrace failed (rc=" + std::to_string(rc) +
                        "); real-time ETW requires administrator privileges");
        session_.reset();
        return ErrorCode::ERR_ENGINE_START;
    }
    session_->session_started = true;

    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    rc = EnableTraceEx2(session_->trace_handle, &kKernelProcessProviderGuid,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, &params);
    if (rc != ERROR_SUCCESS) {
        GCAD_LOG(WARN, "EtwKernelProcess: EnableTraceEx2 failed (rc=" + std::to_string(rc) + ")");
        close_session();
        return ErrorCode::ERR_ENGINE_START;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(kSessionName);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwKernelProcessEngine::trace_callback;
    logfile.Context = this;

    session_->consumer_handle = OpenTraceW(&logfile);
    if (session_->consumer_handle == INVALID_PROCESSTRACE_HANDLE) {
        GCAD_LOG(WARN, "EtwKernelProcess: OpenTrace failed");
        close_session();
        return ErrorCode::ERR_ENGINE_START;
    }
    session_->consumer_opened = true;
    return ErrorCode::OK;
}

void EtwKernelProcessEngine::close_session() {
    if (!session_) return;
    if (session_->consumer_opened) {
        CloseTrace(session_->consumer_handle);
        session_->consumer_opened = false;
    }
    if (session_->session_started) {
        ControlTraceW(session_->trace_handle, nullptr, session_->properties(), EVENT_TRACE_CONTROL_STOP);
        session_->session_started = false;
    }
    session_.reset();
}

ErrorCode EtwKernelProcessEngine::start() {
    if (running_.load()) return ErrorCode::OK;

    const auto rc = open_session();
    if (rc != ErrorCode::OK) return rc;

    running_.store(true);
    const TRACEHANDLE handle = session_->consumer_handle;
    try {
        consumer_thread_ = std::thread([handle] {
            TRACEHANDLE local = handle;
            // Blocks, dispatching to trace_callback, until CloseTrace (stop())
            // ends the real-time session.
            ProcessTrace(&local, 1, nullptr, nullptr);
        });
    } catch (...) {
        running_.store(false);
        close_session();
        return ErrorCode::ERR_ENGINE_START;
    }

    GCAD_LOG(INFO, "EtwKernelProcess engine started (real-time Kernel-Process ETW session)");
    return ErrorCode::OK;
}

ErrorCode EtwKernelProcessEngine::stop() {
    if (!running_.exchange(false)) return ErrorCode::OK;
    close_session(); // CloseTrace releases ProcessTrace's blocking wait
    if (consumer_thread_.joinable()) consumer_thread_.join();
    {
        std::lock_guard lk(known_parents_mtx_);
        known_create_times_.clear();
    }
    return ErrorCode::OK;
}

#endif // GCAD_PLATFORM_WINDOWS

} // namespace gcad::security
