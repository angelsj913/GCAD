#include "gcad/security/etw_kernel_process_engine.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <evntrace.h>
#include <cwchar>

#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)-1)
#endif
#endif

namespace gcad::security {

namespace {

// Fixed-size prefix of a Kernel-Process ProcessStart UserData buffer, per the
// documented manifest field order: ProcessID(4) + ProcessSequenceNumber(8) +
// CreateTime(8) + ParentProcessID(4) + ParentProcessSequenceNumber(8) +
// SessionID(4) + Flags(4).
constexpr size_t kProcessStartFixedPrefixSize = 4 + 8 + 8 + 4 + 8 + 4 + 4;

uint32_t read_u32le(const uint8_t* data) noexcept {
    uint32_t v = 0;
    std::memcpy(&v, data, sizeof(v));
    return v;
}

uint64_t read_u64le(const uint8_t* data) noexcept {
    uint64_t v = 0;
    std::memcpy(&v, data, sizeof(v));
    return v;
}

// Portable UTF-16LE -> UTF-8 conversion (handles surrogate pairs), used
// instead of WideCharToMultiByte so ETW payload decoding has no OS
// dependency beyond raw byte reads. Stops at the first NUL code unit.
std::string utf16le_to_utf8(const uint8_t* data, size_t byte_len) {
    std::string out;
    size_t i = 0;
    while (i + 1 < byte_len) {
        const uint16_t unit = static_cast<uint16_t>(data[i]) | (static_cast<uint16_t>(data[i + 1]) << 8);
        i += 2;
        if (unit == 0) break;

        uint32_t cp = unit;
        if (unit >= 0xD800 && unit <= 0xDBFF && i + 1 < byte_len) {
            const uint16_t low = static_cast<uint16_t>(data[i]) | (static_cast<uint16_t>(data[i + 1]) << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000u + ((static_cast<uint32_t>(unit) - 0xD800u) << 10) + (low - 0xDC00u);
                i += 2;
            }
        }

        if (cp <= 0x7Fu) {
            out += static_cast<char>(cp);
        } else if (cp <= 0x7FFu) {
            out += static_cast<char>(0xC0u | (cp >> 6));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        } else if (cp <= 0xFFFFu) {
            out += static_cast<char>(0xE0u | (cp >> 12));
            out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        } else {
            out += static_cast<char>(0xF0u | (cp >> 18));
            out += static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu));
            out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        }
    }
    return out;
}

#ifdef GCAD_PLATFORM_WINDOWS
constexpr const wchar_t* kSessionName = L"GCAD-EtwKernelProcess";

// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
constexpr GUID kKernelProcessProviderGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

constexpr uint16_t kEventProcessStart = 1;
constexpr uint16_t kEventProcessStop  = 2;
constexpr size_t   MAX_KNOWN_CREATE_TIMES = 8192;
#endif // GCAD_PLATFORM_WINDOWS

} // namespace

std::optional<EtwKernelProcessEngine::DecodedProcessStart> EtwKernelProcessEngine::decode_process_start(
    const uint8_t* data, size_t size) {
    if (!data || size < kProcessStartFixedPrefixSize) return std::nullopt;

    DecodedProcessStart out{};
    out.pid = read_u32le(data + 0);
    // offset 4: ProcessSequenceNumber (8 bytes, unused)
    out.create_time_filetime = read_u64le(data + 12);
    out.parent_pid = read_u32le(data + 20);
    // offset 24: ParentProcessSequenceNumber (8 bytes, unused)
    // offset 32: SessionID (4 bytes, unused)
    // offset 36: Flags (4 bytes, unused)
    if (out.pid == 0) return std::nullopt;

    if (size > kProcessStartFixedPrefixSize)
        out.image_name = utf16le_to_utf8(data + kProcessStartFixedPrefixSize, size - kProcessStartFixedPrefixSize);
    return out;
}

std::optional<uint32_t> EtwKernelProcessEngine::decode_process_stop_pid(const uint8_t* data, size_t size) noexcept {
    if (!data || size < sizeof(uint32_t)) return std::nullopt;
    const uint32_t pid = read_u32le(data);
    if (pid == 0) return std::nullopt;
    return pid;
}

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

void EtwKernelProcessEngine::on_process_start(std::function<void(uint32_t, std::string)> cb) {
    std::lock_guard lk(cb_mtx_);
    process_start_cb_ = std::move(cb);
}

void EtwKernelProcessEngine::dispatch(SecurityObservation observation) {
    std::function<void(SecurityObservation)> cb;
    {
        std::lock_guard lk(cb_mtx_);
        cb = observation_cb_;
    }
    if (cb) cb(std::move(observation)); // invoked outside cb_mtx_
}

void EtwKernelProcessEngine::dispatch_process_start(uint32_t pid, std::string image_name) {
    std::function<void(uint32_t, std::string)> cb;
    {
        std::lock_guard lk(cb_mtx_);
        cb = process_start_cb_;
    }
    if (cb) cb(pid, std::move(image_name)); // invoked outside cb_mtx_
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

void EtwKernelProcessEngine::validate_decoded_event(const DecodedProcessStart& decoded) {
    if (validation_samples_.load() >= kValidationSampleCount) return;
    validation_samples_.fetch_add(1);

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, decoded.pid);
    if (!hProc) return; // process may have exited already

    bool name_ok = true;
    if (!decoded.image_name.empty()) {
        char image[MAX_PATH]{};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProc, 0, image, &size) && size > 0) {
            std::string_view decoded_view = decoded.image_name;
            std::string_view os_view(image, size);
            auto last_sep = [](std::string_view sv) {
                auto p = sv.find_last_of("\\/");
                return p == std::string_view::npos ? size_t{0} : p + 1;
            };
            auto decoded_file = decoded_view.substr(last_sep(decoded_view));
            auto os_file = os_view.substr(last_sep(os_view));
            if (decoded_file.size() == os_file.size()) {
                for (size_t i = 0; i < decoded_file.size(); ++i) {
                    auto lo = [](char c) -> char {
                        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
                    };
                    if (lo(decoded_file[i]) != lo(os_file[i])) { name_ok = false; break; }
                }
            } else {
                name_ok = false;
            }
        }
    }
    CloseHandle(hProc);

    if (!name_ok) {
        const auto failures = validation_failures_.fetch_add(1) + 1;
        if (failures >= 3) {
            GCAD_LOG(ERR, "EtwKernelProcess: decoded image name mismatches OS-reported name in " +
                         std::to_string(failures) + "/" + std::to_string(validation_samples_.load()) +
                         " samples — field layout assumption may be wrong");
        }
    }
}

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

        dispatch_process_start(pid, image_name);
    } else if (event_id == kEventProcessStop) {
        std::lock_guard lk(known_parents_mtx_);
        known_create_times_.erase(pid);
    }
}

void EtwKernelProcessEngine::on_event_record(PEVENT_RECORD record) {
    if (!IsEqualGUID(record->EventHeader.ProviderId, kKernelProcessProviderGuid)) return;
    const uint16_t event_id = record->EventHeader.EventDescriptor.Id;

    const auto* payload = static_cast<const uint8_t*>(record->UserData);
    const size_t payload_size = record->UserDataLength;

    if (event_id == kEventProcessStart) {
        const auto decoded = decode_process_start(payload, payload_size);
        if (!decoded) return; // buffer did not fit the expected shape: never guess
        validate_decoded_event(*decoded);
        handle_process_event(event_id, decoded->pid, decoded->parent_pid,
                             decoded->create_time_filetime, decoded->image_name);
    } else if (event_id == kEventProcessStop) {
        const auto pid = decode_process_stop_pid(payload, payload_size);
        if (!pid) return;
        handle_process_event(event_id, *pid, 0, 0, {});
    }
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
