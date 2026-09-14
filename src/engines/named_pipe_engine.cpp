#include "gcad/engines/named_pipe_engine.hpp"
#include <algorithm>
#include <cctype>

#ifdef GCAD_PLATFORM_WINDOWS
#include <windows.h>
#endif

namespace gcad {

namespace {

std::string to_lower_pipe(std::string_view sv) {
    std::string s;
    s.reserve(sv.size());
    for (char c : sv)
        s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return s;
}

bool starts_with(std::string_view str, std::string_view prefix) {
    return str.rfind(prefix, 0) == 0;
}

} // namespace

NamedPipeEngine::NamedPipeEngine() = default;
NamedPipeEngine::~NamedPipeEngine() { stop(); }

ErrorCode NamedPipeEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&NamedPipeEngine::monitor_loop, this);
    return ErrorCode::OK;
}

ErrorCode NamedPipeEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus NamedPipeEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void NamedPipeEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void NamedPipeEngine::emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.timestamp = std::chrono::system_clock::now();
        ev.level = ThreatLevel::CRITICAL;
        ev.category = cat;
        ev.process_id = pid;
        ev.description = desc;
        cb(std::move(ev));
    }
}

bool NamedPipeEngine::is_c2_pipe(std::string_view pipe_name,
                                 std::string& out_framework,
                                 std::string& out_reason) {
    if (pipe_name.empty()) return false;

    // Strip leading \\.\pipe\ if present
    if (starts_with(pipe_name, "\\\\.\\pipe\\")) {
        pipe_name = pipe_name.substr(9);
    }

    const std::string lower = to_lower_pipe(pipe_name);

    struct C2PipeSignature {
        std::string_view prefix;
        const char*      framework;
        const char*      description;
    };

    static const C2PipeSignature k_signatures[] = {
        {"msagent_",      "Cobalt Strike", "Default Beacon SMB named pipe"},
        {"status_",       "Cobalt Strike", "Secondary Beacon communication pipe"},
        {"mypipe-f",      "Cobalt Strike", "Post-exploitation lateral movement pipe"},
        {"mypipe-i",      "Cobalt Strike", "Interactive Beacon command pipe"},
        {"postex_",       "Cobalt Strike", "Post-exploitation reflective DLL pipe"},
        {"pbind_",        "Cobalt Strike", "Peer-to-peer SMB pipe binding"},
        {"spoolss_",      "Cobalt Strike", "Spoofed Print Spooler named pipe"},
        {"meterpreter_",  "Metasploit",    "Meterpreter reverse/bind SMB pipe"},
        {"metsrv_",       "Metasploit",    "Meterpreter server internal pipe"},
        {"extapi_",       "Metasploit",    "Meterpreter extended API communication pipe"},
        {"sliver_",       "Sliver C2",     "BishopFox Sliver SMB beacon pipe"},
        {"slv_",          "Sliver C2",     "Sliver implant short-named pipe"},
        {"psexec_",       "PsExec",        "Sysinternals/Impacket PsExec lateral execution pipe"},
        {"psexecsvc",     "PsExec",        "PsExec remote service pipe"},
        {"paexec_",       "PAExec",        "PowerAdmin execution pipe"},
        {"csexec_",       "CSExec",        "C# PsExec equivalent execution pipe"}
    };

    for (const auto& sig : k_signatures) {
        if (starts_with(lower, sig.prefix)) {
            out_framework = sig.framework;
            out_reason    = sig.description;
            return true;
        }
    }

    return false;
}

std::vector<PipeInfo> NamedPipeEngine::scan_active_pipes() {
    events_processed_.fetch_add(1);
    std::vector<PipeInfo> results;

#ifdef GCAD_PLATFORM_WINDOWS
    WIN32_FIND_DATAA fd{};
    HANDLE hFind = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            PipeInfo info;
            info.pipe_name = fd.cFileName;
            std::string fw, reason;
            if (is_c2_pipe(info.pipe_name, fw, reason)) {
                info.is_suspicious = true;
                info.matched_framework = std::move(fw);
                info.reason = std::move(reason);
            }
            results.push_back(std::move(info));
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
#endif

    return results;
}

void NamedPipeEngine::monitor_loop() {
    while (running_.load()) {
        for (int i = 0; i < 30 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;

        auto pipes = scan_active_pipes();
        for (auto& p : pipes) {
            if (known_pipes_.count(p.pipe_name)) continue;
            known_pipes_.insert(p.pipe_name);

            if (p.is_suspicious) {
                emit_threat(ThreatCategory::C2_BEACON,
                            "C2 Named Pipe Detected: \\\\.\\pipe\\" + p.pipe_name +
                            " [" + p.matched_framework + "] - " + p.reason);
            }
        }
    }
}

} // namespace gcad
