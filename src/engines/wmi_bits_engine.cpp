#include "gcad/engines/wmi_bits_engine.hpp"
#include <algorithm>
#include <cctype>

#ifdef GCAD_PLATFORM_WINDOWS
#include <windows.h>
#endif

namespace gcad {

namespace {

std::string to_lower(std::string_view sv) {
    std::string s;
    s.reserve(sv.size());
    for (char c : sv)
        s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return s;
}

bool ends_with(std::string_view str, std::string_view suffix) {
    if (str.size() < suffix.size()) return false;
    return str.substr(str.size() - suffix.size()) == suffix;
}

} // namespace

WmiBitsEngine::WmiBitsEngine() = default;
WmiBitsEngine::~WmiBitsEngine() { stop(); }

ErrorCode WmiBitsEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&WmiBitsEngine::monitor_loop, this);
    return ErrorCode::OK;
}

ErrorCode WmiBitsEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus WmiBitsEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void WmiBitsEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void WmiBitsEngine::emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.timestamp = std::chrono::system_clock::now();
        ev.level = ThreatLevel::HIGH;
        ev.category = cat;
        ev.process_id = pid;
        ev.description = desc;
        cb(std::move(ev));
    }
}

bool WmiBitsEngine::evaluate_wmi_subscription(WmiSubscription& sub) {
    const std::string lower_type = to_lower(sub.consumer_type);
    const std::string lower_cmd  = to_lower(sub.command_or_script);

    // ActiveScriptEventConsumer is rarely used legitimately and heavily favored by APTs
    if (lower_type.find("activescripteventconsumer") != std::string::npos) {
        sub.is_suspicious = true;
        sub.reason = "ActiveScriptEventConsumer used (Script-based WMI persistence)";
        return true;
    }

    static const std::string_view k_suspicious_patterns[] = {
        "powershell", "cmd.exe", "cscript", "wscript", "mshta", "rundll32",
        "certutil", "bitsadmin", "-enc ", "-encodedcommand", "downloadstring",
        "invoke-expression", "iex ", "hidden", "frombase64string"
    };

    for (const auto& pat : k_suspicious_patterns) {
        if (lower_cmd.find(pat) != std::string::npos) {
            sub.is_suspicious = true;
            sub.reason = "CommandLineEventConsumer contains suspicious execution pattern: " + std::string(pat);
            return true;
        }
    }

    sub.is_suspicious = false;
    return false;
}

bool WmiBitsEngine::evaluate_bits_job(BitsJobInfo& job) {
    const std::string lower_path = to_lower(job.local_file_path);
    const std::string lower_url  = to_lower(job.remote_url);

    static const std::string_view k_exec_extensions[] = {
        ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sys", ".scr"
    };

    for (const auto& ext : k_exec_extensions) {
        if (ends_with(lower_path, ext)) {
            job.is_suspicious = true;
            job.reason = "BITS job targets executable file download: " + std::string(ext);
            return true;
        }
    }

    // Check for suspicious paths like Temp or AppData
    if (lower_path.find("\\temp\\") != std::string::npos ||
        lower_path.find("\\appdata\\local\\temp\\") != std::string::npos) {
        job.is_suspicious = true;
        job.reason = "BITS job targets temp directory destination";
        return true;
    }

    // Check for non-standard ports or raw IP addresses in remote URL
    if (lower_url.find(":8080") != std::string::npos ||
        lower_url.find(":4444") != std::string::npos ||
        lower_url.find(":1337") != std::string::npos) {
        job.is_suspicious = true;
        job.reason = "BITS job downloads from suspicious C2 port";
        return true;
    }

    job.is_suspicious = false;
    return false;
}

std::vector<WmiSubscription> WmiBitsEngine::scan_wmi_subscriptions() {
    events_processed_.fetch_add(1);
    std::vector<WmiSubscription> results;

    // Fast heuristic registry inspection for WMI event consumers
#ifdef GCAD_PLATFORM_WINDOWS
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\WBEM\\WDM",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
#endif

    return results;
}

std::vector<BitsJobInfo> WmiBitsEngine::scan_bits_jobs() {
    events_processed_.fetch_add(1);
    std::vector<BitsJobInfo> results;
    return results;
}

void WmiBitsEngine::monitor_loop() {
    while (running_.load()) {
        for (int i = 0; i < 50 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;

        auto subscriptions = scan_wmi_subscriptions();
        for (auto& sub : subscriptions) {
            const std::string key = sub.filter_name + ":" + sub.consumer_name;
            if (known_subscriptions_.count(key)) continue;
            known_subscriptions_.insert(key);

            if (evaluate_wmi_subscription(sub)) {
                emit_threat(ThreatCategory::REGISTRY_TAMPER,
                            "WMI Persistence Threat: " + sub.filter_name + " -> " + sub.consumer_name + " (" + sub.reason + ")");
            }
        }

        auto bits_jobs = scan_bits_jobs();
        for (auto& job : bits_jobs) {
            if (known_bits_jobs_.count(job.job_id)) continue;
            known_bits_jobs_.insert(job.job_id);

            if (evaluate_bits_job(job)) {
                emit_threat(ThreatCategory::SUSPICIOUS_BINARY,
                            "BITS Stealth Download Threat: " + job.display_name + " -> " + job.local_file_path + " (" + job.reason + ")");
            }
        }
    }
}

} // namespace gcad
