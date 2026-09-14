#include "gcad/engines/driver_guard_engine.hpp"
#include <chrono>
#include <algorithm>

namespace gcad {

namespace {

std::string to_lower_str(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

const char* KNOWN_BYOVD_DRIVERS[] = {
    "gdrv.sys",
    "kprocesshacker.sys",
    "dbutil_2_3.sys",
    "mhyprot2.sys",
    "rtcore64.sys",
    "procexp.sys",
    "iqvw64e.sys",
    "aswardisk.sys",
    "zam64.sys",
    "cpuz141.sys",
    "echo_driver.sys",
    "speedfan.sys"
};

const char* SUSPICIOUS_PATH_KEYWORDS[] = {
    "\\temp\\",
    "/temp/",
    "\\appdata\\",
    "/appdata/",
    "\\users\\",
    "/users/",
    "\\programdata\\",
    "/programdata/",
    "\\downloads\\",
    "/downloads/"
};

} // namespace

DriverGuardEngine::DriverGuardEngine() = default;

DriverGuardEngine::~DriverGuardEngine() {
    stop();
}

ErrorCode DriverGuardEngine::start() {
    if (running_.exchange(true)) return ErrorCode::OK;
    monitor_thread_ = std::thread(&DriverGuardEngine::monitor_loop, this);
    return ErrorCode::OK;
}

ErrorCode DriverGuardEngine::stop() {
    if (!running_.exchange(false)) return ErrorCode::OK;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    return ErrorCode::OK;
}

EngineStatus DriverGuardEngine::status() const {
    EngineStatus st{};
    st.name = std::string(name());
    st.running = running_.load();
    st.events_processed = events_processed_.load();
    st.threats_detected = threats_detected_.load();
    return st;
}

void DriverGuardEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    threat_cb_ = std::move(cb);
}

void DriverGuardEngine::emit_threat(const DriverInfo& drv) {
    threats_detected_.fetch_add(1, std::memory_order_relaxed);

    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        cb = threat_cb_;
    }

    if (!cb) return;

    ThreatEvent te{};
    te.level = (drv.risk == DriverRiskLevel::VULNERABLE_KNOWN) ? ThreatLevel::CRITICAL :
               (drv.risk == DriverRiskLevel::MALICIOUS_UNSIGNED) ? ThreatLevel::HIGH : ThreatLevel::MEDIUM;
    te.category = ThreatCategory::KERNEL_ATTACK;
    te.description = drv.threat_detail;
    te.process_name = drv.driver_name;
    te.file_path = drv.file_path;
    te.timestamp = std::chrono::system_clock::now();

    cb(te);
}

bool DriverGuardEngine::is_known_vulnerable_driver(std::string_view driver_name) {
    std::string lower = to_lower_str(driver_name);
    for (const char* vuln : KNOWN_BYOVD_DRIVERS) {
        if (lower.find(vuln) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DriverGuardEngine::is_suspicious_driver_path(std::string_view path) {
    std::string lower = to_lower_str(path);
    for (const char* kw : SUSPICIOUS_PATH_KEYWORDS) {
        if (lower.find(kw) != std::string::npos) {
            return true;
        }
    }
    return false;
}

DriverInfo DriverGuardEngine::evaluate_driver_load(std::string_view driver_name, std::string_view path, bool is_signed) {
    events_processed_.fetch_add(1, std::memory_order_relaxed);

    DriverInfo info{};
    info.driver_name = std::string(driver_name);
    info.file_path = std::string(path);
    info.is_signed = is_signed;

    if (is_known_vulnerable_driver(driver_name) || is_known_vulnerable_driver(path)) {
        info.is_vulnerable_byovd = true;
        info.risk = DriverRiskLevel::VULNERABLE_KNOWN;
        info.threat_detail = "BYOVD attack detected: attempt to load known vulnerable signed kernel driver '" +
                             std::string(driver_name) + "' (" + std::string(path) + ")";
        emit_threat(info);
        return info;
    }

    if (!is_signed) {
        info.risk = DriverRiskLevel::MALICIOUS_UNSIGNED;
        info.threat_detail = "Unsigned kernel driver load attempt detected: '" +
                             std::string(driver_name) + "' (" + std::string(path) + ")";
        emit_threat(info);
        return info;
    }

    if (is_suspicious_driver_path(path)) {
        info.risk = DriverRiskLevel::SUSPICIOUS;
        info.threat_detail = "Kernel driver loading from user-writable non-system path: '" +
                             std::string(path) + "'";
        emit_threat(info);
        return info;
    }

    info.risk = DriverRiskLevel::BENIGN;
    return info;
}

void DriverGuardEngine::monitor_loop() {
    while (running_.load()) {
        for (int i = 0; i < 20 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        events_processed_.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace gcad
