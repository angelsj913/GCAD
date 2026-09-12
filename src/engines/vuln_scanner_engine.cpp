#include "gcad/engines/vuln_scanner_engine.hpp"
#include <algorithm>
#include <sstream>

#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#endif

namespace gcad {

VulnScannerEngine::VulnScannerEngine() {
    vuln_db_ = {
        {"GCAD-2024-0001", "OpenSSL",  "3.0.14",  "CRITICAL", 9.8, "Heap buffer overflow in X.509 certificate verification", "Update to OpenSSL 3.0.14+"},
        {"GCAD-2024-0002", "curl",     "8.6.0",   "HIGH",     8.1, "HTTP/2 CONTINUATION flood leading to DoS", "Update to curl 8.6.0+"},
        {"GCAD-2024-0003", "Python",   "3.12.4",  "HIGH",     7.5, "Path traversal in zipfile module", "Update to Python 3.12.4+"},
        {"GCAD-2024-0004", "Node.js",  "20.12.0", "HIGH",     7.8, "Privilege escalation via env variable injection", "Update to Node.js 20.12.0+"},
        {"GCAD-2024-0005", "Git",      "2.44.1",  "CRITICAL", 9.1, "Remote code execution via crafted clone URL", "Update to Git 2.44.1+"},
        {"GCAD-2024-0006", "7-Zip",    "24.01",   "HIGH",     7.3, "Integer overflow in LZMA decompression", "Update to 7-Zip 24.01+"},
        {"GCAD-2024-0007", "PuTTY",    "0.81",    "CRITICAL", 9.4, "ECDSA P521 private key recovery from nonce bias", "Update to PuTTY 0.81+"},
        {"GCAD-2024-0008", "WinRAR",   "6.24",    "HIGH",     7.5, "Arbitrary code execution via crafted RAR archive", "Update to WinRAR 6.24+"},
        {"GCAD-2024-0009", "VLC",      "3.0.21",  "MEDIUM",   6.3, "Buffer overflow in MKV demuxer", "Update to VLC 3.0.21+"},
        {"GCAD-2024-0010", "Notepad++","8.6.5",   "MEDIUM",   5.5, "DLL hijacking via search path", "Update to Notepad++ 8.6.5+"},
        {"GCAD-2024-0011", "Firefox",  "124.0",   "HIGH",     8.0, "Sandbox escape via IPC message", "Update to Firefox 124.0+"},
        {"GCAD-2024-0012", "Chrome",   "123.0.6312.86", "CRITICAL", 9.6, "Type confusion in V8 JavaScript engine", "Update to Chrome 123.0.6312.86+"},
    };
}

VulnScannerEngine::~VulnScannerEngine() { stop(); }

ErrorCode VulnScannerEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&VulnScannerEngine::monitor_loop, this);
    GCAD_LOG(INFO, "VulnScanner engine started");
    return ErrorCode::OK;
}

ErrorCode VulnScannerEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus VulnScannerEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void VulnScannerEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void VulnScannerEngine::add_vuln(const VulnEntry& v) {
    std::lock_guard lk(mtx_);
    vuln_db_.push_back(v);
}

size_t VulnScannerEngine::vuln_db_size() const {
    std::lock_guard lk(mtx_);
    return vuln_db_.size();
}

void VulnScannerEngine::load_vuln_db(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f.is_open()) return;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        std::string id, sw, ver, sev, cvss_str, desc, fix;
        if (!std::getline(ss, id, '|')) continue;
        if (!std::getline(ss, sw, '|')) continue;
        if (!std::getline(ss, ver, '|')) continue;
        if (!std::getline(ss, sev, '|')) continue;
        if (!std::getline(ss, cvss_str, '|')) continue;
        if (!std::getline(ss, desc, '|')) continue;
        std::getline(ss, fix, '|');

        VulnEntry v;
        v.vuln_id = id;
        v.affected_software = sw;
        v.affected_version_below = ver;
        v.severity = sev;
        try { v.cvss = std::stod(cvss_str); } catch (...) { v.cvss = 0.0; }
        v.description = desc;
        v.remediation = fix;

        std::lock_guard lk(mtx_);
        vuln_db_.push_back(std::move(v));
    }
}

void VulnScannerEngine::save_vuln_db(const std::filesystem::path& path) const {
    std::lock_guard lk(mtx_);
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return;
    f << "# GCAD Vulnerability Database\n";
    for (const auto& v : vuln_db_) {
        f << v.vuln_id << '|' << v.affected_software << '|'
          << v.affected_version_below << '|' << v.severity << '|'
          << v.cvss << '|' << v.description << '|' << v.remediation << '\n';
    }
}

std::vector<int> VulnScannerEngine::parse_version(const std::string& ver) {
    std::vector<int> parts;
    std::istringstream ss(ver);
    std::string token;
    while (std::getline(ss, token, '.')) {
        try { parts.push_back(std::stoi(token)); }
        catch (...) { parts.push_back(0); }
    }
    return parts;
}

bool VulnScannerEngine::version_less_than(const std::string& installed, const std::string& threshold) {
    auto a = parse_version(installed);
    auto b = parse_version(threshold);
    size_t len = std::max(a.size(), b.size());
    a.resize(len, 0);
    b.resize(len, 0);
    for (size_t i = 0; i < len; ++i) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

ThreatLevel VulnScannerEngine::severity_to_level(const std::string& severity, double cvss) {
    if (severity == "CRITICAL" || cvss >= 9.0) return ThreatLevel::CRITICAL;
    if (severity == "HIGH" || cvss >= 7.0) return ThreatLevel::HIGH;
    if (severity == "MEDIUM" || cvss >= 4.0) return ThreatLevel::MEDIUM;
    if (severity == "LOW" || cvss >= 0.1) return ThreatLevel::LOW;
    return ThreatLevel::SAFE;
}

std::vector<SoftwareInfo> VulnScannerEngine::enumerate_installed_software() const {
    std::vector<SoftwareInfo> result;
#ifdef GCAD_PLATFORM_WINDOWS
    auto read_key = [&](HKEY root, const char* subkey) {
        HKEY hKey;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
        DWORD index = 0;
        char name_buf[256];
        while (true) {
            DWORD name_len = sizeof(name_buf);
            if (RegEnumKeyExA(hKey, index++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                break;
            HKEY hSubKey;
            if (RegOpenKeyExA(hKey, name_buf, 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) continue;

            auto read_val = [&](const char* val_name) -> std::string {
                char buf[512]{};
                DWORD buf_size = sizeof(buf);
                DWORD type = 0;
                if (RegQueryValueExA(hSubKey, val_name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &buf_size) == ERROR_SUCCESS &&
                    type == REG_SZ)
                    return std::string(buf);
                return {};
            };

            SoftwareInfo info;
            info.name = read_val("DisplayName");
            info.version = read_val("DisplayVersion");
            info.vendor = read_val("Publisher");
            info.install_path = read_val("InstallLocation");
            info.source = "registry";
            if (!info.name.empty() && !info.version.empty())
                result.push_back(std::move(info));

            RegCloseKey(hSubKey);
        }
        RegCloseKey(hKey);
    };

    read_key(HKEY_LOCAL_MACHINE,
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    read_key(HKEY_LOCAL_MACHINE,
             "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    read_key(HKEY_CURRENT_USER,
             "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
#endif
    return result;
}

std::vector<VulnMatch> VulnScannerEngine::scan(const std::vector<SoftwareInfo>& software) {
    std::vector<VulnMatch> results;
    std::lock_guard lk(mtx_);

    for (const auto& sw : software) {
        std::string sw_lower = sw.name;
        std::transform(sw_lower.begin(), sw_lower.end(), sw_lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        for (const auto& v : vuln_db_) {
            std::string vuln_lower = v.affected_software;
            std::transform(vuln_lower.begin(), vuln_lower.end(), vuln_lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (sw_lower.find(vuln_lower) == std::string::npos) continue;
            if (!version_less_than(sw.version, v.affected_version_below)) continue;

            VulnMatch m;
            m.id = next_id_.fetch_add(1);
            m.software = sw;
            m.vuln = v;
            m.detected_at = std::chrono::system_clock::now();
            results.push_back(m);

            matches_.push_back(m);
            while (matches_.size() > MAX_MATCHES) matches_.pop_front();

            events_processed_.fetch_add(1);
            threats_detected_.fetch_add(1);

            auto cb = threat_cb_;
            if (cb) {
                ThreatEvent ev{};
                ev.level = severity_to_level(v.severity, v.cvss);
                ev.category = ThreatCategory::SUSPICIOUS_BINARY;
                ev.description = v.vuln_id + ": " + sw.name + " " + sw.version +
                                 " — " + v.description + " (fix: " + v.remediation + ")";
                ev.file_path = sw.install_path;
                ev.timestamp = std::chrono::system_clock::now();
                cb(std::move(ev));
            }
        }
    }
    return results;
}

std::vector<VulnMatch> VulnScannerEngine::scan_system() {
    auto software = enumerate_installed_software();
    return scan(software);
}

std::vector<VulnMatch> VulnScannerEngine::recent_matches(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, matches_.size());
    return {matches_.end() - static_cast<ptrdiff_t>(count), matches_.end()};
}

void VulnScannerEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 60000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        scan_system();
    }
}

} // namespace gcad
