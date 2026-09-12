#pragma once

#include "../i_security_engine.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <map>

namespace gcad {

struct SoftwareInfo {
    std::string name;
    std::string vendor;
    std::string version;
    std::string install_path;
    std::string source;
};

struct VulnEntry {
    std::string vuln_id;
    std::string affected_software;
    std::string affected_version_below;
    std::string severity;
    double      cvss{0.0};
    std::string description;
    std::string remediation;
};

struct VulnMatch {
    uint64_t    id{0};
    SoftwareInfo software;
    VulnEntry    vuln;
    std::chrono::system_clock::time_point detected_at{};
};

class VulnScannerEngine final : public ISecurityEngine {
public:
    VulnScannerEngine();
    ~VulnScannerEngine() override;

    std::string_view name() const noexcept override { return "VulnScanner"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void add_vuln(const VulnEntry& v);
    void load_vuln_db(const std::filesystem::path& path);
    void save_vuln_db(const std::filesystem::path& path) const;
    size_t vuln_db_size() const;

    std::vector<SoftwareInfo> enumerate_installed_software() const;
    std::vector<VulnMatch> scan(const std::vector<SoftwareInfo>& software);
    std::vector<VulnMatch> scan_system();
    std::vector<VulnMatch> recent_matches(size_t n = 50) const;

    static bool version_less_than(const std::string& installed, const std::string& threshold);
    static std::vector<int> parse_version(const std::string& ver);
    static ThreatLevel severity_to_level(const std::string& severity, double cvss);

    static constexpr size_t MAX_MATCHES = 500;

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};

    mutable std::mutex              mtx_;
    std::vector<VulnEntry>          vuln_db_;
    std::deque<VulnMatch>           matches_;

    std::thread monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;

    void monitor_loop();
};

} // namespace gcad
