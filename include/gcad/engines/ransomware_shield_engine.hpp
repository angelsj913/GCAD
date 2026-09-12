#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <unordered_map>
#include <vector>
#include <atomic>

namespace gcad {

enum class FileIOType : uint8_t {
    IO_WRITE    = 0,
    IO_RENAME   = 1,
    IO_DELETE   = 2,
    IO_CREATE   = 3,
};

struct FileIOEvent {
    uint64_t                              id{0};
    std::chrono::system_clock::time_point timestamp{};
    FileIOType                            type{FileIOType::IO_WRITE};
    uint32_t                              process_id{0};
    std::string                           process_name;
    std::string                           file_path;
    std::string                           new_path;
    uint64_t                              bytes_written{0};
    double                                entropy{0.0};
};

struct RansomwareIndicator {
    uint64_t id{0};
    std::string process_name;
    uint32_t    process_id{0};
    size_t      files_modified{0};
    size_t      files_renamed{0};
    size_t      files_deleted{0};
    double      avg_entropy{0.0};
    bool        shadow_copy_delete{false};
    bool        honeyfile_triggered{false};
    double      risk_score{0.0};
    std::chrono::system_clock::time_point first_seen{};
    std::chrono::system_clock::time_point last_seen{};
};

struct HoneyFile {
    std::filesystem::path path;
    std::string           sha256;
    bool                  triggered{false};
};

class RansomwareShieldEngine final : public ISecurityEngine {
public:
    RansomwareShieldEngine();
    ~RansomwareShieldEngine() override;

    std::string_view name() const noexcept override { return "RansomwareShield"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    void ingest_file_io(const FileIOEvent& ev);
    void report_shadow_copy_delete(uint32_t pid, const std::string& process_name);
    void add_honeyfile(const std::filesystem::path& path);
    void check_honeyfiles();

    std::vector<RansomwareIndicator> active_indicators(size_t n = 50) const;
    std::vector<HoneyFile> honeyfiles() const;

    static double compute_entropy(const uint8_t* data, size_t len);
    static double compute_entropy(const std::vector<uint8_t>& data);
    static bool is_ransomware_extension(const std::string& ext);
    static double score_indicator(const RansomwareIndicator& ind);

    static constexpr size_t   BURST_THRESHOLD      = 10;
    static constexpr int      BURST_WINDOW_SECONDS = 5;
    static constexpr double   HIGH_ENTROPY_THRESHOLD = 7.0;
    static constexpr double   RISK_THRESHOLD_SUSPICIOUS = 0.40;
    static constexpr double   RISK_THRESHOLD_MALICIOUS  = 0.75;
    static constexpr size_t   MAX_INDICATORS       = 500;
    static constexpr size_t   MAX_IO_EVENTS        = 5000;

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};
    std::atomic<uint64_t> next_indicator_id_{1};

    mutable std::mutex    mtx_;
    std::deque<FileIOEvent>                            io_events_;
    std::unordered_map<uint32_t, RansomwareIndicator>  indicators_;
    std::vector<HoneyFile>                             honeyfiles_;
    std::thread           monitor_thread_;

    std::function<void(ThreatEvent)>                   threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void monitor_loop();
    void analyze_burst_patterns();
    void emit_threat(ThreatCategory cat, ThreatLevel level,
                     const std::string& desc, uint32_t pid,
                     const std::string& process_name, const std::string& file_path);
    void emit_observation(security::ObservationKind kind, ThreatLevel level,
                          double confidence, const std::string& evidence,
                          uint32_t pid, const std::string& process_name,
                          const std::string& file_path);
};

} // namespace gcad
