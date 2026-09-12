#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <filesystem>

namespace gcad {

struct UpdateManifest {
    std::string db_name;
    std::string version;
    std::string sha256;
    std::filesystem::path file_path;
    std::chrono::system_clock::time_point updated_at{};
};

enum class UpdateResult : uint8_t {
    SUCCESS = 0,
    FILE_NOT_FOUND,
    CHECKSUM_MISMATCH,
    PARSE_ERROR,
    ALREADY_CURRENT,
};

struct UpdateRecord {
    uint64_t    id{0};
    std::string db_name;
    std::string old_version;
    std::string new_version;
    UpdateResult result{UpdateResult::SUCCESS};
    std::chrono::system_clock::time_point timestamp{};
};

class UpdateEngine final : public ISecurityEngine {
public:
    UpdateEngine();
    ~UpdateEngine() override;

    std::string_view name() const noexcept override { return "AutoUpdate"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void set_data_dir(const std::filesystem::path& dir);

    UpdateResult load_signature_db(const std::filesystem::path& path, const std::string& expected_sha256 = "");
    UpdateResult load_ioc_db(const std::filesystem::path& path, const std::string& expected_sha256 = "");
    UpdateResult load_yara_rules(const std::filesystem::path& path, const std::string& expected_sha256 = "");

    bool write_manifest(const std::filesystem::path& path) const;
    bool read_manifest(const std::filesystem::path& path);

    std::vector<UpdateManifest> current_versions() const;
    std::vector<UpdateRecord> recent_updates(size_t n = 50) const;
    size_t check_for_updates();

    static std::string compute_file_sha256(const std::filesystem::path& path);
    static bool verify_checksum(const std::filesystem::path& path, const std::string& expected);
    static std::string parse_version_from_file(const std::filesystem::path& path);

    static constexpr size_t MAX_UPDATE_LOG = 500;

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};

    mutable std::mutex               mtx_;
    std::vector<UpdateManifest>      manifests_;
    std::deque<UpdateRecord>         update_log_;
    std::filesystem::path            data_dir_;

    std::thread                      monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;

    void monitor_loop();
    void record_update(const std::string& db_name, const std::string& old_ver,
                       const std::string& new_ver, UpdateResult result);
    UpdateResult validate_and_update(const std::string& db_name,
                                     const std::filesystem::path& path,
                                     const std::string& expected_sha256);
};

} // namespace gcad
