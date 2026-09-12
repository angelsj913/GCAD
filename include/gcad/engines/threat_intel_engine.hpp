#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <unordered_map>
#include <unordered_set>

namespace gcad {

enum class IocType : uint8_t {
    SHA256_HASH  = 0,
    MD5_HASH     = 1,
    IPV4_ADDRESS = 2,
    DOMAIN       = 3,
    URL          = 4,
    FILE_NAME    = 5,
};

struct IocEntry {
    uint64_t    id{0};
    IocType     type{IocType::SHA256_HASH};
    std::string value;
    std::string source;
    std::string description;
    ThreatLevel severity{ThreatLevel::HIGH};
    std::string tags;
    std::chrono::system_clock::time_point added_at{};
    bool        active{true};
};

struct IocMatch {
    IocEntry    ioc;
    std::string matched_against;
    std::string context;
    std::chrono::system_clock::time_point matched_at{};
};

class ThreatIntelEngine final : public ISecurityEngine {
public:
    ThreatIntelEngine();
    ~ThreatIntelEngine() override;

    std::string_view name() const noexcept override { return "ThreatIntel"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    uint64_t add_ioc(IocEntry entry);
    bool remove_ioc(uint64_t id);
    size_t load_from_file(const std::filesystem::path& path);
    size_t save_to_file(const std::filesystem::path& path) const;

    bool check_hash(const std::string& hash) const;
    bool check_ip(const std::string& ip) const;
    bool check_domain(const std::string& domain) const;

    std::vector<IocMatch> lookup(const std::string& value) const;
    std::vector<IocMatch> recent_matches(size_t n = 100) const;
    std::vector<IocEntry> all_iocs() const;
    size_t ioc_count() const;

    void install_default_iocs();

    static std::string normalize_domain(std::string_view domain);
    static std::string normalize_hash(std::string_view hash);
    static IocType detect_type(std::string_view value);

    static constexpr size_t MAX_MATCHES = 5000;

private:
    std::atomic<bool>    running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};

    mutable std::mutex   mtx_;
    std::vector<IocEntry>            iocs_;
    std::unordered_set<std::string>  hash_index_;
    std::unordered_set<std::string>  ip_index_;
    std::unordered_set<std::string>  domain_index_;
    std::deque<IocMatch>             match_log_;

    std::thread          monitor_thread_;
    std::function<void(ThreatEvent)> threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void rebuild_indices();
    void monitor_loop();
    void record_match(const IocEntry& ioc, const std::string& against, const std::string& ctx);
    void emit_threat(ThreatCategory cat, const std::string& desc);
    void emit_observation(security::ObservationKind kind, ThreatLevel level,
                          double confidence, const std::string& evidence);
};

} // namespace gcad
