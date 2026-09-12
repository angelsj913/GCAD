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

enum class CredentialAttackType : uint8_t {
    ATK_LSASS_ACCESS       = 0,
    ATK_TOKEN_IMPERSONATE  = 1,
    ATK_TOKEN_DUPLICATE    = 2,
    ATK_PASS_THE_HASH      = 3,
    ATK_PASS_THE_TICKET    = 4,
    ATK_SAM_DUMP           = 5,
    ATK_DCSYNC             = 6,
    ATK_KERBEROASTING      = 7,
    ATK_GOLDEN_TICKET      = 8,
    ATK_SILVER_TICKET      = 9,
};

struct CredentialAccessEvent {
    uint64_t                              id{0};
    std::chrono::system_clock::time_point timestamp{};
    CredentialAttackType                  type{CredentialAttackType::ATK_LSASS_ACCESS};
    uint32_t                              source_pid{0};
    std::string                           source_process;
    uint32_t                              target_pid{0};
    std::string                           target_process;
    uint32_t                              access_mask{0};
    std::string                           detail;
};

struct CredentialThreatIndicator {
    uint64_t    id{0};
    uint32_t    pid{0};
    std::string process_name;
    size_t      lsass_access_count{0};
    size_t      token_manipulation_count{0};
    size_t      lateral_movement_count{0};
    size_t      sam_access_count{0};
    double      risk_score{0.0};
    bool        known_tool{false};
    std::chrono::system_clock::time_point first_seen{};
    std::chrono::system_clock::time_point last_seen{};
};

class CredentialGuardEngine final : public ISecurityEngine {
public:
    CredentialGuardEngine();
    ~CredentialGuardEngine() override;

    std::string_view name() const noexcept override { return "CredentialGuard"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    void ingest(const CredentialAccessEvent& ev);
    void report_lsass_access(uint32_t source_pid, const std::string& source_process,
                              uint32_t access_mask);
    void report_token_manipulation(uint32_t pid, const std::string& process_name,
                                    CredentialAttackType type);
    void report_sam_access(uint32_t pid, const std::string& process_name);

    std::vector<CredentialThreatIndicator> active_indicators(size_t n = 50) const;
    std::vector<CredentialAccessEvent> recent_events(size_t n = 100) const;

    static bool is_known_dump_tool(const std::string& process_name);
    static bool is_suspicious_lsass_access(uint32_t access_mask);
    static ThreatLevel classify_attack(CredentialAttackType type);
    static ThreatCategory map_to_category(CredentialAttackType type);
    static double score_indicator(const CredentialThreatIndicator& ind);
    static const char* attack_type_name(CredentialAttackType type);

    static constexpr uint32_t MASK_VM_READ       = 0x0010;
    static constexpr uint32_t MASK_VM_WRITE      = 0x0020;
    static constexpr uint32_t MASK_VM_OPERATION  = 0x0008;
    static constexpr uint32_t MASK_QUERY_INFO    = 0x0400;
    static constexpr uint32_t MASK_ALL_ACCESS    = 0x1FFFFF;

    static constexpr double RISK_THRESHOLD_SUSPICIOUS = 0.35;
    static constexpr double RISK_THRESHOLD_MALICIOUS  = 0.70;
    static constexpr size_t MAX_EVENTS     = 2000;
    static constexpr size_t MAX_INDICATORS = 500;

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};
    std::atomic<uint64_t> next_indicator_id_{1};

    mutable std::mutex    mtx_;
    std::deque<CredentialAccessEvent>                       events_;
    std::unordered_map<uint32_t, CredentialThreatIndicator> indicators_;
    std::thread           monitor_thread_;

    std::function<void(ThreatEvent)>                   threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void monitor_loop();
    void decay_indicators();
};

} // namespace gcad
