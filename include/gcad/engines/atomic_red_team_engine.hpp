#pragma once
#include "gcad/i_security_engine.hpp"
#include <vector>
#include <string>
#include <string_view>
#include <mutex>
#include <atomic>

namespace gcad {

class EngineManager;

struct AtomicTestResult {
    std::string technique_id;    // e.g. "T1055.001"
    std::string technique_name;  // e.g. "Process Injection: Dynamic-link Library Injection"
    std::string target_engine;   // e.g. "ReflectiveInjection" / "PMSR"
    bool        executed{false};
    bool        detected{false};
    std::string message;
};

class AtomicRedTeamEngine : public ISecurityEngine {
public:
    AtomicRedTeamEngine();
    ~AtomicRedTeamEngine() override;

    std::string_view name() const noexcept override { return "AtomicRedTeam"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    // Simulation APIs
    std::vector<AtomicTestResult> run_all_simulations(EngineManager& em);
    AtomicTestResult run_technique(std::string_view technique_id, EngineManager& em);
    float calculate_defense_score(const std::vector<AtomicTestResult>& results) const;

    // Atomic technique runners
    AtomicTestResult simulate_t1055_dll_injection(EngineManager& em);
    AtomicTestResult simulate_t1562_impair_defenses(EngineManager& em);
    AtomicTestResult simulate_t1003_credential_dump(EngineManager& em);
    AtomicTestResult simulate_t1486_data_encrypted(EngineManager& em);
    AtomicTestResult simulate_t1071_c2_beaconing(EngineManager& em);
    AtomicTestResult simulate_t1218_lolbins(EngineManager& em);
    AtomicTestResult simulate_t1059_powershell_fileless(EngineManager& em);
    AtomicTestResult simulate_t1027_packed_pe(EngineManager& em);

    std::vector<AtomicTestResult> last_results() const;

private:
    std::atomic<bool>                       running_{false};
    mutable std::mutex                      mtx_;
    std::function<void(ThreatEvent)>        threat_cb_;
    std::vector<AtomicTestResult>           last_results_;
    uint64_t                                events_processed_{0};
    size_t                                  threats_detected_{0};
};

} // namespace gcad
