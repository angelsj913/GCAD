#include "gcad/engines/atomic_red_team_engine.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/engines/reflective_injection_engine.hpp"
#include "gcad/engines/self_defense.hpp"
#include "gcad/engines/credential_guard_engine.hpp"
#include "gcad/engines/ransomware_shield_engine.hpp"
#include "gcad/engines/network_dpi_engine.hpp"
#include <functional>
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_atomic_red_team_tests() {
    register_test("atomic_red_team_name_and_lifecycle", [] {
        gcad::AtomicRedTeamEngine engine;
        if (engine.name() != "AtomicRedTeam") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("atomic_red_team_t1055_dll_injection", [] {
        gcad::AtomicRedTeamEngine red_team;
        gcad::EngineManager em;
        auto res = red_team.simulate_t1055_dll_injection(em);
        if (!res.executed) return false;
        if (!res.detected) return false;
        if (res.technique_id != "T1055.001") return false;
        return true;
    });

    register_test("atomic_red_team_t1562_impair_defenses", [] {
        gcad::AtomicRedTeamEngine red_team;
        gcad::EngineManager em;
        auto res = red_team.simulate_t1562_impair_defenses(em);
        if (!res.executed) return false;
        if (!res.detected) return false;
        if (res.technique_id != "T1562.001") return false;
        return true;
    });

    register_test("atomic_red_team_t1003_credential_dump", [] {
        gcad::AtomicRedTeamEngine red_team;
        gcad::EngineManager em;
        auto res = red_team.simulate_t1003_credential_dump(em);
        if (!res.executed) return false;
        if (!res.detected) return false;
        return true;
    });

    register_test("atomic_red_team_t1486_data_encrypted", [] {
        gcad::AtomicRedTeamEngine red_team;
        gcad::EngineManager em;
        auto res = red_team.simulate_t1486_data_encrypted(em);
        if (!res.executed) return false;
        if (!res.detected) return false;
        return true;
    });

    register_test("atomic_red_team_t1071_c2_beaconing", [] {
        gcad::AtomicRedTeamEngine red_team;
        gcad::EngineManager em;
        auto res = red_team.simulate_t1071_c2_beaconing(em);
        if (!res.executed) return false;
        if (!res.detected) return false;
        return true;
    });

    register_test("atomic_red_team_run_all_and_score", [] {
        gcad::AtomicRedTeamEngine red_team;
        gcad::EngineManager em;
        auto results = red_team.run_all_simulations(em);
        if (results.size() != 5) return false;
        float score = red_team.calculate_defense_score(results);
        if (score < 80.0f) return false; // Must achieve high defense score
        auto last = red_team.last_results();
        if (last.size() != 5) return false;
        return true;
    });
}
