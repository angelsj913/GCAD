#include "gcad/engines/credential_guard_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_credential_guard_tests() {
    register_test("cred_known_tool_mimikatz", [] {
        return gcad::CredentialGuardEngine::is_known_dump_tool("mimikatz.exe");
    });

    register_test("cred_known_tool_procdump", [] {
        return gcad::CredentialGuardEngine::is_known_dump_tool("procdump64.exe");
    });

    register_test("cred_known_tool_case_insensitive", [] {
        return gcad::CredentialGuardEngine::is_known_dump_tool("MIMIKATZ.EXE");
    });

    register_test("cred_known_tool_path", [] {
        return gcad::CredentialGuardEngine::is_known_dump_tool("C:\\Temp\\mimikatz.exe");
    });

    register_test("cred_not_known_tool", [] {
        return !gcad::CredentialGuardEngine::is_known_dump_tool("notepad.exe") &&
               !gcad::CredentialGuardEngine::is_known_dump_tool("chrome.exe") &&
               !gcad::CredentialGuardEngine::is_known_dump_tool("");
    });

    register_test("cred_suspicious_access_vm_read", [] {
        return gcad::CredentialGuardEngine::is_suspicious_lsass_access(
            gcad::CredentialGuardEngine::MASK_VM_READ);
    });

    register_test("cred_suspicious_access_all", [] {
        return gcad::CredentialGuardEngine::is_suspicious_lsass_access(
            gcad::CredentialGuardEngine::MASK_ALL_ACCESS);
    });

    register_test("cred_not_suspicious_query", [] {
        return !gcad::CredentialGuardEngine::is_suspicious_lsass_access(
            gcad::CredentialGuardEngine::MASK_QUERY_INFO);
    });

    register_test("cred_classify_critical", [] {
        return gcad::CredentialGuardEngine::classify_attack(
                   gcad::CredentialAttackType::ATK_GOLDEN_TICKET) == gcad::ThreatLevel::CRITICAL &&
               gcad::CredentialGuardEngine::classify_attack(
                   gcad::CredentialAttackType::ATK_PASS_THE_HASH) == gcad::ThreatLevel::CRITICAL;
    });

    register_test("cred_classify_high", [] {
        return gcad::CredentialGuardEngine::classify_attack(
                   gcad::CredentialAttackType::ATK_LSASS_ACCESS) == gcad::ThreatLevel::HIGH &&
               gcad::CredentialGuardEngine::classify_attack(
                   gcad::CredentialAttackType::ATK_SAM_DUMP) == gcad::ThreatLevel::HIGH;
    });

    register_test("cred_map_category_dump", [] {
        return gcad::CredentialGuardEngine::map_to_category(
                   gcad::CredentialAttackType::ATK_LSASS_ACCESS) == gcad::ThreatCategory::CREDENTIAL_DUMP &&
               gcad::CredentialGuardEngine::map_to_category(
                   gcad::CredentialAttackType::ATK_SAM_DUMP) == gcad::ThreatCategory::CREDENTIAL_DUMP;
    });

    register_test("cred_map_category_kerberos", [] {
        return gcad::CredentialGuardEngine::map_to_category(
                   gcad::CredentialAttackType::ATK_PASS_THE_HASH) == gcad::ThreatCategory::KERBEROS_ATTACK &&
               gcad::CredentialGuardEngine::map_to_category(
                   gcad::CredentialAttackType::ATK_GOLDEN_TICKET) == gcad::ThreatCategory::KERBEROS_ATTACK;
    });

    register_test("cred_map_category_token", [] {
        return gcad::CredentialGuardEngine::map_to_category(
                   gcad::CredentialAttackType::ATK_TOKEN_IMPERSONATE) == gcad::ThreatCategory::NTLM_COERCE;
    });

    register_test("cred_attack_type_names", [] {
        for (int i = 0; i <= 9; ++i) {
            auto name = gcad::CredentialGuardEngine::attack_type_name(
                static_cast<gcad::CredentialAttackType>(i));
            if (std::string(name) == "Unknown") return false;
        }
        return true;
    });

    register_test("cred_score_clean", [] {
        gcad::CredentialThreatIndicator ind{};
        double score = gcad::CredentialGuardEngine::score_indicator(ind);
        return score < gcad::CredentialGuardEngine::RISK_THRESHOLD_SUSPICIOUS;
    });

    register_test("cred_score_known_tool", [] {
        gcad::CredentialThreatIndicator ind{};
        ind.known_tool = true;
        double score = gcad::CredentialGuardEngine::score_indicator(ind);
        return score >= 0.50;
    });

    register_test("cred_score_lsass_multi", [] {
        gcad::CredentialThreatIndicator ind{};
        ind.lsass_access_count = 5;
        ind.token_manipulation_count = 2;
        double score = gcad::CredentialGuardEngine::score_indicator(ind);
        return score >= gcad::CredentialGuardEngine::RISK_THRESHOLD_SUSPICIOUS;
    });

    register_test("cred_score_full_attack", [] {
        gcad::CredentialThreatIndicator ind{};
        ind.known_tool = true;
        ind.lsass_access_count = 5;
        ind.token_manipulation_count = 3;
        ind.lateral_movement_count = 1;
        ind.sam_access_count = 1;
        double score = gcad::CredentialGuardEngine::score_indicator(ind);
        return score >= gcad::CredentialGuardEngine::RISK_THRESHOLD_MALICIOUS;
    });

    register_test("cred_score_clamp", [] {
        gcad::CredentialThreatIndicator ind{};
        ind.known_tool = true;
        ind.lsass_access_count = 100;
        ind.token_manipulation_count = 100;
        ind.lateral_movement_count = 100;
        ind.sam_access_count = 100;
        double score = gcad::CredentialGuardEngine::score_indicator(ind);
        return score <= 1.0;
    });

    register_test("cred_ingest_tracks", [] {
        gcad::CredentialGuardEngine engine;
        gcad::CredentialAccessEvent ev;
        ev.type = gcad::CredentialAttackType::ATK_LSASS_ACCESS;
        ev.source_pid = 1234;
        ev.source_process = "suspicious.exe";
        ev.timestamp = std::chrono::system_clock::now();
        engine.ingest(ev);
        auto inds = engine.active_indicators();
        return inds.size() == 1 && inds[0].lsass_access_count == 1;
    });

    register_test("cred_active_indicators_returns_highest_risk_first", [] {
        gcad::CredentialGuardEngine engine;
        engine.report_lsass_access(11001, "low.exe", gcad::CredentialGuardEngine::MASK_VM_READ);
        for (int i = 0; i < 3; ++i)
            engine.report_lsass_access(11002, "high.exe", gcad::CredentialGuardEngine::MASK_VM_READ);
        engine.report_token_manipulation(11002, "high.exe",
                                         gcad::CredentialAttackType::ATK_TOKEN_IMPERSONATE);
        engine.report_sam_access(11002, "high.exe");

        auto inds = engine.active_indicators(1);
        return inds.size() == 1 && inds[0].pid == 11002 && inds[0].risk_score > 0.5;
    });

    register_test("cred_observation_has_source_id", [] {
        gcad::CredentialGuardEngine engine;
        std::vector<gcad::security::SecurityObservation> observations;
        engine.on_observation([&](gcad::security::SecurityObservation obs) {
            observations.push_back(std::move(obs));
        });

        engine.report_lsass_access(11003, "suspicious.exe",
                                   gcad::CredentialGuardEngine::MASK_VM_READ);
        engine.report_token_manipulation(11003, "suspicious.exe",
                                         gcad::CredentialAttackType::ATK_TOKEN_IMPERSONATE);
        engine.report_sam_access(11003, "suspicious.exe");

        return !observations.empty() && observations.back().source_id == "CredentialGuard" &&
               observations.back().valid();
    });

    register_test("cred_known_tool_fires_threat", [] {
        gcad::CredentialGuardEngine engine;
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            if (ev.category == gcad::ThreatCategory::CREDENTIAL_DUMP)
                fired = true;
        });
        gcad::CredentialAccessEvent ev;
        ev.type = gcad::CredentialAttackType::ATK_LSASS_ACCESS;
        ev.source_pid = 42;
        ev.source_process = "mimikatz.exe";
        ev.timestamp = std::chrono::system_clock::now();
        engine.ingest(ev);
        return fired;
    });

    register_test("cred_report_lsass_filters", [] {
        gcad::CredentialGuardEngine engine;
        engine.report_lsass_access(100, "safe.exe",
                                    gcad::CredentialGuardEngine::MASK_QUERY_INFO);
        auto events = engine.recent_events();
        return events.empty();
    });

    register_test("cred_report_lsass_suspicious", [] {
        gcad::CredentialGuardEngine engine;
        engine.report_lsass_access(200, "attacker.exe",
                                    gcad::CredentialGuardEngine::MASK_VM_READ);
        auto events = engine.recent_events();
        return events.size() == 1;
    });

    register_test("cred_report_sam_access", [] {
        gcad::CredentialGuardEngine engine;
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent) { fired = true; });
        engine.report_sam_access(300, "mimikatz.exe");
        return fired;
    });

    register_test("cred_event_ids_unique", [] {
        gcad::CredentialGuardEngine engine;
        auto now = std::chrono::system_clock::now();
        for (int i = 0; i < 5; ++i) {
            gcad::CredentialAccessEvent ev;
            ev.type = gcad::CredentialAttackType::ATK_TOKEN_IMPERSONATE;
            ev.source_pid = 500;
            ev.source_process = "proc.exe";
            ev.timestamp = now;
            engine.ingest(ev);
        }
        auto events = engine.recent_events();
        std::unordered_map<uint64_t, int> ids;
        for (const auto& ev : events) ++ids[ev.id];
        for (const auto& [id, count] : ids)
            if (count > 1) return false;
        return true;
    });

    register_test("cred_start_stop", [] {
        gcad::CredentialGuardEngine engine;
        if (engine.running()) return false;
        engine.start();
        if (!engine.running()) return false;
        auto s = engine.status();
        if (s.name != "CredentialGuard") return false;
        engine.stop();
        return !engine.running();
    });
}
