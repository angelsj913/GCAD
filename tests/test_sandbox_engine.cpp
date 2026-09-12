#include "gcad/engines/sandbox_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_sandbox_engine_tests() {
    register_test("sandbox_classify_clean", [] {
        gcad::SandboxBehavior b;
        b.files_created = 2;
        b.registry_writes = 1;
        double risk = 0.0;
        auto v = gcad::SandboxEngine::classify(b, risk);
        return v == gcad::SandboxVerdict::CLEAN && risk < 30.0;
    });

    register_test("sandbox_classify_suspicious", [] {
        gcad::SandboxBehavior b;
        b.files_deleted = 10;
        b.registry_writes = 12;
        b.network_connections = 6;
        b.child_processes = 3;
        b.attempted_debug_api = true;
        b.suspicious_apis = {"NtCreateSection", "WriteProcessMemory"};
        double risk = 0.0;
        auto v = gcad::SandboxEngine::classify(b, risk);
        return v == gcad::SandboxVerdict::SUSPICIOUS && risk >= 30.0 && risk < 70.0;
    });

    register_test("sandbox_classify_malicious", [] {
        gcad::SandboxBehavior b;
        b.attempted_sandbox_escape = true;
        b.attempted_process_injection = true;
        b.encrypted_files = true;
        b.modified_startup_entries = true;
        double risk = 0.0;
        auto v = gcad::SandboxEngine::classify(b, risk);
        return v == gcad::SandboxVerdict::MALICIOUS && risk >= 70.0;
    });

    register_test("sandbox_classify_risk_capped_at_100", [] {
        gcad::SandboxBehavior b;
        b.attempted_sandbox_escape = true;
        b.attempted_process_injection = true;
        b.attempted_privilege_escalation = true;
        b.attempted_debug_api = true;
        b.encrypted_files = true;
        b.modified_startup_entries = true;
        b.files_deleted = 50;
        b.registry_writes = 20;
        b.network_connections = 10;
        b.child_processes = 10;
        b.memory_allocations = 100;
        b.suspicious_apis = {"a", "b", "c", "d", "e", "f"};
        double risk = 0.0;
        gcad::SandboxEngine::classify(b, risk);
        return risk == 100.0;
    });

    register_test("sandbox_detect_escape_basic", [] {
        gcad::SandboxBehavior b;
        b.attempted_sandbox_escape = true;
        return gcad::SandboxEngine::detect_escape_attempt(b);
    });

    register_test("sandbox_detect_escape_combined", [] {
        gcad::SandboxBehavior b;
        b.attempted_process_injection = true;
        b.attempted_privilege_escalation = true;
        return gcad::SandboxEngine::detect_escape_attempt(b);
    });

    register_test("sandbox_no_escape_clean", [] {
        gcad::SandboxBehavior b;
        b.files_created = 5;
        return !gcad::SandboxEngine::detect_escape_attempt(b);
    });

    register_test("sandbox_generate_summary_clean", [] {
        gcad::SandboxBehavior b;
        b.files_created = 1;
        auto s = gcad::SandboxEngine::generate_summary(b, gcad::SandboxVerdict::CLEAN);
        return s.find("CLEAN") != std::string::npos && s.find("1 created") != std::string::npos;
    });

    register_test("sandbox_generate_summary_malicious", [] {
        gcad::SandboxBehavior b;
        b.attempted_sandbox_escape = true;
        b.encrypted_files = true;
        b.suspicious_apis = {"VirtualAllocEx", "WriteProcessMemory"};
        auto s = gcad::SandboxEngine::generate_summary(b, gcad::SandboxVerdict::MALICIOUS);
        return s.find("MALICIOUS") != std::string::npos
            && s.find("escape") != std::string::npos
            && s.find("encryption") != std::string::npos
            && s.find("VirtualAllocEx") != std::string::npos;
    });

    register_test("sandbox_generate_summary_many_apis", [] {
        gcad::SandboxBehavior b;
        b.suspicious_apis = {"a", "b", "c", "d", "e", "f", "g"};
        auto s = gcad::SandboxEngine::generate_summary(b, gcad::SandboxVerdict::SUSPICIOUS);
        return s.find("+2 more") != std::string::npos;
    });

    register_test("sandbox_start_stop", [] {
        gcad::SandboxEngine se;
        if (se.running()) return false;
        se.start();
        if (!se.running()) return false;
        auto s = se.status();
        if (s.name != "Sandbox") return false;
        se.stop();
        return !se.running();
    });

    register_test("sandbox_submit_nonexistent_file", [] {
        gcad::SandboxEngine se;
        se.start();
        auto id = se.submit("C:\\nonexistent_sandbox_test_file.exe", 100);
        for (int i = 0; i < 40; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            auto a = se.get_analysis(id);
            if (a.verdict != gcad::SandboxVerdict::PENDING) {
                se.stop();
                return a.verdict == gcad::SandboxVerdict::ANALYSIS_ERROR;
            }
        }
        se.stop();
        return false;
    });

    register_test("sandbox_recent_analyses", [] {
        gcad::SandboxEngine se;
        se.submit("test1.exe");
        se.submit("test2.exe");
        auto recent = se.recent_analyses(10);
        return recent.size() == 2;
    });

    register_test("sandbox_analysis_id_unique", [] {
        gcad::SandboxEngine se;
        auto id1 = se.submit("a.exe");
        auto id2 = se.submit("b.exe");
        return id1 != id2;
    });

    register_test("sandbox_threat_callback_on_malicious", [] {
        gcad::SandboxBehavior b;
        b.attempted_sandbox_escape = true;
        b.attempted_process_injection = true;
        b.encrypted_files = true;
        double risk = 0.0;
        auto verdict = gcad::SandboxEngine::classify(b, risk);
        return verdict == gcad::SandboxVerdict::MALICIOUS;
    });
}
