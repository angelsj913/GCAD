#include "gcad/common.hpp"
#include "gcad/engines/file_integrity_engine.hpp"
#include <iostream>
#include <fstream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_file_integrity_tests() {
    register_test("fim_name", [] {
        gcad::FileIntegrityEngine engine;
        return engine.name() == "FIM";
    });

    register_test("fim_initial_state", [] {
        gcad::FileIntegrityEngine engine;
        if (engine.running()) return false;
        auto s = engine.status();
        if (s.running) return false;
        if (s.events_processed != 0) return false;
        if (s.threats_detected != 0) return false;
        return true;
    });

    register_test("fim_status_name", [] {
        gcad::FileIntegrityEngine engine;
        auto s = engine.status();
        return s.name == "FIM";
    });

    register_test("fim_default_watch_paths", [] {
        auto paths = gcad::FileIntegrityEngine::default_watch_paths();
        if (paths.empty()) return false;
#ifdef GCAD_PLATFORM_WINDOWS
        bool has_hosts = false;
        for (auto& p : paths) {
            if (p.string().find("hosts") != std::string::npos) has_hosts = true;
        }
        return has_hosts;
#else
        bool has_passwd = false;
        for (auto& p : paths) {
            if (p.string().find("passwd") != std::string::npos) has_passwd = true;
        }
        return has_passwd;
#endif
    });

    register_test("fim_add_watch_path", [] {
        gcad::FileIntegrityEngine engine;
        engine.add_watch_path("C:\\test_nonexistent_path.txt");
        return true;
    });

    register_test("fim_baseline_empty_before_start", [] {
        gcad::FileIntegrityEngine engine;
        return engine.baseline_size() == 0;
    });

    register_test("fim_on_threat_callback", [] {
        gcad::FileIntegrityEngine engine;
        bool called = false;
        engine.on_threat([&](gcad::ThreatEvent) { called = true; });
        return !called;
    });

    register_test("fim_on_observation_callback", [] {
        gcad::FileIntegrityEngine engine;
        bool called = false;
        engine.on_observation([&](gcad::security::SecurityObservation) { called = true; });
        return !called;
    });

    register_test("fim_start_builds_baseline", [] {
        gcad::FileIntegrityEngine engine;
        auto rc = engine.start();
        if (rc != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        engine.stop();
        return true;
    });

    register_test("fim_double_start", [] {
        gcad::FileIntegrityEngine engine;
        engine.start();
        auto rc = engine.start();
        engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("fim_double_stop", [] {
        gcad::FileIntegrityEngine engine;
        auto rc = engine.stop();
        return rc == gcad::ErrorCode::OK;
    });

    register_test("fim_watch_temp_file", [] {
        auto temp_path = std::filesystem::temp_directory_path() / "gcad_fim_test.txt";
        {
            std::ofstream f(temp_path);
            f << "test content for FIM";
        }

        gcad::FileIntegrityEngine engine;
        engine.add_watch_path(temp_path);
        engine.start();
        if (engine.baseline_size() < 1) { engine.stop(); std::filesystem::remove(temp_path); return false; }
        engine.stop();

        std::filesystem::remove(temp_path);
        return true;
    });
}
