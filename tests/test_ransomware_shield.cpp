#include "gcad/engines/ransomware_shield_engine.hpp"
#include <fstream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_ransomware_shield_tests() {
    register_test("ransom_entropy_zero", [] {
        return gcad::RansomwareShieldEngine::compute_entropy(nullptr, 0) == 0.0;
    });

    register_test("ransom_entropy_uniform", [] {
        std::vector<uint8_t> data(256);
        for (int i = 0; i < 256; ++i) data[i] = static_cast<uint8_t>(i);
        double e = gcad::RansomwareShieldEngine::compute_entropy(data);
        return e >= 7.99 && e <= 8.01;
    });

    register_test("ransom_entropy_low", [] {
        std::vector<uint8_t> data(1000, 0x41);
        double e = gcad::RansomwareShieldEngine::compute_entropy(data);
        return e < 0.01;
    });

    register_test("ransom_entropy_mixed", [] {
        std::vector<uint8_t> data;
        for (int i = 0; i < 500; ++i) data.push_back(0x41);
        for (int i = 0; i < 500; ++i) data.push_back(0x42);
        double e = gcad::RansomwareShieldEngine::compute_entropy(data);
        return e >= 0.9 && e <= 1.1;
    });

    register_test("ransom_ext_known", [] {
        return gcad::RansomwareShieldEngine::is_ransomware_extension(".encrypted") &&
               gcad::RansomwareShieldEngine::is_ransomware_extension(".WNCRY") &&
               gcad::RansomwareShieldEngine::is_ransomware_extension(".locky");
    });

    register_test("ransom_ext_unknown", [] {
        return !gcad::RansomwareShieldEngine::is_ransomware_extension(".txt") &&
               !gcad::RansomwareShieldEngine::is_ransomware_extension(".docx") &&
               !gcad::RansomwareShieldEngine::is_ransomware_extension("");
    });

    register_test("ransom_score_clean", [] {
        gcad::RansomwareIndicator ind{};
        ind.files_modified = 2;
        ind.avg_entropy = 3.0;
        double score = gcad::RansomwareShieldEngine::score_indicator(ind);
        return score < gcad::RansomwareShieldEngine::RISK_THRESHOLD_SUSPICIOUS;
    });

    register_test("ransom_score_shadow_copy", [] {
        gcad::RansomwareIndicator ind{};
        ind.shadow_copy_delete = true;
        double score = gcad::RansomwareShieldEngine::score_indicator(ind);
        return score >= 0.35;
    });

    register_test("ransom_score_honeyfile", [] {
        gcad::RansomwareIndicator ind{};
        ind.honeyfile_triggered = true;
        double score = gcad::RansomwareShieldEngine::score_indicator(ind);
        return score >= 0.30;
    });

    register_test("ransom_score_mass_modify", [] {
        gcad::RansomwareIndicator ind{};
        ind.files_modified = 100;
        ind.files_renamed = 50;
        ind.avg_entropy = 7.5;
        double score = gcad::RansomwareShieldEngine::score_indicator(ind);
        return score >= gcad::RansomwareShieldEngine::RISK_THRESHOLD_SUSPICIOUS;
    });

    register_test("ransom_score_full_attack", [] {
        gcad::RansomwareIndicator ind{};
        ind.files_modified = 100;
        ind.files_renamed = 50;
        ind.files_deleted = 20;
        ind.avg_entropy = 7.8;
        ind.shadow_copy_delete = true;
        ind.honeyfile_triggered = true;
        double score = gcad::RansomwareShieldEngine::score_indicator(ind);
        return score >= gcad::RansomwareShieldEngine::RISK_THRESHOLD_MALICIOUS;
    });

    register_test("ransom_score_clamp", [] {
        gcad::RansomwareIndicator ind{};
        ind.files_modified = 1000;
        ind.files_renamed = 500;
        ind.files_deleted = 200;
        ind.avg_entropy = 7.99;
        ind.shadow_copy_delete = true;
        ind.honeyfile_triggered = true;
        double score = gcad::RansomwareShieldEngine::score_indicator(ind);
        return score <= 1.0;
    });

    register_test("ransom_ingest_tracks_indicator", [] {
        gcad::RansomwareShieldEngine engine;
        gcad::FileIOEvent ev;
        ev.type = gcad::FileIOType::IO_WRITE;
        ev.process_id = 1234;
        ev.process_name = "evil.exe";
        ev.file_path = "C:\\Users\\victim\\doc.txt";
        ev.entropy = 5.0;
        ev.timestamp = std::chrono::system_clock::now();
        engine.ingest_file_io(ev);
        auto inds = engine.active_indicators();
        return inds.size() == 1 && inds[0].process_id == 1234 && inds[0].files_modified == 1;
    });

    register_test("ransom_ingest_rename_counts", [] {
        gcad::RansomwareShieldEngine engine;
        gcad::FileIOEvent ev;
        ev.type = gcad::FileIOType::IO_RENAME;
        ev.process_id = 5678;
        ev.process_name = "rename.exe";
        ev.file_path = "C:\\data\\file.doc";
        ev.new_path = "C:\\data\\file.doc.locked";
        ev.timestamp = std::chrono::system_clock::now();
        engine.ingest_file_io(ev);
        auto inds = engine.active_indicators();
        return inds.size() == 1 && inds[0].files_renamed >= 1;
    });

    register_test("ransom_ransomware_ext_bonus", [] {
        gcad::RansomwareShieldEngine engine;
        gcad::FileIOEvent ev;
        ev.type = gcad::FileIOType::IO_RENAME;
        ev.process_id = 9999;
        ev.process_name = "ransom.exe";
        ev.file_path = "file.doc";
        ev.new_path = "file.doc.encrypted";
        ev.timestamp = std::chrono::system_clock::now();
        engine.ingest_file_io(ev);
        auto inds = engine.active_indicators();
        return inds[0].files_renamed >= 3;
    });

    register_test("ransom_shadow_copy_alert", [] {
        gcad::RansomwareShieldEngine engine;
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            fired = ev.category == gcad::ThreatCategory::RANSOMWARE &&
                    ev.level == gcad::ThreatLevel::CRITICAL;
        });
        engine.report_shadow_copy_delete(111, "vssadmin.exe");
        return fired;
    });

    register_test("ransom_malicious_fires_threat", [] {
        gcad::RansomwareShieldEngine engine;
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            if (ev.category == gcad::ThreatCategory::RANSOMWARE &&
                ev.level == gcad::ThreatLevel::CRITICAL)
                fired = true;
        });
        auto now = std::chrono::system_clock::now();
        engine.report_shadow_copy_delete(42, "evil.exe");
        for (int i = 0; i < 60; ++i) {
            gcad::FileIOEvent ev;
            ev.type = gcad::FileIOType::IO_WRITE;
            ev.process_id = 42;
            ev.process_name = "evil.exe";
            ev.file_path = "file" + std::to_string(i) + ".doc";
            ev.entropy = 7.5;
            ev.timestamp = now;
            engine.ingest_file_io(ev);
        }
        return fired;
    });

    register_test("ransom_honeyfile_deleted", [] {
        auto tmp = std::filesystem::temp_directory_path() / "gcad_honey_test.txt";
        { std::ofstream f(tmp); f << "canary data"; }
        gcad::RansomwareShieldEngine engine;
        engine.add_honeyfile(tmp);
        std::filesystem::remove(tmp);
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            if (ev.category == gcad::ThreatCategory::RANSOMWARE) fired = true;
        });
        engine.check_honeyfiles();
        return fired;
    });

    register_test("ransom_honeyfile_tampered", [] {
        auto tmp = std::filesystem::temp_directory_path() / "gcad_honey_tamper.txt";
        { std::ofstream f(tmp); f << "original content"; }
        gcad::RansomwareShieldEngine engine;
        engine.add_honeyfile(tmp);
        { std::ofstream f(tmp, std::ios::trunc); f << "ENCRYPTED DATA!!!!"; }
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            if (ev.category == gcad::ThreatCategory::RANSOMWARE) fired = true;
        });
        engine.check_honeyfiles();
        std::filesystem::remove(tmp);
        return fired;
    });

    register_test("ransom_honeyfile_untouched", [] {
        auto tmp = std::filesystem::temp_directory_path() / "gcad_honey_safe.txt";
        { std::ofstream f(tmp); f << "safe content here"; }
        gcad::RansomwareShieldEngine engine;
        engine.add_honeyfile(tmp);
        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent) { fired = true; });
        engine.check_honeyfiles();
        std::filesystem::remove(tmp);
        return !fired;
    });

    register_test("ransom_start_stop", [] {
        gcad::RansomwareShieldEngine engine;
        if (engine.running()) return false;
        engine.start();
        if (!engine.running()) return false;
        auto s = engine.status();
        if (s.name != "RansomwareShield") return false;
        engine.stop();
        return !engine.running();
    });

    register_test("ransom_indicator_ids_unique", [] {
        gcad::RansomwareShieldEngine engine;
        auto now = std::chrono::system_clock::now();
        for (uint32_t pid = 1; pid <= 5; ++pid) {
            gcad::FileIOEvent ev;
            ev.type = gcad::FileIOType::IO_WRITE;
            ev.process_id = pid;
            ev.process_name = "proc" + std::to_string(pid);
            ev.file_path = "f.txt";
            ev.timestamp = now;
            engine.ingest_file_io(ev);
        }
        auto inds = engine.active_indicators();
        if (inds.size() != 5) return false;
        std::unordered_map<uint64_t, int> ids;
        for (const auto& ind : inds) ++ids[ind.id];
        for (const auto& [id, count] : ids)
            if (count > 1) return false;
        return true;
    });

    register_test("ransom_delete_event", [] {
        gcad::RansomwareShieldEngine engine;
        gcad::FileIOEvent ev;
        ev.type = gcad::FileIOType::IO_DELETE;
        ev.process_id = 7777;
        ev.process_name = "del.exe";
        ev.file_path = "important.xlsx";
        ev.timestamp = std::chrono::system_clock::now();
        engine.ingest_file_io(ev);
        auto inds = engine.active_indicators();
        return inds.size() == 1 && inds[0].files_deleted == 1;
    });

    register_test("ransom_multiple_honeyfiles", [] {
        gcad::RansomwareShieldEngine engine;
        auto tmp1 = std::filesystem::temp_directory_path() / "gcad_hf1.txt";
        auto tmp2 = std::filesystem::temp_directory_path() / "gcad_hf2.txt";
        { std::ofstream f(tmp1); f << "honey1"; }
        { std::ofstream f(tmp2); f << "honey2"; }
        engine.add_honeyfile(tmp1);
        engine.add_honeyfile(tmp2);
        auto hfs = engine.honeyfiles();
        std::filesystem::remove(tmp1);
        std::filesystem::remove(tmp2);
        return hfs.size() == 2;
    });
}
