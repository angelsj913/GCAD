#include "gcad/engines/update_engine.hpp"
#include <fstream>

extern void register_test(const char* name, std::function<bool()> fn);

static std::filesystem::path temp_dir() {
    return std::filesystem::temp_directory_path() / "gcad_update_test";
}

static void write_test_file(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream f(path, std::ios::trunc);
    f << content;
}

void register_update_engine_tests() {
    register_test("update_compute_sha256", [] {
        auto dir = temp_dir();
        auto file = dir / "test_sha.txt";
        write_test_file(file, "hello");
        auto hash = gcad::UpdateEngine::compute_file_sha256(file);
        std::filesystem::remove_all(dir);
        return hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    });

    register_test("update_compute_sha256_nonexistent", [] {
        return gcad::UpdateEngine::compute_file_sha256("nonexistent_file_xyz").empty();
    });

    register_test("update_verify_checksum_valid", [] {
        auto dir = temp_dir();
        auto file = dir / "verify.txt";
        write_test_file(file, "hello");
        bool ok = gcad::UpdateEngine::verify_checksum(file,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        std::filesystem::remove_all(dir);
        return ok;
    });

    register_test("update_verify_checksum_invalid", [] {
        auto dir = temp_dir();
        auto file = dir / "verify2.txt";
        write_test_file(file, "hello");
        bool ok = gcad::UpdateEngine::verify_checksum(file, "0000000000000000000000000000000000000000000000000000000000000000");
        std::filesystem::remove_all(dir);
        return !ok;
    });

    register_test("update_verify_checksum_empty_expected", [] {
        auto dir = temp_dir();
        auto file = dir / "verify3.txt";
        write_test_file(file, "anything");
        bool ok = gcad::UpdateEngine::verify_checksum(file, "");
        std::filesystem::remove_all(dir);
        return ok;
    });

    register_test("update_verify_checksum_case_insensitive", [] {
        auto dir = temp_dir();
        auto file = dir / "verify4.txt";
        write_test_file(file, "hello");
        bool ok = gcad::UpdateEngine::verify_checksum(file,
            "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824");
        std::filesystem::remove_all(dir);
        return ok;
    });

    register_test("update_parse_version_with_header", [] {
        auto dir = temp_dir();
        auto file = dir / "versioned.db";
        write_test_file(file, "# version: 2.5.1\n# some comment\ndata\n");
        auto ver = gcad::UpdateEngine::parse_version_from_file(file);
        std::filesystem::remove_all(dir);
        return ver == "2.5.1";
    });

    register_test("update_parse_version_no_header", [] {
        auto dir = temp_dir();
        auto file = dir / "noheader.db";
        write_test_file(file, "just data\n");
        auto ver = gcad::UpdateEngine::parse_version_from_file(file);
        std::filesystem::remove_all(dir);
        return ver == "1.0.0";
    });

    register_test("update_parse_version_nonexistent", [] {
        return gcad::UpdateEngine::parse_version_from_file("no_such_file") == "0.0.0";
    });

    register_test("update_load_signature_db_success", [] {
        auto dir = temp_dir();
        auto file = dir / "sigs.db";
        write_test_file(file, "# version: 1.0.0\ntest|4|4142|test sig\n");
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        auto result = ue.load_signature_db(file);
        std::filesystem::remove_all(dir);
        return result == gcad::UpdateResult::SUCCESS;
    });

    register_test("update_load_signature_db_not_found", [] {
        gcad::UpdateEngine ue;
        return ue.load_signature_db("nonexistent_db.dat") == gcad::UpdateResult::FILE_NOT_FOUND;
    });

    register_test("update_load_signature_db_bad_checksum", [] {
        auto dir = temp_dir();
        auto file = dir / "sigs2.db";
        write_test_file(file, "# version: 1.0.0\ndata\n");
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        auto result = ue.load_signature_db(file, "0000000000000000000000000000000000000000000000000000000000000000");
        std::filesystem::remove_all(dir);
        return result == gcad::UpdateResult::CHECKSUM_MISMATCH;
    });

    register_test("update_load_already_current", [] {
        auto dir = temp_dir();
        auto file = dir / "sigs3.db";
        write_test_file(file, "# version: 1.0.0\ndata\n");
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        ue.load_signature_db(file);
        auto result = ue.load_signature_db(file);
        std::filesystem::remove_all(dir);
        return result == gcad::UpdateResult::ALREADY_CURRENT;
    });

    register_test("update_load_ioc_db", [] {
        auto dir = temp_dir();
        auto file = dir / "ioc.db";
        write_test_file(file, "# version: 1.0.0\ndomain|evil.com|high|test|test\n");
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        return ue.load_ioc_db(file) == gcad::UpdateResult::SUCCESS;
    });

    register_test("update_load_yara_rules", [] {
        auto dir = temp_dir();
        auto file = dir / "rules.yar";
        write_test_file(file, "# version: 1.0.0\nrule test { condition: true }\n");
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        auto result = ue.load_yara_rules(file);
        std::filesystem::remove_all(dir);
        return result == gcad::UpdateResult::SUCCESS;
    });

    register_test("update_current_versions", [] {
        auto dir = temp_dir();
        auto file = dir / "sigs4.db";
        write_test_file(file, "# version: 3.2.0\ndata\n");
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        ue.load_signature_db(file);
        auto versions = ue.current_versions();
        std::filesystem::remove_all(dir);
        return versions.size() == 1 && versions[0].version == "3.2.0";
    });

    register_test("update_recent_updates_logged", [] {
        auto dir = temp_dir();
        auto file = dir / "sigs5.db";
        write_test_file(file, "# version: 1.0.0\ndata\n");
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        ue.load_signature_db(file);
        auto updates = ue.recent_updates();
        std::filesystem::remove_all(dir);
        return !updates.empty() && updates.back().db_name == "signatures";
    });

    register_test("update_manifest_roundtrip", [] {
        auto dir = temp_dir();
        auto db = dir / "sigs6.db";
        auto manifest = dir / "manifest.txt";
        write_test_file(db, "# version: 2.0.0\ndata\n");

        gcad::UpdateEngine ue1;
        ue1.set_data_dir(dir);
        ue1.load_signature_db(db);
        ue1.write_manifest(manifest);

        gcad::UpdateEngine ue2;
        ue2.set_data_dir(dir);
        ue2.read_manifest(manifest);
        auto versions = ue2.current_versions();

        std::filesystem::remove_all(dir);
        return versions.size() == 1 && versions[0].db_name == "signatures" && versions[0].version == "2.0.0";
    });

    register_test("update_check_detects_change", [] {
        auto dir = temp_dir();
        auto db = dir / "sigs7.db";
        write_test_file(db, "# version: 1.0.0\ndata\n");

        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        ue.load_signature_db(db);

        write_test_file(db, "# version: 1.1.0\nnew data\n");
        size_t changed = ue.check_for_updates();

        std::filesystem::remove_all(dir);
        return changed == 1;
    });

    register_test("update_check_no_change", [] {
        auto dir = temp_dir();
        auto db = dir / "sigs8.db";
        write_test_file(db, "# version: 1.0.0\ndata\n");

        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        ue.load_signature_db(db);
        size_t changed = ue.check_for_updates();

        std::filesystem::remove_all(dir);
        return changed == 0;
    });

    register_test("update_tamper_threat_callback", [] {
        auto dir = temp_dir();
        auto db = dir / "sigs9.db";
        write_test_file(db, "data");

        bool threat_fired = false;
        gcad::UpdateEngine ue;
        ue.set_data_dir(dir);
        ue.on_threat([&](gcad::ThreatEvent) { threat_fired = true; });
        ue.load_signature_db(db, "0000000000000000000000000000000000000000000000000000000000000000");

        std::filesystem::remove_all(dir);
        return threat_fired;
    });

    register_test("update_start_stop", [] {
        gcad::UpdateEngine ue;
        if (ue.running()) return false;
        ue.start();
        if (!ue.running()) return false;
        auto s = ue.status();
        if (s.name != "AutoUpdate") return false;
        ue.stop();
        return !ue.running();
    });
}
