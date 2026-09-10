#include "gcad/common.hpp"
#include "gcad/engines/arhs_engine.hpp"
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_arhs_tests() {
    register_test("arhs_name", [] {
        gcad::ARHSEngine engine;
        return engine.name() == "ARHS";
    });

    register_test("arhs_initial_state", [] {
        gcad::ARHSEngine engine;
        if (engine.running()) return false;
        if (engine.rollbacks_performed() != 0) return false;
        if (!engine.sandboxed_processes().empty()) return false;
        return true;
    });

    register_test("arhs_status", [] {
        gcad::ARHSEngine engine;
        auto s = engine.status();
        if (s.name != "ARHS") return false;
        if (s.running) return false;
        return true;
    });

    register_test("arhs_cow_snapshot_struct", [] {
        gcad::CowSnapshot snap;
        snap.path = "/tmp/test.txt";
        snap.original_data = {1, 2, 3};
        snap.original_size = 3;
        snap.sha256_hash = "abc123";
        if (snap.path != "/tmp/test.txt") return false;
        if (snap.original_data.size() != 3) return false;
        return true;
    });

    register_test("arhs_ransomware_entropy_threshold", [] {
        std::array<uint8_t, 256> data;
        for (int i = 0; i < 256; i++) data[i] = static_cast<uint8_t>(i);
        double ent = gcad::shannon_entropy(data.data(), data.size());
        return ent > 7.8;
    });

    register_test("arhs_sha256_file_hash", [] {
        auto hash = gcad::SHA256::hash_bytes(
            reinterpret_cast<const uint8_t*>("ransomware_test"), 15);
        return hash.size() == 64;
    });

    register_test("arhs_snapshot_and_rollback", [] {
        gcad::ARHSEngine engine;
        auto temp_dir = std::filesystem::temp_directory_path() / "gcad_test_arhs";
        std::error_code ec;
        std::filesystem::create_directories(temp_dir, ec);
        auto test_file = temp_dir / "protected.txt";

        {
            std::ofstream f(test_file, std::ios::binary);
            f.write("ORIGINAL_CLEAN_DATA", 19);
        }

        engine.take_snapshot(test_file);

        {
            std::ofstream f(test_file, std::ios::binary);
            f.write("ENCRYPTED_MALICIOUS", 19);
        }

        auto rc = engine.rollback_file(test_file);
        if (rc != gcad::ErrorCode::OK) {
            std::filesystem::remove_all(temp_dir, ec);
            return false;
        }

        std::string content;
        {
            std::ifstream f(test_file, std::ios::binary);
            content.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        }
        std::filesystem::remove_all(temp_dir, ec);
        return content == "ORIGINAL_CLEAN_DATA" && engine.rollbacks_performed() == 1;
    });
}
