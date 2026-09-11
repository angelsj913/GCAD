#include "gcad/common.hpp"
#include "gcad/engines/yara_engine.hpp"
#include <iostream>
#include <fstream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_yara_engine_tests() {
    register_test("yara_name", [] {
        gcad::YaraEngine engine;
        return engine.name() == "YARA";
    });

    register_test("yara_initial_state", [] {
        gcad::YaraEngine engine;
        if (engine.running()) return false;
        auto s = engine.status();
        if (s.running) return false;
        if (s.events_processed != 0) return false;
        if (s.threats_detected != 0) return false;
        return true;
    });

    register_test("yara_status_name", [] {
        gcad::YaraEngine engine;
        auto s = engine.status();
        return s.name == "YARA";
    });

    register_test("yara_no_rules_initially", [] {
        gcad::YaraEngine engine;
        return engine.rule_count() == 0;
    });

    register_test("yara_load_builtin_rules", [] {
        gcad::YaraEngine engine;
        engine.load_builtin_rules();
        return engine.rule_count() >= 5;
    });

    register_test("yara_add_custom_rule", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "test_rule";
        gcad::YaraString s;
        s.identifier = "$test";
        s.pattern = {'T', 'E', 'S', 'T'};
        s.mask = {0xFF, 0xFF, 0xFF, 0xFF};
        r.strings.push_back(std::move(s));
        r.condition = gcad::YaraRule::ConditionOp::ANY_OF_THEM;
        engine.add_rule(std::move(r));
        return engine.rule_count() == 1;
    });

    register_test("yara_parse_hex_pattern_simple", [] {
        std::vector<uint8_t> pattern, mask;
        bool ok = gcad::YaraEngine::parse_hex_pattern("4D 5A 90 00", pattern, mask);
        if (!ok) return false;
        if (pattern.size() != 4) return false;
        if (pattern[0] != 0x4D || pattern[1] != 0x5A) return false;
        if (mask[0] != 0xFF || mask[1] != 0xFF) return false;
        return true;
    });

    register_test("yara_parse_hex_pattern_wildcard", [] {
        std::vector<uint8_t> pattern, mask;
        bool ok = gcad::YaraEngine::parse_hex_pattern("4D ?? 90 ??", pattern, mask);
        if (!ok) return false;
        if (pattern.size() != 4) return false;
        if (mask[0] != 0xFF) return false;
        if (mask[1] != 0x00) return false;
        if (mask[2] != 0xFF) return false;
        if (mask[3] != 0x00) return false;
        return true;
    });

    register_test("yara_parse_hex_pattern_empty", [] {
        std::vector<uint8_t> pattern, mask;
        return !gcad::YaraEngine::parse_hex_pattern("", pattern, mask);
    });

    register_test("yara_text_to_pattern_ascii", [] {
        auto p = gcad::YaraEngine::text_to_pattern("MZ", false);
        if (p.size() != 2) return false;
        return p[0] == 'M' && p[1] == 'Z';
    });

    register_test("yara_text_to_pattern_wide", [] {
        auto p = gcad::YaraEngine::text_to_pattern("MZ", true);
        if (p.size() != 4) return false;
        return p[0] == 'M' && p[1] == 0x00 && p[2] == 'Z' && p[3] == 0x00;
    });

    register_test("yara_scan_buffer_match", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "find_hello";
        gcad::YaraString s;
        s.identifier = "$hello";
        s.pattern = {'H', 'E', 'L', 'L', 'O'};
        r.strings.push_back(std::move(s));
        r.condition = gcad::YaraRule::ConditionOp::ANY_OF_THEM;
        engine.add_rule(std::move(r));

        const char* data = "xxHELLOyy";
        auto matches = engine.scan_buffer(reinterpret_cast<const uint8_t*>(data), 9);
        if (matches.empty()) return false;
        if (matches[0].rule_name != "find_hello") return false;
        if (matches[0].offset != 2) return false;
        return true;
    });

    register_test("yara_scan_buffer_no_match", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "find_hello";
        gcad::YaraString s;
        s.identifier = "$hello";
        s.pattern = {'H', 'E', 'L', 'L', 'O'};
        r.strings.push_back(std::move(s));
        r.condition = gcad::YaraRule::ConditionOp::ANY_OF_THEM;
        engine.add_rule(std::move(r));

        const char* data = "no match here";
        auto matches = engine.scan_buffer(reinterpret_cast<const uint8_t*>(data), 13);
        return matches.empty();
    });

    register_test("yara_scan_buffer_nocase", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "nocase_test";
        gcad::YaraString s;
        s.identifier = "$target";
        s.pattern = {'H', 'E', 'L', 'L', 'O'};
        s.nocase = true;
        r.strings.push_back(std::move(s));
        r.condition = gcad::YaraRule::ConditionOp::ANY_OF_THEM;
        engine.add_rule(std::move(r));

        const char* data = "xxhelloxx";
        auto matches = engine.scan_buffer(reinterpret_cast<const uint8_t*>(data), 9);
        return !matches.empty();
    });

    register_test("yara_scan_buffer_hex_wildcard", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "wildcard_test";
        gcad::YaraString s;
        s.identifier = "$wild";
        gcad::YaraEngine::parse_hex_pattern("41 ?? 43", s.pattern, s.mask);
        s.is_hex = true;
        r.strings.push_back(std::move(s));
        r.condition = gcad::YaraRule::ConditionOp::ANY_OF_THEM;
        engine.add_rule(std::move(r));

        uint8_t data[] = {0x00, 0x41, 0xFF, 0x43, 0x00};
        auto matches = engine.scan_buffer(data, sizeof(data));
        return !matches.empty();
    });

    register_test("yara_condition_all_of_them", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "all_test";

        gcad::YaraString s1;
        s1.identifier = "$a";
        s1.pattern = {'A', 'A'};
        r.strings.push_back(std::move(s1));

        gcad::YaraString s2;
        s2.identifier = "$b";
        s2.pattern = {'B', 'B'};
        r.strings.push_back(std::move(s2));

        r.condition = gcad::YaraRule::ConditionOp::ALL_OF_THEM;
        engine.add_rule(std::move(r));

        const char* data_both = "AABB";
        auto m1 = engine.scan_buffer(reinterpret_cast<const uint8_t*>(data_both), 4);
        if (m1.empty()) return false;

        gcad::YaraEngine engine2;
        gcad::YaraRule r2;
        r2.name = "all_test2";
        gcad::YaraString s3;
        s3.identifier = "$a";
        s3.pattern = {'A', 'A'};
        r2.strings.push_back(std::move(s3));
        gcad::YaraString s4;
        s4.identifier = "$b";
        s4.pattern = {'B', 'B'};
        r2.strings.push_back(std::move(s4));
        r2.condition = gcad::YaraRule::ConditionOp::ALL_OF_THEM;
        engine2.add_rule(std::move(r2));

        const char* data_one = "AACC";
        auto m2 = engine2.scan_buffer(reinterpret_cast<const uint8_t*>(data_one), 4);
        return m2.empty();
    });

    register_test("yara_condition_count_ge", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "count_test";

        gcad::YaraString s1; s1.identifier = "$a"; s1.pattern = {'A'};
        gcad::YaraString s2; s2.identifier = "$b"; s2.pattern = {'B'};
        gcad::YaraString s3; s3.identifier = "$c"; s3.pattern = {'C'};
        r.strings.push_back(std::move(s1));
        r.strings.push_back(std::move(s2));
        r.strings.push_back(std::move(s3));
        r.condition = gcad::YaraRule::ConditionOp::COUNT_GE;
        r.condition_count = 2;
        engine.add_rule(std::move(r));

        const char* data = "AB";
        auto m = engine.scan_buffer(reinterpret_cast<const uint8_t*>(data), 2);
        if (m.empty()) return false;

        gcad::YaraEngine engine2;
        gcad::YaraRule r2;
        r2.name = "count_test2";
        gcad::YaraString s4; s4.identifier = "$a"; s4.pattern = {'A'};
        gcad::YaraString s5; s5.identifier = "$b"; s5.pattern = {'B'};
        gcad::YaraString s6; s6.identifier = "$c"; s6.pattern = {'C'};
        r2.strings.push_back(std::move(s4));
        r2.strings.push_back(std::move(s5));
        r2.strings.push_back(std::move(s6));
        r2.condition = gcad::YaraRule::ConditionOp::COUNT_GE;
        r2.condition_count = 2;
        engine2.add_rule(std::move(r2));

        const char* data2 = "ADDD";
        auto m2 = engine2.scan_buffer(reinterpret_cast<const uint8_t*>(data2), 4);
        return m2.empty();
    });

    register_test("yara_scan_file", [] {
        auto temp = std::filesystem::temp_directory_path() / "gcad_yara_test.bin";
        {
            std::ofstream f(temp, std::ios::binary);
            f << "PREFIX_TESTPATTERN_SUFFIX";
        }

        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "file_test";
        gcad::YaraString s;
        s.identifier = "$pat";
        s.pattern = {'T', 'E', 'S', 'T', 'P', 'A', 'T', 'T', 'E', 'R', 'N'};
        r.strings.push_back(std::move(s));
        r.condition = gcad::YaraRule::ConditionOp::ANY_OF_THEM;
        engine.add_rule(std::move(r));

        auto matches = engine.scan_file(temp);
        std::filesystem::remove(temp);

        if (matches.empty()) return false;
        return matches[0].offset == 7;
    });

    register_test("yara_scan_file_nonexistent", [] {
        gcad::YaraEngine engine;
        engine.load_builtin_rules();
        auto matches = engine.scan_file("C:\\nonexistent_path_12345.bin");
        return matches.empty();
    });

    register_test("yara_start_loads_builtins", [] {
        gcad::YaraEngine engine;
        engine.start();
        bool has_rules = engine.rule_count() >= 5;
        engine.stop();
        return has_rules;
    });

    register_test("yara_start_stop", [] {
        gcad::YaraEngine engine;
        auto rc = engine.start();
        if (rc != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        rc = engine.stop();
        if (rc != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("yara_mz_header_detection", [] {
        gcad::YaraEngine engine;
        engine.load_builtin_rules();

        uint8_t pe_header[] = { 0x4D, 0x5A, 0x90, 0x00, 0x03 };
        auto matches = engine.scan_buffer(pe_header, sizeof(pe_header));
        bool found_mz = false;
        for (auto& m : matches) {
            if (m.rule_name == "GCAD_MZ_Header") found_mz = true;
        }
        return found_mz;
    });

    register_test("yara_nop_sled_detection", [] {
        gcad::YaraEngine engine;
        engine.load_builtin_rules();

        std::vector<uint8_t> data(32, 0x90);
        auto matches = engine.scan_buffer(data.data(), data.size());
        bool found = false;
        for (auto& m : matches) {
            if (m.rule_name == "GCAD_Shellcode_NOP_Sled") found = true;
        }
        return found;
    });

    register_test("yara_multiple_matches_same_buffer", [] {
        gcad::YaraEngine engine;
        gcad::YaraRule r;
        r.name = "multi_match";
        gcad::YaraString s;
        s.identifier = "$ab";
        s.pattern = {'A', 'B'};
        r.strings.push_back(std::move(s));
        r.condition = gcad::YaraRule::ConditionOp::ANY_OF_THEM;
        engine.add_rule(std::move(r));

        const char* data = "ABABAB";
        auto matches = engine.scan_buffer(reinterpret_cast<const uint8_t*>(data), 6);
        return matches.size() == 3;
    });

    register_test("yara_on_threat_callback", [] {
        gcad::YaraEngine engine;
        bool called = false;
        engine.on_threat([&](gcad::ThreatEvent) { called = true; });
        return !called;
    });

    register_test("yara_on_observation_callback", [] {
        gcad::YaraEngine engine;
        bool called = false;
        engine.on_observation([&](gcad::security::SecurityObservation) { called = true; });
        return !called;
    });
}
