#include "gcad/engines/threat_intel_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_threat_intel_engine_tests() {
    register_test("ti_add_and_count", [] {
        gcad::ThreatIntelEngine ti;
        gcad::IocEntry e;
        e.type = gcad::IocType::SHA256_HASH;
        e.value = "AABBCCDD";
        ti.add_ioc(e);
        return ti.ioc_count() == 1;
    });

    register_test("ti_remove_ioc", [] {
        gcad::ThreatIntelEngine ti;
        gcad::IocEntry e;
        e.type = gcad::IocType::DOMAIN;
        e.value = "evil.com";
        auto id = ti.add_ioc(e);
        if (ti.ioc_count() != 1) return false;
        ti.remove_ioc(id);
        return ti.ioc_count() == 0;
    });

    register_test("ti_check_hash_found", [] {
        gcad::ThreatIntelEngine ti;
        gcad::IocEntry e;
        e.type = gcad::IocType::SHA256_HASH;
        e.value = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        ti.add_ioc(e);
        return ti.check_hash("ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    });

    register_test("ti_check_hash_not_found", [] {
        gcad::ThreatIntelEngine ti;
        return !ti.check_hash("0000000000000000000000000000000000000000000000000000000000000000");
    });

    register_test("ti_check_ip_found", [] {
        gcad::ThreatIntelEngine ti;
        gcad::IocEntry e;
        e.type = gcad::IocType::IPV4_ADDRESS;
        e.value = "192.168.1.100";
        ti.add_ioc(e);
        return ti.check_ip("192.168.1.100");
    });

    register_test("ti_check_domain_found", [] {
        gcad::ThreatIntelEngine ti;
        gcad::IocEntry e;
        e.type = gcad::IocType::DOMAIN;
        e.value = "Evil.COM.";
        ti.add_ioc(e);
        return ti.check_domain("evil.com");
    });

    register_test("ti_lookup_multiple_matches", [] {
        gcad::ThreatIntelEngine ti;
        gcad::IocEntry e1;
        e1.type = gcad::IocType::DOMAIN;
        e1.value = "bad.com";
        e1.source = "feed-A";
        ti.add_ioc(e1);

        gcad::IocEntry e2;
        e2.type = gcad::IocType::DOMAIN;
        e2.value = "bad.com";
        e2.source = "feed-B";
        ti.add_ioc(e2);

        auto matches = ti.lookup("bad.com");
        return matches.size() == 2;
    });

    register_test("ti_normalize_domain", [] {
        return gcad::ThreatIntelEngine::normalize_domain("Evil.COM.") == "evil.com";
    });

    register_test("ti_normalize_hash", [] {
        return gcad::ThreatIntelEngine::normalize_hash("AABB") == "aabb";
    });

    register_test("ti_detect_type_sha256", [] {
        return gcad::ThreatIntelEngine::detect_type(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ) == gcad::IocType::SHA256_HASH;
    });

    register_test("ti_detect_type_md5", [] {
        return gcad::ThreatIntelEngine::detect_type(
            "abcdef0123456789abcdef0123456789"
        ) == gcad::IocType::MD5_HASH;
    });

    register_test("ti_detect_type_ip", [] {
        return gcad::ThreatIntelEngine::detect_type("192.168.1.1") == gcad::IocType::IPV4_ADDRESS;
    });

    register_test("ti_detect_type_domain", [] {
        return gcad::ThreatIntelEngine::detect_type("evil.example.com") == gcad::IocType::DOMAIN;
    });

    register_test("ti_detect_type_url", [] {
        return gcad::ThreatIntelEngine::detect_type("https://evil.com/payload") == gcad::IocType::URL;
    });

    register_test("ti_detect_type_filename", [] {
        return gcad::ThreatIntelEngine::detect_type("mimikatz") == gcad::IocType::FILE_NAME;
    });

    register_test("ti_save_load_roundtrip", [] {
        auto path = std::filesystem::temp_directory_path() / "gcad_ti_test.ioc";

        gcad::ThreatIntelEngine ti1;
        gcad::IocEntry e;
        e.type = gcad::IocType::DOMAIN;
        e.value = "test.evil.com";
        e.severity = gcad::ThreatLevel::HIGH;
        e.source = "unit-test";
        e.description = "test IOC";
        ti1.add_ioc(e);
        size_t saved = ti1.save_to_file(path);

        gcad::ThreatIntelEngine ti2;
        size_t loaded = ti2.load_from_file(path);

        std::error_code ec;
        std::filesystem::remove(path, ec);

        return saved == 1 && loaded == 1 && ti2.check_domain("test.evil.com");
    });

    register_test("ti_default_iocs_installed", [] {
        gcad::ThreatIntelEngine ti;
        ti.start();
        auto count = ti.ioc_count();
        ti.stop();
        return count >= 5;
    });

    register_test("ti_start_stop", [] {
        gcad::ThreatIntelEngine ti;
        if (ti.running()) return false;
        ti.start();
        if (!ti.running()) return false;
        auto s = ti.status();
        if (s.name != "ThreatIntel") return false;
        ti.stop();
        return !ti.running();
    });

    register_test("ti_all_iocs_returns_copy", [] {
        gcad::ThreatIntelEngine ti;
        gcad::IocEntry e;
        e.type = gcad::IocType::IPV4_ADDRESS;
        e.value = "10.0.0.1";
        ti.add_ioc(e);
        auto all = ti.all_iocs();
        return all.size() == 1 && all[0].value == "10.0.0.1";
    });

    register_test("ti_remove_nonexistent", [] {
        gcad::ThreatIntelEngine ti;
        return !ti.remove_ioc(99999);
    });

    register_test("ti_import_iocs_from_string", [] {
        gcad::ThreatIntelEngine ti;
        const std::string ioc_data =
            "# Custom Feed\n"
            "ip|198.51.100.99|critical|C2Feed|Cobalt Strike Server\n"
            "domain|malicious-apt-c2.net|high|AptFeed|APT Command and Control\n";

        size_t imported = ti.import_iocs_from_string(ioc_data, "TestFeed");
        if (imported != 2) return false;
        return ti.check_ip("198.51.100.99") && ti.check_domain("malicious-apt-c2.net");
    });

    register_test("ti_hot_reload_from_directory", [] {
        auto dir = std::filesystem::temp_directory_path() / "gcad_ti_hotreload_test";
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);

        std::ofstream out(dir / "threats.ioc");
        out << "ip|203.0.113.55|critical|Feed|Active Scanner\n";
        out.close();

        gcad::ThreatIntelEngine ti;
        size_t total = ti.reload_all(dir);
        std::filesystem::remove_all(dir, ec);

        return total >= 6 && ti.check_ip("203.0.113.55");
    });
}
