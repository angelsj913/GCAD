#include "gcad/common.hpp"
#include <iostream>
#include <vector>
#include <functional>
#include <string>

struct TestCase {
    std::string name;
    std::function<bool()> fn;
};

static std::vector<TestCase>& registry() {
    static std::vector<TestCase> v;
    return v;
}

void register_test(const char* name, std::function<bool()> fn) {
    registry().push_back({name, std::move(fn)});
}

#define TEST(name) \
    static bool test_##name(); \
    static struct _reg_##name { _reg_##name() { register_test(#name, test_##name); } } _inst_##name; \
    static bool test_##name()

#define ASSERT_TRUE(expr) do { if (!(expr)) { std::cerr << "  FAIL: " #expr " at " __FILE__ ":" << __LINE__ << "\n"; return false; } } while(0)
#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { std::cerr << "  FAIL: " #a " != " #b " at " __FILE__ ":" << __LINE__ << "\n"; return false; } } while(0)

// --- core tests ---

TEST(sha256_empty) {
    gcad::SHA256 h;
    auto digest = h.finalize();
    auto hex = gcad::SHA256::hex(digest);
    ASSERT_EQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    return true;
}

TEST(sha256_hello) {
    auto hex = gcad::SHA256::hash_bytes(reinterpret_cast<const uint8_t*>("hello"), 5);
    ASSERT_EQ(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    return true;
}

TEST(sha384_empty) {
    // Ground truth from `openssl dgst -sha384` (dev-time oracle only, never
    // a GCAD runtime dependency) rather than a hand-typed constant -- a
    // 96-hex-digit literal is exactly the kind of value transcription
    // easily drops a character from.
    auto hex = gcad::SHA384::hash_bytes(reinterpret_cast<const uint8_t*>(""), 0);
    ASSERT_EQ(hex, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    return true;
}

TEST(sha384_abc) {
    auto hex = gcad::SHA384::hash_bytes(reinterpret_cast<const uint8_t*>("abc"), 3);
    ASSERT_EQ(hex, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    return true;
}

TEST(shannon_entropy_zeros) {
    std::array<uint8_t, 256> data{};
    double ent = gcad::shannon_entropy(data.data(), data.size());
    ASSERT_TRUE(ent < 0.001);
    return true;
}

TEST(shannon_entropy_random) {
    std::array<uint8_t, 256> data;
    for (int i = 0; i < 256; i++) data[i] = static_cast<uint8_t>(i);
    double ent = gcad::shannon_entropy(data.data(), data.size());
    ASSERT_TRUE(ent > 7.99);
    return true;
}

TEST(chi_squared_uniform) {
    std::array<uint8_t, 256> data;
    for (int i = 0; i < 256; i++) data[i] = static_cast<uint8_t>(i);
    double chi2 = gcad::chi_squared(data.data(), data.size());
    ASSERT_TRUE(chi2 < 1.0);
    return true;
}

TEST(chi_squared_skewed) {
    std::array<uint8_t, 256> data;
    data.fill(0x41);
    double chi2 = gcad::chi_squared(data.data(), data.size());
    ASSERT_TRUE(chi2 > 200.0);
    return true;
}

TEST(spinlock_basic) {
    gcad::SpinLock lock;
    lock.lock();
    lock.unlock();
    return true;
}

TEST(thread_pool_basic) {
    gcad::ThreadPool pool(2);
    std::atomic<int> counter{0};
    for (int i = 0; i < 100; i++) {
        pool.enqueue([&counter] { counter++; });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    ASSERT_EQ(counter.load(), 100);
    return true;
}

TEST(logger_basic) {
    auto& log = gcad::Logger::instance();
    log.clear();
    log.log(gcad::LogLevel::INFO, "test message");
    auto recent = log.recent(10);
    ASSERT_TRUE(recent.size() >= 1);
    ASSERT_TRUE(recent.back().find("test message") != std::string::npos);
    return true;
}

TEST(secure_zero_works) {
    char buf[16] = "hello world!!!!";
    gcad::secure_zero(buf, sizeof(buf));
    for (auto c : buf) ASSERT_EQ(c, '\0');
    return true;
}

TEST(error_code_values) {
    ASSERT_EQ(static_cast<uint32_t>(gcad::ErrorCode::OK), 0u);
    ASSERT_TRUE(static_cast<uint32_t>(gcad::ErrorCode::ERR_NOMEM) > 0);
    return true;
}

TEST(threat_level_ordering) {
    ASSERT_TRUE(gcad::ThreatLevel::SAFE < gcad::ThreatLevel::LOW);
    ASSERT_TRUE(gcad::ThreatLevel::LOW < gcad::ThreatLevel::MEDIUM);
    ASSERT_TRUE(gcad::ThreatLevel::MEDIUM < gcad::ThreatLevel::HIGH);
    ASSERT_TRUE(gcad::ThreatLevel::HIGH < gcad::ThreatLevel::CRITICAL);
    return true;
}

// External test registrations
void register_pmsr_tests();
void register_etg_ri_tests();
void register_arhs_tests();
void register_zrgp_tests();
void register_self_defense_tests();
void register_fuzz_tests();
void register_forensic_graph_tests();
void register_security_pipeline_tests();
void register_artifact_trust_tests();
void register_process_behavior_tests();
void register_etw_kernel_process_tests();
void register_legacy_adapter_tests();
void register_policy_store_tests();
void register_quarantine_executor_tests();
void register_deep_scanner_tests();
void register_asn1_tests();
void register_x509_tests();
void register_bignum_tests();
void register_rsa_pkcs1_tests();
void register_pkcs7_tests();
void register_pe_authenticode_hash_tests();
void register_trust_anchors_tests();
void register_authenticode_tests();
void register_registry_monitor_tests();
void register_file_integrity_tests();
void register_dns_monitor_tests();
void register_yara_engine_tests();
void register_alert_manager_tests();
void register_report_generator_tests();
void register_firewall_engine_tests();
void register_sandbox_engine_tests();
void register_threat_intel_engine_tests();
void register_system_tray_tests();
void register_update_engine_tests();
void register_behavior_scorer_tests();

int main() {
    register_pmsr_tests();
    register_etg_ri_tests();
    register_arhs_tests();
    register_zrgp_tests();
    register_self_defense_tests();
    register_fuzz_tests();
    register_forensic_graph_tests();
    register_security_pipeline_tests();
    register_artifact_trust_tests();
    register_process_behavior_tests();
    register_etw_kernel_process_tests();
    register_legacy_adapter_tests();
    register_policy_store_tests();
    register_quarantine_executor_tests();
    register_deep_scanner_tests();
    register_asn1_tests();
    register_x509_tests();
    register_bignum_tests();
    register_rsa_pkcs1_tests();
    register_pkcs7_tests();
    register_pe_authenticode_hash_tests();
    register_trust_anchors_tests();
    register_authenticode_tests();
    register_registry_monitor_tests();
    register_file_integrity_tests();
    register_dns_monitor_tests();
    register_yara_engine_tests();
    register_alert_manager_tests();
    register_report_generator_tests();
    register_firewall_engine_tests();
    register_sandbox_engine_tests();
    register_threat_intel_engine_tests();
    register_system_tray_tests();
    register_update_engine_tests();
    register_behavior_scorer_tests();

    int passed = 0, failed = 0;
    std::cout << "GCAD Test Suite\n";
    std::cout << "===============\n";
    for (auto& tc : registry()) {
        std::cout << "[RUN ] " << tc.name << "\n";
        bool ok = false;
        try {
            ok = tc.fn();
        } catch (const std::exception& e) {
            std::cerr << "  EXCEPTION: " << e.what() << "\n";
        }
        if (ok) {
            std::cout << "[PASS] " << tc.name << "\n";
            passed++;
        } else {
            std::cout << "[FAIL] " << tc.name << "\n";
            failed++;
        }
    }
    std::cout << "===============\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed, "
              << (passed + failed) << " total\n";
    return failed > 0 ? 1 : 0;
}
