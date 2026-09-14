#include "gcad/common.hpp"
#include "gcad/engines/etg_ri_engine.hpp"
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_etg_ri_tests() {
    register_test("etg_ri_name", [] {
        gcad::ETGRIEngine engine;
        return engine.name() == "ETG-RI";
    });

    register_test("etg_ri_initial_state", [] {
        gcad::ETGRIEngine engine;
        if (engine.running()) return false;
        if (engine.packets_captured() != 0) return false;
        return true;
    });

    register_test("etg_ri_status", [] {
        gcad::ETGRIEngine engine;
        auto s = engine.status();
        if (s.name != "ETG-RI") return false;
        if (s.running) return false;
        return true;
    });

    register_test("etg_ri_block_unblock_ip", [] {
        gcad::ETGRIEngine engine;
        engine.block_ip(0xC0A80001);
        auto blocked = engine.get_blocked_ips();
        bool found = false;
        for (auto ip : blocked) {
            if (ip == 0xC0A80001) found = true;
        }
        if (!found) return false;
        engine.unblock_ip(0xC0A80001);
        blocked = engine.get_blocked_ips();
        for (auto ip : blocked) {
            if (ip == 0xC0A80001) return false;
        }
        return true;
    });

    register_test("etg_ri_blocking_same_ip_is_idempotent", [] {
        gcad::ETGRIEngine engine;
        constexpr uint32_t ip = 0x0A000001;
        engine.block_ip(ip);
        engine.block_ip(ip);
        engine.block_ip(ip);
        const auto blocked = engine.get_blocked_ips();
        return std::count(blocked.begin(), blocked.end(), ip) == 1;
    });

    register_test("etg_ri_entropy_detection_high", [] {
        std::array<uint8_t, 1024> data;
        for (int i = 0; i < 1024; i++) data[i] = static_cast<uint8_t>(i % 256);
        double ent = gcad::shannon_entropy(data.data(), data.size());
        return ent > 7.0;
    });

    register_test("etg_ri_entropy_detection_low", [] {
        std::array<uint8_t, 1024> data;
        data.fill(0x00);
        double ent = gcad::shannon_entropy(data.data(), data.size());
        return ent < 0.5;
    });
}
