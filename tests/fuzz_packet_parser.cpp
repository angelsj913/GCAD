#include "gcad/common.hpp"
#include <iostream>
#include <random>

extern void register_test(const char* name, std::function<bool()> fn);

void register_fuzz_tests() {
    register_test("fuzz_entropy_no_crash", [] {
        std::mt19937 rng(42);
        for (int round = 0; round < 1000; round++) {
            size_t len = rng() % 4096;
            std::vector<uint8_t> data(len);
            for (auto& b : data) b = static_cast<uint8_t>(rng() & 0xFF);
            double ent = gcad::shannon_entropy(data.data(), data.size());
            if (ent < 0.0 || ent > 8.1) return false;
        }
        return true;
    });

    register_test("fuzz_chi_squared_no_crash", [] {
        std::mt19937 rng(99);
        for (int round = 0; round < 1000; round++) {
            size_t len = rng() % 4096;
            std::vector<uint8_t> data(len);
            for (auto& b : data) b = static_cast<uint8_t>(rng() & 0xFF);
            double chi2 = gcad::chi_squared(data.data(), data.size());
            if (chi2 < 0.0) return false;
        }
        return true;
    });

    register_test("fuzz_sha256_no_crash", [] {
        std::mt19937 rng(123);
        for (int round = 0; round < 500; round++) {
            size_t len = rng() % 8192;
            std::vector<uint8_t> data(len);
            for (auto& b : data) b = static_cast<uint8_t>(rng() & 0xFF);
            auto hex = gcad::SHA256::hash_bytes(data.data(), data.size());
            if (hex.size() != 64) return false;
        }
        return true;
    });

    register_test("fuzz_entropy_edge_cases", [] {
        if (gcad::shannon_entropy(nullptr, 0) != 0.0) return false;
        uint8_t one = 0x42;
        double ent = gcad::shannon_entropy(&one, 1);
        if (ent != 0.0) return false;
        uint8_t two[2] = {0, 1};
        ent = gcad::shannon_entropy(two, 2);
        if (ent < 0.99 || ent > 1.01) return false;
        return true;
    });

    register_test("fuzz_sha256_deterministic", [] {
        std::vector<uint8_t> data(1024, 0xAB);
        auto h1 = gcad::SHA256::hash_bytes(data.data(), data.size());
        auto h2 = gcad::SHA256::hash_bytes(data.data(), data.size());
        return h1 == h2;
    });

    register_test("fuzz_sha256_known_vectors", [] {
        auto empty = gcad::SHA256::hash_bytes(nullptr, 0);
        if (empty != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") return false;

        const char* abc = "abc";
        auto abc_hash = gcad::SHA256::hash_bytes(reinterpret_cast<const uint8_t*>(abc), 3);
        if (abc_hash != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") return false;
        return true;
    });
}
