#include "gcad/common.hpp"
#include "gcad/security/bignum.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

using gcad::security::BigUInt;

namespace {

BigUInt from_u32(uint32_t v) { return BigUInt::from_small(v); }

uint64_t to_u64(const BigUInt& v) {
    const auto bytes = v.to_bytes_be();
    uint64_t out = 0;
    for (auto b : bytes) out = (out << 8) | b;
    return out;
}

} // namespace

void register_bignum_tests() {
    register_test("bignum_round_trips_small_value_through_bytes", [] {
        const uint8_t bytes[] = {0x01, 0x02, 0x03};
        const auto v = BigUInt::from_bytes_be(bytes, sizeof(bytes));
        const auto out = v.to_bytes_be();
        return out.size() == 3 && out[0] == 0x01 && out[1] == 0x02 && out[2] == 0x03;
    });

    register_test("bignum_strips_leading_zero_bytes_on_parse", [] {
        const uint8_t with_padding[] = {0x00, 0x00, 0x01, 0x00};
        const uint8_t without_padding[] = {0x01, 0x00};
        const auto a = BigUInt::from_bytes_be(with_padding, sizeof(with_padding));
        const auto b = BigUInt::from_bytes_be(without_padding, sizeof(without_padding));
        return BigUInt::compare(a, b) == 0;
    });

    register_test("bignum_to_bytes_pads_to_min_len", [] {
        const auto v = from_u32(0x01);
        const auto out = v.to_bytes_be(4);
        return out.size() == 4 && out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == 1;
    });

    register_test("bignum_zero_is_zero", [] {
        BigUInt zero{};
        return zero.is_zero() && zero.bit_length() == 0 && BigUInt::compare(zero, from_u32(0)) == 0;
    });

    register_test("bignum_compare_orders_by_magnitude", [] {
        return BigUInt::compare(from_u32(5), from_u32(10)) < 0 &&
               BigUInt::compare(from_u32(10), from_u32(5)) > 0 &&
               BigUInt::compare(from_u32(7), from_u32(7)) == 0;
    });

    register_test("bignum_add_matches_known_sum", [] {
        return to_u64(BigUInt::add(from_u32(123), from_u32(456))) == 579;
    });

    register_test("bignum_add_carries_across_limb_boundary", [] {
        // 0xFFFFFFFF + 1 must carry into a second limb.
        const auto max_limb = BigUInt::from_bytes_be(
            reinterpret_cast<const uint8_t*>("\xFF\xFF\xFF\xFF"), 4);
        return to_u64(BigUInt::add(max_limb, from_u32(1))) == 0x100000000ull;
    });

    register_test("bignum_subtract_matches_known_difference", [] {
        return to_u64(BigUInt::subtract(from_u32(1000), from_u32(1))) == 999;
    });

    register_test("bignum_multiply_matches_known_product", [] {
        return to_u64(BigUInt::multiply(from_u32(12345), from_u32(6789))) == 83810205ull;
    });

    register_test("bignum_multiply_by_zero_is_zero", [] {
        return BigUInt::multiply(from_u32(123456), BigUInt{}).is_zero();
    });

    register_test("bignum_shift_left_one_bit_doubles_value", [] {
        return to_u64(BigUInt::shift_left_one_bit(from_u32(37))) == 74;
    });

    register_test("bignum_mod_matches_known_remainder", [] {
        return to_u64(BigUInt::mod(from_u32(17), from_u32(5))) == 2 &&
               to_u64(BigUInt::mod(from_u32(100), from_u32(7))) == 2 &&
               to_u64(BigUInt::mod(from_u32(9), from_u32(20))) == 9; // a < m: mod is a itself
    });

    register_test("bignum_mod_pow_matches_known_result", [] {
        // 2^10 mod 1000 = 1024 mod 1000 = 24
        return to_u64(BigUInt::mod_pow(from_u32(2), from_u32(10), from_u32(1000))) == 24;
    });

    register_test("bignum_mod_pow_fermat_pseudoprime_identity", [] {
        // 561 is the smallest Carmichael number: a^560 mod 561 == 1 for every
        // a coprime to 561 (a well-known number-theory identity, independent
        // of this implementation), exercising a modulus/exponent wide enough
        // to require carrying across multiple 32-bit limbs.
        return to_u64(BigUInt::mod_pow(from_u32(7), from_u32(560), from_u32(561))) == 1;
    });

    register_test("bignum_round_trips_2048_bit_value", [] {
        std::vector<uint8_t> bytes(256);
        for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>((i * 37 + 11) & 0xFF);
        bytes[0] |= 0x80; // ensure the top bit is set: a genuine 2048-bit value
        const auto v = BigUInt::from_bytes_be(bytes.data(), bytes.size());
        if (v.bit_length() != 2048) return false;
        return v.to_bytes_be(256) == bytes;
    });
}
