#pragma once

#include "../common.hpp"

namespace gcad::security {

// Arbitrary-precision unsigned integer arithmetic, built only to support RSA
// PKCS#1 v1.5 signature verification (modular exponentiation) so Authenticode
// checking does not need to call into a cryptographic library GCAD did not
// write. Not a general-purpose bignum library: only the operations
// verify_pkcs1v15_sha256() actually needs are implemented, and none of them
// are constant-time -- this checks a signature that is already public data
// (embedded in the file being scanned), not a secret, so timing leaks about
// which comparison failed disclose nothing an attacker does not already have.
class BigUInt final {
public:
    BigUInt() = default; // value 0

    static BigUInt from_bytes_be(const uint8_t* data, size_t len);
    static BigUInt from_small(uint32_t value);

    // Big-endian bytes with no leading zero byte, except padded with leading
    // zero bytes up to `min_len` when given (RSA operations are defined on
    // fixed-width, modulus-sized byte strings).
    std::vector<uint8_t> to_bytes_be(size_t min_len = 0) const;

    bool is_zero() const noexcept { return limbs_.empty(); }
    size_t bit_length() const noexcept;
    bool get_bit(size_t index) const noexcept;

    static int compare(const BigUInt& a, const BigUInt& b) noexcept; // -1, 0, or 1
    static BigUInt add(const BigUInt& a, const BigUInt& b);
    static BigUInt subtract(const BigUInt& a, const BigUInt& b); // requires a >= b
    static BigUInt multiply(const BigUInt& a, const BigUInt& b);
    static BigUInt shift_left_one_bit(const BigUInt& a);

    // a mod m via bit-by-bit binary long division. Returns 0 if m is zero
    // (a genuine RSA modulus is never zero; callers must not rely on this
    // case for anything meaningful).
    static BigUInt mod(const BigUInt& a, const BigUInt& m);

    // base^exp mod m via left-to-right square-and-multiply.
    static BigUInt mod_pow(const BigUInt& base, const BigUInt& exp, const BigUInt& m);

private:
    std::vector<uint32_t> limbs_; // little-endian 32-bit limbs; no trailing zero limb unless value is 0 (empty)

    void trim() noexcept;
};

} // namespace gcad::security
