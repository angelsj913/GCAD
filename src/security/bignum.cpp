#include "gcad/security/bignum.hpp"

namespace gcad::security {

void BigUInt::trim() noexcept {
    while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back();
}

BigUInt BigUInt::from_bytes_be(const uint8_t* data, size_t len) {
    BigUInt result;
    if (!data) return result;

    size_t start = 0;
    while (start < len && data[start] == 0) ++start;
    const size_t n = len - start;
    if (n == 0) return result;

    result.limbs_.assign((n + 3) / 4, 0);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t byte = data[start + n - 1 - i]; // i-th least-significant byte
        result.limbs_[i / 4] |= static_cast<uint32_t>(byte) << ((i % 4) * 8);
    }
    result.trim();
    return result;
}

BigUInt BigUInt::from_small(uint32_t value) {
    BigUInt result;
    if (value != 0) result.limbs_.assign(1, value);
    return result;
}

std::vector<uint8_t> BigUInt::to_bytes_be(size_t min_len) const {
    std::vector<uint8_t> little_endian(limbs_.size() * 4);
    for (size_t i = 0; i < limbs_.size(); ++i) {
        little_endian[i * 4 + 0] = static_cast<uint8_t>(limbs_[i] & 0xFFu);
        little_endian[i * 4 + 1] = static_cast<uint8_t>((limbs_[i] >> 8) & 0xFFu);
        little_endian[i * 4 + 2] = static_cast<uint8_t>((limbs_[i] >> 16) & 0xFFu);
        little_endian[i * 4 + 3] = static_cast<uint8_t>((limbs_[i] >> 24) & 0xFFu);
    }

    std::vector<uint8_t> big_endian(little_endian.rbegin(), little_endian.rend());
    size_t first_nonzero = 0;
    while (first_nonzero + 1 < big_endian.size() && big_endian[first_nonzero] == 0) ++first_nonzero;
    std::vector<uint8_t> trimmed(big_endian.begin() + static_cast<std::ptrdiff_t>(first_nonzero), big_endian.end());
    if (trimmed.size() == 1 && trimmed[0] == 0 && min_len == 0) return {}; // zero value, no padding requested

    if (trimmed.size() < min_len) {
        std::vector<uint8_t> padded(min_len - trimmed.size(), 0);
        padded.insert(padded.end(), trimmed.begin(), trimmed.end());
        return padded;
    }
    return trimmed;
}

size_t BigUInt::bit_length() const noexcept {
    if (limbs_.empty()) return 0;
    size_t n = (limbs_.size() - 1) * 32;
    uint32_t top = limbs_.back();
    while (top) { ++n; top >>= 1; }
    return n;
}

bool BigUInt::get_bit(size_t index) const noexcept {
    const size_t limb = index / 32, bit = index % 32;
    if (limb >= limbs_.size()) return false;
    return ((limbs_[limb] >> bit) & 1u) != 0;
}

int BigUInt::compare(const BigUInt& a, const BigUInt& b) noexcept {
    if (a.limbs_.size() != b.limbs_.size())
        return a.limbs_.size() < b.limbs_.size() ? -1 : 1;
    for (size_t i = a.limbs_.size(); i-- > 0;) {
        if (a.limbs_[i] != b.limbs_[i]) return a.limbs_[i] < b.limbs_[i] ? -1 : 1;
    }
    return 0;
}

BigUInt BigUInt::add(const BigUInt& a, const BigUInt& b) {
    BigUInt result;
    const size_t n = std::max(a.limbs_.size(), b.limbs_.size()) + 1;
    result.limbs_.assign(n, 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        const uint64_t ai = (i < a.limbs_.size()) ? a.limbs_[i] : 0;
        const uint64_t bi = (i < b.limbs_.size()) ? b.limbs_[i] : 0;
        const uint64_t sum = ai + bi + carry;
        result.limbs_[i] = static_cast<uint32_t>(sum & 0xFFFFFFFFu);
        carry = sum >> 32;
    }
    result.trim();
    return result;
}

BigUInt BigUInt::subtract(const BigUInt& a, const BigUInt& b) {
    // Precondition: a >= b (checked by every internal caller via compare()
    // first). An out-of-contract call would wrap around; callers in this
    // file never make one.
    BigUInt result;
    result.limbs_.assign(a.limbs_.size(), 0);
    int64_t borrow = 0;
    for (size_t i = 0; i < a.limbs_.size(); ++i) {
        const int64_t bi = (i < b.limbs_.size()) ? static_cast<int64_t>(b.limbs_[i]) : 0;
        int64_t diff = static_cast<int64_t>(a.limbs_[i]) - bi - borrow;
        if (diff < 0) { diff += (static_cast<int64_t>(1) << 32); borrow = 1; } else { borrow = 0; }
        result.limbs_[i] = static_cast<uint32_t>(diff);
    }
    result.trim();
    return result;
}

BigUInt BigUInt::multiply(const BigUInt& a, const BigUInt& b) {
    if (a.is_zero() || b.is_zero()) return BigUInt{};
    BigUInt result;
    result.limbs_.assign(a.limbs_.size() + b.limbs_.size(), 0);
    for (size_t i = 0; i < a.limbs_.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.limbs_.size(); ++j) {
            const uint64_t prod = static_cast<uint64_t>(a.limbs_[i]) * b.limbs_[j] + result.limbs_[i + j] + carry;
            result.limbs_[i + j] = static_cast<uint32_t>(prod & 0xFFFFFFFFu);
            carry = prod >> 32;
        }
        size_t k = i + b.limbs_.size();
        while (carry != 0) {
            const uint64_t sum = static_cast<uint64_t>(result.limbs_[k]) + carry;
            result.limbs_[k] = static_cast<uint32_t>(sum & 0xFFFFFFFFu);
            carry = sum >> 32;
            ++k;
        }
    }
    result.trim();
    return result;
}

BigUInt BigUInt::shift_left_one_bit(const BigUInt& a) {
    if (a.is_zero()) return BigUInt{};
    BigUInt result;
    result.limbs_.assign(a.limbs_.size() + 1, 0);
    uint32_t carry = 0;
    for (size_t i = 0; i < a.limbs_.size(); ++i) {
        result.limbs_[i] = (a.limbs_[i] << 1) | carry;
        carry = a.limbs_[i] >> 31;
    }
    result.limbs_[a.limbs_.size()] = carry;
    result.trim();
    return result;
}

BigUInt BigUInt::mod(const BigUInt& a, const BigUInt& m) {
    if (m.is_zero()) return BigUInt{};
    if (compare(a, m) < 0) return a;

    BigUInt remainder;
    const size_t total_bits = a.bit_length();
    for (size_t idx = total_bits; idx-- > 0;) {
        remainder = shift_left_one_bit(remainder);
        if (a.get_bit(idx)) remainder = add(remainder, from_small(1));
        if (compare(remainder, m) >= 0) remainder = subtract(remainder, m);
    }
    return remainder;
}

BigUInt BigUInt::mod_pow(const BigUInt& base_in, const BigUInt& exp, const BigUInt& m) {
    if (m.is_zero()) return BigUInt{};
    BigUInt result = from_small(1);
    BigUInt base = mod(base_in, m);
    const size_t bits = exp.bit_length();
    for (size_t i = 0; i < bits; ++i) {
        if (exp.get_bit(i)) result = mod(multiply(result, base), m);
        base = mod(multiply(base, base), m);
    }
    return result;
}

} // namespace gcad::security
