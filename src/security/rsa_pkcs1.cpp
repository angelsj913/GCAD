#include "gcad/security/rsa_pkcs1.hpp"
#include "gcad/security/bignum.hpp"

namespace gcad::security {

namespace {

// DER encoding of DigestInfo's fixed prefix for SHA-256 (RFC 8017 Appendix
// B: the DigestInfo SEQUENCE, containing the id-sha256 AlgorithmIdentifier
// with a NULL parameter, and the OCTET STRING header for a 32-byte digest --
// everything except the digest bytes themselves, which are appended after).
constexpr std::array<uint8_t, 19> kSha256DigestInfoPrefix = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
};

} // namespace

bool verify_pkcs1v15_sha256(const std::vector<uint8_t>& signature, const RsaPublicKey& key,
                            const std::array<uint8_t, 32>& digest) {
    if (signature.empty() || key.modulus.empty() || key.exponent.empty()) return false;

    const BigUInt n = BigUInt::from_bytes_be(key.modulus.data(), key.modulus.size());
    const BigUInt e = BigUInt::from_bytes_be(key.exponent.data(), key.exponent.size());
    const BigUInt sig = BigUInt::from_bytes_be(signature.data(), signature.size());
    if (n.is_zero() || e.is_zero() || sig.is_zero()) return false;
    if (BigUInt::compare(sig, n) >= 0) return false; // a valid signature is always < modulus

    const BigUInt decoded = BigUInt::mod_pow(sig, e, n);
    const auto em = decoded.to_bytes_be(key.modulus.size()); // left-pad to the modulus byte width

    // EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || DigestInfo
    if (em.size() != key.modulus.size()) return false;
    if (em.size() < 11 || em[0] != 0x00 || em[1] != 0x01) return false;

    size_t i = 2;
    while (i < em.size() && em[i] == 0xFF) ++i;
    const size_t padding_len = i - 2;
    if (padding_len < 8) return false; // RFC 8017 requires at least 8 padding bytes
    if (i >= em.size() || em[i] != 0x00) return false;
    ++i;

    if (em.size() - i != kSha256DigestInfoPrefix.size() + digest.size()) return false;
    if (!std::equal(kSha256DigestInfoPrefix.begin(), kSha256DigestInfoPrefix.end(), em.begin() + static_cast<std::ptrdiff_t>(i)))
        return false;
    i += kSha256DigestInfoPrefix.size();

    return std::equal(digest.begin(), digest.end(), em.begin() + static_cast<std::ptrdiff_t>(i));
}

} // namespace gcad::security
