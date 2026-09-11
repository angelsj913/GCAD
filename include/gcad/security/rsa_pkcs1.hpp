#pragma once

#include "x509.hpp"

namespace gcad::security {

// Verifies an RSA PKCS#1 v1.5 signature (RFC 8017 SS8.2, the scheme X.509 and
// Authenticode both use) over a SHA-256 digest, using only BigUInt's modular
// exponentiation -- no CryptoAPI/CNG call. Recovers signature^e mod n, checks
// the 0x00 0x01 0xFF...0xFF 0x00 padding, then compares the trailing
// DigestInfo (the fixed, well-known ASN.1 prefix identifying SHA-256, per
// RFC 8017 Appendix that lists this OID's DER encoding, followed by the raw
// digest) against `digest` byte-for-byte. Returns false for any structural
// mismatch, a signature not smaller than the modulus, or a digest mismatch --
// there is no partial-success outcome.
bool verify_pkcs1v15_sha256(const std::vector<uint8_t>& signature, const RsaPublicKey& key,
                            const std::array<uint8_t, 32>& digest);

// Same as verify_pkcs1v15_sha256, over a SHA-384 digest instead -- needed
// because real Authenticode certificate chains commonly sign an
// intermediate CA with sha384WithRSAEncryption even when that intermediate
// signs leaf certificates with sha256WithRSAEncryption.
bool verify_pkcs1v15_sha384(const std::vector<uint8_t>& signature, const RsaPublicKey& key,
                            const std::array<uint8_t, 48>& digest);

} // namespace gcad::security
