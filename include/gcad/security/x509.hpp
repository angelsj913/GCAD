#pragma once

#include "../common.hpp"

namespace gcad::security {

struct RsaPublicKey {
    std::vector<uint8_t> modulus;  // big-endian unsigned, DER pad byte stripped
    std::vector<uint8_t> exponent; // big-endian unsigned
};

// Fields GCAD's Authenticode chain needs from a DER-encoded X.509 certificate
// (RFC 5280), parsed directly on the ASN.1 reader instead of through
// CertGetCertificateChain/CryptDecodeObject. This layer only extracts values;
// it makes no trust or validity decision.
struct X509Certificate {
    std::vector<uint8_t> raw;              // the complete input DER bytes
    std::vector<uint8_t> tbs_certificate;  // raw TBSCertificate TLV -- what the signature actually covers
    std::vector<uint8_t> serial_number;
    std::vector<uint8_t> issuer_der;       // raw Name TLV, for exact chain-matching by byte comparison
    std::vector<uint8_t> subject_der;      // raw Name TLV
    std::string          issuer_common_name;  // best-effort CN, may be empty
    std::string          subject_common_name; // best-effort CN, may be empty
    std::string          not_before;       // raw UTCTime/GeneralizedTime string, e.g. "260911114141Z"
    std::string          not_after;
    std::string          public_key_algorithm_oid;
    std::optional<RsaPublicKey> rsa_public_key; // populated only when public_key_algorithm_oid is rsaEncryption
    std::string          signature_algorithm_oid; // outer signatureAlgorithm (what signed this certificate)
    std::vector<uint8_t> signature_value;         // outer signatureValue, BIT STRING content (unused-bits stripped)
    std::string          sha256_thumbprint;       // hex SHA-256 of `raw`, for a trust-anchor allowlist
};

class X509Parser final {
public:
    // Parses a single DER-encoded Certificate. Returns nullopt for anything
    // that does not fit the expected ASN.1 shape (RFC 5280 §4.1) -- an
    // optional/extension field being absent is fine, but a required field
    // missing or malformed fails the whole parse rather than returning a
    // partially-populated certificate.
    static std::optional<X509Certificate> parse(const std::vector<uint8_t>& der);
};

} // namespace gcad::security
