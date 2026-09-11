#include "gcad/security/x509.hpp"
#include "gcad/security/asn1.hpp"

namespace gcad::security {

namespace {

namespace a = asn1;

constexpr std::string_view kRsaEncryptionOid = "1.2.840.113549.1.1.1";
constexpr std::string_view kCommonNameOid    = "2.5.4.3";

// BMPString (X.690) is UTF-16BE and has no surrogate pairs by definition
// (it only covers the Basic Multilingual Plane), so this is simpler than the
// UTF-16LE-with-surrogates conversion EtwKernelProcessEngine needs.
std::string bmp_string_to_utf8(const uint8_t* data, size_t len) {
    std::string out;
    for (size_t i = 0; i + 1 < len; i += 2) {
        const uint32_t cp = (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
        if (cp <= 0x7Fu) {
            out += static_cast<char>(cp);
        } else if (cp <= 0x7FFu) {
            out += static_cast<char>(0xC0u | (cp >> 6));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        } else {
            out += static_cast<char>(0xE0u | (cp >> 12));
            out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        }
    }
    return out;
}

// Name ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue)
std::string extract_common_name(const uint8_t* data, const a::Element& name_seq) {
    const auto rdns = a::parse_sequence_children(data, name_seq.content_offset, name_seq.content_length);
    for (const auto& rdn : rdns) {
        if (!rdn.is_universal(a::UniversalTag::SET)) continue;
        const auto atvs = a::parse_sequence_children(data, rdn.content_offset, rdn.content_length);
        for (const auto& atv : atvs) {
            if (!atv.is_universal(a::UniversalTag::SEQUENCE)) continue;
            const auto fields = a::parse_sequence_children(data, atv.content_offset, atv.content_length);
            if (fields.size() != 2 || !fields[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) continue;
            if (a::oid_to_string(data, fields[0]) != kCommonNameOid) continue;

            const auto& value = fields[1];
            if (value.is_universal(a::UniversalTag::BMP_STRING))
                return bmp_string_to_utf8(data + value.content_offset, value.content_length);
            // PrintableString/UTF8String/IA5String/T61String: ASCII-range
            // encodings GCAD copies verbatim rather than interpreting.
            return std::string(reinterpret_cast<const char*>(data + value.content_offset), value.content_length);
        }
    }
    return {};
}

std::string extract_time_string(const uint8_t* data, const a::Element& time_el) {
    if (!time_el.is_universal(a::UniversalTag::UTC_TIME) &&
        !time_el.is_universal(a::UniversalTag::GENERALIZED_TIME))
        return {};
    return std::string(reinterpret_cast<const char*>(data + time_el.content_offset), time_el.content_length);
}

// BIT STRING content begins with a one-byte "unused bits" count; every BIT
// STRING GCAD reads here (signatures, encoded keys) is byte-aligned DER, so
// that count must be zero.
bool read_byte_aligned_bit_string(const uint8_t* data, const a::Element& el,
                                  const uint8_t*& out_data, size_t& out_len) {
    if (!el.is_universal(a::UniversalTag::BIT_STRING) || el.content_length == 0) return false;
    if (data[el.content_offset] != 0) return false;
    out_data = data + el.content_offset + 1;
    out_len = el.content_length - 1;
    return true;
}

} // namespace

std::optional<X509Certificate> X509Parser::parse(const std::vector<uint8_t>& der) {
    const uint8_t* data = der.data();

    const auto cert_seq = a::parse_element(data, der.size(), 0);
    if (!cert_seq || !cert_seq->is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;

    const auto top = a::parse_sequence_children(data, cert_seq->content_offset, cert_seq->content_length);
    if (top.size() != 3) return std::nullopt;
    const auto& tbs_el = top[0];
    const auto& sig_alg_el = top[1];
    const auto& sig_val_el = top[2];
    if (!tbs_el.is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;
    if (!sig_alg_el.is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;

    X509Certificate cert{};
    cert.raw = der;
    cert.tbs_certificate = a::raw_bytes(data, tbs_el);
    cert.sha256_thumbprint = SHA256::hash_bytes(der.data(), der.size());

    {
        const auto sig_alg_children = a::parse_sequence_children(data, sig_alg_el.content_offset, sig_alg_el.content_length);
        if (sig_alg_children.empty() || !sig_alg_children[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER))
            return std::nullopt;
        cert.signature_algorithm_oid = a::oid_to_string(data, sig_alg_children[0]);
        if (cert.signature_algorithm_oid.empty()) return std::nullopt;
    }

    {
        const uint8_t* sig_data = nullptr;
        size_t sig_len = 0;
        if (!read_byte_aligned_bit_string(data, sig_val_el, sig_data, sig_len)) return std::nullopt;
        cert.signature_value.assign(sig_data, sig_data + sig_len);
    }

    const auto tbs_children = a::parse_sequence_children(data, tbs_el.content_offset, tbs_el.content_length);
    size_t idx = 0;

    // optional [0] EXPLICIT version
    if (idx < tbs_children.size() && tbs_children[idx].tag_class == a::TagClass::CONTEXT_SPECIFIC &&
        tbs_children[idx].tag_number == 0) {
        ++idx; // GCAD does not need the version number itself
    }

    if (idx >= tbs_children.size() || !tbs_children[idx].is_universal(a::UniversalTag::INTEGER))
        return std::nullopt;
    cert.serial_number = a::read_unsigned_integer(data, tbs_children[idx]);
    if (cert.serial_number.empty()) return std::nullopt;
    ++idx;

    // signature (AlgorithmIdentifier, duplicate of the outer one) -- skip
    if (idx >= tbs_children.size() || !tbs_children[idx].is_universal(a::UniversalTag::SEQUENCE))
        return std::nullopt;
    ++idx;

    if (idx >= tbs_children.size() || !tbs_children[idx].is_universal(a::UniversalTag::SEQUENCE))
        return std::nullopt;
    cert.issuer_der = a::raw_bytes(data, tbs_children[idx]);
    cert.issuer_common_name = extract_common_name(data, tbs_children[idx]);
    ++idx;

    if (idx >= tbs_children.size() || !tbs_children[idx].is_universal(a::UniversalTag::SEQUENCE))
        return std::nullopt;
    {
        const auto validity = a::parse_sequence_children(data, tbs_children[idx].content_offset,
                                                          tbs_children[idx].content_length);
        if (validity.size() != 2) return std::nullopt;
        cert.not_before = extract_time_string(data, validity[0]);
        cert.not_after = extract_time_string(data, validity[1]);
        if (cert.not_before.empty() || cert.not_after.empty()) return std::nullopt;
    }
    ++idx;

    if (idx >= tbs_children.size() || !tbs_children[idx].is_universal(a::UniversalTag::SEQUENCE))
        return std::nullopt;
    cert.subject_der = a::raw_bytes(data, tbs_children[idx]);
    cert.subject_common_name = extract_common_name(data, tbs_children[idx]);
    ++idx;

    if (idx >= tbs_children.size() || !tbs_children[idx].is_universal(a::UniversalTag::SEQUENCE))
        return std::nullopt;
    {
        const auto spki = a::parse_sequence_children(data, tbs_children[idx].content_offset,
                                                      tbs_children[idx].content_length);
        if (spki.size() < 2 || !spki[0].is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;

        const auto alg = a::parse_sequence_children(data, spki[0].content_offset, spki[0].content_length);
        if (alg.empty() || !alg[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) return std::nullopt;
        cert.public_key_algorithm_oid = a::oid_to_string(data, alg[0]);
        if (cert.public_key_algorithm_oid.empty()) return std::nullopt;

        const uint8_t* key_data = nullptr;
        size_t key_len = 0;
        if (!read_byte_aligned_bit_string(data, spki[1], key_data, key_len)) return std::nullopt;

        if (cert.public_key_algorithm_oid == kRsaEncryptionOid) {
            const auto rsa_seq = a::parse_element(key_data, key_len, 0);
            if (rsa_seq && rsa_seq->is_universal(a::UniversalTag::SEQUENCE)) {
                const auto rsa_fields = a::parse_sequence_children(key_data, rsa_seq->content_offset,
                                                                    rsa_seq->content_length);
                if (rsa_fields.size() == 2 && rsa_fields[0].is_universal(a::UniversalTag::INTEGER) &&
                    rsa_fields[1].is_universal(a::UniversalTag::INTEGER)) {
                    RsaPublicKey key{};
                    key.modulus = a::read_unsigned_integer(key_data, rsa_fields[0]);
                    key.exponent = a::read_unsigned_integer(key_data, rsa_fields[1]);
                    if (!key.modulus.empty() && !key.exponent.empty())
                        cert.rsa_public_key = std::move(key);
                }
            }
        }
    }

    // Remaining optional fields (unique IDs, extensions) are intentionally
    // not parsed: nothing past subjectPublicKeyInfo is needed yet.
    return cert;
}

} // namespace gcad::security
