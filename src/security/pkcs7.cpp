#include "gcad/security/pkcs7.hpp"
#include "gcad/security/asn1.hpp"

namespace gcad::security {

namespace {

namespace a = asn1;

constexpr std::string_view kSignedDataOid     = "1.2.840.113549.1.7.2";
constexpr std::string_view kContentTypeAttrOid = "1.2.840.113549.1.9.3";
constexpr std::string_view kMessageDigestAttrOid = "1.2.840.113549.1.9.4";

// content [0] EXPLICIT ANY -- an explicit tag wraps exactly one inner TLV,
// which is what we actually want to look at.
std::optional<a::Element> unwrap_explicit(const uint8_t* data, const a::Element& wrapper) {
    const auto inner = a::parse_sequence_children(data, wrapper.content_offset, wrapper.content_length);
    if (inner.size() != 1) return std::nullopt;
    return inner[0];
}

bool parse_certificates_set(const uint8_t* data, const a::Element& certs_el,
                            std::vector<X509Certificate>& out) {
    const auto entries = a::parse_sequence_children(data, certs_el.content_offset, certs_el.content_length);
    for (const auto& entry : entries) {
        if (!entry.is_universal(a::UniversalTag::SEQUENCE)) continue; // skip non-Certificate choices (e.g. AttrCert)
        auto cert = X509Parser::parse(a::raw_bytes(data, entry));
        if (!cert) return false;
        out.push_back(std::move(*cert));
    }
    return true;
}

// Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF AttributeValue }
// Scans a SignedAttributes SET's raw content for `contentType`/`messageDigest`
// and fills the corresponding SignerInfo fields.
void extract_signed_attributes(const uint8_t* data, size_t content_offset, size_t content_length,
                                SignerInfo& signer) {
    const auto attrs = a::parse_sequence_children(data, content_offset, content_length);
    for (const auto& attr : attrs) {
        if (!attr.is_universal(a::UniversalTag::SEQUENCE)) continue;
        const auto fields = a::parse_sequence_children(data, attr.content_offset, attr.content_length);
        if (fields.size() != 2 || !fields[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) continue;
        if (!fields[1].is_universal(a::UniversalTag::SET) || fields[1].content_length == 0) continue;

        const std::string oid = a::oid_to_string(data, fields[0]);
        const auto values = a::parse_sequence_children(data, fields[1].content_offset, fields[1].content_length);
        if (values.empty()) continue;

        if (oid == kContentTypeAttrOid && values[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) {
            signer.content_type_attr = a::oid_to_string(data, values[0]);
        } else if (oid == kMessageDigestAttrOid && values[0].is_universal(a::UniversalTag::OCTET_STRING)) {
            signer.message_digest = std::vector<uint8_t>(
                data + values[0].content_offset, data + values[0].content_offset + values[0].content_length);
        }
    }
}

std::optional<SignerInfo> parse_signer_info(const uint8_t* data, const a::Element& si_el) {
    const auto fields = a::parse_sequence_children(data, si_el.content_offset, si_el.content_length);
    size_t idx = 0;

    // version INTEGER -- not needed
    if (idx >= fields.size() || !fields[idx].is_universal(a::UniversalTag::INTEGER)) return std::nullopt;
    ++idx;

    // sid: only the IssuerAndSerialNumber choice (a SEQUENCE) is supported --
    // SubjectKeyIdentifier (a CONTEXT_SPECIFIC [0]) never appears in
    // Authenticode signatures.
    if (idx >= fields.size() || !fields[idx].is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;
    SignerInfo signer{};
    {
        const auto iasn = a::parse_sequence_children(data, fields[idx].content_offset, fields[idx].content_length);
        if (iasn.size() != 2 || !iasn[0].is_universal(a::UniversalTag::SEQUENCE) ||
            !iasn[1].is_universal(a::UniversalTag::INTEGER))
            return std::nullopt;
        signer.issuer_der = a::raw_bytes(data, iasn[0]);
        signer.serial_number = a::read_unsigned_integer(data, iasn[1]);
        if (signer.issuer_der.empty() || signer.serial_number.empty()) return std::nullopt;
    }
    ++idx;

    // digestAlgorithm AlgorithmIdentifier
    if (idx >= fields.size() || !fields[idx].is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;
    {
        const auto alg = a::parse_sequence_children(data, fields[idx].content_offset, fields[idx].content_length);
        if (alg.empty() || !alg[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) return std::nullopt;
        signer.digest_algorithm_oid = a::oid_to_string(data, alg[0]);
        if (signer.digest_algorithm_oid.empty()) return std::nullopt;
    }
    ++idx;

    // signedAttrs [0] IMPLICIT SET OF Attribute -- Authenticode always has
    // these (they carry the messageDigest tying the signature to the
    // claimed PE hash), so its absence fails the parse.
    if (idx >= fields.size() || fields[idx].tag_class != a::TagClass::CONTEXT_SPECIFIC ||
        fields[idx].tag_number != 0)
        return std::nullopt;
    signer.signed_attrs_content.assign(data + fields[idx].content_offset,
                                       data + fields[idx].content_offset + fields[idx].content_length);
    extract_signed_attributes(data, fields[idx].content_offset, fields[idx].content_length, signer);
    ++idx;

    // signatureAlgorithm AlgorithmIdentifier
    if (idx >= fields.size() || !fields[idx].is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;
    {
        const auto alg = a::parse_sequence_children(data, fields[idx].content_offset, fields[idx].content_length);
        if (alg.empty() || !alg[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) return std::nullopt;
        signer.signature_algorithm_oid = a::oid_to_string(data, alg[0]);
        if (signer.signature_algorithm_oid.empty()) return std::nullopt;
    }
    ++idx;

    // signature OCTET STRING
    if (idx >= fields.size() || !fields[idx].is_universal(a::UniversalTag::OCTET_STRING)) return std::nullopt;
    signer.signature.assign(data + fields[idx].content_offset,
                            data + fields[idx].content_offset + fields[idx].content_length);
    if (signer.signature.empty()) return std::nullopt;

    // unsignedAttrs [1] IMPLICIT, if present, carries only counter-signature
    // timestamps -- not needed for GCAD's Authenticode chain.
    return signer;
}

} // namespace

std::optional<SignedData> Pkcs7Parser::parse(const std::vector<uint8_t>& der) {
    const uint8_t* data = der.data();

    const auto content_info = a::parse_element(data, der.size(), 0);
    if (!content_info || !content_info->is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;

    const auto ci_children = a::parse_sequence_children(data, content_info->content_offset, content_info->content_length);
    if (ci_children.size() != 2 || !ci_children[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) return std::nullopt;
    if (a::oid_to_string(data, ci_children[0]) != kSignedDataOid) return std::nullopt;
    if (ci_children[1].tag_class != a::TagClass::CONTEXT_SPECIFIC || ci_children[1].tag_number != 0) return std::nullopt;

    const auto signed_data_el = unwrap_explicit(data, ci_children[1]);
    if (!signed_data_el || !signed_data_el->is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;

    const auto sd_fields = a::parse_sequence_children(data, signed_data_el->content_offset, signed_data_el->content_length);
    size_t idx = 0;

    // version INTEGER
    if (idx >= sd_fields.size() || !sd_fields[idx].is_universal(a::UniversalTag::INTEGER)) return std::nullopt;
    ++idx;

    // digestAlgorithms SET OF AlgorithmIdentifier -- not needed individually,
    // each SignerInfo carries its own.
    if (idx >= sd_fields.size() || !sd_fields[idx].is_universal(a::UniversalTag::SET)) return std::nullopt;
    ++idx;

    // encapContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    if (idx >= sd_fields.size() || !sd_fields[idx].is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;
    SignedData result{};
    {
        const auto eci = a::parse_sequence_children(data, sd_fields[idx].content_offset, sd_fields[idx].content_length);
        if (eci.empty() || !eci[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) return std::nullopt;
        result.content_type = a::oid_to_string(data, eci[0]);
        if (result.content_type.empty()) return std::nullopt;

        if (eci.size() >= 2 && eci[1].tag_class == a::TagClass::CONTEXT_SPECIFIC && eci[1].tag_number == 0) {
            const auto inner = unwrap_explicit(data, eci[1]);
            if (!inner) return std::nullopt;
            // Strict CMS (RFC 5652 Section 5.2) wraps eContent in an OCTET
            // STRING. Real Authenticode signatures (signtool.exe output)
            // deviate from this: instead of wrapping the encoded
            // SpcIndirectDataContent in an OCTET STRING, Microsoft's tooling
            // places the SpcIndirectDataContent SEQUENCE directly inside the
            // [0] EXPLICIT wrapper. Either way, `content` is defined as the
            // inner element's *content octets only* (never including that
            // element's own tag+length header) -- this is the exact byte
            // string CMS's messageDigest signed attribute is computed over
            // (RFC 5652 Section 5.4), confirmed against a real signature:
            // hashing the full SEQUENCE TLV (header included) does NOT
            // reproduce the messageDigest attribute; hashing just its
            // content bytes does.
            if (!inner->is_universal(a::UniversalTag::OCTET_STRING) && !inner->is_universal(a::UniversalTag::SEQUENCE))
                return std::nullopt;
            result.content.assign(data + inner->content_offset, data + inner->content_offset + inner->content_length);
        }
    }
    ++idx;

    // certificates [0] IMPLICIT CertificateSet OPTIONAL
    if (idx < sd_fields.size() && sd_fields[idx].tag_class == a::TagClass::CONTEXT_SPECIFIC &&
        sd_fields[idx].tag_number == 0) {
        if (!parse_certificates_set(data, sd_fields[idx], result.certificates)) return std::nullopt;
        ++idx;
    }

    // crls [1] IMPLICIT RevocationInfoChoices OPTIONAL -- GCAD does not
    // perform revocation checking (that is an OS-delegated trust judgment).
    if (idx < sd_fields.size() && sd_fields[idx].tag_class == a::TagClass::CONTEXT_SPECIFIC &&
        sd_fields[idx].tag_number == 1) {
        ++idx;
    }

    // signerInfos SET OF SignerInfo
    if (idx >= sd_fields.size() || !sd_fields[idx].is_universal(a::UniversalTag::SET)) return std::nullopt;
    {
        const auto entries = a::parse_sequence_children(data, sd_fields[idx].content_offset, sd_fields[idx].content_length);
        if (entries.empty()) return std::nullopt;
        for (const auto& entry : entries) {
            if (!entry.is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;
            auto signer = parse_signer_info(data, entry);
            if (!signer) return std::nullopt;
            result.signer_infos.push_back(std::move(*signer));
        }
    }

    return result;
}

const X509Certificate* Pkcs7Parser::find_signer_certificate(const SignedData& data, const SignerInfo& signer) {
    for (const auto& cert : data.certificates) {
        if (cert.issuer_der == signer.issuer_der && cert.serial_number == signer.serial_number) return &cert;
    }
    return nullptr;
}

std::vector<uint8_t> Pkcs7Parser::der_encode_set(const std::vector<uint8_t>& content) {
    std::vector<uint8_t> out;
    out.push_back(0x31); // UNIVERSAL, constructed, tag number 17 (SET)

    const size_t len = content.size();
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
    } else {
        uint8_t len_bytes[sizeof(size_t)];
        int num_bytes = 0;
        size_t remaining = len;
        while (remaining > 0) { len_bytes[num_bytes++] = static_cast<uint8_t>(remaining & 0xFF); remaining >>= 8; }
        out.push_back(static_cast<uint8_t>(0x80 | num_bytes));
        for (int i = num_bytes - 1; i >= 0; --i) out.push_back(len_bytes[i]);
    }

    out.insert(out.end(), content.begin(), content.end());
    return out;
}

} // namespace gcad::security
