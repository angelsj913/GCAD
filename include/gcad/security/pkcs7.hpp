#pragma once

#include "../common.hpp"
#include "x509.hpp"

namespace gcad::security {

// One SignerInfo from a CMS SignedData (RFC 5652 §5.3). Authenticode always
// identifies its signer by IssuerAndSerialNumber (never SubjectKeyIdentifier)
// and always carries signedAttrs, so this layer only supports that shape --
// anything else fails the whole parse rather than guessing.
struct SignerInfo {
    std::vector<uint8_t> issuer_der;     // IssuerAndSerialNumber.issuer, raw Name TLV
    std::vector<uint8_t> serial_number;  // IssuerAndSerialNumber.serialNumber, unsigned big-endian
    std::string          digest_algorithm_oid;

    // Raw *content* bytes of the [0] IMPLICIT SignedAttributes SET (i.e. with
    // the IMPLICIT tag/length header already stripped, not yet re-tagged).
    // RFC 5652 §5.4: what the signature actually covers is this content
    // re-encoded under a UNIVERSAL SET tag -- see der_encode_set().
    std::vector<uint8_t> signed_attrs_content;
    std::optional<std::string>          content_type_attr; // signed attr 1.2.840.113549.1.9.3, if present
    std::optional<std::vector<uint8_t>> message_digest;    // signed attr 1.2.840.113549.1.9.4, if present

    std::string          signature_algorithm_oid;
    std::vector<uint8_t> signature; // SignatureValue, OCTET STRING content (the encrypted digest)
};

// Fields GCAD's Authenticode chain needs from a CMS SignedData (RFC 5652),
// parsed directly on the ASN.1/X.509 readers instead of through
// CryptDecodeObject/CryptQueryObject. This layer only extracts and structures
// values; it makes no trust or validity decision, and it does not itself
// verify any signature.
struct SignedData {
    std::string           content_type; // encapContentInfo.eContentType OID

    // encapContentInfo.eContent, content octets only -- the inner element's
    // tag+length header is always excluded, whether eContent was a strict
    // CMS OCTET STRING (RFC 5652 5.2) or, as real Authenticode signatures
    // from signtool.exe actually encode it, the SpcIndirectDataContent
    // SEQUENCE placed directly inside the [0] EXPLICIT wrapper with no
    // OCTET STRING layer at all. This is confirmed (not assumed) to be
    // exactly the byte string CMS's messageDigest signed attribute is
    // computed over (RFC 5652 5.4), verified against a real production
    // Authenticode signature: hashing the full inner TLV does not reproduce
    // messageDigest; hashing just its content bytes does.
    std::vector<uint8_t>  content;
    std::vector<X509Certificate> certificates;
    std::vector<SignerInfo>      signer_infos;
};

class Pkcs7Parser final {
public:
    // Parses a ContentInfo{contentType=signedData, content=SignedData} blob --
    // exactly the bytes stored in a PE's WIN_CERTIFICATE.bCertificate when
    // wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA (Authenticode).
    // Returns nullopt for anything that does not fit the expected shape.
    static std::optional<SignedData> parse(const std::vector<uint8_t>& der);

    // Finds the certificate in `data.certificates` whose subject Name and
    // serial number match `signer`'s IssuerAndSerialNumber (byte-exact DER
    // comparison), or nullptr if none matches.
    static const X509Certificate* find_signer_certificate(const SignedData& data, const SignerInfo& signer);

    // Wraps `content` as a complete, minimal-DER UNIVERSAL SET TLV (tag
    // 0x31). Used to re-tag a SignerInfo's [0] IMPLICIT signedAttrs content
    // as the UNIVERSAL SET the signature was actually computed over (RFC
    // 5652 §5.4) before hashing it for RSA signature verification.
    static std::vector<uint8_t> der_encode_set(const std::vector<uint8_t>& content);
};

} // namespace gcad::security
