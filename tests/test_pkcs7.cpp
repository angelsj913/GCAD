#include "gcad/common.hpp"
#include "gcad/security/pkcs7.hpp"
#include "gcad/security/rsa_pkcs1.hpp"
#include "test_pkcs7_fixture.hpp"
#include <algorithm>

extern void register_test(const char* name, std::function<bool()> fn);

using gcad_test_fixtures::kGcadTestAuthenticodePkcs7;

namespace {

// Ground truth for kGcadTestAuthenticodePkcs7, read independently via .NET
// System.Security.Cryptography.Pkcs.SignedCms / X509Certificate2 (a read-only
// oracle, never a GCAD runtime dependency -- see test_pkcs7_fixture.hpp).
constexpr std::string_view kSpcIndirectDataOid      = "1.3.6.1.4.1.311.2.1.4";
constexpr std::string_view kSha256DigestOid         = "2.16.840.1.101.3.4.2.1";
constexpr std::string_view kExpectedLeafThumbprint  =
    "38d0c90a5c501f9709fc09aca9a96dd3732edd621af0d6476d54b03e89ea006a";

std::array<uint8_t, 32> sha256_of(const std::vector<uint8_t>& bytes) {
    gcad::SHA256 ctx;
    ctx.update(bytes.data(), bytes.size());
    return ctx.finalize();
}

} // namespace

void register_pkcs7_tests() {
    register_test("pkcs7_parses_real_authenticode_content_type", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        return sd.has_value() && sd->content_type == kSpcIndirectDataOid;
    });

    register_test("pkcs7_parses_real_authenticode_econtent_length", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        // The SpcIndirectDataContent SEQUENCE's content octets (tag+length
        // header excluded) are 76 bytes; see the eContent-parsing comment in
        // pkcs7.cpp for why the header must be excluded here.
        return sd.has_value() && sd->content.size() == 76;
    });

    register_test("pkcs7_parses_real_authenticode_certificate_count", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        // SignedCms.Certificates.Count == 2 (leaf + issuing CA).
        return sd.has_value() && sd->certificates.size() == 2;
    });

    register_test("pkcs7_parses_leaf_certificate_matching_known_thumbprint", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        if (!sd) return false;
        for (const auto& cert : sd->certificates) {
            if (cert.sha256_thumbprint == kExpectedLeafThumbprint) return true;
        }
        return false;
    });

    register_test("pkcs7_parses_real_authenticode_signer_info_count_and_digest_algorithm", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        return sd.has_value() && sd->signer_infos.size() == 1 &&
               sd->signer_infos[0].digest_algorithm_oid == kSha256DigestOid;
    });

    register_test("pkcs7_signer_info_resolves_to_leaf_certificate_via_issuer_and_serial", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        if (!sd || sd->signer_infos.empty()) return false;
        const auto* signer_cert = gcad::security::Pkcs7Parser::find_signer_certificate(*sd, sd->signer_infos[0]);
        return signer_cert != nullptr && signer_cert->sha256_thumbprint == kExpectedLeafThumbprint;
    });

    register_test("pkcs7_signed_attrs_content_type_attribute_matches_econtent_type", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        if (!sd || sd->signer_infos.empty()) return false;
        const auto& signer = sd->signer_infos[0];
        return signer.content_type_attr.has_value() && *signer.content_type_attr == sd->content_type;
    });

    register_test("pkcs7_signed_attrs_message_digest_matches_sha256_of_econtent", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        if (!sd || sd->signer_infos.empty()) return false;
        const auto& signer = sd->signer_infos[0];
        if (!signer.message_digest) return false;
        const auto digest = sha256_of(sd->content);
        return std::equal(digest.begin(), digest.end(), signer.message_digest->begin(), signer.message_digest->end());
    });

    // The strongest evidence this from-scratch PKCS#7 parser is correct: it
    // recovers a REAL, production Authenticode signature (AhnLab's binary,
    // signed under a DigiCert code-signing CA -- not self-signed, not
    // synthetic) well enough that GCAD's own RSA PKCS#1v1.5 verifier accepts
    // the signature over the re-encoded signedAttrs SET using the leaf
    // certificate's own RSA public key, with no shortcuts.
    register_test("pkcs7_verifies_real_authenticode_signature_over_signed_attrs", [] {
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        if (!sd || sd->signer_infos.empty()) return false;
        const auto& signer = sd->signer_infos[0];
        const auto* signer_cert = gcad::security::Pkcs7Parser::find_signer_certificate(*sd, signer);
        if (!signer_cert || !signer_cert->rsa_public_key) return false;

        const auto set_bytes = gcad::security::Pkcs7Parser::der_encode_set(signer.signed_attrs_content);
        const auto digest = sha256_of(set_bytes);
        return gcad::security::verify_pkcs1v15_sha256(signer.signature, *signer_cert->rsa_public_key, digest);
    });

    register_test("pkcs7_der_encode_set_wraps_content_as_universal_set_tlv", [] {
        const std::vector<uint8_t> content = {0x01, 0x02, 0x03};
        const auto encoded = gcad::security::Pkcs7Parser::der_encode_set(content);
        if (encoded.size() != 5) return false; // tag(1) + short-form length(1) + content(3)
        return encoded[0] == 0x31 && encoded[1] == 0x03 &&
               encoded[2] == 0x01 && encoded[3] == 0x02 && encoded[4] == 0x03;
    });

    register_test("pkcs7_der_encode_set_uses_long_form_length_past_127_bytes", [] {
        const std::vector<uint8_t> content(200, 0xAB);
        const auto encoded = gcad::security::Pkcs7Parser::der_encode_set(content);
        // tag(1) + 0x81 long-form-length-of-length(1) + length value 0xC8=200(1) + content(200)
        return encoded.size() == 3 + 200 && encoded[0] == 0x31 &&
               encoded[1] == 0x81 && encoded[2] == 0xC8;
    });

    register_test("pkcs7_rejects_empty_input", [] {
        return !gcad::security::Pkcs7Parser::parse({}).has_value();
    });

    register_test("pkcs7_rejects_non_sequence_top_level", [] {
        const std::vector<uint8_t> not_a_sequence = {0x02, 0x01, 0x05};
        return !gcad::security::Pkcs7Parser::parse(not_a_sequence).has_value();
    });

    register_test("pkcs7_rejects_content_type_other_than_signed_data", [] {
        // SEQUENCE { OID 1.2.3 (arbitrary, not signedData), [0] EXPLICIT {} }
        const std::vector<uint8_t> wrong_content_type = {
            0x30, 0x08,                   // SEQUENCE, len 8
            0x06, 0x02, 0x2a, 0x03,       // OID 1.2.3
            0xa0, 0x02, 0x30, 0x00,       // [0] EXPLICIT { SEQUENCE {} }
        };
        return !gcad::security::Pkcs7Parser::parse(wrong_content_type).has_value();
    });

    register_test("pkcs7_rejects_truncated_signed_data", [] {
        std::vector<uint8_t> truncated(kGcadTestAuthenticodePkcs7.begin(),
                                       kGcadTestAuthenticodePkcs7.begin() + 100);
        return !gcad::security::Pkcs7Parser::parse(truncated).has_value();
    });
}
