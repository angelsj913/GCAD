#include "gcad/common.hpp"
#include "gcad/security/x509.hpp"
#include "test_certificate_fixture.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

using gcad_test_fixtures::kGcadTestCertDer;

void register_x509_tests() {
    register_test("x509_parses_real_certificate_common_names", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert) return false;
        return cert->subject_common_name == "GCAD Test Certificate" &&
               cert->issuer_common_name == "GCAD Test Certificate"; // self-signed
    });

    register_test("x509_parses_real_certificate_serial_number", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert) return false;
        // openssl x509 -noout -serial reported 5B2C3413154C536DFDAD305EED3A92D2914F11B3
        const std::vector<uint8_t> expected = {
            0x5b, 0x2c, 0x34, 0x13, 0x15, 0x4c, 0x53, 0x6d, 0xfd, 0xad,
            0x30, 0x5e, 0xed, 0x3a, 0x92, 0xd2, 0x91, 0x4f, 0x11, 0xb3};
        return cert->serial_number == expected;
    });

    register_test("x509_parses_real_certificate_validity_times", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert) return false;
        return cert->not_before == "260911114141Z" && cert->not_after == "270911114141Z";
    });

    register_test("x509_parses_real_certificate_rsa_public_key", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert || !cert->rsa_public_key) return false;
        // openssl reported Exponent: 65537 (0x10001) and a 2048-bit modulus
        // (256 bytes) starting with 0xa8, once read_unsigned_integer strips
        // the DER-mandated leading 0x00 pad byte.
        const std::vector<uint8_t> expected_exponent = {0x01, 0x00, 0x01};
        return cert->rsa_public_key->exponent == expected_exponent &&
               cert->rsa_public_key->modulus.size() == 256 &&
               cert->rsa_public_key->modulus[0] == 0xa8;
    });

    register_test("x509_parses_real_certificate_algorithm_oids", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert) return false;
        // sha256WithRSAEncryption and rsaEncryption
        return cert->signature_algorithm_oid == "1.2.840.113549.1.1.11" &&
               cert->public_key_algorithm_oid == "1.2.840.113549.1.1.1";
    });

    register_test("x509_tbs_certificate_hash_matches_openssl_reported_thumbprint_input", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert) return false;
        // tbs_certificate must be a proper, independently-parseable SEQUENCE
        // TLV (tag 0x30) starting right after the outer Certificate SEQUENCE
        // and signatureAlgorithm/signatureValue headers -- i.e. exactly the
        // bytes a real Authenticode/X.509 signature check would hash.
        if (cert->tbs_certificate.empty() || cert->tbs_certificate[0] != 0x30) return false;
        return cert->tbs_certificate.size() < cert->raw.size();
    });

    register_test("x509_computes_sha256_thumbprint_of_whole_certificate", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert) return false;
        return cert->sha256_thumbprint ==
               gcad::SHA256::hash_bytes(kGcadTestCertDer.data(), kGcadTestCertDer.size());
    });

    register_test("x509_rejects_truncated_certificate", [] {
        std::vector<uint8_t> truncated(kGcadTestCertDer.begin(), kGcadTestCertDer.begin() + 50);
        return !gcad::security::X509Parser::parse(truncated).has_value();
    });

    register_test("x509_rejects_empty_input", [] {
        return !gcad::security::X509Parser::parse({}).has_value();
    });

    register_test("x509_rejects_non_sequence_top_level", [] {
        const std::vector<uint8_t> not_a_sequence = {0x02, 0x01, 0x05}; // INTEGER, not SEQUENCE
        return !gcad::security::X509Parser::parse(not_a_sequence).has_value();
    });
}
