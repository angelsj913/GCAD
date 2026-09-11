#include "gcad/common.hpp"
#include "gcad/security/rsa_pkcs1.hpp"
#include "gcad/security/x509.hpp"
#include "test_certificate_fixture.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

using gcad_test_fixtures::kGcadTestCertDer;

namespace {

std::array<uint8_t, 32> hash_tbs_certificate(const gcad::security::X509Certificate& cert) {
    gcad::SHA256 ctx;
    ctx.update(cert.tbs_certificate.data(), cert.tbs_certificate.size());
    return ctx.finalize();
}

} // namespace

void register_rsa_pkcs1_tests() {
    // The strongest evidence this hand-rolled bignum + PKCS#1v1.5 stack is
    // correct: the test fixture is self-signed, so its own certificate
    // carries a real RSA-2048/SHA-256 signature produced by openssl's
    // private key over its own TBSCertificate bytes. Recovering and checking
    // that signature end-to-end -- with no shortcuts, against the same
    // public key the certificate itself carries -- either verifies (proving
    // BigUInt::mod_pow and the PKCS#1v1.5 padding check are both correct
    // against genuine RSA-2048 math) or it does not, with no room for a
    // coincidental pass.
    register_test("rsa_pkcs1_verifies_real_self_signed_certificate_signature", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert || !cert->rsa_public_key) return false;
        if (cert->signature_algorithm_oid != "1.2.840.113549.1.1.11") return false; // sha256WithRSAEncryption

        const auto digest = hash_tbs_certificate(*cert);
        return gcad::security::verify_pkcs1v15_sha256(cert->signature_value, *cert->rsa_public_key, digest);
    });

    register_test("rsa_pkcs1_rejects_when_signed_content_was_tampered", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert || !cert->rsa_public_key) return false;
        auto digest = hash_tbs_certificate(*cert);
        digest[0] ^= 0xFF; // simulates verifying against different (tampered) signed content
        return !gcad::security::verify_pkcs1v15_sha256(cert->signature_value, *cert->rsa_public_key, digest);
    });

    register_test("rsa_pkcs1_rejects_tampered_signature_bytes", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert || !cert->rsa_public_key) return false;
        const auto digest = hash_tbs_certificate(*cert);
        auto bad_signature = cert->signature_value;
        bad_signature[bad_signature.size() / 2] ^= 0xFF;
        return !gcad::security::verify_pkcs1v15_sha256(bad_signature, *cert->rsa_public_key, digest);
    });

    register_test("rsa_pkcs1_rejects_signature_under_a_different_key", [] {
        const auto cert = gcad::security::X509Parser::parse(kGcadTestCertDer);
        if (!cert || !cert->rsa_public_key) return false;
        const auto digest = hash_tbs_certificate(*cert);
        auto wrong_key = *cert->rsa_public_key;
        wrong_key.modulus[10] ^= 0xFF; // a different RSA key entirely
        return !gcad::security::verify_pkcs1v15_sha256(cert->signature_value, wrong_key, digest);
    });

    register_test("rsa_pkcs1_rejects_empty_signature", [] {
        gcad::security::RsaPublicKey key{};
        key.modulus = {0x01, 0x00};
        key.exponent = {0x03};
        const std::array<uint8_t, 32> digest{};
        return !gcad::security::verify_pkcs1v15_sha256({}, key, digest);
    });

    register_test("rsa_pkcs1_rejects_signature_not_smaller_than_modulus", [] {
        // A signature value >= the modulus can never be a valid PKCS#1v1.5
        // encoding; this must be rejected before any exponentiation, not
        // merely happen to fail the padding check.
        gcad::security::RsaPublicKey key{};
        key.modulus = {0x01, 0x00}; // n = 256
        key.exponent = {0x03};
        const std::vector<uint8_t> signature = {0x02, 0x00}; // 512 >= 256
        const std::array<uint8_t, 32> digest{};
        return !gcad::security::verify_pkcs1v15_sha256(signature, key, digest);
    });
}
