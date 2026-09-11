#include "gcad/common.hpp"
#include "gcad/security/authenticode.hpp"
#include "gcad/security/pkcs7.hpp"
#include "test_pkcs7_fixture.hpp"
#include "test_chain_fixture.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

using gcad_test_fixtures::kGcadTestAuthenticodePkcs7;

namespace {

using gcad::security::AuthenticodeVerdict;
using gcad::security::X509Parser;

void write_u16(std::vector<uint8_t>& buf, size_t offset, uint16_t value) {
    buf[offset] = static_cast<uint8_t>(value & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

void write_u32(std::vector<uint8_t>& buf, size_t offset, uint32_t value) {
    for (int i = 0; i < 4; ++i) buf[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
}

// A minimal well-formed PE32, unrelated to any real signed binary -- used
// only to prove that GCAD's Authenticode PE hash of an arbitrary (but
// well-formed) file does NOT match a real signature's embedded claimed
// hash, without depending on any file outside this repository.
std::vector<uint8_t> build_minimal_pe() {
    constexpr size_t kSizeOfHeaders = 512;
    constexpr size_t kSectionSize = 64;
    std::vector<uint8_t> buf(kSizeOfHeaders + kSectionSize, 0);

    buf[0] = 'M'; buf[1] = 'Z';
    write_u32(buf, 0x3C, 64);
    buf[64] = 'P'; buf[65] = 'E'; buf[66] = 0; buf[67] = 0;
    write_u16(buf, 68, 0x014c);
    write_u16(buf, 70, 1);
    write_u16(buf, 84, 224);
    write_u16(buf, 88, 0x010b);
    write_u32(buf, 88 + 60, kSizeOfHeaders);
    write_u32(buf, 88 + 92, 16);
    const char name[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};
    std::memcpy(buf.data() + 312, name, 8);
    write_u32(buf, 312 + 16, static_cast<uint32_t>(kSectionSize));
    write_u32(buf, 312 + 20, static_cast<uint32_t>(kSizeOfHeaders));
    for (size_t i = 0; i < kSectionSize; ++i) buf[kSizeOfHeaders + i] = static_cast<uint8_t>(i);
    return buf;
}

} // namespace

void register_authenticode_tests() {
    register_test("authenticode_chain_reaches_trusted_root_for_real_signature", [] {
        // Doesn't need the real signed binary on disk -- only the PKCS#7
        // blob (a committed fixture) is needed to walk leaf -> DigiCert
        // intermediate -> GCAD's compiled-in "DigiCert Trusted Root G4"
        // anchor, verifying two real RSA signatures (SHA-256 then SHA-384)
        // along the way.
        const auto sd = gcad::security::Pkcs7Parser::parse(kGcadTestAuthenticodePkcs7);
        if (!sd || sd->signer_infos.empty()) return false;
        const auto* leaf = gcad::security::Pkcs7Parser::find_signer_certificate(*sd, sd->signer_infos[0]);
        if (!leaf) return false;
        return gcad::security::verify_certificate_chain(*leaf, sd->certificates) == AuthenticodeVerdict::TRUSTED;
    });

    register_test("authenticode_chain_untrusted_when_root_is_not_a_compiled_in_anchor", [] {
        using namespace gcad_test_fixtures;
        const auto leaf = X509Parser::parse(kGcadTestChainLeafDer);
        const auto intermediate = X509Parser::parse(kGcadTestChainIntermediateDer);
        if (!leaf || !intermediate) return false;
        // The synthetic root is deliberately excluded from available_issuers
        // and is not in GCAD's trust_anchors allowlist -- the walk should
        // verify leaf->intermediate, then stop for lack of further data.
        return gcad::security::verify_certificate_chain(*leaf, {*intermediate}) ==
               AuthenticodeVerdict::VALID_UNTRUSTED_ROOT;
    });

    register_test("authenticode_chain_invalid_when_intermediate_signature_is_tampered", [] {
        using namespace gcad_test_fixtures;
        const auto leaf = X509Parser::parse(kGcadTestChainLeafDer);
        auto intermediate = X509Parser::parse(kGcadTestChainIntermediateDer);
        const auto root = X509Parser::parse(kGcadTestChainRootDer);
        if (!leaf || !intermediate || !root) return false;
        // intermediate.signature_value is how the ROOT signed intermediate,
        // so the root must be reachable (as an available issuer, since it's
        // not a compiled-in trust anchor) for the walk to ever reach the
        // point that checks it -- otherwise the walk stops one level
        // earlier at VALID_UNTRUSTED_ROOT without ever looking at it.
        intermediate->signature_value[intermediate->signature_value.size() / 2] ^= 0xFF;
        return gcad::security::verify_certificate_chain(*leaf, {*intermediate, *root}) ==
               AuthenticodeVerdict::CHAIN_INVALID;
    });

    register_test("authenticode_chain_invalid_when_intermediate_public_key_is_wrong", [] {
        using namespace gcad_test_fixtures;
        const auto leaf = X509Parser::parse(kGcadTestChainLeafDer);
        auto intermediate = X509Parser::parse(kGcadTestChainIntermediateDer);
        if (!leaf || !intermediate || !intermediate->rsa_public_key) return false;
        // Here the wrong key is checked at the leaf->intermediate step
        // itself (verifying leaf's signature against intermediate's public
        // key), so no root is needed for this one to exercise the failure.
        intermediate->rsa_public_key->modulus[5] ^= 0xFF;
        return gcad::security::verify_certificate_chain(*leaf, {*intermediate}) ==
               AuthenticodeVerdict::CHAIN_INVALID;
    });

    register_test("authenticode_verify_rejects_empty_pkcs7", [] {
        const auto pe = build_minimal_pe();
        const auto result = gcad::security::verify_authenticode(pe, {});
        return result.verdict == AuthenticodeVerdict::MALFORMED;
    });

    register_test("authenticode_verify_rejects_truncated_pkcs7", [] {
        const auto pe = build_minimal_pe();
        const std::vector<uint8_t> truncated(kGcadTestAuthenticodePkcs7.begin(),
                                             kGcadTestAuthenticodePkcs7.begin() + 100);
        const auto result = gcad::security::verify_authenticode(pe, truncated);
        return result.verdict == AuthenticodeVerdict::MALFORMED;
    });

    register_test("authenticode_verify_reports_hash_mismatch_for_unrelated_pe", [] {
        // The real signature is structurally valid (its own RSA/signedAttrs
        // check will pass on its own terms), but it was never computed over
        // this synthetic, unrelated PE -- the embedded claimed hash cannot
        // match GCAD's own Authenticode hash of it.
        const auto pe = build_minimal_pe();
        const auto result = gcad::security::verify_authenticode(pe, kGcadTestAuthenticodePkcs7);
        return result.verdict == AuthenticodeVerdict::HASH_MISMATCH;
    });

    register_test("authenticode_verify_reports_signer_identity_even_on_hash_mismatch", [] {
        const auto pe = build_minimal_pe();
        const auto result = gcad::security::verify_authenticode(pe, kGcadTestAuthenticodePkcs7);
        return result.signer_subject_cn.find("AhnLab") != std::string::npos &&
               !result.signer_sha256_thumbprint.empty();
    });

    // Opportunistic full end-to-end proof: if the real signed binary this
    // PKCS#7 blob was extracted from is present on this dev machine, the
    // complete pipeline -- signature, content digest, PE hash, and chain to
    // a compiled-in trust anchor -- must agree it's TRUSTED, with zero calls
    // to WinVerifyTrust or CertGetCertificateChain. Skipped (not failed)
    // elsewhere, matching the same pattern as the pe_authenticode_hash test.
    register_test("authenticode_verify_full_pipeline_trusted_for_real_binary_when_present", [] {
        const std::filesystem::path real_pe =
            "C:/Program Files/AhnLab/Safe Transaction/MUpdate2/Update/patch/04/mup/mupdate2.exe";
        std::error_code ec;
        if (!std::filesystem::is_regular_file(real_pe, ec) || ec) {
            std::cerr << "  [SKIP] real Authenticode fixture not present on this machine: "
                      << real_pe.string() << "\n";
            return true;
        }
        std::ifstream f(real_pe, std::ios::binary);
        if (!f) return false;
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        const auto result = gcad::security::verify_authenticode(bytes, kGcadTestAuthenticodePkcs7);
        return result.verdict == AuthenticodeVerdict::TRUSTED &&
               result.signer_subject_cn.find("AhnLab") != std::string::npos;
    });
}
