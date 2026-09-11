#pragma once

#include "../common.hpp"
#include "pkcs7.hpp"

namespace gcad::security {

enum class AuthenticodeVerdict {
    TRUSTED,              // signature valid, PE hash matches, chain reaches a compiled-in trusted root
    VALID_UNTRUSTED_ROOT, // signature valid, PE hash matches, but the chain doesn't reach a trusted root
    HASH_MISMATCH,        // the file's actual bytes don't match what the signature covers (tampered/wrong file)
    SIGNATURE_INVALID,    // the SignerInfo's RSA signature does not verify
    CHAIN_INVALID,        // an intermediate certificate's signature doesn't verify against its issuer
    MALFORMED,            // the PKCS#7 blob doesn't parse, or uses an algorithm/shape GCAD doesn't support
};

struct AuthenticodeResult {
    AuthenticodeVerdict verdict{AuthenticodeVerdict::MALFORMED};
    std::string signer_subject_cn;         // best-effort, may be empty
    std::string signer_sha256_thumbprint;  // empty when the signer certificate could not be resolved
};

// Fully verifies an Authenticode signature against the PE bytes it claims to
// cover, using only GCAD's own from-scratch implementations:
//   1. the SignerInfo's RSA/SHA-256 signature over the re-encoded
//      signedAttrs SET, checked against the signer certificate's own
//      embedded public key (rsa_pkcs1 + pkcs7)
//   2. the signedAttrs messageDigest attribute against a hash of the
//      encapsulated content (internal consistency of the signature blob)
//   3. the PE hash embedded in SpcIndirectDataContent against GCAD's own
//      Authenticode-specific hash of `pe_bytes` (pe_authenticode_hash) --
//      this is what ties the signature to *this exact file*
//   4. the certificate chain from the signer up through any intermediates
//      present in the PKCS#7 blob to a compiled-in trusted root
//      (trust_anchors)
// No step here calls WinVerifyTrust, CertGetCertificateChain, or any other
// OS API that would make the trust judgment on GCAD's behalf.
AuthenticodeResult verify_authenticode(const std::vector<uint8_t>& pe_bytes,
                                       const std::vector<uint8_t>& pkcs7_der);

// Walks the certificate chain starting at `leaf`, using `available_issuers`
// (typically a PKCS#7 blob's embedded certificate set) to find each next
// issuer by matching subject_der against the current certificate's
// issuer_der, verifying that certificate's RSA/SHA-256 signature against the
// issuer's public key at each step. Stops and returns CHAIN_INVALID the
// moment a signature fails to verify. If the walk reaches a certificate
// whose issuer matches a compiled-in trust anchor (trust_anchors.hpp), that
// anchor's signature over it is verified too; success is TRUSTED, failure
// is CHAIN_INVALID. If no further issuer can be found (neither in
// `available_issuers` nor as a trust anchor) before that point, the walk
// stops there and returns VALID_UNTRUSTED_ROOT -- every signature checked
// out, the chain simply doesn't terminate at a certificate GCAD trusts.
// Bounded to a small max depth to make a malformed or cyclic certificate
// set fail closed (CHAIN_INVALID) rather than loop.
AuthenticodeVerdict verify_certificate_chain(const X509Certificate& leaf,
                                             const std::vector<X509Certificate>& available_issuers);

} // namespace gcad::security
