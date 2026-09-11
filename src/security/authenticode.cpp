#include "gcad/security/authenticode.hpp"
#include "gcad/security/asn1.hpp"
#include "gcad/security/rsa_pkcs1.hpp"
#include "gcad/security/pe_authenticode_hash.hpp"
#include "gcad/security/trust_anchors.hpp"

namespace gcad::security {

namespace {

namespace a = asn1;

constexpr std::string_view kSha256DigestOid = "2.16.840.1.101.3.4.2.1";
constexpr std::string_view kSha256WithRsaOid = "1.2.840.113549.1.1.11";
constexpr std::string_view kSha384WithRsaOid = "1.2.840.113549.1.1.12";
constexpr int kMaxChainDepth = 6;

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& bytes) {
    SHA256 ctx;
    ctx.update(bytes.data(), bytes.size());
    return ctx.finalize();
}

std::array<uint8_t, 48> sha384(const std::vector<uint8_t>& bytes) {
    SHA384 ctx;
    ctx.update(bytes.data(), bytes.size());
    return ctx.finalize();
}

// Decodes SpcIndirectDataContent's embedded PE hash. `content` is
// SignedData.content as defined in pkcs7.hpp: the encapContentInfo content
// octets with the outer SEQUENCE header already stripped, so its two
// children (SpcAttributeTypeAndOptionalValue, DigestInfo) are read directly
// via parse_sequence_children over the whole buffer.
std::optional<std::vector<uint8_t>> extract_spc_pe_hash(const std::vector<uint8_t>& content) {
    const auto children = a::parse_sequence_children(content.data(), 0, content.size());
    if (children.size() != 2 || !children[1].is_universal(a::UniversalTag::SEQUENCE)) return std::nullopt;

    const auto digest_info = a::parse_sequence_children(content.data(), children[1].content_offset, children[1].content_length);
    if (digest_info.size() != 2 || !digest_info[0].is_universal(a::UniversalTag::SEQUENCE) ||
        !digest_info[1].is_universal(a::UniversalTag::OCTET_STRING))
        return std::nullopt;

    const auto alg = a::parse_sequence_children(content.data(), digest_info[0].content_offset, digest_info[0].content_length);
    if (alg.empty() || !alg[0].is_universal(a::UniversalTag::OBJECT_IDENTIFIER)) return std::nullopt;
    if (a::oid_to_string(content.data(), alg[0]) != kSha256DigestOid) return std::nullopt; // only SHA-256 PE hashes supported

    const auto& digest_el = digest_info[1];
    if (digest_el.content_length != 32) return std::nullopt;
    return std::vector<uint8_t>(content.data() + digest_el.content_offset,
                                content.data() + digest_el.content_offset + digest_el.content_length);
}

// Verifies `subject`'s own certificate signature against `issuer`'s public
// key, dispatching on subject.signature_algorithm_oid -- real Authenticode
// chains mix SHA-256 and SHA-384 across levels of the same chain (see
// rsa_pkcs1.hpp). Any other algorithm is unsupported and fails closed.
bool verify_cert_signed_by(const X509Certificate& subject, const X509Certificate& issuer) {
    if (!issuer.rsa_public_key) return false;
    if (subject.signature_algorithm_oid == kSha256WithRsaOid) {
        return verify_pkcs1v15_sha256(subject.signature_value, *issuer.rsa_public_key, sha256(subject.tbs_certificate));
    }
    if (subject.signature_algorithm_oid == kSha384WithRsaOid) {
        return verify_pkcs1v15_sha384(subject.signature_value, *issuer.rsa_public_key, sha384(subject.tbs_certificate));
    }
    return false;
}

} // namespace

AuthenticodeVerdict verify_certificate_chain(const X509Certificate& leaf,
                                             const std::vector<X509Certificate>& available_issuers) {
    const X509Certificate* current = &leaf;
    for (int depth = 0; depth < kMaxChainDepth; ++depth) {
        if (const auto* anchor = find_trust_anchor_by_subject(current->issuer_der)) {
            return verify_cert_signed_by(*current, *anchor) ? AuthenticodeVerdict::TRUSTED
                                                             : AuthenticodeVerdict::CHAIN_INVALID;
        }

        const X509Certificate* issuer = nullptr;
        for (const auto& candidate : available_issuers) {
            if (&candidate == current) continue; // guard against a self-referential entry
            if (candidate.subject_der == current->issuer_der) { issuer = &candidate; break; }
        }
        if (!issuer) return AuthenticodeVerdict::VALID_UNTRUSTED_ROOT; // ran out of chain data before reaching a trust anchor

        if (!verify_cert_signed_by(*current, *issuer)) return AuthenticodeVerdict::CHAIN_INVALID;
        current = issuer;
    }
    return AuthenticodeVerdict::VALID_UNTRUSTED_ROOT; // depth exhausted without reaching a trust anchor
}

AuthenticodeResult verify_authenticode(const std::vector<uint8_t>& pe_bytes, const std::vector<uint8_t>& pkcs7_der) {
    AuthenticodeResult result{}; // verdict defaults to MALFORMED

    const auto sd = Pkcs7Parser::parse(pkcs7_der);
    if (!sd || sd->signer_infos.empty()) return result;

    const auto& signer = sd->signer_infos[0];
    const auto* leaf = Pkcs7Parser::find_signer_certificate(*sd, signer);
    if (!leaf || !leaf->rsa_public_key) return result;

    result.signer_subject_cn = leaf->subject_common_name;
    result.signer_sha256_thumbprint = leaf->sha256_thumbprint;

    if (signer.digest_algorithm_oid != kSha256DigestOid) return result; // unsupported CMS digest algorithm

    const auto set_bytes = Pkcs7Parser::der_encode_set(signer.signed_attrs_content);
    if (!verify_pkcs1v15_sha256(signer.signature, *leaf->rsa_public_key, sha256(set_bytes))) {
        result.verdict = AuthenticodeVerdict::SIGNATURE_INVALID;
        return result;
    }

    if (signer.message_digest) {
        const auto content_digest = sha256(sd->content);
        if (!std::equal(content_digest.begin(), content_digest.end(),
                        signer.message_digest->begin(), signer.message_digest->end())) {
            return result; // internally inconsistent signature blob -- MALFORMED
        }
    }

    const auto claimed_pe_hash = extract_spc_pe_hash(sd->content);
    if (!claimed_pe_hash) return result;

    const auto actual_pe_hash = compute_authenticode_pe_hash_sha256(pe_bytes.data(), pe_bytes.size());
    if (!actual_pe_hash) return result; // pe_bytes isn't a well-formed PE

    if (!std::equal(claimed_pe_hash->begin(), claimed_pe_hash->end(), actual_pe_hash->begin(), actual_pe_hash->end())) {
        result.verdict = AuthenticodeVerdict::HASH_MISMATCH;
        return result;
    }

    result.verdict = verify_certificate_chain(*leaf, sd->certificates);
    return result;
}

} // namespace gcad::security
