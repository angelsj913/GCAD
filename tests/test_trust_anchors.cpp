#include "gcad/common.hpp"
#include "gcad/security/trust_anchors.hpp"
#include "test_chain_fixture.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

void register_trust_anchors_tests() {
    register_test("trust_anchors_parses_all_compiled_in_roots", [] {
        // All 5 compiled-in root DER blobs must parse cleanly and carry an
        // RSA public key -- a parse failure here would silently shrink the
        // trust list, which must be loud (a test failure), not silent.
        const auto& roots = gcad::security::trusted_root_certificates();
        if (roots.size() != 5) return false;
        for (const auto& root : roots) {
            if (!root.rsa_public_key) return false;
            if (root.subject_der.empty()) return false;
        }
        return true;
    });

    register_test("trust_anchors_finds_known_root_by_subject", [] {
        const auto& roots = gcad::security::trusted_root_certificates();
        const auto* found = gcad::security::find_trust_anchor_by_subject(roots[0].subject_der);
        return found == &roots[0];
    });

    register_test("trust_anchors_does_not_match_unrelated_subject", [] {
        using namespace gcad_test_fixtures;
        const auto synthetic_root = gcad::security::X509Parser::parse(kGcadTestChainRootDer);
        if (!synthetic_root) return false;
        // The synthetic openssl-generated test root is deliberately not in
        // GCAD's compiled-in allowlist.
        return gcad::security::find_trust_anchor_by_subject(synthetic_root->subject_der) == nullptr;
    });

    register_test("trust_anchors_rejects_empty_subject", [] {
        return gcad::security::find_trust_anchor_by_subject({}) == nullptr;
    });
}
