#pragma once

#include "../common.hpp"
#include "x509.hpp"

namespace gcad::security {

// GCAD's own compiled-in set of trusted root Certificate Authorities, used
// as the terminal point of Authenticode chain verification in place of the
// OS trust store or CertGetCertificateChain (both ruled out as delegating
// GCAD's trust judgment to Windows). Each entry is the complete, real DER
// encoding of a well-known public root CA certificate -- extracted once
// from this development machine's local Windows Root store (itself sourced
// from the same public CA program, the Mozilla/Microsoft-audited CCADB,
// that every OS and browser root store draws from) purely to obtain the
// authentic bytes to compile in. GCAD's shipped binary never queries any OS
// certificate store at runtime; trust decisions are made only against these
// compiled-in bytes.
//
// This list requires manual maintenance as CAs rotate or add roots -- an
// inherent, openly acknowledged consequence of not delegating trust
// judgment to the OS. It is intentionally small (major code-signing CAs
// only), not a full root program.
const std::vector<X509Certificate>& trusted_root_certificates();

// Finds a compiled-in root whose Subject Name (raw DER) matches
// `subject_der` exactly. Returns nullptr if none of the compiled-in roots
// match -- this is not itself a trust decision about the certificate that
// carries this issuer, only a lookup.
const X509Certificate* find_trust_anchor_by_subject(const std::vector<uint8_t>& subject_der);

} // namespace gcad::security
