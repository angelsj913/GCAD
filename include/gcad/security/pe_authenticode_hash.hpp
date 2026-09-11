#pragma once

#include "../common.hpp"

namespace gcad::security {

// Computes the Authenticode-specific SHA-256 hash of a PE image: the same
// hash a valid Authenticode signature's SpcIndirectDataContent.messageDigest
// claims to cover (Microsoft's "Windows Authenticode Portable Executable
// Signature Format" spec). This is NOT a plain hash of the file bytes --
// three regions are excluded because a signature computed over them would
// be self-referential:
//   - the Optional Header's CheckSum field (4 bytes) -- recomputed by tools
//     that modify the file after signing would otherwise invalidate it
//   - the Certificate Table directory entry in the Data Directory (8 bytes)
//     -- its value (offset/size of the signature itself) does not exist
//     until after signing
//   - the Certificate Table itself (the embedded WIN_CERTIFICATE blob,
//     i.e. the Authenticode signature) -- hashing the signature's own
//     container would make verification circular
// Returns nullopt for anything that does not parse as a well-formed PE:
// bad DOS/PE signature, an unrecognized Optional Header magic, or any
// offset/size read from the header that does not fit within `size`. GCAD
// makes no trust decision here -- this only produces the value a signature
// claims to match; comparing it against SpcIndirectDataContent's embedded
// digest is the caller's job.
std::optional<std::array<uint8_t, 32>> compute_authenticode_pe_hash_sha256(const uint8_t* data, size_t size);

} // namespace gcad::security
