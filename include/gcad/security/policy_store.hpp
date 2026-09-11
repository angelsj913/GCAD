#pragma once

#include "policy.hpp"

namespace gcad::security {

// Loads and saves LocalSecurityPolicy to a small, deterministic key=value text
// file -- not JSON/YAML: GCAD adds no third-party parser, and a hand-rolled
// JSON parser is unnecessary surface for a handful of scalar fields in a
// security product's policy loader. A missing file, an unreadable file, or a
// corrupt individual line never blocks startup or throws: each field falls
// back to its LocalSecurityPolicy{} default independently, and out-of-range
// numeric values (critical_threshold outside [0,100], finding_window outside
// (0, 1440] minutes) are rejected per field rather than accepted verbatim
// from a file that could have been tampered with.
//
// A file with zero "protected_path_prefix=" lines keeps the built-in default
// prefixes rather than clearing them -- this format has no way to persist an
// intentionally empty protected-path list, by design, so a missing or
// truncated policy file can never silently disable path protection.
class PolicyStore final {
public:
    static LocalSecurityPolicy load(const std::filesystem::path& path);
    static ErrorCode save(const std::filesystem::path& path, const LocalSecurityPolicy& policy);
};

} // namespace gcad::security
