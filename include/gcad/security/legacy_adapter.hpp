#pragma once

#include "observation.hpp"

namespace gcad::security {

// Converts a legacy ISecurityEngine ThreatEvent into a SecurityObservation.
//
// The blanket, level-only mapping this replaces (LOW=0.30/MEDIUM=0.50/
// HIGH=0.70/CRITICAL=0.90 for every category, and "legacy:<category>" as the
// source id) could not tell an exact byte-for-byte tamper check apart from a
// statistical threshold, and made every category look like an independent
// "source" even when the same engine reports several categories -- inflating
// CorrelationEngine's multi-source bonus. This adapter instead keys confidence
// and determinism off (engine_name, category), because the same ThreatCategory
// can be a deterministic check in one engine and a weak heuristic in another
// (EVASION_UNHOOK is an exact memcmp of remote ntdll bytes in SyscallGuard, but
// only "an OS query on our own process failed" in SelfDefense).
//
// `engine_name` should be ISecurityEngine::name(); an empty or unrecognized
// name falls back to the original level-based confidence with a
// "legacy:<category>" source id so unknown future categories still degrade
// safely instead of guessing.
SecurityObservation adapt_legacy_event(const ThreatEvent& event, std::string_view engine_name);

} // namespace gcad::security
