#pragma once

#include "observation.hpp"

namespace gcad::security {

class ArtifactTrustEngine final {
public:
    std::vector<SecurityObservation> inspect(const std::filesystem::path& path) const;

private:
    static bool looks_like_invalid_pe(const std::vector<uint8_t>& bytes) noexcept;
    static bool is_risky_location(const std::filesystem::path& path);
    static SecurityObservation observation_for(ObservationKind kind, ThreatLevel level,
                                               double confidence, const std::filesystem::path& path,
                                               const std::string& hash, std::string evidence);
};

} // namespace gcad::security
