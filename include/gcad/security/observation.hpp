#pragma once

#include "../common.hpp"

namespace gcad::security {

enum class ObservationKind : uint8_t {
    ARTIFACT_SIGNATURE,
    ARTIFACT_STRUCTURE,
    ARTIFACT_TRUST,
    INVALID_PE,
    UNSIGNED_RISKY_LOCATION,
    INVALID_SIGNATURE,
    HIGH_ENTROPY,
    PROCESS_MEMORY,
    PROCESS_LINEAGE,
    NETWORK_CONNECTION,
    LEGACY_ENGINE,
};

struct SecurityObservation {
    std::string                         source_id;
    ObservationKind                     kind{ObservationKind::LEGACY_ENGINE};
    std::chrono::system_clock::time_point timestamp{};
    ThreatLevel                         suggested_level{ThreatLevel::SAFE};
    double                              confidence{0.0};
    bool                                deterministic{false}; // exact/structural check vs. statistical heuristic
    uint32_t                            process_id{0};
    std::string                         process_name;
    std::string                         file_path;
    std::string                         sha256;
    std::string                         evidence;

    bool valid() const noexcept {
        return !source_id.empty() && !evidence.empty() &&
               std::isfinite(confidence) && confidence >= 0.0 && confidence <= 1.0 &&
               suggested_level != ThreatLevel::SAFE;
    }

    std::string correlation_key() const {
        auto normalize = [](std::string value) {
            std::replace(value.begin(), value.end(), '\\', '/');
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value;
        };

        std::string identity;
        if (!sha256.empty()) {
            identity = normalize(sha256);
        } else if (!file_path.empty()) {
            identity = normalize(file_path);
        } else if (process_id != 0) {
            identity = "pid:" + std::to_string(process_id);
        } else {
            identity = normalize(process_name);
        }
        return std::to_string(static_cast<unsigned>(kind)) + ":" + identity;
    }
};

} // namespace gcad::security
