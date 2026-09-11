#include "gcad/security/artifact_trust_engine.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <softpub.h>
#include <wintrust.h>
#endif

namespace gcad::security {

namespace {

constexpr size_t MAX_INSPECTION_BYTES = 4 * 1024 * 1024;

std::string normalized_path(const std::filesystem::path& path) {
    std::string value = path.generic_string();
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

#ifdef GCAD_PLATFORM_WINDOWS
bool has_valid_offline_signature(const std::filesystem::path& path) {
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    const std::wstring wide_path = path.wstring();
    file_info.pcwszFilePath = wide_path.c_str();

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG result = WinVerifyTrust(nullptr, &action, &trust_data);
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trust_data);
    return result == ERROR_SUCCESS;
}
#endif

} // namespace

bool ArtifactTrustEngine::looks_like_invalid_pe(const std::vector<uint8_t>& bytes) noexcept {
    if (bytes.size() < 2 || bytes[0] != 'M' || bytes[1] != 'Z') return false;
    if (bytes.size() < 64) return true;

    uint32_t pe_offset = 0;
    std::memcpy(&pe_offset, bytes.data() + 60, sizeof(pe_offset));
    if (pe_offset > bytes.size() || bytes.size() - pe_offset < 4) return true;
    return bytes[pe_offset] != 'P' || bytes[pe_offset + 1] != 'E' ||
           bytes[pe_offset + 2] != 0 || bytes[pe_offset + 3] != 0;
}

bool ArtifactTrustEngine::is_risky_location(const std::filesystem::path& path) {
    const std::string value = normalized_path(path);
    return value.find("/appdata/local/temp/") != std::string::npos ||
           value.find("/downloads/") != std::string::npos ||
           value.rfind("c:/temp/", 0) == 0;
}

SecurityObservation ArtifactTrustEngine::observation_for(
    ObservationKind kind, ThreatLevel level, double confidence,
    const std::filesystem::path& path, const std::string& hash, std::string evidence) {
    SecurityObservation observation{};
    observation.source_id = "artifact-trust";
    observation.kind = kind;
    observation.timestamp = std::chrono::system_clock::now();
    observation.suggested_level = level;
    observation.confidence = confidence;
    observation.file_path = path.generic_string();
    observation.sha256 = hash;
    observation.evidence = std::move(evidence);
    return observation;
}

std::vector<SecurityObservation> ArtifactTrustEngine::inspect(const std::filesystem::path& path) const {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) return {};

    const auto file_size = std::filesystem::file_size(path, ec);
    if (ec) return {};
    const size_t read_size = static_cast<size_t>(std::min<uintmax_t>(file_size, MAX_INSPECTION_BYTES));
    std::vector<uint8_t> bytes(read_size);
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<size_t>(input.gcount()));
    const std::string hash = SHA256::hash_file(path);

    std::vector<SecurityObservation> observations;
    if (looks_like_invalid_pe(bytes)) {
        observations.push_back(observation_for(ObservationKind::INVALID_PE, ThreatLevel::HIGH, 0.95,
                                               path, hash, "MZ executable has an invalid PE header"));
        return observations;
    }

    const std::string extension = normalized_path(path.extension());
    const bool executable = extension == ".exe" || extension == ".dll" || extension == ".sys";
    if (!executable) return observations;

    if (bytes.size() > 4096 && shannon_entropy(bytes.data(), bytes.size()) > 7.8) {
        observations.push_back(observation_for(ObservationKind::HIGH_ENTROPY, ThreatLevel::MEDIUM, 0.60,
                                               path, hash, "Executable inspection bytes have high entropy"));
    }

#ifdef GCAD_PLATFORM_WINDOWS
    if (!has_valid_offline_signature(path) && is_risky_location(path)) {
        observations.push_back(observation_for(ObservationKind::UNSIGNED_RISKY_LOCATION,
                                               ThreatLevel::MEDIUM, 0.55, path, hash,
                                               "Unsigned executable in a risky user-writable location"));
    }
#else
    (void)executable;
#endif
    return observations;
}

} // namespace gcad::security
