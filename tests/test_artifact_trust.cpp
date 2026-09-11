#include "gcad/common.hpp"
#include "gcad/security/artifact_trust_engine.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

std::filesystem::path write_invalid_pe_fixture() {
    const auto path = std::filesystem::temp_directory_path() / "gcad-invalid-pe-fixture.bin";
    std::array<uint8_t, 64> data{};
    data[0] = 'M';
    data[1] = 'Z';
    const uint32_t invalid_offset = 0xFFFF'FFF0u;
    std::memcpy(data.data() + 60, &invalid_offset, sizeof(invalid_offset));
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return path;
}

bool has_kind(const std::vector<gcad::security::SecurityObservation>& observations,
              gcad::security::ObservationKind kind) {
    return std::any_of(observations.begin(), observations.end(),
                       [kind](const auto& observation) { return observation.kind == kind; });
}

} // namespace

void register_artifact_trust_tests() {
    register_test("artifact_trust_reports_invalid_pe_fixture", [] {
        const auto fixture = write_invalid_pe_fixture();
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(fixture);
        std::error_code ec;
        std::filesystem::remove(fixture, ec);
        return has_kind(observations, gcad::security::ObservationKind::INVALID_PE);
    });

    register_test("artifact_trust_marks_invalid_pe_structurally_deterministic", [] {
        const auto fixture = write_invalid_pe_fixture();
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(fixture);
        std::error_code ec;
        std::filesystem::remove(fixture, ec);
        const auto it = std::find_if(observations.begin(), observations.end(), [](const auto& o) {
            return o.kind == gcad::security::ObservationKind::INVALID_PE;
        });
        return it != observations.end() && it->deterministic;
    });
}
