#include "gcad/common.hpp"
#include "gcad/security/artifact_trust_engine.hpp"
#include <iostream>

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

void write_u16(std::vector<uint8_t>& buf, size_t offset, uint16_t value) {
    buf[offset] = static_cast<uint8_t>(value & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

void write_u32(std::vector<uint8_t>& buf, size_t offset, uint32_t value) {
    for (int i = 0; i < 4; ++i) buf[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
}

// A minimal, well-formed, but unsigned PE32 -- valid enough to pass
// looks_like_invalid_pe(), with no certificate table at all.
std::filesystem::path write_unsigned_pe_fixture(const std::filesystem::path& path) {
    constexpr size_t kSizeOfHeaders = 512;
    constexpr size_t kSectionSize = 64;
    std::vector<uint8_t> buf(kSizeOfHeaders + kSectionSize, 0);
    buf[0] = 'M'; buf[1] = 'Z';
    write_u32(buf, 0x3C, 64);
    buf[64] = 'P'; buf[65] = 'E'; buf[66] = 0; buf[67] = 0;
    write_u16(buf, 68, 0x014c);
    write_u16(buf, 70, 1);
    write_u16(buf, 84, 224);
    write_u16(buf, 88, 0x010b);
    write_u32(buf, 88 + 60, kSizeOfHeaders);
    write_u32(buf, 88 + 92, 16);
    const char name[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};
    std::memcpy(buf.data() + 312, name, 8);
    write_u32(buf, 312 + 16, static_cast<uint32_t>(kSectionSize));
    write_u32(buf, 312 + 20, static_cast<uint32_t>(kSizeOfHeaders));
    for (size_t i = 0; i < kSectionSize; ++i) buf[kSizeOfHeaders + i] = static_cast<uint8_t>(i);

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    return path;
}

} // namespace

void register_artifact_trust_tests() {
    register_test("artifact_trust_empty_file_no_crash", [] {
        const auto path = std::filesystem::temp_directory_path() / "gcad-empty-fixture.bin";
        { std::ofstream out(path, std::ios::binary | std::ios::trunc); }
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return true;
    });

    register_test("artifact_trust_nonexistent_file", [] {
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect("C:\\nonexistent_path_99999.exe");
        return observations.empty();
    });

    register_test("artifact_trust_text_file_no_observations", [] {
        const auto path = std::filesystem::temp_directory_path() / "gcad-text-fixture.txt";
        {
            std::ofstream out(path);
            out << "This is just a plain text file";
        }
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return observations.empty();
    });

    register_test("artifact_trust_invalid_pe_has_high_confidence", [] {
        const auto fixture = write_invalid_pe_fixture();
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(fixture);
        std::error_code ec;
        std::filesystem::remove(fixture, ec);
        const auto it = std::find_if(observations.begin(), observations.end(), [](const auto& o) {
            return o.kind == gcad::security::ObservationKind::INVALID_PE;
        });
        return it != observations.end() && it->confidence >= 0.8;
    });

    register_test("artifact_trust_observation_fields_valid", [] {
        const auto fixture = write_invalid_pe_fixture();
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(fixture);
        std::error_code ec;
        std::filesystem::remove(fixture, ec);
        for (auto& obs : observations) {
            if (obs.source_id.empty()) return false;
            if (obs.evidence.empty()) return false;
            if (obs.confidence < 0.0 || obs.confidence > 1.0) return false;
        }
        return true;
    });


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

#ifdef GCAD_PLATFORM_WINDOWS
    register_test("artifact_trust_flags_unsigned_executable_in_risky_temp_location", [] {
        const auto path = std::filesystem::temp_directory_path() / "gcad-unsigned-risky-fixture.exe";
        write_unsigned_pe_fixture(path);
        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return has_kind(observations, gcad::security::ObservationKind::UNSIGNED_RISKY_LOCATION);
    });

    // Opportunistic end-to-end proof that has_valid_offline_signature's
    // from-scratch Authenticode verification (no WinVerifyTrust) correctly
    // recognizes a genuinely trusted signed binary and therefore does NOT
    // flag it, even when placed in an otherwise-risky location. Skipped,
    // not failed, when the real fixture binary isn't present on this
    // machine (see pe_authenticode_hash/pkcs7/authenticode tests for the
    // same file used as ground truth elsewhere).
    register_test("artifact_trust_does_not_flag_real_trusted_signed_binary_in_risky_location", [] {
        const std::filesystem::path real_pe =
            "C:/Program Files/AhnLab/Safe Transaction/MUpdate2/Update/patch/04/mup/mupdate2.exe";
        std::error_code ec;
        if (!std::filesystem::is_regular_file(real_pe, ec) || ec) {
            std::cerr << "  [SKIP] real Authenticode fixture not present on this machine: "
                      << real_pe.string() << "\n";
            return true;
        }
        const auto copy_path = std::filesystem::temp_directory_path() / "gcad-trusted-signed-fixture.exe";
        std::filesystem::copy_file(real_pe, copy_path, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) return false;

        gcad::security::ArtifactTrustEngine engine;
        const auto observations = engine.inspect(copy_path);
        std::filesystem::remove(copy_path, ec);
        return !has_kind(observations, gcad::security::ObservationKind::UNSIGNED_RISKY_LOCATION);
    });
#endif
}
