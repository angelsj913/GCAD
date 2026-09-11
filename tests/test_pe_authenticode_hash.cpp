#include "gcad/common.hpp"
#include "gcad/security/pe_authenticode_hash.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

using gcad::security::compute_authenticode_pe_hash_sha256;

void write_u16(std::vector<uint8_t>& buf, size_t offset, uint16_t value) {
    buf[offset] = static_cast<uint8_t>(value & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

void write_u32(std::vector<uint8_t>& buf, size_t offset, uint32_t value) {
    for (int i = 0; i < 4; ++i) buf[offset + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
}

// Builds a minimal, well-formed PE32 image with one section:
//   [0,64)     DOS header (MZ + e_lfanew=64, no stub)
//   [64,68)    "PE\0\0"
//   [68,88)    FileHeader (NumberOfSections=1, SizeOfOptionalHeader=224)
//   [88,312)   OptionalHeader (PE32, Magic=0x10b)
//   [312,352)  one IMAGE_SECTION_HEADER (".text")
//   [352,512)  zero padding out to SizeOfHeaders=512
//   [512,576)  section raw data: 64 bytes, section_fill repeated
// CheckSum field is at 152, the Security Directory entry (DataDirectory[4])
// at [216,224). Both are deliberately populated with `checksum`/left as
// given so tests can prove they don't affect the resulting hash.
std::vector<uint8_t> build_minimal_pe(uint8_t section_fill, uint32_t checksum,
                                      uint32_t cert_table_offset, uint32_t cert_table_size,
                                      const std::vector<uint8_t>& trailing_data) {
    constexpr size_t kSizeOfHeaders = 512;
    constexpr size_t kSectionSize = 64;
    constexpr size_t kSectionStart = kSizeOfHeaders;
    const size_t total = kSectionStart + kSectionSize + trailing_data.size();

    std::vector<uint8_t> buf(total, 0);

    buf[0] = 'M'; buf[1] = 'Z';
    write_u32(buf, 0x3C, 64); // e_lfanew

    buf[64] = 'P'; buf[65] = 'E'; buf[66] = 0; buf[67] = 0;

    // FileHeader @68
    write_u16(buf, 68, 0x014c);  // Machine
    write_u16(buf, 70, 1);       // NumberOfSections
    write_u32(buf, 72, 0);       // TimeDateStamp
    write_u32(buf, 76, 0);       // PointerToSymbolTable
    write_u32(buf, 80, 0);       // NumberOfSymbols
    write_u16(buf, 84, 224);     // SizeOfOptionalHeader
    write_u16(buf, 86, 0x0102);  // Characteristics

    // OptionalHeader @88 (PE32)
    write_u16(buf, 88, 0x010b);           // Magic
    write_u32(buf, 88 + 60, kSizeOfHeaders); // SizeOfHeaders
    write_u32(buf, 88 + 64, checksum);       // CheckSum
    write_u32(buf, 88 + 92, 16);              // NumberOfRvaAndSizes
    write_u32(buf, 88 + 96 + 4 * 8, cert_table_offset);     // DataDirectory[4].VirtualAddress
    write_u32(buf, 88 + 96 + 4 * 8 + 4, cert_table_size);   // DataDirectory[4].Size

    // Section header @312 (".text")
    const char name[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};
    std::memcpy(buf.data() + 312, name, 8);
    write_u32(buf, 312 + 8, static_cast<uint32_t>(kSectionSize));  // VirtualSize
    write_u32(buf, 312 + 12, 0x1000);                              // VirtualAddress
    write_u32(buf, 312 + 16, static_cast<uint32_t>(kSectionSize)); // SizeOfRawData
    write_u32(buf, 312 + 20, static_cast<uint32_t>(kSectionStart)); // PointerToRawData

    for (size_t i = 0; i < kSectionSize; ++i) buf[kSectionStart + i] = section_fill;
    if (!trailing_data.empty())
        std::memcpy(buf.data() + kSectionStart + kSectionSize, trailing_data.data(), trailing_data.size());

    return buf;
}

std::array<uint8_t, 32> sha256_of(const std::vector<uint8_t>& bytes) {
    gcad::SHA256 ctx;
    ctx.update(bytes.data(), bytes.size());
    return ctx.finalize();
}

std::string hex(const std::array<uint8_t, 32>& digest) { return gcad::SHA256::hex(digest); }

std::vector<uint8_t> hex_to_bytes(const std::string& hex_str) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex_str.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(hex_str.substr(i, 2), nullptr, 16)));
    return out;
}

// Independently reproduces "what the Authenticode algorithm should hash" by
// concatenating the kept byte ranges of build_minimal_pe()'s fixed layout --
// CheckSum is at [152,156), the Security Directory entry at [216,224) --
// OMITTING those two ranges entirely (not zeroing them in place, which would
// change the total byte count fed to SHA-256 and therefore produce a
// different, wrong digest). `content_end` is the file offset the hashed
// content should stop at: 576 for a PE with no certificate table appended,
// or the certificate table's start offset when one is present.
std::vector<uint8_t> expected_hashed_bytes(const std::vector<uint8_t>& pe, size_t content_end) {
    std::vector<uint8_t> out;
    out.insert(out.end(), pe.begin(), pe.begin() + 152);
    out.insert(out.end(), pe.begin() + 156, pe.begin() + 216);
    out.insert(out.end(), pe.begin() + 224, pe.begin() + static_cast<std::ptrdiff_t>(content_end));
    return out;
}

} // namespace

void register_pe_authenticode_hash_tests() {
    register_test("pe_hash_excludes_checksum_and_security_directory_entry", [] {
        // Same PE, differing only in the CheckSum value and the Security
        // Directory entry's offset field (both would-be-excluded fields) --
        // if the implementation correctly skips them, the resulting hash
        // must be identical. cert_size stays 0 for both (no certificate
        // table), so the garbage offset in pe_b is never dereferenced --
        // only its presence in the excluded byte range is being tested.
        const auto pe_a = build_minimal_pe(0x41, /*checksum=*/0, /*cert_off=*/0, /*cert_size=*/0, {});
        const auto pe_b = build_minimal_pe(0x41, /*checksum=*/0xDEADBEEF, /*cert_off=*/0xDEAD, /*cert_size=*/0, {});
        const auto hash_a = compute_authenticode_pe_hash_sha256(pe_a.data(), pe_a.size());
        const auto hash_b = compute_authenticode_pe_hash_sha256(pe_b.data(), pe_b.size());
        return hash_a && hash_b && *hash_a == *hash_b;
    });

    register_test("pe_hash_changes_when_section_content_changes", [] {
        const auto pe_a = build_minimal_pe(0x41, 0, 0, 0, {});
        const auto pe_b = build_minimal_pe(0x42, 0, 0, 0, {});
        const auto hash_a = compute_authenticode_pe_hash_sha256(pe_a.data(), pe_a.size());
        const auto hash_b = compute_authenticode_pe_hash_sha256(pe_b.data(), pe_b.size());
        return hash_a && hash_b && *hash_a != *hash_b;
    });

    register_test("pe_hash_matches_manually_assembled_reference_buffer", [] {
        // Independently build "what should be hashed" (the kept byte ranges
        // concatenated, checksum and directory-entry ranges omitted -- not
        // zeroed) and compare against the implementation's result. This is
        // the structural correctness check that doesn't depend on external
        // ground truth.
        const auto pe = build_minimal_pe(0x7A, 0xCAFEBABE, 0, 0, {});
        const auto expected = sha256_of(expected_hashed_bytes(pe, pe.size()));
        const auto actual = compute_authenticode_pe_hash_sha256(pe.data(), pe.size());
        return actual && hex(*actual) == hex(expected);
    });

    register_test("pe_hash_excludes_appended_certificate_table_entirely", [] {
        // A signed PE with no extra/overlay data: the certificate table
        // starts immediately after the last section. Appending it (and
        // changing its content) must not change the hash at all -- it must
        // equal the hash of the exact same PE with no certificate table.
        const std::vector<uint8_t> fake_cert(20, 0xFF);
        const auto unsigned_pe = build_minimal_pe(0x41, 0, 0, 0, {});
        const auto signed_pe = build_minimal_pe(0x41, 0, /*cert_off=*/576, /*cert_size=*/20, fake_cert);

        const auto hash_unsigned = compute_authenticode_pe_hash_sha256(unsigned_pe.data(), unsigned_pe.size());
        const auto hash_signed = compute_authenticode_pe_hash_sha256(signed_pe.data(), signed_pe.size());
        if (!hash_unsigned || !hash_signed || *hash_unsigned != *hash_signed) return false;

        std::vector<uint8_t> different_cert_content(20, 0x11);
        const auto signed_pe2 = build_minimal_pe(0x41, 0, 576, 20, different_cert_content);
        const auto hash_signed2 = compute_authenticode_pe_hash_sha256(signed_pe2.data(), signed_pe2.size());
        return hash_signed2 && *hash_signed2 == *hash_unsigned;
    });

    register_test("pe_hash_includes_trailing_overlay_data_before_certificate_table", [] {
        // Real overlay/appended data that sits between the last section and
        // the certificate table IS part of the signed content and must be
        // hashed.
        std::vector<uint8_t> overlay(10, 0x99);
        std::vector<uint8_t> trailing = overlay;
        const std::vector<uint8_t> fake_cert(20, 0xFF);
        trailing.insert(trailing.end(), fake_cert.begin(), fake_cert.end());
        const auto pe = build_minimal_pe(0x41, 0, /*cert_off=*/586, /*cert_size=*/20, trailing);

        // headers + section + overlay, cert table excluded (content_end=586
        // stops right at the certificate table's start offset).
        const auto expected = sha256_of(expected_hashed_bytes(pe, 586));

        const auto actual = compute_authenticode_pe_hash_sha256(pe.data(), pe.size());
        return actual && hex(*actual) == hex(expected);
    });

    register_test("pe_hash_rejects_buffer_too_small_for_dos_header", [] {
        const std::vector<uint8_t> tiny(10, 0);
        return !compute_authenticode_pe_hash_sha256(tiny.data(), tiny.size()).has_value();
    });

    register_test("pe_hash_rejects_bad_dos_magic", [] {
        auto pe = build_minimal_pe(0x41, 0, 0, 0, {});
        pe[0] = 'X';
        return !compute_authenticode_pe_hash_sha256(pe.data(), pe.size()).has_value();
    });

    register_test("pe_hash_rejects_bad_pe_signature", [] {
        auto pe = build_minimal_pe(0x41, 0, 0, 0, {});
        pe[64] = 'X';
        return !compute_authenticode_pe_hash_sha256(pe.data(), pe.size()).has_value();
    });

    register_test("pe_hash_rejects_unrecognized_optional_header_magic", [] {
        auto pe = build_minimal_pe(0x41, 0, 0, 0, {});
        write_u16(pe, 88, 0x9999);
        return !compute_authenticode_pe_hash_sha256(pe.data(), pe.size()).has_value();
    });

    register_test("pe_hash_rejects_size_of_headers_past_end_of_buffer", [] {
        auto pe = build_minimal_pe(0x41, 0, 0, 0, {});
        write_u32(pe, 88 + 60, static_cast<uint32_t>(pe.size() + 1000)); // SizeOfHeaders
        return !compute_authenticode_pe_hash_sha256(pe.data(), pe.size()).has_value();
    });

    register_test("pe_hash_rejects_section_raw_data_past_end_of_buffer", [] {
        auto pe = build_minimal_pe(0x41, 0, 0, 0, {});
        write_u32(pe, 312 + 20, static_cast<uint32_t>(pe.size())); // PointerToRawData past EOF
        return !compute_authenticode_pe_hash_sha256(pe.data(), pe.size()).has_value();
    });

    // Opportunistic real-world cross-check: if a genuinely Authenticode-signed
    // binary is present on this dev machine at a known path, verify GCAD's
    // from-scratch PE hash reproduces the exact messageDigest value embedded
    // in its own SpcIndirectDataContent (extracted once via a real signature
    // inspection -- see the pkcs7 fixture/tests for how that value was
    // obtained and cross-checked). Skipped (treated as pass) when the file
    // isn't present, e.g. on CI or another machine -- this is a bonus
    // real-world check on top of the always-run synthetic tests above, not
    // the sole evidence of correctness.
    register_test("pe_hash_matches_real_authenticode_signed_binary_when_present", [] {
        const std::filesystem::path real_pe =
            "C:/Program Files/AhnLab/Safe Transaction/MUpdate2/Update/patch/04/mup/mupdate2.exe";
        std::error_code ec;
        if (!std::filesystem::is_regular_file(real_pe, ec) || ec) {
            std::cerr << "  [SKIP] real Authenticode fixture not present on this machine: "
                      << real_pe.string() << "\n";
            return true;
        }

        std::ifstream f(real_pe, std::ios::binary);
        if (!f) return false;
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        const auto actual = compute_authenticode_pe_hash_sha256(bytes.data(), bytes.size());
        if (!actual) return false;

        // The real messageDigest embedded in this file's own Authenticode
        // signature (SpcIndirectDataContent.messageDigest), extracted once
        // via .NET SignedCms as a read-only oracle -- see the pkcs7 tests.
        const std::string expected_hex = "af0882c32ad55c43ee552d83932e50ab50158bc1b06325fe7ee303f6d88991e0";
        const auto expected_bytes = hex_to_bytes(expected_hex.substr(0, 64));
        return std::equal(actual->begin(), actual->end(), expected_bytes.begin(), expected_bytes.end());
    });
}
