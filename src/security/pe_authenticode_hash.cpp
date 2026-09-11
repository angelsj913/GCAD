#include "gcad/security/pe_authenticode_hash.hpp"

namespace gcad::security {

namespace {

uint16_t read_u16(const uint8_t* data, size_t offset) {
    return static_cast<uint16_t>(data[offset]) | (static_cast<uint16_t>(data[offset + 1]) << 8);
}

uint32_t read_u32(const uint8_t* data, size_t offset) {
    return static_cast<uint32_t>(data[offset]) | (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) | (static_cast<uint32_t>(data[offset + 3]) << 24);
}

bool fits(size_t size, size_t offset, size_t length) {
    return offset <= size && length <= size - offset;
}

struct SectionRange {
    size_t offset;
    size_t length;
};

} // namespace

std::optional<std::array<uint8_t, 32>> compute_authenticode_pe_hash_sha256(const uint8_t* data, size_t size) {
    if (!data || size < 64) return std::nullopt;
    if (data[0] != 'M' || data[1] != 'Z') return std::nullopt;

    const uint32_t pe_offset = read_u32(data, 0x3C);
    if (!fits(size, pe_offset, 4)) return std::nullopt;
    if (data[pe_offset] != 'P' || data[pe_offset + 1] != 'E' || data[pe_offset + 2] != 0 || data[pe_offset + 3] != 0)
        return std::nullopt;

    const size_t file_header_offset = pe_offset + 4;
    if (!fits(size, file_header_offset, 20)) return std::nullopt;
    const uint16_t number_of_sections = read_u16(data, file_header_offset + 2);
    const uint16_t size_of_optional_header = read_u16(data, file_header_offset + 16);

    const size_t opt_header_offset = file_header_offset + 20;
    if (!fits(size, opt_header_offset, size_of_optional_header)) return std::nullopt;
    if (size_of_optional_header < 2) return std::nullopt;
    const uint16_t magic = read_u16(data, opt_header_offset);

    size_t data_dir_base = 0; // offset of DataDirectory[0] within the Optional Header
    if (magic == 0x10b) data_dir_base = 96;       // PE32
    else if (magic == 0x20b) data_dir_base = 112; // PE32+
    else return std::nullopt;

    // CheckSum sits at the same offset (64) in both PE32 and PE32+.
    const size_t checksum_offset = opt_header_offset + 64;
    if (!fits(size, checksum_offset, 4)) return std::nullopt;

    const size_t size_of_headers_offset = opt_header_offset + 60;
    if (!fits(size, size_of_headers_offset, 4)) return std::nullopt;
    const uint32_t size_of_headers = read_u32(data, size_of_headers_offset);
    if (!fits(size, 0, size_of_headers)) return std::nullopt;
    if (size_of_headers < checksum_offset + 4) return std::nullopt; // headers must at least cover CheckSum

    const size_t security_dir_entry_offset = opt_header_offset + data_dir_base + 4 * 8;
    if (!fits(size, security_dir_entry_offset, 8)) return std::nullopt;
    if (security_dir_entry_offset + 8 > size_of_headers) return std::nullopt;
    const uint32_t cert_table_offset = read_u32(data, security_dir_entry_offset);
    const uint32_t cert_table_size = read_u32(data, security_dir_entry_offset + 4);
    if (cert_table_size > 0 && !fits(size, cert_table_offset, cert_table_size)) return std::nullopt;

    // Section headers immediately follow the Optional Header.
    const size_t section_table_offset = opt_header_offset + size_of_optional_header;
    constexpr size_t kSectionHeaderSize = 40;
    if (!fits(size, section_table_offset, static_cast<size_t>(number_of_sections) * kSectionHeaderSize))
        return std::nullopt;
    if (section_table_offset + static_cast<size_t>(number_of_sections) * kSectionHeaderSize > size_of_headers)
        return std::nullopt;

    std::vector<SectionRange> sections;
    sections.reserve(number_of_sections);
    for (uint16_t i = 0; i < number_of_sections; ++i) {
        const size_t hdr = section_table_offset + static_cast<size_t>(i) * kSectionHeaderSize;
        const uint32_t raw_size = read_u32(data, hdr + 16);
        const uint32_t raw_ptr = read_u32(data, hdr + 20);
        if (raw_size == 0) continue; // contributes no file bytes
        if (!fits(size, raw_ptr, raw_size)) return std::nullopt;
        sections.push_back({raw_ptr, raw_size});
    }
    std::sort(sections.begin(), sections.end(),
              [](const SectionRange& a, const SectionRange& b) { return a.offset < b.offset; });

    SHA256 ctx;
    ctx.update(data, checksum_offset);
    ctx.update(data + checksum_offset + 4, security_dir_entry_offset - (checksum_offset + 4));
    ctx.update(data + security_dir_entry_offset + 8, size_of_headers - (security_dir_entry_offset + 8));

    size_t extra_data_start = size_of_headers;
    for (const auto& section : sections) {
        ctx.update(data + section.offset, section.length);
        const size_t section_end = section.offset + section.length;
        if (section_end > extra_data_start) extra_data_start = section_end;
    }

    const size_t extra_data_end = (cert_table_size > 0) ? static_cast<size_t>(cert_table_offset) : size;
    if (extra_data_end > extra_data_start) {
        if (extra_data_end > size) return std::nullopt;
        ctx.update(data + extra_data_start, extra_data_end - extra_data_start);
    }

    return ctx.finalize();
}

std::optional<std::vector<uint8_t>> extract_authenticode_signature(const uint8_t* data, size_t size) {
    if (!data || size < 64) return std::nullopt;
    if (data[0] != 'M' || data[1] != 'Z') return std::nullopt;

    const uint32_t pe_offset = read_u32(data, 0x3C);
    if (!fits(size, pe_offset, 4)) return std::nullopt;
    if (data[pe_offset] != 'P' || data[pe_offset + 1] != 'E' || data[pe_offset + 2] != 0 || data[pe_offset + 3] != 0)
        return std::nullopt;

    const size_t file_header_offset = pe_offset + 4;
    if (!fits(size, file_header_offset, 20)) return std::nullopt;
    const uint16_t size_of_optional_header = read_u16(data, file_header_offset + 16);

    const size_t opt_header_offset = file_header_offset + 20;
    if (!fits(size, opt_header_offset, size_of_optional_header)) return std::nullopt;
    if (size_of_optional_header < 2) return std::nullopt;
    const uint16_t magic = read_u16(data, opt_header_offset);

    size_t data_dir_base = 0;
    if (magic == 0x10b) data_dir_base = 96;
    else if (magic == 0x20b) data_dir_base = 112;
    else return std::nullopt;

    const size_t security_dir_entry_offset = opt_header_offset + data_dir_base + 4 * 8;
    if (!fits(size, security_dir_entry_offset, 8)) return std::nullopt;
    const uint32_t cert_table_offset = read_u32(data, security_dir_entry_offset);
    const uint32_t cert_table_size = read_u32(data, security_dir_entry_offset + 4);
    if (cert_table_size == 0) return std::nullopt; // unsigned: no certificate table
    if (cert_table_size < 8) return std::nullopt;  // smaller than a WIN_CERTIFICATE header
    if (!fits(size, cert_table_offset, cert_table_size)) return std::nullopt;

    const uint32_t wc_length = read_u32(data, cert_table_offset);
    const uint16_t wc_cert_type = read_u16(data, cert_table_offset + 6);
    if (wc_cert_type != 0x0002) return std::nullopt; // not WIN_CERT_TYPE_PKCS_SIGNED_DATA
    if (wc_length < 8 || wc_length > cert_table_size) return std::nullopt;

    const size_t pkcs7_offset = cert_table_offset + 8;
    const size_t pkcs7_size = wc_length - 8;
    if (!fits(size, pkcs7_offset, pkcs7_size)) return std::nullopt;
    return std::vector<uint8_t>(data + pkcs7_offset, data + pkcs7_offset + pkcs7_size);
}

} // namespace gcad::security
