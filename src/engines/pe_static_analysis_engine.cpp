#include "gcad/engines/pe_static_analysis_engine.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace gcad {

namespace {

// Safe bounds check
inline bool fits(size_t size, size_t offset, size_t length) noexcept {
    return offset <= size && length <= size - offset;
}

inline uint16_t read_u16(const uint8_t* data, size_t offset) noexcept {
    return static_cast<uint16_t>(data[offset]) |
           (static_cast<uint16_t>(data[offset + 1]) << 8);
}

inline uint32_t read_u32(const uint8_t* data, size_t offset) noexcept {
    return static_cast<uint32_t>(data[offset]) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           (static_cast<uint32_t>(data[offset + 2]) << 16) |
           (static_cast<uint32_t>(data[offset + 3]) << 24);
}

inline uint64_t read_u64(const uint8_t* data, size_t offset) noexcept {
    return static_cast<uint64_t>(read_u32(data, offset)) |
           (static_cast<uint64_t>(read_u32(data, offset + 4)) << 32);
}

std::string to_lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string strip_dll_ext(std::string_view dll_name) {
    std::string s = to_lower_ascii(dll_name);
    if (s.size() > 4 && s.substr(s.size() - 4) == ".dll") {
        s.resize(s.size() - 4);
    }
    return s;
}

// Convert RVA to raw file offset using section list
std::optional<size_t> rva_to_offset(uint32_t rva, const std::vector<PeSectionInfo>& sections) noexcept {
    for (const auto& sec : sections) {
        uint32_t sec_size = std::max(sec.virtual_size, sec.raw_data_size);
        if (rva >= sec.virtual_address && rva < sec.virtual_address + sec_size) {
            uint32_t diff = rva - sec.virtual_address;
            if (diff < sec.raw_data_size) {
                return sec.raw_data_offset + diff;
            }
        }
    }
    return std::nullopt;
}

// Safe read of null-terminated ASCII string
std::string read_ascii_string(const uint8_t* data, size_t size, size_t offset, size_t max_len = 256) {
    std::string res;
    while (offset < size && data[offset] != 0 && res.size() < max_len) {
        char c = static_cast<char>(data[offset++]);
        if (c >= 32 && c <= 126) {
            res.push_back(c);
        } else {
            break;
        }
    }
    return res;
}

// RFC 1321 MD5 Implementation (Pure native C++20, zero dependencies)
class Md5Context {
public:
    Md5Context() { reset(); }

    void reset() noexcept {
        state_[0] = 0x67452301;
        state_[1] = 0xefcdab89;
        state_[2] = 0x98badcfe;
        state_[3] = 0x10325476;
        count_ = 0;
        buffer_.fill(0);
    }

    void update(const uint8_t* input, size_t length) noexcept {
        size_t index = static_cast<size_t>((count_ >> 3) & 0x3F);
        count_ += static_cast<uint64_t>(length) << 3;
        size_t part_len = 64 - index;
        size_t i = 0;

        if (length >= part_len) {
            std::memcpy(&buffer_[index], input, part_len);
            transform(buffer_.data());
            for (i = part_len; i + 63 < length; i += 64) {
                transform(&input[i]);
            }
            index = 0;
        }
        if (i < length) {
            std::memcpy(&buffer_[index], &input[i], length - i);
        }
    }

    std::array<uint8_t, 16> finalize() noexcept {
        std::array<uint8_t, 8> bits{};
        for (size_t i = 0; i < 8; ++i) {
            bits[i] = static_cast<uint8_t>((count_ >> (i * 8)) & 0xFF);
        }

        size_t index = static_cast<size_t>((count_ >> 3) & 0x3F);
        size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
        static const uint8_t padding[64] = {0x80};
        update(padding, pad_len);
        update(bits.data(), 8);

        std::array<uint8_t, 16> digest{};
        for (size_t i = 0; i < 4; ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>(state_[i] & 0xFF);
            digest[i * 4 + 1] = static_cast<uint8_t>((state_[i] >> 8) & 0xFF);
            digest[i * 4 + 2] = static_cast<uint8_t>((state_[i] >> 16) & 0xFF);
            digest[i * 4 + 3] = static_cast<uint8_t>((state_[i] >> 24) & 0xFF);
        }
        return digest;
    }

    static std::string to_hex(const std::array<uint8_t, 16>& digest) {
        static const char hex_chars[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(32);
        for (uint8_t b : digest) {
            hex.push_back(hex_chars[(b >> 4) & 0x0F]);
            hex.push_back(hex_chars[b & 0x0F]);
        }
        return hex;
    }

private:
    std::array<uint32_t, 4> state_{};
    uint64_t                count_{0};
    std::array<uint8_t, 64> buffer_{};

    static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & y) | (~x & z); }
    static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) noexcept { return (x & z) | (y & ~z); }
    static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) noexcept { return x ^ y ^ z; }
    static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) noexcept { return y ^ (x | ~z); }

    static inline uint32_t rotl(uint32_t x, uint32_t n) noexcept { return (x << n) | (x >> (32 - n)); }

    void transform(const uint8_t block[64]) noexcept {
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t x[16];
        for (size_t i = 0; i < 16; ++i) {
            x[i] = read_u32(block, i * 4);
        }

        // Round 1
        #define FF(a, b, c, d, k, s, t) a = b + rotl(a + F(b, c, d) + x[k] + t, s)
        FF(a, b, c, d,  0,  7, 0xd76aa478); FF(d, a, b, c,  1, 12, 0xe8c7b756);
        FF(c, d, a, b,  2, 17, 0x242070db); FF(b, c, d, a,  3, 22, 0xc1bdceee);
        FF(a, b, c, d,  4,  7, 0xf57c0faf); FF(d, a, b, c,  5, 12, 0x4787c62a);
        FF(c, d, a, b,  6, 17, 0xa8304613); FF(b, c, d, a,  7, 22, 0xfd469501);
        FF(a, b, c, d,  8,  7, 0x698098d8); FF(d, a, b, c,  9, 12, 0x8b44f7af);
        FF(c, d, a, b, 10, 17, 0xffff5bb1); FF(b, c, d, a, 11, 22, 0x895cd7be);
        FF(a, b, c, d, 12,  7, 0x6b901122); FF(d, a, b, c, 13, 12, 0xfd987193);
        FF(c, d, a, b, 14, 17, 0xa679438e); FF(b, c, d, a, 15, 22, 0x49b40821);
        #undef FF

        // Round 2
        #define GG(a, b, c, d, k, s, t) a = b + rotl(a + G(b, c, d) + x[k] + t, s)
        GG(a, b, c, d,  1,  5, 0xf61e2562); GG(d, a, b, c,  6,  9, 0xc040b340);
        GG(c, d, a, b, 11, 14, 0x265e5a51); GG(b, c, d, a,  0, 20, 0xe9b6c7aa);
        GG(a, b, c, d,  5,  5, 0xd62f105d); GG(d, a, b, c, 10,  9, 0x02441453);
        GG(c, d, a, b, 15, 14, 0xd8a1e681); GG(b, c, d, a,  4, 20, 0xe7d3fbc8);
        GG(a, b, c, d,  9,  5, 0x21e1cde6); GG(d, a, b, c, 14,  9, 0xc33707d6);
        GG(c, d, a, b,  3, 14, 0xf4d50d87); GG(b, c, d, a,  8, 20, 0x455a14ed);
        GG(a, b, c, d, 13,  5, 0xa9e3e905); GG(d, a, b, c,  2,  9, 0xfcefa3f8);
        GG(c, d, a, b,  7, 14, 0x676f02d9); GG(b, c, d, a, 12, 20, 0x8d2a4c8a);
        #undef GG

        // Round 3
        #define HH(a, b, c, d, k, s, t) a = b + rotl(a + H(b, c, d) + x[k] + t, s)
        HH(a, b, c, d,  5,  4, 0xfffa3942); HH(d, a, b, c,  8, 11, 0x8771f681);
        HH(c, d, a, b, 11, 16, 0x6d9d6122); HH(b, c, d, a, 14, 23, 0xfde5380c);
        HH(a, b, c, d,  1,  4, 0xa4beea44); HH(d, a, b, c,  4, 11, 0x4bdecfa9);
        HH(c, d, a, b,  7, 16, 0xf6bb4b60); HH(b, c, d, a, 10, 23, 0xbebfbc70);
        HH(a, b, c, d, 13,  4, 0x289b7ec6); HH(d, a, b, c,  0, 11, 0xeaa127fa);
        HH(c, d, a, b,  3, 16, 0xd4ef3085); HH(b, c, d, a,  6, 23, 0x04881d05);
        HH(a, b, c, d,  9,  4, 0xd9d4d039); HH(d, a, b, c, 12, 11, 0xe6db99e5);
        HH(c, d, a, b, 15, 16, 0x1fa27cf8); HH(b, c, d, a,  2, 23, 0xc4ac5665);
        #undef HH

        // Round 4
        #define II(a, b, c, d, k, s, t) a = b + rotl(a + I(b, c, d) + x[k] + t, s)
        II(a, b, c, d,  0,  6, 0xf4292244); II(d, a, b, c,  7, 10, 0x432aff97);
        II(c, d, a, b, 14, 15, 0xab9423a7); II(b, c, d, a,  5, 21, 0xfc93a039);
        II(a, b, c, d, 12,  6, 0x655b59c3); II(d, a, b, c,  3, 10, 0x8f0ccc92);
        II(c, d, a, b, 10, 15, 0xffeff47d); II(b, c, d, a,  1, 21, 0x85845dd1);
        II(a, b, c, d,  8,  6, 0x6fa87e4f); II(d, a, b, c, 15, 10, 0xfe2ce6e0);
        II(c, d, a, b,  6, 15, 0xa3014314); II(b, c, d, a, 13, 21, 0x4e0811a1);
        II(a, b, c, d,  4,  6, 0xf7537e82); II(d, a, b, c, 11, 10, 0xbd3af235);
        II(c, d, a, b,  2, 15, 0x2ad7d2bb); II(b, c, d, a,  9, 21, 0xeb86d391);
        #undef II

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
    }
};

} // namespace

PeStaticAnalysisEngine::PeStaticAnalysisEngine() = default;
PeStaticAnalysisEngine::~PeStaticAnalysisEngine() {
    stop();
}

ErrorCode PeStaticAnalysisEngine::start() {
    running_.store(true);
    return ErrorCode::OK;
}

ErrorCode PeStaticAnalysisEngine::stop() {
    running_.store(false);
    return ErrorCode::OK;
}

EngineStatus PeStaticAnalysisEngine::status() const {
    EngineStatus st{};
    st.name = name();
    st.running = running_.load();
    st.events_processed = scans_performed_.load();
    st.threats_detected = threats_detected_.load();
    return st;
}

void PeStaticAnalysisEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    threat_cb_ = std::move(cb);
}

double PeStaticAnalysisEngine::calculate_entropy(const uint8_t* data, size_t size) noexcept {
    if (!data || size == 0) return 0.0;
    std::array<size_t, 256> freq{};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    double total = static_cast<double>(size);
    for (size_t count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

std::string PeStaticAnalysisEngine::calculate_md5(const uint8_t* data, size_t size) {
    if (!data && size > 0) return "";
    Md5Context ctx;
    if (data && size > 0) {
        ctx.update(data, size);
    }
    return Md5Context::to_hex(ctx.finalize());
}

PeAnalysisReport PeStaticAnalysisEngine::analyze_buffer(const uint8_t* data, size_t size) const {
    scans_performed_.fetch_add(1);
    PeAnalysisReport report;
    if (!data || size < 64) return report;

    // Check DOS Signature
    if (data[0] != 'M' || data[1] != 'Z') return report;

    uint32_t pe_offset = read_u32(data, 0x3C);
    if (!fits(size, pe_offset, 4)) return report;

    // Check PE Signature
    if (data[pe_offset] != 'P' || data[pe_offset + 1] != 'E' ||
        data[pe_offset + 2] != 0 || data[pe_offset + 3] != 0) {
        return report;
    }
    report.is_valid_pe = true;
    report.overall_entropy = calculate_entropy(data, size);

    size_t file_header_offset = pe_offset + 4;
    if (!fits(size, file_header_offset, 20)) return report;

    uint16_t num_sections = read_u16(data, file_header_offset + 2);
    uint16_t opt_header_size = read_u16(data, file_header_offset + 16);

    size_t opt_header_offset = file_header_offset + 20;
    if (!fits(size, opt_header_offset, opt_header_size) || opt_header_size < 2) return report;

    uint16_t magic = read_u16(data, opt_header_offset);
    if (magic == 0x10B) {
        report.is_64bit = false;
    } else if (magic == 0x20B) {
        report.is_64bit = true;
    } else {
        return report;
    }

    if (!fits(size, opt_header_offset + 16, 4)) return report;
    report.entry_point = read_u32(data, opt_header_offset + 16);

    // Data Directories
    size_t data_dir_offset = opt_header_offset + (report.is_64bit ? 112 : 96);
    uint32_t import_rva = 0;
    uint32_t import_size = 0;
    uint32_t tls_rva = 0;

    if (fits(size, data_dir_offset + 8 * 1, 8)) {
        import_rva = read_u32(data, data_dir_offset + 8 * 1);
        import_size = read_u32(data, data_dir_offset + 8 * 1 + 4);
    }
    if (fits(size, data_dir_offset + 8 * 9, 8)) {
        tls_rva = read_u32(data, data_dir_offset + 8 * 9);
    }

    // Section Headers
    size_t section_table_offset = opt_header_offset + opt_header_size;
    report.sections.reserve(num_sections);

    bool ep_found = false;
    for (uint16_t i = 0; i < num_sections; ++i) {
        size_t sec_offset = section_table_offset + i * 40;
        if (!fits(size, sec_offset, 40)) break;

        PeSectionInfo sec;
        // Section Name (8 bytes)
        char name_buf[9]{};
        std::memcpy(name_buf, data + sec_offset, 8);
        sec.name = name_buf;

        sec.virtual_size = read_u32(data, sec_offset + 8);
        sec.virtual_address = read_u32(data, sec_offset + 12);
        sec.raw_data_size = read_u32(data, sec_offset + 16);
        sec.raw_data_offset = read_u32(data, sec_offset + 20);
        sec.characteristics = read_u32(data, sec_offset + 36);

        sec.is_executable = (sec.characteristics & 0x20000000) != 0;
        sec.is_writable   = (sec.characteristics & 0x80000000) != 0;
        sec.is_wx         = sec.is_executable && sec.is_writable;

        if (sec.raw_data_size > 0 && fits(size, sec.raw_data_offset, sec.raw_data_size)) {
            sec.entropy = calculate_entropy(data + sec.raw_data_offset, sec.raw_data_size);
        }

        // Check if EntryPoint is in this section
        uint32_t effective_size = std::max(sec.virtual_size, sec.raw_data_size);
        if (report.entry_point >= sec.virtual_address &&
            report.entry_point < sec.virtual_address + effective_size) {
            report.entry_point_section = sec.name;
            ep_found = true;
            if (i == num_sections - 1 && num_sections > 1) {
                report.entry_point_anomaly = true; // EP in last section (packer hallmark)
            }
        }

        // Packer Section Names
        std::string lower_sec = to_lower_ascii(sec.name);
        if (lower_sec.find("upx") != std::string::npos) {
            report.is_packed = true;
            report.detected_packer = "UPX";
        } else if (lower_sec.find("aspack") != std::string::npos || lower_sec.find(".adata") != std::string::npos) {
            report.is_packed = true;
            report.detected_packer = "ASPack";
        } else if (lower_sec.find("themida") != std::string::npos) {
            report.is_packed = true;
            report.detected_packer = "Themida";
        } else if (lower_sec.find("vmp") != std::string::npos) {
            report.is_packed = true;
            report.detected_packer = "VMProtect";
        } else if (lower_sec.find("mpress") != std::string::npos) {
            report.is_packed = true;
            report.detected_packer = "Mpress";
        } else if (lower_sec.find("enigma") != std::string::npos) {
            report.is_packed = true;
            report.detected_packer = "Enigma";
        }

        report.sections.push_back(std::move(sec));
    }

    if (!ep_found && report.entry_point != 0) {
        report.entry_point_anomaly = true; // EP outside any defined section
    }

    // Heuristic high-entropy packer detection
    if (!report.is_packed && report.overall_entropy >= 7.2) {
        for (const auto& sec : report.sections) {
            if ((sec.is_executable && sec.entropy >= 7.1) || sec.is_wx) {
                report.is_packed = true;
                report.detected_packer = "Generic High-Entropy Packer";
                break;
            }
        }
    }

    // Parse Imports & Calculate Imphash
    std::vector<std::string> imphash_items;
    if (import_rva != 0 && import_size > 0) {
        auto import_off = rva_to_offset(import_rva, report.sections);
        if (import_off.has_value() && fits(size, *import_off, 20)) {
            size_t desc_offset = *import_off;
            while (fits(size, desc_offset, 20)) {
                uint32_t original_first_thunk = read_u32(data, desc_offset);
                uint32_t name_rva = read_u32(data, desc_offset + 12);
                uint32_t first_thunk = read_u32(data, desc_offset + 16);

                if (name_rva == 0 && first_thunk == 0) break; // End of descriptors

                std::string dll_name;
                auto name_off = rva_to_offset(name_rva, report.sections);
                if (name_off.has_value()) {
                    dll_name = read_ascii_string(data, size, *name_off);
                }
                if (!dll_name.empty()) {
                    report.imported_dlls.push_back(dll_name);
                }

                uint32_t thunk_rva = (original_first_thunk != 0) ? original_first_thunk : first_thunk;
                auto thunk_off = rva_to_offset(thunk_rva, report.sections);

                if (thunk_off.has_value() && !dll_name.empty()) {
                    std::string mod_prefix = strip_dll_ext(dll_name);
                    size_t curr_thunk = *thunk_off;
                    size_t step = report.is_64bit ? 8 : 4;

                    while (fits(size, curr_thunk, step)) {
                        bool is_ordinal = false;
                        uint32_t ord_num = 0;
                        uint32_t func_rva = 0;

                        if (report.is_64bit) {
                            uint64_t val = read_u64(data, curr_thunk);
                            if (val == 0) break;
                            if ((val & 0x8000000000000000ULL) != 0) {
                                is_ordinal = true;
                                ord_num = static_cast<uint32_t>(val & 0xFFFF);
                            } else {
                                func_rva = static_cast<uint32_t>(val & 0xFFFFFFFF);
                            }
                        } else {
                            uint32_t val = read_u32(data, curr_thunk);
                            if (val == 0) break;
                            if ((val & 0x80000000) != 0) {
                                is_ordinal = true;
                                ord_num = val & 0xFFFF;
                            } else {
                                func_rva = val;
                            }
                        }

                        std::string func_name;
                        if (is_ordinal) {
                            func_name = "ord" + std::to_string(ord_num);
                        } else if (func_rva != 0) {
                            auto func_off = rva_to_offset(func_rva, report.sections);
                            if (func_off.has_value() && fits(size, *func_off + 2, 2)) {
                                func_name = read_ascii_string(data, size, *func_off + 2);
                            }
                        }

                        if (!func_name.empty()) {
                            report.imported_functions.push_back(func_name);
                            imphash_items.push_back(mod_prefix + "." + to_lower_ascii(func_name));
                        }
                        curr_thunk += step;
                    }
                }
                desc_offset += 20;
            }
        }
    }

    // Build Imphash string
    if (!imphash_items.empty()) {
        std::string imphash_joined;
        for (size_t i = 0; i < imphash_items.size(); ++i) {
            if (i > 0) imphash_joined.push_back(',');
            imphash_joined.append(imphash_items[i]);
        }
        report.imphash = calculate_md5(reinterpret_cast<const uint8_t*>(imphash_joined.data()),
                                       imphash_joined.size());
    }

    // Dangerous API Cluster Scoring
    static const std::vector<std::string> dangerous_list = {
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
        "writeprocessmemory", "createremotethread", "ntcreatethreadex",
        "queueuserapc", "setthreadcontext", "resumethread",
        "ntunmapviewofsection", "zwunmapviewofsection",
        "minidumpwritedump", "openprocesstoken", "adjusttokenprivileges",
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "loadlibrarya", "loadlibraryw", "getprocaddress", "ldrloaddll"
    };

    for (const auto& func : report.imported_functions) {
        std::string lower_func = to_lower_ascii(func);
        for (const auto& danger : dangerous_list) {
            if (lower_func == danger) {
                report.dangerous_apis.push_back(func);
                report.dangerous_api_score += 10;
                break;
            }
        }
    }

    // Parse TLS Callbacks
    if (tls_rva != 0) {
        auto tls_off = rva_to_offset(tls_rva, report.sections);
        if (tls_off.has_value()) {
            size_t callback_array_rva_off = *tls_off + (report.is_64bit ? 24 : 12);
            if (fits(size, callback_array_rva_off, report.is_64bit ? 8 : 4)) {
                report.has_tls_callbacks = true;
                report.tls_callback_count = 1; // Presence of TLS directory callback table
            }
        }
    }

    // Assess Threat Level and Reasons
    assess_threat(report);
    return report;
}

void PeStaticAnalysisEngine::assess_threat(PeAnalysisReport& report) const {
    uint32_t risk_score = 0;

    // 1. W^X Section Violation (Critical memory anomaly)
    for (const auto& sec : report.sections) {
        if (sec.is_wx) {
            report.threat_reasons.push_back("Section '" + sec.name + "' is both Writable and Executable (W^X violation)");
            risk_score += 40;
        }
    }

    // 2. Packer / Crypter Detected
    if (report.is_packed) {
        report.threat_reasons.push_back("Packer detected: " + report.detected_packer);
        risk_score += 35;
    }

    // 3. Entry Point Anomaly
    if (report.entry_point_anomaly) {
        report.threat_reasons.push_back("Entry point anomaly: EP located in unusual section ('" + report.entry_point_section + "')");
        risk_score += 25;
    }

    // 4. Overall High Entropy
    if (report.overall_entropy >= 7.2) {
        std::ostringstream oss;
        oss << "High overall Shannon entropy: " << std::fixed << std::setprecision(2) << report.overall_entropy;
        report.threat_reasons.push_back(oss.str());
        risk_score += 20;
    }

    // 5. Dangerous API Clustering
    if (report.dangerous_api_score >= 30) {
        report.threat_reasons.push_back("Dangerous injection/evasion API cluster detected (" +
                                        std::to_string(report.dangerous_apis.size()) + " APIs)");
        risk_score += 30;
    } else if (report.dangerous_api_score >= 10) {
        risk_score += 10;
    }

    // 6. TLS Callbacks
    if (report.has_tls_callbacks && (report.is_packed || report.overall_entropy >= 6.8)) {
        report.threat_reasons.push_back("TLS callbacks detected with high-entropy/packed payload");
        risk_score += 15;
    }

    // Map score to ThreatLevel
    if (risk_score >= 60) {
        report.assessed_level = ThreatLevel::CRITICAL;
    } else if (risk_score >= 35) {
        report.assessed_level = ThreatLevel::HIGH;
    } else if (risk_score >= 15) {
        report.assessed_level = ThreatLevel::MEDIUM;
    } else if (risk_score > 0) {
        report.assessed_level = ThreatLevel::LOW;
    } else {
        report.assessed_level = ThreatLevel::SAFE;
    }
}

PeAnalysisReport PeStaticAnalysisEngine::analyze_file(const std::filesystem::path& path) const {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        PeAnalysisReport report;
        return report;
    }
    auto fsize = ifs.tellg();
    if (fsize <= 0 || fsize > 100 * 1024 * 1024) { // 100MB limit for static scan
        PeAnalysisReport report;
        return report;
    }
    std::vector<uint8_t> buffer(static_cast<size_t>(fsize));
    ifs.seekg(0, std::ios::beg);
    ifs.read(reinterpret_cast<char*>(buffer.data()), fsize);

    auto report = analyze_buffer(buffer.data(), buffer.size());
    if (report.assessed_level >= ThreatLevel::HIGH && running_.load()) {
        const_cast<PeStaticAnalysisEngine*>(this)->emit_threat(path.string(), report);
    }
    return report;
}

void PeStaticAnalysisEngine::emit_threat(const std::string& target, const PeAnalysisReport& report) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.id = threats_detected_.load();
        ev.timestamp = std::chrono::system_clock::now();
        ev.level = report.assessed_level;
        ev.category = report.is_packed ? ThreatCategory::ENTROPY_ANOMALY : ThreatCategory::SUSPICIOUS_BINARY;
        ev.file_path = target;
        std::string desc = "PE Static Analysis Threat: ";
        for (size_t i = 0; i < report.threat_reasons.size(); ++i) {
            if (i > 0) desc += "; ";
            desc += report.threat_reasons[i];
        }
        ev.description = desc;
        cb(std::move(ev));
    }
}

} // namespace gcad
