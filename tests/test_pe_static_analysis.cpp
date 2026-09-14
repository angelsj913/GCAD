#include "gcad/engines/pe_static_analysis_engine.hpp"
#include <functional>
#include <vector>
#include <cstring>
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

// Helper to construct a minimal valid PE32 buffer for testing
std::vector<uint8_t> create_synthetic_pe(const std::string& sec_name,
                                         uint32_t sec_chars,
                                         uint32_t entry_point = 0x1000,
                                         const std::vector<uint8_t>& sec_data = {}) {
    std::vector<uint8_t> pe(1024, 0);

    // DOS Header
    pe[0] = 'M';
    pe[1] = 'Z';
    // e_lfanew at 0x3C points to 0x80
    pe[0x3C] = 0x80;

    // PE Signature at 0x80
    pe[0x80] = 'P';
    pe[0x81] = 'E';
    pe[0x82] = 0;
    pe[0x83] = 0;

    // File Header at 0x84
    pe[0x84] = 0x4C; pe[0x85] = 0x01; // Machine = i386
    pe[0x86] = 1;    pe[0x87] = 0;    // NumberOfSections = 1
    pe[0x94] = 0xE0; pe[0x95] = 0;    // SizeOfOptionalHeader = 224 (PE32)
    pe[0x96] = 0x02; pe[0x97] = 0x01; // Characteristics = EXECUTABLE_IMAGE | 32BIT_MACHINE

    // Optional Header at 0x98
    pe[0x98] = 0x0B; pe[0x99] = 0x01; // Magic = PE32 (0x10B)
    // AddressOfEntryPoint at 0x98 + 16 = 0xA8
    *reinterpret_cast<uint32_t*>(&pe[0xA8]) = entry_point;

    // Section Header at 0x98 + 224 = 0x178
    size_t sec_off = 0x178;
    for (size_t i = 0; i < 8 && i < sec_name.size(); ++i) {
        pe[sec_off + i] = static_cast<uint8_t>(sec_name[i]);
    }
    // VirtualSize at sec_off + 8
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 8]) = 0x1000;
    // VirtualAddress at sec_off + 12
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 12]) = 0x1000;
    // SizeOfRawData at sec_off + 16
    uint32_t raw_sz = static_cast<uint32_t>(std::max<size_t>(sec_data.size(), 512));
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 16]) = raw_sz;
    // PointerToRawData at sec_off + 20 = 0x200 (512)
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 20]) = 0x200;
    // Characteristics at sec_off + 36
    *reinterpret_cast<uint32_t*>(&pe[sec_off + 36]) = sec_chars;

    // Put section data at 0x200
    if (pe.size() < 0x200 + raw_sz) {
        pe.resize(0x200 + raw_sz, 0);
    }
    if (!sec_data.empty()) {
        std::memcpy(&pe[0x200], sec_data.data(), sec_data.size());
    }

    return pe;
}

} // namespace

void register_pe_static_analysis_tests() {
    register_test("pe_static_analysis_name_and_lifecycle", [] {
        gcad::PeStaticAnalysisEngine engine;
        if (engine.name() != "PeStaticAnalysis") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("pe_static_analysis_entropy_calculation", [] {
        // Zero buffer should have 0.0 entropy
        std::vector<uint8_t> zeros(1024, 0);
        double zero_ent = gcad::PeStaticAnalysisEngine::calculate_entropy(zeros.data(), zeros.size());
        if (zero_ent != 0.0) return false;

        // Uniform byte distribution should have entropy close to 8.0
        std::vector<uint8_t> uniform(256 * 10);
        for (size_t i = 0; i < uniform.size(); ++i) {
            uniform[i] = static_cast<uint8_t>(i % 256);
        }
        double uni_ent = gcad::PeStaticAnalysisEngine::calculate_entropy(uniform.data(), uniform.size());
        if (uni_ent < 7.99 || uni_ent > 8.01) return false;

        return true;
    });

    register_test("pe_static_analysis_md5_rfc1321_vectors", [] {
        // RFC 1321 standard MD5 test vectors
        const std::string v1 = "";
        const std::string v2 = "a";
        const std::string v3 = "abc";
        const std::string v4 = "message digest";

        if (gcad::PeStaticAnalysisEngine::calculate_md5(reinterpret_cast<const uint8_t*>(v1.data()), v1.size()) !=
            "d41d8cd98f00b204e9800998ecf8427e") return false;

        if (gcad::PeStaticAnalysisEngine::calculate_md5(reinterpret_cast<const uint8_t*>(v2.data()), v2.size()) !=
            "0cc175b9c0f1b6a831c399e269772661") return false;

        if (gcad::PeStaticAnalysisEngine::calculate_md5(reinterpret_cast<const uint8_t*>(v3.data()), v3.size()) !=
            "900150983cd24fb0d6963f7d28e17f72") return false;

        if (gcad::PeStaticAnalysisEngine::calculate_md5(reinterpret_cast<const uint8_t*>(v4.data()), v4.size()) !=
            "f96b697d7cb7938d525a2f31aaf161d0") return false;

        return true;
    });

    register_test("pe_static_analysis_invalid_buffer", [] {
        gcad::PeStaticAnalysisEngine engine;
        std::vector<uint8_t> junk = {0x01, 0x02, 0x03, 0x04};
        auto report = engine.analyze_buffer(junk.data(), junk.size());
        if (report.is_valid_pe) return false;
        if (report.assessed_level != gcad::ThreatLevel::SAFE) return false;
        return true;
    });

    register_test("pe_static_analysis_detects_upx_packer", [] {
        gcad::PeStaticAnalysisEngine engine;
        // UPX section name (e.g. "UPX0")
        auto pe = create_synthetic_pe("UPX0", 0x60000020); // Executable & Readable
        auto report = engine.analyze_buffer(pe.data(), pe.size());

        if (!report.is_valid_pe) return false;
        if (!report.is_packed) return false;
        if (report.detected_packer != "UPX") return false;
        if (report.assessed_level < gcad::ThreatLevel::HIGH) return false;
        return true;
    });

    register_test("pe_static_analysis_detects_wx_violation", [] {
        gcad::PeStaticAnalysisEngine engine;
        // W^X violation: 0x20000000 (Exec) | 0x80000000 (Write) | 0x40000000 (Read)
        uint32_t wx_chars = 0x20000000 | 0x80000000 | 0x40000000;
        auto pe = create_synthetic_pe(".text", wx_chars);
        auto report = engine.analyze_buffer(pe.data(), pe.size());

        if (!report.is_valid_pe) return false;
        if (report.sections.empty()) return false;
        if (!report.sections[0].is_wx) return false;
        if (report.assessed_level < gcad::ThreatLevel::HIGH) return false;

        bool found_reason = false;
        for (const auto& reason : report.threat_reasons) {
            if (reason.find("W^X violation") != std::string::npos) {
                found_reason = true;
                break;
            }
        }
        return found_reason;
    });

    register_test("pe_static_analysis_detects_entrypoint_anomaly", [] {
        gcad::PeStaticAnalysisEngine engine;
        // EP outside any section (e.g. 0x99990000)
        auto pe = create_synthetic_pe(".text", 0x60000020, 0x99990000);
        auto report = engine.analyze_buffer(pe.data(), pe.size());

        if (!report.is_valid_pe) return false;
        if (!report.entry_point_anomaly) return false;
        return true;
    });

    register_test("pe_static_analysis_threat_callback_fired", [] {
        gcad::PeStaticAnalysisEngine engine;
        engine.start();

        bool fired = false;
        engine.on_threat([&](gcad::ThreatEvent ev) {
            fired = true;
            if (ev.level < gcad::ThreatLevel::HIGH) fired = false;
        });

        // Create a temporary malicious PE file with W^X and UPX
        auto pe = create_synthetic_pe("UPX0", 0xA0000020);
        auto temp_path = std::filesystem::temp_directory_path() / "gcad_test_malware.exe";
        {
            std::ofstream ofs(temp_path, std::ios::binary);
            ofs.write(reinterpret_cast<const char*>(pe.data()), pe.size());
        }

        auto report = engine.analyze_file(temp_path);
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);

        engine.stop();
        return fired && report.is_valid_pe && report.is_packed;
    });
}
