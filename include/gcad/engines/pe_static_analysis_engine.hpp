#pragma once

#include "../i_security_engine.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace gcad {

struct PeSectionInfo {
    std::string name;
    uint32_t    virtual_address{0};
    uint32_t    virtual_size{0};
    uint32_t    raw_data_offset{0};
    uint32_t    raw_data_size{0};
    uint32_t    characteristics{0};
    double      entropy{0.0};
    bool        is_executable{false};
    bool        is_writable{false};
    bool        is_wx{false}; // W^X memory violation (both writable and executable)
};

struct PeAnalysisReport {
    bool                        is_valid_pe{false};
    bool                        is_64bit{false};
    uint32_t                    entry_point{0};
    std::string                 entry_point_section;
    bool                        entry_point_anomaly{false};
    double                      overall_entropy{0.0};
    bool                        is_packed{false};
    std::string                 detected_packer;
    std::vector<PeSectionInfo>  sections;
    std::vector<std::string>    imported_dlls;
    std::vector<std::string>    imported_functions;
    std::vector<std::string>    dangerous_apis;
    uint32_t                    dangerous_api_score{0};
    std::string                 imphash;
    bool                        has_tls_callbacks{false};
    uint32_t                    tls_callback_count{0};
    ThreatLevel                 assessed_level{ThreatLevel::SAFE};
    std::vector<std::string>    threat_reasons;
};

class PeStaticAnalysisEngine final : public ISecurityEngine {
public:
    PeStaticAnalysisEngine();
    ~PeStaticAnalysisEngine() override;

    std::string_view name() const noexcept override { return "PeStaticAnalysis"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    // Static analysis methods
    PeAnalysisReport analyze_buffer(const uint8_t* data, size_t size) const;
    PeAnalysisReport analyze_file(const std::filesystem::path& path) const;

    // Shannon entropy calculation helper
    static double calculate_entropy(const uint8_t* data, size_t size) noexcept;

    // RFC 1321 MD5 hash calculation helper (32-character hex string)
    static std::string calculate_md5(const uint8_t* data, size_t size);

private:
    std::atomic<bool>                running_{false};
    std::function<void(ThreatEvent)> threat_cb_;
    mutable std::mutex               mtx_;
    mutable std::atomic<uint64_t>            scans_performed_{0};
    mutable std::atomic<uint64_t>            threats_detected_{0};

    void assess_threat(PeAnalysisReport& report) const;
    void emit_threat(const std::string& target, const PeAnalysisReport& report);
};

} // namespace gcad
