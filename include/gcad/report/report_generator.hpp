#pragma once
#include "../common.hpp"
#include "../security/observation.hpp"
#include "../security/policy.hpp"
#include <array>

namespace gcad {
class EngineManager;
class AlertManager;
}

namespace gcad::report {

struct ReportData {
    std::string generated_at;
    std::string gcad_version;
    int64_t     uptime_seconds{0};

    struct EngineInfo {
        std::string name;
        bool        running{false};
        uint64_t    events_processed{0};
        uint64_t    threats_detected{0};
    };
    std::vector<EngineInfo> engines;

    size_t                    total_events{0};
    size_t                    total_threats{0};
    std::array<size_t, 5>     severity_histogram{};
    std::vector<std::pair<ThreatCategory, size_t>> category_histogram;
    std::vector<ThreatEvent>  recent_events;
    std::vector<security::SecurityFinding> findings;

    size_t total_alerts{0};
    size_t unacknowledged_alerts{0};
};

struct MitreTtpInfo {
    const char* tactic;
    const char* technique_id;
    const char* technique_name;
};

class ReportGenerator {
public:
    static ReportData collect(const EngineManager& em,
                              const AlertManager* am = nullptr,
                              int64_t uptime_seconds = 0);

    static std::string generate_html(const ReportData& data);
    static std::string generate_text(const ReportData& data);

    static bool save_to_file(const std::string& content,
                             const std::filesystem::path& path);

    static const char* category_label(ThreatCategory cat);
    static const char* level_label(ThreatLevel level);
    static MitreTtpInfo mitre_ttp_for_category(ThreatCategory cat);
};

} // namespace gcad::report
