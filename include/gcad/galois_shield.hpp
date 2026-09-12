#pragma once

#include "engine_manager.hpp"
#include <string_view>
#include <vector>
#include <array>

namespace gcad {

enum class EngineCategory : uint8_t {
    MEMORY_PROTECTION  = 0,
    PROCESS_DEFENSE    = 1,
    NETWORK_SECURITY   = 2,
    FILE_PROTECTION    = 3,
    SYSTEM_INTEGRITY   = 4,
    THREAT_ANALYSIS    = 5,
    ENDPOINT_CONTROL   = 6,
};

static constexpr size_t ENGINE_CATEGORY_COUNT = 7;

struct EngineCategoryInfo {
    EngineCategory           category;
    std::string_view         label;
    std::vector<std::string> engine_names;
};

struct ShieldHealthReport {
    double   overall_score{0.0};
    size_t   engines_total{0};
    size_t   engines_running{0};
    size_t   engines_stopped{0};
    uint64_t total_events{0};
    size_t   total_threats{0};
    ThreatLevel current_threat_level{ThreatLevel::SAFE};
    bool     etw_active{false};
    std::vector<std::string> stopped_engine_names;
};

class GaloisShield {
public:
    static constexpr std::string_view ENGINE_NAME    = "GaloisShield Engine";
    static constexpr std::string_view VERSION        = "1.0.0";
    static constexpr std::string_view VENDOR         = "Galoisconnection";
    static constexpr std::string_view BUILD_CODENAME = "Bastion";

    explicit GaloisShield(EngineManager& mgr);

    std::string_view name()     const noexcept { return ENGINE_NAME; }
    std::string_view version()  const noexcept { return VERSION; }
    std::string_view vendor()   const noexcept { return VENDOR; }
    std::string_view codename() const noexcept { return BUILD_CODENAME; }

    std::string version_string() const;

    ErrorCode start();
    ErrorCode stop();

    ShieldHealthReport health() const;

    std::vector<EngineCategoryInfo> categories() const;

    static EngineCategory categorize(std::string_view engine_name);
    static std::string_view category_label(EngineCategory cat);

    size_t engine_count() const noexcept { return mgr_.engine_count(); }
    std::vector<EngineStatus> statuses() const { return mgr_.statuses(); }

    EngineManager& manager() noexcept { return mgr_; }
    const EngineManager& manager() const noexcept { return mgr_; }

private:
    EngineManager& mgr_;
};

} // namespace gcad
