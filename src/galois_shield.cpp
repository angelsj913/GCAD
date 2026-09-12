#include "gcad/galois_shield.hpp"
#include <algorithm>

namespace gcad {

GaloisShield::GaloisShield(EngineManager& mgr) : mgr_(mgr) {}

std::string GaloisShield::version_string() const {
    return std::string(ENGINE_NAME) + " v" + std::string(VERSION) +
           " (" + std::string(BUILD_CODENAME) + ") — " + std::string(VENDOR);
}

ErrorCode GaloisShield::start() { return mgr_.start_all(); }
ErrorCode GaloisShield::stop()  { return mgr_.stop_all();  }

ShieldHealthReport GaloisShield::health() const {
    ShieldHealthReport r;
    r.engines_total   = mgr_.engine_count();
    r.stopped_engine_names = mgr_.stopped_engines();
    r.engines_stopped = r.stopped_engine_names.size();
    r.engines_running = r.engines_total - r.engines_stopped;
    r.total_events    = mgr_.total_engine_events();
    r.total_threats   = mgr_.total_threats();
    r.current_threat_level = mgr_.current_threat_level();
    r.etw_active      = mgr_.etw_kernel_process_active();

    if (r.engines_total == 0) {
        r.overall_score = 0.0;
        return r;
    }

    double engine_ratio = static_cast<double>(r.engines_running) /
                          static_cast<double>(r.engines_total);
    double threat_penalty = 0.0;
    switch (r.current_threat_level) {
        case ThreatLevel::SAFE:     threat_penalty = 0.00; break;
        case ThreatLevel::LOW:      threat_penalty = 0.05; break;
        case ThreatLevel::MEDIUM:   threat_penalty = 0.15; break;
        case ThreatLevel::HIGH:     threat_penalty = 0.30; break;
        case ThreatLevel::CRITICAL: threat_penalty = 0.50; break;
    }

    r.overall_score = std::clamp(engine_ratio - threat_penalty, 0.0, 1.0);
    return r;
}

EngineCategory GaloisShield::categorize(std::string_view engine_name) {
    if (engine_name == "PMSR" || engine_name == "ETG-RI")
        return EngineCategory::MEMORY_PROTECTION;

    if (engine_name == "ARHS" || engine_name == "ZRGP" ||
        engine_name == "SelfDefense" || engine_name == "SyscallGuard" ||
        engine_name == "CredentialGuard")
        return EngineCategory::PROCESS_DEFENSE;

    if (engine_name == "DnsMonitor" || engine_name == "Firewall" ||
        engine_name == "NetworkDPI")
        return EngineCategory::NETWORK_SECURITY;

    if (engine_name == "FileIntegrity" || engine_name == "RansomwareShield")
        return EngineCategory::FILE_PROTECTION;

    if (engine_name == "KernelMonitor" || engine_name == "RegistryMonitor" ||
        engine_name == "DeviceControl")
        return EngineCategory::SYSTEM_INTEGRITY;

    if (engine_name == "YARA" || engine_name == "BehaviorML" ||
        engine_name == "ThreatIntel" || engine_name == "ForensicTimeline" ||
        engine_name == "VulnScanner")
        return EngineCategory::THREAT_ANALYSIS;

    if (engine_name == "Sandbox" || engine_name == "AutoUpdate")
        return EngineCategory::ENDPOINT_CONTROL;

    return EngineCategory::ENDPOINT_CONTROL;
}

std::string_view GaloisShield::category_label(EngineCategory cat) {
    switch (cat) {
        case EngineCategory::MEMORY_PROTECTION: return "Memory Protection";
        case EngineCategory::PROCESS_DEFENSE:   return "Process Defense";
        case EngineCategory::NETWORK_SECURITY:  return "Network Security";
        case EngineCategory::FILE_PROTECTION:   return "File Protection";
        case EngineCategory::SYSTEM_INTEGRITY:  return "System Integrity";
        case EngineCategory::THREAT_ANALYSIS:   return "Threat Analysis";
        case EngineCategory::ENDPOINT_CONTROL:  return "Endpoint Control";
    }
    return "Unknown";
}

std::vector<EngineCategoryInfo> GaloisShield::categories() const {
    std::array<std::vector<std::string>, ENGINE_CATEGORY_COUNT> buckets;

    for (auto& s : mgr_.statuses()) {
        auto cat = categorize(s.name);
        buckets[static_cast<size_t>(cat)].push_back(s.name);
    }

    std::vector<EngineCategoryInfo> result;
    for (size_t i = 0; i < ENGINE_CATEGORY_COUNT; ++i) {
        if (buckets[i].empty()) continue;
        auto cat = static_cast<EngineCategory>(i);
        EngineCategoryInfo info;
        info.category = cat;
        info.label = category_label(cat);
        info.engine_names = std::move(buckets[i]);
        result.push_back(std::move(info));
    }
    return result;
}

} // namespace gcad
