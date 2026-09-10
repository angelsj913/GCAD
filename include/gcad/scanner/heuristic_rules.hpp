#pragma once
#include "../common.hpp"

namespace gcad {

struct HeuristicResult {
    std::string rule_name;
    ThreatLevel level;
    ThreatCategory category;
    double      confidence;
    std::string description;
};

class HeuristicEngine {
public:
    HeuristicEngine();

    std::vector<HeuristicResult> analyze_binary(const uint8_t* data, size_t len,
                                                 const std::filesystem::path& path);
    std::vector<HeuristicResult> analyze_process(uint32_t pid);
    std::vector<HeuristicResult> analyze_network_behavior(uint32_t src_ip, uint16_t dst_port,
                                                           size_t packet_count, double avg_entropy);

private:
    bool check_packed_binary(const uint8_t* data, size_t len, HeuristicResult& out);
    bool check_suspicious_imports(const uint8_t* data, size_t len, HeuristicResult& out);
    bool check_code_cave(const uint8_t* data, size_t len, HeuristicResult& out);
    bool check_anti_debug(const uint8_t* data, size_t len, HeuristicResult& out);
    bool check_obfuscated_strings(const uint8_t* data, size_t len, HeuristicResult& out);
    bool check_process_injection_api(const uint8_t* data, size_t len, HeuristicResult& out);
};

} // namespace gcad
