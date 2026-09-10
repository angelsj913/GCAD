#include "gcad/scanner/heuristic_rules.hpp"

namespace gcad {

HeuristicEngine::HeuristicEngine() = default;

std::vector<HeuristicResult> HeuristicEngine::analyze_binary(const uint8_t* data, size_t len,
                                                              const std::filesystem::path& path) {
    std::vector<HeuristicResult> results;
    HeuristicResult r;
    if (check_packed_binary(data, len, r))         results.push_back(r);
    if (check_suspicious_imports(data, len, r))    results.push_back(r);
    if (check_code_cave(data, len, r))             results.push_back(r);
    if (check_anti_debug(data, len, r))            results.push_back(r);
    if (check_obfuscated_strings(data, len, r))    results.push_back(r);
    if (check_process_injection_api(data, len, r)) results.push_back(r);
    (void)path;
    return results;
}

std::vector<HeuristicResult> HeuristicEngine::analyze_process(uint32_t pid) {
    (void)pid;
    return {};
}

std::vector<HeuristicResult> HeuristicEngine::analyze_network_behavior(uint32_t src_ip, uint16_t dst_port,
                                                                        size_t packet_count, double avg_entropy) {
    std::vector<HeuristicResult> results;
    if (packet_count > 1000 && dst_port < 1024) {
        results.push_back({"high_rate_to_privileged_port", ThreatLevel::HIGH, ThreatCategory::SYN_FLOOD,
            0.85, "High packet rate to privileged port " + std::to_string(dst_port)});
    }
    if (avg_entropy > 7.5) {
        results.push_back({"encrypted_exfil", ThreatLevel::HIGH, ThreatCategory::DNS_TUNNEL,
            0.75, "High average entropy suggests encrypted C2/exfil channel"});
    }
    (void)src_ip;
    return results;
}

bool HeuristicEngine::check_packed_binary(const uint8_t* data, size_t len, HeuristicResult& out) {
    if (len < 1024) return false;
    size_t section_count = 0;
    double total_entropy = 0.0;
    size_t chunk = 4096;
    for (size_t i = 0; i + chunk <= len; i += chunk) {
        double ent = shannon_entropy(data + i, chunk);
        total_entropy += ent;
        ++section_count;
    }
    if (section_count == 0) return false;
    double avg = total_entropy / section_count;
    if (avg > 7.2) {
        out = {"packed_binary", ThreatLevel::MEDIUM, ThreatCategory::SUSPICIOUS_BINARY,
               avg / 8.0, "Binary appears packed/encrypted (avg entropy " +
               std::format("{:.2f}", avg) + ")"};
        return true;
    }
    return false;
}

bool HeuristicEngine::check_suspicious_imports(const uint8_t* data, size_t len, HeuristicResult& out) {
    static const std::vector<std::string_view> dangerous_apis = {
        "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
        "SetWindowsHookEx", "VirtualProtectEx", "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory", "ZwMapViewOfSection",
    };
    int count = 0;
    for (auto& api : dangerous_apis) {
        for (size_t i = 0; i + api.size() <= len; ++i) {
            if (std::memcmp(data + i, api.data(), api.size()) == 0) { ++count; break; }
        }
    }
    if (count >= 3) {
        out = {"suspicious_import_combo", ThreatLevel::HIGH, ThreatCategory::MEMORY_INJECTION,
               static_cast<double>(count) / dangerous_apis.size(),
               "Multiple dangerous API imports detected (" + std::to_string(count) + ")"};
        return true;
    }
    return false;
}

bool HeuristicEngine::check_code_cave(const uint8_t* data, size_t len, HeuristicResult& out) {
    if (len < 512) return false;
    size_t zero_run = 0, max_zero = 0;
    for (size_t i = 0; i < len; ++i) {
        if (data[i] == 0x00) { ++zero_run; if (zero_run > max_zero) max_zero = zero_run; }
        else zero_run = 0;
    }
    if (max_zero > 4096 && max_zero < len / 2) {
        out = {"code_cave", ThreatLevel::LOW, ThreatCategory::SUSPICIOUS_BINARY,
               0.5, "Large zero-filled code cave (" + std::to_string(max_zero) + " bytes)"};
        return true;
    }
    return false;
}

bool HeuristicEngine::check_anti_debug(const uint8_t* data, size_t len, HeuristicResult& out) {
    static const std::vector<std::string_view> anti_dbg = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
    };
    int count = 0;
    for (auto& func : anti_dbg) {
        for (size_t i = 0; i + func.size() <= len; ++i) {
            if (std::memcmp(data + i, func.data(), func.size()) == 0) { ++count; break; }
        }
    }
    if (count >= 3) {
        out = {"anti_debug_techniques", ThreatLevel::MEDIUM, ThreatCategory::EVASION_AMSI,
               static_cast<double>(count) / anti_dbg.size(),
               "Multiple anti-debugging technique imports (" + std::to_string(count) + ")"};
        return true;
    }
    return false;
}

bool HeuristicEngine::check_obfuscated_strings(const uint8_t* data, size_t len, HeuristicResult& out) {
    if (len < 256) return false;
    size_t printable_runs = 0, total_runs = 0;
    size_t current_run = 0;
    for (size_t i = 0; i < len; ++i) {
        if (data[i] >= 0x20 && data[i] < 0x7F) {
            ++current_run;
        } else {
            if (current_run >= 4) ++printable_runs;
            total_runs += (current_run > 0) ? 1 : 0;
            current_run = 0;
        }
    }
    if (total_runs > 0 && printable_runs == 0 && len > 4096) {
        out = {"obfuscated_strings", ThreatLevel::MEDIUM, ThreatCategory::SUSPICIOUS_BINARY,
               0.6, "No readable strings in binary — likely obfuscated"};
        return true;
    }
    return false;
}

bool HeuristicEngine::check_process_injection_api(const uint8_t* data, size_t len, HeuristicResult& out) {
    bool has_alloc = false, has_write = false, has_exec = false;
    auto find_str = [&](std::string_view s) {
        for (size_t i = 0; i + s.size() <= len; ++i)
            if (std::memcmp(data + i, s.data(), s.size()) == 0) return true;
        return false;
    };
    has_alloc = find_str("VirtualAllocEx") || find_str("NtAllocateVirtualMemory");
    has_write = find_str("WriteProcessMemory") || find_str("NtWriteVirtualMemory");
    has_exec  = find_str("CreateRemoteThread") || find_str("NtCreateThreadEx") || find_str("QueueUserAPC");

    if (has_alloc && has_write && has_exec) {
        out = {"classic_injection_triad", ThreatLevel::CRITICAL, ThreatCategory::MEMORY_INJECTION,
               0.95, "Classic injection API triad: alloc+write+execute"};
        return true;
    }
    return false;
}

} // namespace gcad
