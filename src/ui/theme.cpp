#include "gcad/ui/theme.hpp"
#include "gcad/common.hpp"
#include "imgui.h"

namespace gcad::ui {

void apply_dark_theme() {
    auto& style = ImGui::GetStyle();
    auto* colors = style.Colors;

    style.WindowRounding    = 4.0f;
    style.FrameRounding     = 3.0f;
    style.GrabRounding      = 3.0f;
    style.TabRounding       = 3.0f;
    style.ScrollbarRounding = 3.0f;
    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 0.0f;
    style.WindowPadding     = {10, 10};
    style.FramePadding      = {8, 4};
    style.ItemSpacing       = {8, 6};
    style.ScrollbarSize     = 12.0f;

    auto from_hex = [](unsigned int hex) -> ImVec4 {
        return ImVec4(
            ((hex >> 16) & 0xFF) / 255.0f,
            ((hex >>  8) & 0xFF) / 255.0f,
            ((hex      ) & 0xFF) / 255.0f,
            ((hex >> 24) & 0xFF) / 255.0f
        );
    };

    colors[ImGuiCol_WindowBg]          = from_hex(0xFF0d1117);
    colors[ImGuiCol_ChildBg]           = from_hex(0xFF161b22);
    colors[ImGuiCol_PopupBg]           = from_hex(0xF0161b22);
    colors[ImGuiCol_Border]            = from_hex(0xFF30363d);
    colors[ImGuiCol_BorderShadow]      = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_FrameBg]           = from_hex(0xFF1a1f26);
    colors[ImGuiCol_FrameBgHovered]    = from_hex(0xFF252b33);
    colors[ImGuiCol_FrameBgActive]     = from_hex(0xFF303840);
    colors[ImGuiCol_TitleBg]           = from_hex(0xFF0d1117);
    colors[ImGuiCol_TitleBgActive]     = from_hex(0xFF161b22);
    colors[ImGuiCol_TitleBgCollapsed]  = from_hex(0xFF0d1117);
    colors[ImGuiCol_MenuBarBg]         = from_hex(0xFF161b22);
    colors[ImGuiCol_ScrollbarBg]       = from_hex(0xFF0d1117);
    colors[ImGuiCol_ScrollbarGrab]     = from_hex(0xFF30363d);
    colors[ImGuiCol_ScrollbarGrabHovered] = from_hex(0xFF484f58);
    colors[ImGuiCol_ScrollbarGrabActive]  = from_hex(0xFF6e7681);
    colors[ImGuiCol_CheckMark]         = from_hex(0xFF39d353);
    colors[ImGuiCol_SliderGrab]        = from_hex(0xFF39d353);
    colors[ImGuiCol_SliderGrabActive]  = from_hex(0xFF2ea043);
    colors[ImGuiCol_Button]            = from_hex(0xFF21262d);
    colors[ImGuiCol_ButtonHovered]     = from_hex(0xFF30363d);
    colors[ImGuiCol_ButtonActive]      = from_hex(0xFF484f58);
    colors[ImGuiCol_Header]            = from_hex(0xFF161b22);
    colors[ImGuiCol_HeaderHovered]     = from_hex(0xFF1f242c);
    colors[ImGuiCol_HeaderActive]      = from_hex(0xFF252b33);
    colors[ImGuiCol_Separator]         = from_hex(0xFF30363d);
    colors[ImGuiCol_Tab]               = from_hex(0xFF0d1117);
    colors[ImGuiCol_TabHovered]        = from_hex(0xFF1f242c);
    colors[ImGuiCol_TabSelected]       = from_hex(0xFF161b22);
    colors[ImGuiCol_Text]              = from_hex(0xFFe6edf3);
    colors[ImGuiCol_TextDisabled]      = from_hex(0xFF484f58);
    colors[ImGuiCol_PlotLines]         = from_hex(0xFF58a6ff);
    colors[ImGuiCol_PlotLinesHovered]  = from_hex(0xFF79c0ff);
    colors[ImGuiCol_PlotHistogram]     = from_hex(0xFF39d353);
    colors[ImGuiCol_PlotHistogramHovered] = from_hex(0xFF2ea043);
    colors[ImGuiCol_TableHeaderBg]     = from_hex(0xFF161b22);
    colors[ImGuiCol_TableBorderStrong] = from_hex(0xFF30363d);
    colors[ImGuiCol_TableBorderLight]  = from_hex(0xFF21262d);
    colors[ImGuiCol_TableRowBg]        = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_TableRowBgAlt]     = from_hex(0x08FFFFFF);
}

unsigned int threat_level_color(uint8_t level) {
    switch (level) {
        case 0: return 0xFF39d353;
        case 1: return 0xFF58a6ff;
        case 2: return 0xFFd29922;
        case 3: return 0xFFf0883e;
        case 4: return 0xFFf85149;
        default: return 0xFFe6edf3;
    }
}

const char* threat_level_label(uint8_t level) {
    switch (level) {
        case 0: return "SAFE";
        case 1: return "LOW";
        case 2: return "MEDIUM";
        case 3: return "HIGH";
        case 4: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char* threat_category_label(uint16_t category) {
    switch (static_cast<ThreatCategory>(category)) {
        case ThreatCategory::NONE:              return "None";
        case ThreatCategory::MEMORY_INJECTION:  return "Memory Injection";
        case ThreatCategory::PROCESS_HOLLOW:    return "Process Hollowing";
        case ThreatCategory::DLL_INJECTION:     return "DLL Injection";
        case ThreatCategory::APC_INJECTION:     return "APC Injection";
        case ThreatCategory::REFLECTIVE_LOAD:   return "Reflective Load";
        case ThreatCategory::SHELLCODE:         return "Shellcode";
        case ThreatCategory::NETWORK_SCAN:      return "Network Scan";
        case ThreatCategory::SYN_FLOOD:         return "SYN Flood";
        case ThreatCategory::UDP_FLOOD:         return "UDP Flood";
        case ThreatCategory::DNS_TUNNEL:        return "DNS Tunnel";
        case ThreatCategory::ARP_POISON:        return "ARP Poisoning";
        case ThreatCategory::ICMP_COVERT:       return "ICMP Covert Channel";
        case ThreatCategory::RAW_SOCKET_PROBE:  return "Raw Socket Probe";
        case ThreatCategory::RANSOMWARE:        return "Ransomware";
        case ThreatCategory::FILE_ENCRYPT:      return "Bulk File Encryption";
        case ThreatCategory::REGISTRY_TAMPER:   return "Registry Tampering";
        case ThreatCategory::BACKDOOR_ACCOUNT:  return "Backdoor Account";
        case ThreatCategory::EVASION_AMSI:      return "AMSI Bypass";
        case ThreatCategory::EVASION_ETW:       return "ETW Bypass";
        case ThreatCategory::EVASION_UNHOOK:    return "NTDLL Unhooking";
        case ThreatCategory::DIRECT_SYSCALL:    return "Direct Syscall";
        case ThreatCategory::PPID_SPOOF:        return "PPID Spoofing";
        case ThreatCategory::KERBEROS_ATTACK:   return "Kerberos Attack";
        case ThreatCategory::NTLM_COERCE:       return "NTLM Coercion";
        case ThreatCategory::CREDENTIAL_DUMP:   return "Credential Dump";
        case ThreatCategory::ENTROPY_ANOMALY:   return "Entropy Anomaly";
        case ThreatCategory::SUSPICIOUS_BINARY: return "Suspicious Binary";
        case ThreatCategory::FILELESS_EXEC:     return "Fileless Execution";
        case ThreatCategory::ANTI_FORENSIC:     return "Anti-Forensics";
        default:                                return "Other";
    }
}

void push_threat_color(uint8_t level) {
    auto c = threat_level_color(level);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(c));
}

void pop_threat_color() {
    ImGui::PopStyleColor();
}

} // namespace gcad::ui
