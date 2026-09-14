#include "gcad/engines/fileless_ast_engine.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

#ifdef GCAD_PLATFORM_WINDOWS
#include <windows.h>
#endif

namespace gcad {

namespace {

std::string to_lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

} // namespace

FilelessAstEngine::FilelessAstEngine() = default;
FilelessAstEngine::~FilelessAstEngine() {
    stop();
}

ErrorCode FilelessAstEngine::start() {
    running_.store(true);
    return ErrorCode::OK;
}

ErrorCode FilelessAstEngine::stop() {
    running_.store(false);
    return ErrorCode::OK;
}

EngineStatus FilelessAstEngine::status() const {
    EngineStatus st{};
    st.name = name();
    st.running = running_.load();
    st.events_processed = scripts_scanned_.load();
    st.threats_detected = threats_detected_.load();
    return st;
}

void FilelessAstEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    threat_cb_ = std::move(cb);
}

std::string FilelessAstEngine::strip_backticks(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '`' && i + 1 < s.size()) {
            // If next char is alphanumeric, skip the backtick
            if (std::isalnum(static_cast<unsigned char>(s[i + 1]))) {
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

std::string FilelessAstEngine::deobfuscate_char_casts(std::string_view s) {
    std::string out;
    out.reserve(s.size());

    size_t i = 0;
    while (i < s.size()) {
        // Look for [char] or ([char]) pattern
        if (i + 6 < s.size()) {
            std::string_view sub = s.substr(i, 6);
            std::string lower_sub = to_lower_ascii(sub);
            if (lower_sub == "[char]") {
                size_t num_start = i + 6;
                while (num_start < s.size() && (s[num_start] == ' ' || s[num_start] == '(')) {
                    num_start++;
                }
                size_t num_end = num_start;
                bool is_hex = false;
                if (num_end + 2 < s.size() && s[num_end] == '0' &&
                    (s[num_end + 1] == 'x' || s[num_end + 1] == 'X')) {
                    is_hex = true;
                    num_end += 2;
                }
                while (num_end < s.size() &&
                       (is_hex ? std::isxdigit(static_cast<unsigned char>(s[num_end]))
                               : std::isdigit(static_cast<unsigned char>(s[num_end])))) {
                    num_end++;
                }

                if (num_end > num_start) {
                    try {
                        std::string num_str(s.substr(num_start, num_end - num_start));
                        int val = is_hex ? std::stoi(num_str, nullptr, 16)
                                         : std::stoi(num_str, nullptr, 10);
                        if (val >= 32 && val <= 126) {
                            out.push_back(static_cast<char>(val));
                            i = num_end;
                            // skip optional closing paren
                            if (i < s.size() && s[i] == ')') i++;
                            continue;
                        }
                    } catch (...) {}
                }
            }
        }
        out.push_back(s[i++]);
    }
    return out;
}

std::string FilelessAstEngine::deobfuscate_string_concat(std::string_view s) {
    std::string out;
    out.reserve(s.size());

    size_t i = 0;
    while (i < s.size()) {
        char quote = s[i];
        if (quote == '\'' || quote == '"') {
            // Find end of this string
            size_t str1_start = i + 1;
            size_t str1_end = s.find(quote, str1_start);
            if (str1_end != std::string_view::npos) {
                // Check if followed by '+' and another string with quotes
                size_t next_idx = str1_end + 1;
                while (next_idx < s.size() && std::isspace(static_cast<unsigned char>(s[next_idx]))) {
                    next_idx++;
                }
                if (next_idx < s.size() && s[next_idx] == '+') {
                    size_t plus_idx = next_idx + 1;
                    while (plus_idx < s.size() && std::isspace(static_cast<unsigned char>(s[plus_idx]))) {
                        plus_idx++;
                    }
                    if (plus_idx < s.size() && (s[plus_idx] == '\'' || s[plus_idx] == '"')) {
                        char quote2 = s[plus_idx];
                        size_t str2_start = plus_idx + 1;
                        size_t str2_end = s.find(quote2, str2_start);
                        if (str2_end != std::string_view::npos) {
                            // Concatenate both string contents into a single quoted string
                            out.push_back('\'');
                            out.append(s.substr(str1_start, str1_end - str1_start));
                            out.append(s.substr(str2_start, str2_end - str2_start));
                            out.push_back('\'');
                            i = str2_end + 1;
                            continue;
                        }
                    }
                }
            }
        }
        out.push_back(s[i++]);
    }
    return out;
}

std::string FilelessAstEngine::deobfuscate_reverse_patterns(std::string_view s) {
    std::string out(s);
    static const std::vector<std::pair<std::string, std::string>> known_reversals = {
        {"gnirtsdaolnwod", "downloadstring"},
        {"elifdaolnwod",   "downloadfile"},
        {"ataddaolnwod",   "downloaddata"},
        {"noisserpxe-ekovni", "invoke-expression"},
        {"tpeccatrap",     "partaccept"},
        {"xei",            "iex"}
    };

    std::string lower = to_lower_ascii(out);
    for (const auto& [rev, orig] : known_reversals) {
        size_t pos = 0;
        while ((pos = lower.find(rev, pos)) != std::string::npos) {
            out.replace(pos, rev.size(), orig);
            lower.replace(pos, rev.size(), orig);
            pos += orig.size();
        }
    }
    return out;
}

std::string FilelessAstEngine::deobfuscate_powershell(std::string_view script) {
    std::string step1 = strip_backticks(script);
    std::string step2 = deobfuscate_char_casts(step1);
    // Multiple passes of concatenation in case of 'a'+'b'+'c'
    std::string step3 = deobfuscate_string_concat(step2);
    step3 = deobfuscate_string_concat(step3);
    std::string step4 = deobfuscate_reverse_patterns(step3);
    return step4;
}

FilelessEvaluation FilelessAstEngine::evaluate_script(std::string_view script) {
    scripts_scanned_.fetch_add(1);
    FilelessEvaluation eval;
    eval.original_script = std::string(script);
    eval.deobfuscated_script = deobfuscate_powershell(script);

    std::string lower = to_lower_ascii(eval.deobfuscated_script);

    // 1. In-Memory Reflection Assembly Loading (T1059.001)
    if ((lower.find("reflection.assembly") != std::string::npos ||
         lower.find("system.reflection") != std::string::npos) &&
        lower.find("load") != std::string::npos) {
        eval.is_malicious = true;
        eval.mitre_technique = "T1059.001";
        eval.severity = ThreatLevel::CRITICAL;
        eval.reason = "In-memory reflection assembly loading (Assembly::Load)";
        eval.indicators.push_back("Reflection.Assembly::Load");
    }

    // 2. AMSI Bypass Memory Patching (T1562.001)
    if (lower.find("amsiutils") != std::string::npos ||
        lower.find("amsiinitfailed") != std::string::npos ||
        lower.find("amsiscanbuffer") != std::string::npos) {
        eval.is_malicious = true;
        eval.mitre_technique = "T1562.001";
        eval.severity = ThreatLevel::CRITICAL;
        eval.reason = "In-memory AMSI patch bypass tampering";
        eval.indicators.push_back("AmsiUtils tampering");
    }

    // 3. Download Cradle Execution (T1059.001)
    if ((lower.find("downloadstring") != std::string::npos ||
         lower.find("downloadfile") != std::string::npos ||
         lower.find("downloaddata") != std::string::npos) &&
        (lower.find("iex") != std::string::npos ||
         lower.find("invoke-expression") != std::string::npos)) {
        eval.is_malicious = true;
        eval.mitre_technique = "T1059.001";
        eval.severity = ThreatLevel::CRITICAL;
        eval.reason = "Deobfuscated remote download & execute cradle (IEX + DownloadString)";
        eval.indicators.push_back("IEX + WebClient.DownloadString");
    }

    // 4. Compressed In-Memory Payload Deflation (T1027)
    if ((lower.find("deflatestream") != std::string::npos || lower.find("gzipstream") != std::string::npos) &&
        (lower.find("memorystream") != std::string::npos || lower.find("frombase64string") != std::string::npos)) {
        eval.is_malicious = true;
        if (eval.mitre_technique.empty()) eval.mitre_technique = "T1027";
        if (eval.severity < ThreatLevel::HIGH) eval.severity = ThreatLevel::HIGH;
        if (eval.reason.empty()) eval.reason = "Compressed in-memory payload stream decompression";
        eval.indicators.push_back("DeflateStream/GzipStream decompression");
    }

    // 5. Execution Policy Bypass
    if (lower.find("set-executionpolicy") != std::string::npos &&
        (lower.find("bypass") != std::string::npos || lower.find("unrestricted") != std::string::npos)) {
        eval.indicators.push_back("Set-ExecutionPolicy Bypass");
        if (eval.severity < ThreatLevel::MEDIUM) {
            eval.severity = ThreatLevel::MEDIUM;
            eval.reason = "PowerShell execution policy bypass attempt";
        }
    }

    if (eval.is_malicious && running_.load()) {
        dispatch_threat(eval);
    }
    return eval;
}

std::vector<ComHijackRecord> FilelessAstEngine::scan_com_hijacking() {
    std::vector<ComHijackRecord> records;

#ifdef GCAD_PLATFORM_WINDOWS
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\CLSID", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char subkey_name[256];
        DWORD index = 0;
        DWORD name_len = sizeof(subkey_name);

        while (RegEnumKeyExA(hKey, index++, subkey_name, &name_len, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            name_len = sizeof(subkey_name);
            std::string inproc_path = std::string("Software\\Classes\\CLSID\\") + subkey_name + "\\InprocServer32";
            HKEY hInproc = nullptr;

            if (RegOpenKeyExA(HKEY_CURRENT_USER, inproc_path.c_str(), 0, KEY_READ, &hInproc) == ERROR_SUCCESS) {
                char val_buf[512]{};
                DWORD val_size = sizeof(val_buf);
                DWORD type = 0;

                if (RegQueryValueExA(hInproc, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(val_buf), &val_size) == ERROR_SUCCESS) {
                    std::string dll_path(val_buf);
                    std::string lower_path = to_lower_ascii(dll_path);

                    bool suspicious = false;
                    std::string reason;

                    if (lower_path.find("\\temp\\") != std::string::npos ||
                        lower_path.find("\\appdata\\local\\temp\\") != std::string::npos) {
                        suspicious = true;
                        reason = "InprocServer32 points to temporary directory";
                    } else if (lower_path.find("\\users\\") != std::string::npos &&
                               lower_path.find("\\system32\\") == std::string::npos) {
                        suspicious = true;
                        reason = "User-writable path InprocServer32 COM hijack";
                    }

                    if (suspicious) {
                        ComHijackRecord rec;
                        rec.clsid = subkey_name;
                        rec.inproc_server_path = dll_path;
                        rec.is_hijacked = true;
                        rec.reason = reason;
                        records.push_back(std::move(rec));
                    }
                }
                RegCloseKey(hInproc);
            }
        }
        RegCloseKey(hKey);
    }
#endif

    return records;
}

void FilelessAstEngine::dispatch_threat(const FilelessEvaluation& eval) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.id = threats_detected_.load();
        ev.timestamp = std::chrono::system_clock::now();
        ev.level = eval.severity;
        ev.category = ThreatCategory::FILELESS_EXEC;
        ev.process_name = "powershell.exe";
        ev.description = "Fileless Threat [" + eval.mitre_technique + "]: " + eval.reason;
        cb(std::move(ev));
    }
}

} // namespace gcad
