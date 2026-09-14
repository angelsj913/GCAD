#include "gcad/engines/lolbins_engine.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

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

std::string get_filename_only(std::string_view path) {
    size_t last_slash = path.find_last_of("/\\");
    if (last_slash != std::string_view::npos) {
        return std::string(path.substr(last_slash + 1));
    }
    return std::string(path);
}

} // namespace

LolbinsEngine::LolbinsEngine() = default;
LolbinsEngine::~LolbinsEngine() {
    stop();
}

ErrorCode LolbinsEngine::start() {
    running_.store(true);
    return ErrorCode::OK;
}

ErrorCode LolbinsEngine::stop() {
    running_.store(false);
    return ErrorCode::OK;
}

EngineStatus LolbinsEngine::status() const {
    EngineStatus st{};
    st.name = name();
    st.running = running_.load();
    st.events_processed = evaluations_count_.load();
    st.threats_detected = threats_detected_.load();
    return st;
}

void LolbinsEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    threat_cb_ = std::move(cb);
}

std::string LolbinsEngine::normalize_command_line(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());

    bool in_quotes = false;
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        // Strip caret (cmd.exe escape character)
        if (c == '^') {
            continue;
        }
        // Handle double quotes
        if (c == '"') {
            in_quotes = !in_quotes;
            // If quote is inside a word (e.g. c"e"rtutil), skip quote character
            if (i > 0 && i + 1 < raw.size() && std::isalnum(static_cast<unsigned char>(raw[i - 1])) &&
                std::isalnum(static_cast<unsigned char>(raw[i + 1]))) {
                continue;
            }
        }
        out.push_back(c);
    }

    // Collapse multiple whitespace
    std::string collapsed;
    collapsed.reserve(out.size());
    bool last_space = false;
    for (char c : out) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!last_space) {
                collapsed.push_back(' ');
                last_space = true;
            }
        } else {
            collapsed.push_back(c);
            last_space = false;
        }
    }
    return collapsed;
}

std::optional<std::string> LolbinsEngine::decode_base64(std::string_view b64) {
    if (b64.empty()) return std::nullopt;

    static const int b64_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1, // '=' is treated as 0 for padding
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::vector<uint8_t> raw_bytes;
    raw_bytes.reserve(b64.size() * 3 / 4);

    uint32_t val = 0;
    int bits = -8;
    for (unsigned char c : b64) {
        if (c == '=') break;
        int d = b64_table[c];
        if (d == -1) continue; // Skip non-base64 chars (like newlines or spaces)
        val = (val << 6) | static_cast<uint32_t>(d);
        bits += 6;
        if (bits >= 0) {
            raw_bytes.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }

    if (raw_bytes.empty()) return std::nullopt;

    // Check if UTF-16LE (PowerShell default)
    bool is_utf16le = false;
    if (raw_bytes.size() >= 4 && raw_bytes[1] == 0 && raw_bytes[3] == 0) {
        is_utf16le = true;
    }

    std::string result;
    if (is_utf16le) {
        result.reserve(raw_bytes.size() / 2);
        for (size_t i = 0; i + 1 < raw_bytes.size(); i += 2) {
            uint16_t w = static_cast<uint16_t>(raw_bytes[i]) |
                         (static_cast<uint16_t>(raw_bytes[i + 1]) << 8);
            if (w >= 32 && w <= 126) {
                result.push_back(static_cast<char>(w));
            } else if (w == '\n' || w == '\r' || w == '\t') {
                result.push_back(static_cast<char>(w));
            }
        }
    } else {
        result.assign(reinterpret_cast<const char*>(raw_bytes.data()), raw_bytes.size());
    }
    return result;
}

std::optional<std::string> LolbinsEngine::extract_and_decode_encoded_command(std::string_view cmdline) {
    std::string lower = to_lower_ascii(cmdline);
    static const std::vector<std::string> enc_flags = {
        "-encodedcommand ", "/encodedcommand ",
        "-encoded ", "/encoded ",
        "-enc ", "/enc ",
        "-e "
    };

    for (const auto& flag : enc_flags) {
        size_t pos = lower.find(flag);
        if (pos != std::string::npos) {
            size_t start = pos + flag.size();
            while (start < cmdline.size() && std::isspace(static_cast<unsigned char>(cmdline[start]))) {
                start++;
            }
            // Find end of token
            size_t end = start;
            while (end < cmdline.size() && !std::isspace(static_cast<unsigned char>(cmdline[end])) && cmdline[end] != '"') {
                end++;
            }
            if (end > start) {
                std::string_view token = cmdline.substr(start, end - start);
                return decode_base64(token);
            }
        }
    }
    return std::nullopt;
}

LolbinExecution LolbinsEngine::evaluate_command_line(uint32_t pid,
                                                    std::string_view binary_name,
                                                    std::string_view cmdline) {
    evaluations_count_.fetch_add(1);
    LolbinExecution exec;
    exec.pid = pid;
    exec.binary_name = get_filename_only(binary_name);
    exec.command_line = std::string(cmdline);
    exec.normalized_command_line = normalize_command_line(cmdline);

    std::string bin_lower = to_lower_ascii(exec.binary_name);
    std::string cmd_lower = to_lower_ascii(exec.normalized_command_line);

    // 1. certutil.exe
    if (bin_lower.find("certutil") != std::string::npos) {
        if (cmd_lower.find("-urlcache") != std::string::npos || cmd_lower.find("/urlcache") != std::string::npos) {
            exec.is_malicious = true;
            exec.mitre_technique = "T1105";
            exec.severity = ThreatLevel::HIGH;
            exec.reason = "certutil.exe -urlcache file download abuse";
        } else if (cmd_lower.find("-decode") != std::string::npos || cmd_lower.find("/decode") != std::string::npos ||
                   cmd_lower.find("-decodehex") != std::string::npos) {
            exec.is_malicious = true;
            exec.mitre_technique = "T1140";
            exec.severity = ThreatLevel::HIGH;
            exec.reason = "certutil.exe payload deobfuscation/decoding abuse";
        }
    }
    // 2. mshta.exe
    else if (bin_lower.find("mshta") != std::string::npos) {
        if (cmd_lower.find("javascript:") != std::string::npos ||
            cmd_lower.find("vbscript:") != std::string::npos ||
            cmd_lower.find("about:") != std::string::npos ||
            cmd_lower.find("http://") != std::string::npos ||
            cmd_lower.find("https://") != std::string::npos) {
            exec.is_malicious = true;
            exec.mitre_technique = "T1218.005";
            exec.severity = ThreatLevel::CRITICAL;
            exec.reason = "mshta.exe inline or remote script execution";
        }
    }
    // 3. regsvr32.exe
    else if (bin_lower.find("regsvr32") != std::string::npos) {
        if ((cmd_lower.find("/i:http:") != std::string::npos || cmd_lower.find("/i:https:") != std::string::npos ||
             cmd_lower.find("scrobj.dll") != std::string::npos) &&
            (cmd_lower.find("/s") != std::string::npos || cmd_lower.find("-s") != std::string::npos)) {
            exec.is_malicious = true;
            exec.mitre_technique = "T1218.010";
            exec.severity = ThreatLevel::CRITICAL;
            exec.reason = "regsvr32.exe Squiblydoo remote scriptlet execution";
        }
    }
    // 4. rundll32.exe
    else if (bin_lower.find("rundll32") != std::string::npos) {
        if (cmd_lower.find("javascript:") != std::string::npos ||
            cmd_lower.find("shell32.dll,control_rundll") != std::string::npos ||
            cmd_lower.find("\\temp\\") != std::string::npos ||
            cmd_lower.find("\\appdata\\") != std::string::npos) {
            exec.is_malicious = true;
            exec.mitre_technique = "T1218.011";
            exec.severity = ThreatLevel::HIGH;
            exec.reason = "rundll32.exe suspicious DLL path or inline script execution";
        }
    }
    // 5. wmic.exe
    else if (bin_lower.find("wmic") != std::string::npos) {
        if (cmd_lower.find("process call create") != std::string::npos ||
            cmd_lower.find("/node:") != std::string::npos) {
            exec.is_malicious = true;
            exec.mitre_technique = "T1047";
            exec.severity = ThreatLevel::HIGH;
            exec.reason = "wmic.exe process call create or remote node execution";
        }
    }
    // 6. bitsadmin.exe
    else if (bin_lower.find("bitsadmin") != std::string::npos) {
        if ((cmd_lower.find("/transfer") != std::string::npos || cmd_lower.find("/create") != std::string::npos) &&
            (cmd_lower.find("http://") != std::string::npos || cmd_lower.find("https://") != std::string::npos)) {
            exec.is_malicious = true;
            exec.mitre_technique = "T1197";
            exec.severity = ThreatLevel::HIGH;
            exec.reason = "bitsadmin.exe remote file transfer abuse";
        }
    }
    // 7. powershell.exe / pwsh.exe
    else if (bin_lower.find("powershell") != std::string::npos || bin_lower.find("pwsh") != std::string::npos) {
        auto decoded = extract_and_decode_encoded_command(exec.normalized_command_line);
        if (decoded.has_value()) {
            exec.decoded_payload = *decoded;
            std::string dec_lower = to_lower_ascii(*decoded);
            if (dec_lower.find("iex") != std::string::npos ||
                dec_lower.find("invoke-expression") != std::string::npos ||
                dec_lower.find("downloadstring") != std::string::npos ||
                dec_lower.find("downloadfile") != std::string::npos ||
                dec_lower.find("webclient") != std::string::npos ||
                dec_lower.find("start-process") != std::string::npos ||
                dec_lower.find("reflection.assembly") != std::string::npos) {
                exec.is_malicious = true;
                exec.mitre_technique = "T1059.001";
                exec.severity = ThreatLevel::CRITICAL;
                exec.reason = "PowerShell encoded download cradle / reflective loader execution";
            }
        } else {
            // Check direct unencoded cradle
            if (cmd_lower.find("downloadstring") != std::string::npos ||
                cmd_lower.find("downloadfile") != std::string::npos ||
                cmd_lower.find("invoke-webrequest") != std::string::npos) {
                if (cmd_lower.find("iex") != std::string::npos || cmd_lower.find("invoke-expression") != std::string::npos) {
                    exec.is_malicious = true;
                    exec.mitre_technique = "T1059.001";
                    exec.severity = ThreatLevel::CRITICAL;
                    exec.reason = "PowerShell direct WebClient download cradle";
                }
            }
        }
    }

    if (exec.is_malicious && running_.load()) {
        dispatch_threat(exec);
    }
    return exec;
}

bool LolbinsEngine::inspect_lnk_file(const std::filesystem::path& lnk_path, LolbinExecution& out_exec) {
    std::ifstream ifs(lnk_path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) return false;
    auto fsize = ifs.tellg();
    if (fsize < 76 || fsize > 10 * 1024 * 1024) return false; // LNK header is 76 bytes

    std::vector<uint8_t> buf(static_cast<size_t>(fsize));
    ifs.seekg(0, std::ios::beg);
    ifs.read(reinterpret_cast<char*>(buf.data()), fsize);

    // Extract ASCII and UTF-16 printable strings from LNK file
    std::string extracted_text;
    extracted_text.reserve(buf.size());

    for (size_t i = 0; i < buf.size(); ++i) {
        char c = static_cast<char>(buf[i]);
        if (c >= 32 && c <= 126) {
            extracted_text.push_back(c);
        } else if (c == 0) {
            // Null byte in UTF-16
            continue;
        } else {
            extracted_text.push_back(' ');
        }
    }

    std::string lower = to_lower_ascii(extracted_text);
    static const std::vector<std::pair<std::string, std::string>> suspicious_bins = {
        {"powershell", "powershell.exe"},
        {"cmd.exe", "cmd.exe"},
        {"mshta", "mshta.exe"},
        {"certutil", "certutil.exe"},
        {"cscript", "cscript.exe"},
        {"wscript", "wscript.exe"}
    };

    for (const auto& [needle, bin_name] : suspicious_bins) {
        size_t pos = lower.find(needle);
        if (pos != std::string::npos) {
            // Extract trailing command line arguments around this match
            size_t end = std::min(pos + 512, extracted_text.size());
            std::string sub_cmd = extracted_text.substr(pos, end - pos);
            out_exec = evaluate_command_line(0, bin_name, sub_cmd);
            if (out_exec.is_malicious) {
                out_exec.reason = "Weaponized LNK shortcut: " + out_exec.reason;
                return true;
            }
        }
    }
    return false;
}

void LolbinsEngine::dispatch_threat(const LolbinExecution& exec) {
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
        ev.level = exec.severity;
        ev.category = ThreatCategory::SUSPICIOUS_BINARY;
        ev.process_id = exec.pid;
        ev.process_name = exec.binary_name;
        ev.description = "LOLBin Execution [" + exec.mitre_technique + "]: " + exec.reason +
                         " (Cmd: " + exec.normalized_command_line + ")";
        cb(std::move(ev));
    }
}

} // namespace gcad
