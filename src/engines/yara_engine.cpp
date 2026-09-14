#include "gcad/engines/yara_engine.hpp"

#include <algorithm>
#include <array>

namespace gcad {

YaraEngine::YaraEngine() = default;
YaraEngine::~YaraEngine() { stop(); }

void YaraEngine::add_rule(YaraRule rule) {
    std::lock_guard lk(mtx_);
    rules_.push_back(std::move(rule));
}

size_t YaraEngine::rule_count() const {
    std::lock_guard lk(mtx_);
    return rules_.size();
}

void YaraEngine::clear_rules() {
    std::lock_guard lk(mtx_);
    rules_.clear();
}

bool YaraEngine::add_rule_from_string(const std::string& rule_text) {
    std::istringstream stream(rule_text);
    std::string line;
    YaraRule current_rule;
    bool in_rule = false;
    bool added_any = false;

    while (std::getline(stream, line)) {
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        auto end = line.find_last_not_of(" \t\r\n");
        std::string trimmed = line.substr(start, end - start + 1);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed.starts_with("//")) continue;

        if (trimmed.starts_with("rule ") || trimmed.starts_with("rule:")) {
            if (in_rule && !current_rule.strings.empty()) {
                add_rule(std::move(current_rule));
                added_any = true;
                current_rule = YaraRule{};
            }
            in_rule = true;
            size_t name_start = trimmed.find_first_of(" \t:", 4);
            name_start = trimmed.find_first_not_of(" \t:{", name_start);
            if (name_start != std::string::npos) {
                size_t name_end = trimmed.find_first_of(" \t:{", name_start);
                current_rule.name = trimmed.substr(name_start, name_end == std::string::npos ? std::string::npos : name_end - name_start);
            }
            if (current_rule.name.empty()) current_rule.name = "CustomRule_" + std::to_string(rule_count() + 1);
            continue;
        }

        if (!in_rule) continue;

        if (trimmed.find("CRITICAL") != std::string::npos) current_rule.threat_level = ThreatLevel::CRITICAL;
        else if (trimmed.find("HIGH") != std::string::npos) current_rule.threat_level = ThreatLevel::HIGH;
        else if (trimmed.find("MEDIUM") != std::string::npos) current_rule.threat_level = ThreatLevel::MEDIUM;

        if (trimmed[0] == '$') {
            size_t eq_pos = trimmed.find('=');
            if (eq_pos != std::string::npos) {
                std::string id = trimmed.substr(0, trimmed.find_first_of(" \t=", 0));
                std::string rest = trimmed.substr(eq_pos + 1);
                auto quote_start = rest.find('"');
                auto hex_start = rest.find('{');

                if (quote_start != std::string::npos) {
                    auto quote_end = rest.rfind('"');
                    if (quote_end != std::string::npos && quote_end > quote_start) {
                        std::string literal = rest.substr(quote_start + 1, quote_end - quote_start - 1);
                        bool nocase = rest.find("nocase", quote_end) != std::string::npos;
                        bool wide = rest.find("wide", quote_end) != std::string::npos;

                        YaraString ys;
                        ys.identifier = id;
                        ys.pattern = text_to_pattern(literal, wide);
                        ys.mask = std::vector<uint8_t>(ys.pattern.size(), 0xFF);
                        ys.nocase = nocase;
                        ys.wide = wide;
                        ys.ascii = !wide;
                        current_rule.strings.push_back(std::move(ys));
                    }
                } else if (hex_start != std::string::npos) {
                    auto hex_end = rest.rfind('}');
                    if (hex_end != std::string::npos && hex_end > hex_start) {
                        std::string hex_content = rest.substr(hex_start + 1, hex_end - hex_start - 1);
                        std::vector<uint8_t> pat, msk;
                        if (parse_hex_pattern(hex_content, pat, msk)) {
                            YaraString ys;
                            ys.identifier = id;
                            ys.pattern = std::move(pat);
                            ys.mask = std::move(msk);
                            ys.is_hex = true;
                            current_rule.strings.push_back(std::move(ys));
                        }
                    }
                }
            }
        }

        if (trimmed.find("all of them") != std::string::npos) {
            current_rule.condition = YaraRule::ConditionOp::ALL_OF_THEM;
        } else if (trimmed.find("any of them") != std::string::npos) {
            current_rule.condition = YaraRule::ConditionOp::ANY_OF_THEM;
        }
    }

    if (in_rule && !current_rule.strings.empty()) {
        add_rule(std::move(current_rule));
        return true;
    }
    return added_any;
}

size_t YaraEngine::load_rules_from_directory(const std::filesystem::path& dir_path) {
    std::error_code ec;
    if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) return 0;

    size_t loaded = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const auto ext = entry.path().extension().string();
        if (ext == ".yar" || ext == ".yara" || ext == ".txt") {
            std::ifstream file(entry.path());
            if (!file) continue;
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (add_rule_from_string(content)) ++loaded;
        }
    }
    return loaded;
}

size_t YaraEngine::reload_rules(const std::filesystem::path& dir_path) {
    clear_rules();
    load_builtin_rules();
    if (!dir_path.empty()) {
        load_rules_from_directory(dir_path);
    }
    return rule_count();
}

bool YaraEngine::parse_hex_pattern(const std::string& hex_str,
                                    std::vector<uint8_t>& out_pattern,
                                    std::vector<uint8_t>& out_mask) {
    out_pattern.clear();
    out_mask.clear();

    size_t i = 0;
    while (i < hex_str.size()) {
        char c = hex_str[i];
        if (c == ' ' || c == '{' || c == '}') { ++i; continue; }

        if (c == '?') {
            if (i + 1 < hex_str.size() && hex_str[i + 1] == '?') {
                out_pattern.push_back(0x00);
                out_mask.push_back(0x00);
                i += 2;
            } else {
                out_pattern.push_back(0x00);
                out_mask.push_back(0x00);
                ++i;
            }
            continue;
        }

        if (i + 1 >= hex_str.size()) return false;
        char hi = c;
        char lo = hex_str[i + 1];

        auto hex_val = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };

        int h = hex_val(hi);
        int l = hex_val(lo);
        if (h < 0 || l < 0) return false;

        out_pattern.push_back(static_cast<uint8_t>((h << 4) | l));
        out_mask.push_back(0xFF);
        i += 2;
    }

    return !out_pattern.empty();
}

std::vector<uint8_t> YaraEngine::text_to_pattern(const std::string& text, bool wide) {
    std::vector<uint8_t> result;
    if (wide) {
        result.reserve(text.size() * 2);
        for (char c : text) {
            result.push_back(static_cast<uint8_t>(c));
            result.push_back(0x00);
        }
    } else {
        result.assign(text.begin(), text.end());
    }
    return result;
}

std::vector<size_t> YaraEngine::find_pattern(const uint8_t* data, size_t data_len,
                                              const YaraString& str) const {
    std::vector<size_t> offsets;
    if (str.pattern.empty() || data_len < str.pattern.size()) return offsets;

    const size_t pat_len = str.pattern.size();
    const size_t last_pos = data_len - pat_len;
    const bool has_wildcards = std::any_of(str.mask.begin(), str.mask.end(),
        [](uint8_t m) { return m != 0xFF; });

    // Boyer-Moore-Horspool for patterns >= 4 bytes without wildcards
    if (pat_len >= 4 && !has_wildcards) {
        std::array<size_t, 256> shift;
        shift.fill(pat_len);
        for (size_t j = 0; j < pat_len - 1; ++j) {
            uint8_t p = str.pattern[j];
            if (str.nocase && !str.is_hex) {
                uint8_t lo = (p >= 'A' && p <= 'Z') ? static_cast<uint8_t>(p - 'A' + 'a') : p;
                uint8_t hi = (p >= 'a' && p <= 'z') ? static_cast<uint8_t>(p - 'a' + 'A') : p;
                shift[lo] = pat_len - 1 - j;
                shift[hi] = pat_len - 1 - j;
            } else {
                shift[p] = pat_len - 1 - j;
            }
        }

        size_t i = 0;
        while (i <= last_pos) {
            bool match = true;
            for (size_t j = pat_len; j-- > 0; ) {
                uint8_t d = data[i + j];
                uint8_t p = str.pattern[j];
                if (str.nocase && !str.is_hex) {
                    if (d >= 'A' && d <= 'Z') d = static_cast<uint8_t>(d - 'A' + 'a');
                    if (p >= 'A' && p <= 'Z') p = static_cast<uint8_t>(p - 'A' + 'a');
                }
                if (d != p) { match = false; break; }
            }
            if (match) {
                offsets.push_back(i);
                ++i;
            } else {
                uint8_t last = data[i + pat_len - 1];
                if (str.nocase && !str.is_hex && last >= 'A' && last <= 'Z')
                    last = static_cast<uint8_t>(last - 'A' + 'a');
                i += shift[last];
            }
        }
    } else {
        for (size_t i = 0; i <= last_pos; ++i) {
            bool match = true;
            for (size_t j = 0; j < pat_len; ++j) {
                uint8_t d = data[i + j];
                uint8_t p = str.pattern[j];
                uint8_t m = (j < str.mask.size()) ? str.mask[j] : 0xFF;
                if (str.nocase && m == 0xFF && !str.is_hex) {
                    if (d >= 'A' && d <= 'Z') d = static_cast<uint8_t>(d - 'A' + 'a');
                    if (p >= 'A' && p <= 'Z') p = static_cast<uint8_t>(p - 'A' + 'a');
                }
                if ((d & m) != (p & m)) { match = false; break; }
            }
            if (match) offsets.push_back(i);
        }
    }

    return offsets;
}

bool YaraEngine::evaluate_condition(const YaraRule& rule,
                                     const std::unordered_map<std::string, std::vector<size_t>>& matches) const {
    switch (rule.condition) {
        case YaraRule::ConditionOp::ALL_OF_THEM: {
            for (auto& s : rule.strings) {
                auto it = matches.find(s.identifier);
                if (it == matches.end() || it->second.empty()) return false;
            }
            return true;
        }
        case YaraRule::ConditionOp::ANY_OF_THEM: {
            for (auto& s : rule.strings) {
                auto it = matches.find(s.identifier);
                if (it != matches.end() && !it->second.empty()) return true;
            }
            return false;
        }
        case YaraRule::ConditionOp::COUNT_GE: {
            size_t count = 0;
            for (auto& s : rule.strings) {
                auto it = matches.find(s.identifier);
                if (it != matches.end() && !it->second.empty()) ++count;
            }
            return count >= rule.condition_count;
        }
    }
    return false;
}

std::vector<YaraMatch> YaraEngine::scan_buffer(const uint8_t* data, size_t len) const {
    std::vector<YaraMatch> results;
    std::lock_guard lk(mtx_);

    for (auto& rule : rules_) {
        std::unordered_map<std::string, std::vector<size_t>> string_matches;
        for (auto& s : rule.strings) {
            auto offsets = find_pattern(data, len, s);
            if (!offsets.empty()) string_matches[s.identifier] = std::move(offsets);
        }

        if (evaluate_condition(rule, string_matches)) {
            for (auto& [id, offs] : string_matches) {
                for (size_t off : offs) {
                    auto& s = *std::find_if(rule.strings.begin(), rule.strings.end(),
                        [&](const YaraString& ys) { return ys.identifier == id; });
                    results.push_back({rule.name, id, off, s.pattern.size()});
                }
            }
        }
    }

    return results;
}

std::vector<YaraMatch> YaraEngine::scan_file(const std::filesystem::path& path) const {
    std::error_code ec;
    auto fsize = std::filesystem::file_size(path, ec);
    if (ec || fsize == 0 || fsize > 64 * 1024 * 1024) return {};

    std::ifstream f(path, std::ios::binary);
    if (!f) return {};

    std::vector<uint8_t> buf(static_cast<size_t>(fsize));
    f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(fsize));
    if (!f) return {};

    return scan_buffer(buf.data(), buf.size());
}

void YaraEngine::load_builtin_rules() {
    {
        YaraRule r;
        r.name = "GCAD_MZ_Header";
        r.description = "Detects PE executables";
        r.tags = {"pe", "executable"};
        YaraString s;
        s.identifier = "$mz";
        s.pattern = {0x4D, 0x5A};
        s.mask = {0xFF, 0xFF};
        s.is_hex = true;
        r.strings.push_back(std::move(s));
        r.condition = YaraRule::ConditionOp::ANY_OF_THEM;
        r.threat_level = ThreatLevel::LOW;
        add_rule(std::move(r));
    }

    {
        YaraRule r;
        r.name = "GCAD_Suspicious_PowerShell";
        r.description = "Detects obfuscated PowerShell patterns";
        r.tags = {"powershell", "obfuscation"};

        YaraString s1;
        s1.identifier = "$enc_cmd";
        s1.pattern = text_to_pattern("-EncodedCommand", false);
        s1.nocase = true;
        r.strings.push_back(std::move(s1));

        YaraString s2;
        s2.identifier = "$bypass";
        s2.pattern = text_to_pattern("-ExecutionPolicy Bypass", false);
        s2.nocase = true;
        r.strings.push_back(std::move(s2));

        YaraString s3;
        s3.identifier = "$hidden";
        s3.pattern = text_to_pattern("-WindowStyle Hidden", false);
        s3.nocase = true;
        r.strings.push_back(std::move(s3));

        YaraString s4;
        s4.identifier = "$iex";
        s4.pattern = text_to_pattern("IEX(New-Object", false);
        s4.nocase = true;
        r.strings.push_back(std::move(s4));

        r.condition = YaraRule::ConditionOp::COUNT_GE;
        r.condition_count = 2;
        r.threat_level = ThreatLevel::HIGH;
        add_rule(std::move(r));
    }

    {
        YaraRule r;
        r.name = "GCAD_Cobalt_Strike_Beacon";
        r.description = "Detects Cobalt Strike beacon patterns";
        r.tags = {"apt", "c2", "cobalt_strike"};

        YaraString s1;
        s1.identifier = "$pipe";
        s1.pattern = text_to_pattern("\\\\.\\pipe\\msagent_", false);
        r.strings.push_back(std::move(s1));

        YaraString s2;
        s2.identifier = "$config";
        parse_hex_pattern("00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ??", s2.pattern, s2.mask);
        s2.is_hex = true;
        s2.identifier = "$config";
        r.strings.push_back(std::move(s2));

        YaraString s3;
        s3.identifier = "$sleep_mask";
        s3.pattern = text_to_pattern("beacon.dll", false);
        r.strings.push_back(std::move(s3));

        r.condition = YaraRule::ConditionOp::COUNT_GE;
        r.condition_count = 2;
        r.threat_level = ThreatLevel::CRITICAL;
        add_rule(std::move(r));
    }

    {
        YaraRule r;
        r.name = "GCAD_Mimikatz_Strings";
        r.description = "Detects Mimikatz credential dumper";
        r.tags = {"credential", "mimikatz"};

        YaraString s1;
        s1.identifier = "$sekurlsa";
        s1.pattern = text_to_pattern("sekurlsa::logonpasswords", false);
        s1.nocase = true;
        r.strings.push_back(std::move(s1));

        YaraString s2;
        s2.identifier = "$gentilkiwi";
        s2.pattern = text_to_pattern("gentilkiwi", false);
        r.strings.push_back(std::move(s2));

        YaraString s3;
        s3.identifier = "$lsadump";
        s3.pattern = text_to_pattern("lsadump::sam", false);
        s3.nocase = true;
        r.strings.push_back(std::move(s3));

        r.condition = YaraRule::ConditionOp::ANY_OF_THEM;
        r.threat_level = ThreatLevel::CRITICAL;
        add_rule(std::move(r));
    }

    {
        YaraRule r;
        r.name = "GCAD_Ransomware_Note";
        r.description = "Detects common ransomware note patterns";
        r.tags = {"ransomware", "ransom_note"};

        YaraString s1;
        s1.identifier = "$encrypted";
        s1.pattern = text_to_pattern("Your files have been encrypted", false);
        s1.nocase = true;
        r.strings.push_back(std::move(s1));

        YaraString s2;
        s2.identifier = "$bitcoin";
        s2.pattern = text_to_pattern("bitcoin wallet", false);
        s2.nocase = true;
        r.strings.push_back(std::move(s2));

        YaraString s3;
        s3.identifier = "$decrypt_tool";
        s3.pattern = text_to_pattern("decryption tool", false);
        s3.nocase = true;
        r.strings.push_back(std::move(s3));

        YaraString s4;
        s4.identifier = "$pay_ransom";
        s4.pattern = text_to_pattern("pay the ransom", false);
        s4.nocase = true;
        r.strings.push_back(std::move(s4));

        r.condition = YaraRule::ConditionOp::COUNT_GE;
        r.condition_count = 2;
        r.threat_level = ThreatLevel::CRITICAL;
        add_rule(std::move(r));
    }

    {
        YaraRule r;
        r.name = "GCAD_Shellcode_NOP_Sled";
        r.description = "Detects NOP sled patterns common in shellcode";
        r.tags = {"shellcode", "exploit"};

        YaraString s1;
        s1.identifier = "$nop_sled";
        s1.pattern = std::vector<uint8_t>(16, 0x90);
        s1.mask = std::vector<uint8_t>(16, 0xFF);
        s1.is_hex = true;
        r.strings.push_back(std::move(s1));

        r.condition = YaraRule::ConditionOp::ANY_OF_THEM;
        r.threat_level = ThreatLevel::HIGH;
        add_rule(std::move(r));
    }
}

ErrorCode YaraEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    if (rules_.empty()) load_builtin_rules();
    running_.store(true);
    scan_thread_ = std::thread(&YaraEngine::scan_loop, this);
    GCAD_LOG(INFO, "YARA engine started, rules: " + std::to_string(rule_count()));
    return ErrorCode::OK;
}

ErrorCode YaraEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (scan_thread_.joinable()) scan_thread_.join();
    return ErrorCode::OK;
}

EngineStatus YaraEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void YaraEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void YaraEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

void YaraEngine::scan_loop() {
    while (running_.load()) {
        for (int i = 0; i < 100 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void YaraEngine::emit_threat(const std::string& rule_name, const std::string& file_path,
                              const std::string& evidence) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::HIGH;
        ev.category = ThreatCategory::YARA_RULE_MATCH;
        ev.description = "YARA rule matched: " + rule_name + " — " + evidence;
        ev.file_path = file_path;
        cb(std::move(ev));
    }
}

void YaraEngine::emit_observation(const std::string& rule_name, const std::string& file_path,
                                   double confidence, const std::string& evidence) {
    std::function<void(security::SecurityObservation)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = observation_cb_;
    }
    if (cb) {
        security::SecurityObservation obs{};
        obs.source_id = "yara";
        obs.kind = security::ObservationKind::YARA_MATCH;
        obs.timestamp = std::chrono::system_clock::now();
        obs.suggested_level = ThreatLevel::HIGH;
        obs.confidence = confidence;
        obs.deterministic = true;
        obs.file_path = file_path;
        obs.evidence = "YARA:" + rule_name + " " + evidence;
        cb(std::move(obs));
    }
}

} // namespace gcad
