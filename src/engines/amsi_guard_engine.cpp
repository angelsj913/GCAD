#include "gcad/engines/amsi_guard_engine.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>

#ifdef GCAD_PLATFORM_WINDOWS
#include <windows.h>
#endif

namespace gcad {

namespace {

std::string to_lower_string(std::string_view sv) {
    std::string s;
    s.reserve(sv.size());
    for (char c : sv)
        s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return s;
}

} // namespace

AmsiGuardEngine::AmsiGuardEngine() {
#ifdef GCAD_PLATFORM_WINDOWS
    HMODULE h_amsi = GetModuleHandleA("amsi.dll");
    if (!h_amsi) h_amsi = LoadLibraryA("amsi.dll");
    if (h_amsi) {
        auto p_func = reinterpret_cast<void*>(GetProcAddress(h_amsi, "AmsiScanBuffer"));
        if (p_func) {
            amsi_scan_buffer_addr_ = reinterpret_cast<uintptr_t>(p_func);
            original_prologue_.resize(16);
            std::memcpy(original_prologue_.data(), p_func, 16);
            amsi_available_ = true;
        }
    }
#endif
}

AmsiGuardEngine::~AmsiGuardEngine() {
    stop();
}

ErrorCode AmsiGuardEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&AmsiGuardEngine::monitor_loop, this);
    return ErrorCode::OK;
}

ErrorCode AmsiGuardEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus AmsiGuardEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void AmsiGuardEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void AmsiGuardEngine::emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.timestamp = std::chrono::system_clock::now();
        ev.level = ThreatLevel::HIGH;
        ev.category = cat;
        ev.process_id = pid;
        ev.description = desc;
        cb(std::move(ev));
    }
}

bool AmsiGuardEngine::is_patch_bypass(const uint8_t* code_bytes, size_t len) {
    if (!code_bytes || len == 0) return false;

    // Pattern 1: Direct RET opcode
    if (code_bytes[0] == 0xC3 || code_bytes[0] == 0xC2)
        return true;

    // Pattern 2: mov eax, 0x80070057; ret (E_INVALIDARG)
    if (len >= 6 && code_bytes[0] == 0xB8 &&
        code_bytes[1] == 0x57 && code_bytes[2] == 0x00 &&
        code_bytes[3] == 0x07 && code_bytes[4] == 0x80 &&
        code_bytes[5] == 0xC3) {
        return true;
    }

    // Pattern 3: xor eax, eax; ret (0x31 0xC0 0xC3 or 0x29 0xC0 0xC3)
    if (len >= 3 &&
        ((code_bytes[0] == 0x31 && code_bytes[1] == 0xC0) ||
         (code_bytes[0] == 0x29 && code_bytes[1] == 0xC0)) &&
        code_bytes[2] == 0xC3) {
        return true;
    }

    // Pattern 4: xor rax, rax; ret (0x48 0x31 0xC0 0xC3)
    if (len >= 4 && code_bytes[0] == 0x48 && code_bytes[1] == 0x31 &&
        code_bytes[2] == 0xC0 && code_bytes[3] == 0xC3) {
        return true;
    }

    return false;
}

bool AmsiGuardEngine::check_amsi_integrity() {
    events_processed_.fetch_add(1);
#ifdef GCAD_PLATFORM_WINDOWS
    if (!amsi_available_ || amsi_scan_buffer_addr_ == 0 || original_prologue_.empty())
        return true;

    const auto* current_bytes = reinterpret_cast<const uint8_t*>(amsi_scan_buffer_addr_);
    if (is_patch_bypass(current_bytes, original_prologue_.size())) {
        return false;
    }
    if (std::memcmp(current_bytes, original_prologue_.data(), original_prologue_.size()) != 0) {
        return false;
    }
    return true;
#else
    return true;
#endif
}

bool AmsiGuardEngine::restore_amsi_prologue() {
#ifdef GCAD_PLATFORM_WINDOWS
    if (!amsi_available_ || amsi_scan_buffer_addr_ == 0 || original_prologue_.empty())
        return false;

    DWORD old_protect = 0;
    auto* target = reinterpret_cast<void*>(amsi_scan_buffer_addr_);
    if (!VirtualProtect(target, original_prologue_.size(), PAGE_EXECUTE_READWRITE, &old_protect))
        return false;

    std::memcpy(target, original_prologue_.data(), original_prologue_.size());
    VirtualProtect(target, original_prologue_.size(), old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target, original_prologue_.size());
    return true;
#else
    return true;
#endif
}

ScriptScanResult AmsiGuardEngine::scan_script_buffer(std::string_view script_content) {
    events_processed_.fetch_add(1);
    ScriptScanResult result;
    if (script_content.empty()) return result;

    const std::string lower = to_lower_string(script_content);

    struct IndicatorRule {
        std::string_view pattern;
        int              weight;
        const char*      name;
    };

    static const IndicatorRule k_rules[] = {
        {"invoke-expression",          25, "IEX_EXECUTION"},
        {"iex ",                       25, "IEX_SHORT"},
        {"downloadstring",             25, "WEB_DOWNLOAD_STRING"},
        {"downloadfile",               20, "WEB_DOWNLOAD_FILE"},
        {"frombase64string",           20, "BASE64_DECODE"},
        {"amsiutils",                  35, "AMSI_UTILS_TARGETING"},
        {"amsiinitfailed",             35, "AMSI_BYPASS_INIT"},
        {"system.reflection.assembly", 20, "REFLECTION_INJECTION"},
        {"virtualalloc",               30, "MEM_ALLOC_INJECTION"},
        {"createthread",               30, "THREAD_INJECTION"},
        {"windowstyle hidden",         15, "STEALTH_WINDOW"},
        {"bypass",                     10, "EXECUTION_POLICY_BYPASS"},
        {"net.webclient",              15, "WEBCLIENT_USAGE"},
        {"mimikatz",                   50, "MIMIKATZ_KEYWORD"},
        {"-enc ",                      20, "ENCODED_COMMAND"},
        {"-encodedcommand",            20, "ENCODED_COMMAND"}
    };

    for (const auto& rule : k_rules) {
        if (lower.find(rule.pattern) != std::string::npos) {
            result.score += rule.weight;
            result.matched_indicators.push_back(rule.name);
        }
    }

    if (result.score >= 40) {
        result.risk = ScriptRiskLevel::MALICIOUS;
        emit_threat(ThreatCategory::FILELESS_EXEC,
                    "Malicious script buffer detected (score=" + std::to_string(result.score) + ")");
    } else if (result.score >= 15) {
        result.risk = ScriptRiskLevel::SUSPICIOUS;
    } else {
        result.risk = ScriptRiskLevel::BENIGN;
    }

    return result;
}

void AmsiGuardEngine::monitor_loop() {
    bool was_bypassed = false;
    while (running_.load()) {
        for (int i = 0; i < 30 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;

        if (!check_amsi_integrity()) {
            if (!was_bypassed) {
                was_bypassed = true;
                emit_threat(ThreatCategory::EVASION_AMSI,
                            "AMSI AmsiScanBuffer memory patch bypass detected; repairing prologue");
                restore_amsi_prologue();
            }
        } else {
            was_bypassed = false;
        }
    }
}

} // namespace gcad
