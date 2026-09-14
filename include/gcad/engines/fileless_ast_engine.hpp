#pragma once

#include "../i_security_engine.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gcad {

struct FilelessEvaluation {
    std::string              original_script;
    std::string              deobfuscated_script;
    bool                     is_malicious{false};
    std::string              mitre_technique;
    std::string              reason;
    ThreatLevel              severity{ThreatLevel::SAFE};
    std::vector<std::string> indicators;
};

struct ComHijackRecord {
    std::string clsid;
    std::string inproc_server_path;
    bool        is_hijacked{false};
    std::string reason;
};

class FilelessAstEngine final : public ISecurityEngine {
public:
    FilelessAstEngine();
    ~FilelessAstEngine() override;

    std::string_view name() const noexcept override { return "FilelessAstGuard"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    // Evaluates a script for fileless/obfuscated malicious behavior
    FilelessEvaluation evaluate_script(std::string_view script);

    // Full deobfuscation pipeline: string concat, char casts, reverse arrays, backticks
    static std::string deobfuscate_powershell(std::string_view script);

    // Specific deobfuscation helpers
    static std::string deobfuscate_string_concat(std::string_view s);
    static std::string deobfuscate_char_casts(std::string_view s);
    static std::string deobfuscate_reverse_patterns(std::string_view s);
    static std::string strip_backticks(std::string_view s);

    // COM Hijacking Scanner (HKCU\Software\Classes\CLSID)
    std::vector<ComHijackRecord> scan_com_hijacking();

private:
    std::atomic<bool>                        running_{false};
    std::function<void(ThreatEvent)>         threat_cb_;
    mutable std::mutex                       mtx_;
    mutable std::atomic<uint64_t>            scripts_scanned_{0};
    mutable std::atomic<uint64_t>            threats_detected_{0};

    void dispatch_threat(const FilelessEvaluation& eval);
};

} // namespace gcad
