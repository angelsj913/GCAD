#pragma once

#include "../i_security_engine.hpp"
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gcad {

struct LolbinExecution {
    uint32_t    pid{0};
    std::string binary_name;
    std::string command_line;
    std::string normalized_command_line;
    std::string decoded_payload;
    bool        is_malicious{false};
    std::string mitre_technique;
    std::string reason;
    ThreatLevel severity{ThreatLevel::SAFE};
};

class LolbinsEngine final : public ISecurityEngine {
public:
    LolbinsEngine();
    ~LolbinsEngine() override;

    std::string_view name() const noexcept override { return "LolbinsGuard"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    // Evaluates a command line execution of a binary
    LolbinExecution evaluate_command_line(uint32_t pid,
                                          std::string_view binary_name,
                                          std::string_view cmdline);

    // Command-line normalization (removes carets, quotes inside tokens, etc.)
    static std::string normalize_command_line(std::string_view raw);

    // Base64 decoding helper (supports standard base64 and UTF-16LE / ASCII)
    static std::optional<std::string> decode_base64(std::string_view b64);

    // Extracts and decodes base64 payload from PowerShell -enc arguments
    static std::optional<std::string> extract_and_decode_encoded_command(std::string_view cmdline);

    // Inspects a .lnk file for weaponized embedded arguments
    bool inspect_lnk_file(const std::filesystem::path& lnk_path, LolbinExecution& out_exec);

private:
    std::atomic<bool>                        running_{false};
    std::function<void(ThreatEvent)>         threat_cb_;
    mutable std::mutex                       mtx_;
    mutable std::atomic<uint64_t>            evaluations_count_{0};
    mutable std::atomic<uint64_t>            threats_detected_{0};

    void dispatch_threat(const LolbinExecution& exec);
};

} // namespace gcad
