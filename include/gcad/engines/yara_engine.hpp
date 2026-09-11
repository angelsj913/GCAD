#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <unordered_map>

namespace gcad {

struct YaraString {
    std::string identifier;
    std::vector<uint8_t> pattern;
    std::vector<uint8_t> mask;
    bool is_hex{false};
    bool nocase{false};
    bool wide{false};
    bool ascii{true};
};

struct YaraRule {
    std::string name;
    std::string description;
    std::vector<std::string> tags;
    std::vector<YaraString> strings;
    enum class ConditionOp { ALL_OF_THEM, ANY_OF_THEM, COUNT_GE };
    ConditionOp condition{ConditionOp::ANY_OF_THEM};
    size_t condition_count{1};
    ThreatLevel threat_level{ThreatLevel::HIGH};
};

struct YaraMatch {
    std::string rule_name;
    std::string matched_string_id;
    size_t offset{0};
    size_t length{0};
};

class YaraEngine final : public ISecurityEngine {
public:
    YaraEngine();
    ~YaraEngine() override;

    std::string_view name() const noexcept override { return "YARA"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;

    void on_observation(std::function<void(security::SecurityObservation)> cb);

    void add_rule(YaraRule rule);
    size_t rule_count() const;

    std::vector<YaraMatch> scan_buffer(const uint8_t* data, size_t len) const;
    std::vector<YaraMatch> scan_file(const std::filesystem::path& path) const;

    static bool parse_hex_pattern(const std::string& hex_str,
                                  std::vector<uint8_t>& out_pattern,
                                  std::vector<uint8_t>& out_mask);
    static std::vector<uint8_t> text_to_pattern(const std::string& text, bool wide);

    void load_builtin_rules();

private:
    std::atomic<bool>                        running_{false};
    std::atomic<uint64_t>                    events_processed_{0};
    std::atomic<uint64_t>                    threats_detected_{0};
    std::thread                              scan_thread_;
    mutable std::mutex                       mtx_;
    std::function<void(ThreatEvent)>         threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    std::vector<YaraRule> rules_;

    std::vector<size_t> find_pattern(const uint8_t* data, size_t data_len,
                                     const YaraString& str) const;
    bool evaluate_condition(const YaraRule& rule,
                            const std::unordered_map<std::string, std::vector<size_t>>& matches) const;
    void scan_loop();
    void emit_threat(const std::string& rule_name, const std::string& file_path,
                     const std::string& evidence);
    void emit_observation(const std::string& rule_name, const std::string& file_path,
                          double confidence, const std::string& evidence);
};

} // namespace gcad
