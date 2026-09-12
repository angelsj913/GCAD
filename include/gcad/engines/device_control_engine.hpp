#pragma once

#include "../i_security_engine.hpp"
#include "../security/observation.hpp"
#include <thread>
#include <mutex>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <atomic>

namespace gcad {

enum class DeviceType : uint8_t {
    DEV_USB_STORAGE  = 0,
    DEV_USB_HID      = 1,
    DEV_USB_NETWORK  = 2,
    DEV_USB_OTHER    = 3,
    DEV_CDROM        = 4,
    DEV_FLOPPY       = 5,
    DEV_MTP          = 6,
    DEV_BLUETOOTH    = 7,
};

enum class DeviceAction : uint8_t {
    ACT_CONNECTED    = 0,
    ACT_DISCONNECTED = 1,
    ACT_READ         = 2,
    ACT_WRITE        = 3,
    ACT_EXECUTE      = 4,
    ACT_BLOCKED      = 5,
};

enum class DevicePolicy : uint8_t {
    POL_ALLOW        = 0,
    POL_READ_ONLY    = 1,
    POL_BLOCK        = 2,
    POL_AUDIT        = 3,
};

struct DeviceInfo {
    std::string   device_id;
    std::string   friendly_name;
    std::string   vendor_id;
    std::string   product_id;
    std::string   serial_number;
    DeviceType    type{DeviceType::DEV_USB_OTHER};
    std::string   drive_letter;
};

struct DeviceEvent {
    uint64_t                              id{0};
    std::chrono::system_clock::time_point timestamp{};
    DeviceInfo                            device;
    DeviceAction                          action{DeviceAction::ACT_CONNECTED};
    std::string                           file_path;
    std::string                           detail;
    bool                                  policy_violation{false};
};

struct DeviceRule {
    std::string   rule_id;
    std::string   vendor_id;
    std::string   product_id;
    std::string   serial_number;
    DeviceType    device_type{DeviceType::DEV_USB_STORAGE};
    DevicePolicy  policy{DevicePolicy::POL_BLOCK};
    std::string   description;
};

class DeviceControlEngine final : public ISecurityEngine {
public:
    DeviceControlEngine();
    ~DeviceControlEngine() override;

    std::string_view name() const noexcept override { return "DeviceControl"; }
    ErrorCode start() override;
    ErrorCode stop() override;
    bool running() const noexcept override { return running_.load(); }
    EngineStatus status() const override;
    void on_threat(std::function<void(ThreatEvent)> cb) override;
    void on_observation(std::function<void(security::SecurityObservation)> cb);

    void report_device_event(const DeviceInfo& device, DeviceAction action,
                              const std::string& file_path = {});
    void add_rule(const DeviceRule& rule);
    void remove_rule(const std::string& rule_id);
    void whitelist_device(const std::string& serial_number);
    void blacklist_device(const std::string& serial_number);

    DevicePolicy evaluate_policy(const DeviceInfo& device) const;
    std::vector<DeviceEvent> recent_events(size_t n = 100) const;
    std::vector<DeviceRule> rules() const;
    std::vector<DeviceInfo> connected_devices() const;

    static const char* device_type_name(DeviceType type);
    static const char* action_name(DeviceAction action);
    static const char* policy_name(DevicePolicy policy);
    static DeviceType classify_device(const std::string& vendor_id,
                                       const std::string& product_id);

    DevicePolicy default_policy() const;
    void set_default_policy(DevicePolicy policy);

    static constexpr size_t MAX_EVENTS = 5000;
    static constexpr size_t MAX_RULES  = 1000;

private:
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> threats_detected_{0};
    std::atomic<uint64_t> next_id_{1};

    mutable std::mutex    mtx_;
    DevicePolicy          default_policy_{DevicePolicy::POL_AUDIT};
    std::deque<DeviceEvent>               events_;
    std::vector<DeviceRule>               rules_;
    std::unordered_set<std::string>       whitelist_;
    std::unordered_set<std::string>       blacklist_;
    std::unordered_map<std::string, DeviceInfo> connected_;
    std::thread           monitor_thread_;

    std::function<void(ThreatEvent)>                   threat_cb_;
    std::function<void(security::SecurityObservation)> observation_cb_;

    void monitor_loop();
    void scan_connected_devices();
};

} // namespace gcad
