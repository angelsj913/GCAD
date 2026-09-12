#include "gcad/engines/device_control_engine.hpp"
#include <algorithm>

namespace gcad {

DeviceControlEngine::DeviceControlEngine() = default;
DeviceControlEngine::~DeviceControlEngine() { stop(); }

ErrorCode DeviceControlEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    monitor_thread_ = std::thread(&DeviceControlEngine::monitor_loop, this);
    GCAD_LOG(INFO, "DeviceControl engine started");
    return ErrorCode::OK;
}

ErrorCode DeviceControlEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus DeviceControlEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void DeviceControlEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void DeviceControlEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

const char* DeviceControlEngine::device_type_name(DeviceType type) {
    switch (type) {
        case DeviceType::DEV_USB_STORAGE:  return "USB Storage";
        case DeviceType::DEV_USB_HID:      return "USB HID";
        case DeviceType::DEV_USB_NETWORK:  return "USB Network";
        case DeviceType::DEV_USB_OTHER:    return "USB Other";
        case DeviceType::DEV_CDROM:        return "CD-ROM";
        case DeviceType::DEV_FLOPPY:       return "Floppy";
        case DeviceType::DEV_MTP:          return "MTP";
        case DeviceType::DEV_BLUETOOTH:    return "Bluetooth";
        default:                           return "Unknown";
    }
}

const char* DeviceControlEngine::action_name(DeviceAction action) {
    switch (action) {
        case DeviceAction::ACT_CONNECTED:    return "Connected";
        case DeviceAction::ACT_DISCONNECTED: return "Disconnected";
        case DeviceAction::ACT_READ:         return "Read";
        case DeviceAction::ACT_WRITE:        return "Write";
        case DeviceAction::ACT_EXECUTE:      return "Execute";
        case DeviceAction::ACT_BLOCKED:      return "Blocked";
        default:                             return "Unknown";
    }
}

const char* DeviceControlEngine::policy_name(DevicePolicy policy) {
    switch (policy) {
        case DevicePolicy::POL_ALLOW:     return "Allow";
        case DevicePolicy::POL_READ_ONLY: return "Read-Only";
        case DevicePolicy::POL_BLOCK:     return "Block";
        case DevicePolicy::POL_AUDIT:     return "Audit";
        default:                          return "Unknown";
    }
}

DeviceType DeviceControlEngine::classify_device(const std::string& vendor_id,
                                                  const std::string& product_id) {
    (void)product_id;
    if (vendor_id.empty()) return DeviceType::DEV_USB_OTHER;

    static const std::unordered_set<std::string> hid_vendors = {
        "046D", "045E", "04F2", "1532",
    };
    static const std::unordered_set<std::string> network_vendors = {
        "0BDA", "148F", "0CF3", "2357",
    };

    std::string upper = vendor_id;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (hid_vendors.count(upper)) return DeviceType::DEV_USB_HID;
    if (network_vendors.count(upper)) return DeviceType::DEV_USB_NETWORK;

    return DeviceType::DEV_USB_STORAGE;
}

DevicePolicy DeviceControlEngine::evaluate_policy(const DeviceInfo& device) const {
    std::lock_guard lk(mtx_);

    if (!device.serial_number.empty()) {
        if (blacklist_.count(device.serial_number))
            return DevicePolicy::POL_BLOCK;
        if (whitelist_.count(device.serial_number))
            return DevicePolicy::POL_ALLOW;
    }

    for (const auto& rule : rules_) {
        bool type_match = (rule.device_type == device.type);
        bool vendor_match = rule.vendor_id.empty() || rule.vendor_id == device.vendor_id;
        bool product_match = rule.product_id.empty() || rule.product_id == device.product_id;
        bool serial_match = rule.serial_number.empty() ||
                            rule.serial_number == device.serial_number;

        if (type_match && vendor_match && product_match && serial_match)
            return rule.policy;
    }

    return default_policy_;
}

void DeviceControlEngine::report_device_event(const DeviceInfo& device,
                                                DeviceAction action,
                                                const std::string& file_path) {
    events_processed_.fetch_add(1);

    DevicePolicy policy = evaluate_policy(device);
    bool violation = false;

    if (policy == DevicePolicy::POL_BLOCK && action != DeviceAction::ACT_DISCONNECTED) {
        violation = true;
    } else if (policy == DevicePolicy::POL_READ_ONLY &&
               (action == DeviceAction::ACT_WRITE || action == DeviceAction::ACT_EXECUTE)) {
        violation = true;
    }

    std::function<void(ThreatEvent)> threat_cb;
    std::function<void(security::SecurityObservation)> obs_cb;

    {
        std::lock_guard lk(mtx_);
        threat_cb = threat_cb_;
        obs_cb = observation_cb_;

        DeviceEvent ev;
        ev.id = next_id_.fetch_add(1);
        ev.timestamp = std::chrono::system_clock::now();
        ev.device = device;
        ev.action = violation ? DeviceAction::ACT_BLOCKED : action;
        ev.file_path = file_path;
        ev.policy_violation = violation;
        ev.detail = std::string(device_type_name(device.type)) + " " +
                    action_name(action) + " — policy: " + policy_name(policy);
        events_.push_back(ev);
        while (events_.size() > MAX_EVENTS) events_.pop_front();

        if (action == DeviceAction::ACT_CONNECTED) {
            connected_[device.device_id] = device;
        } else if (action == DeviceAction::ACT_DISCONNECTED) {
            connected_.erase(device.device_id);
        }
    }

    if (violation) {
        threats_detected_.fetch_add(1);
        if (threat_cb) {
            ThreatEvent te{};
            te.level = (policy == DevicePolicy::POL_BLOCK)
                        ? ThreatLevel::HIGH : ThreatLevel::MEDIUM;
            te.category = ThreatCategory::DEVICE_POLICY;
            te.description = "Device policy violation: " +
                             std::string(device_type_name(device.type)) +
                             " '" + device.friendly_name + "' " +
                             action_name(action) + " blocked (policy: " +
                             policy_name(policy) + ")";
            te.file_path = file_path;
            te.timestamp = std::chrono::system_clock::now();
            threat_cb(std::move(te));
        }
    } else if (policy == DevicePolicy::POL_AUDIT && obs_cb) {
        security::SecurityObservation obs;
        obs.kind = security::ObservationKind::FILE_INTEGRITY;
        obs.suggested_level = ThreatLevel::LOW;
        obs.confidence = 0.3;
        obs.source_id = "DeviceControl";
        obs.evidence = "Device activity: " +
                       std::string(device_type_name(device.type)) +
                       " '" + device.friendly_name + "' " + action_name(action);
        obs.file_path = file_path;
        obs.timestamp = std::chrono::system_clock::now();
        obs_cb(std::move(obs));
    }
}

void DeviceControlEngine::add_rule(const DeviceRule& rule) {
    std::lock_guard lk(mtx_);
    rules_.push_back(rule);
    while (rules_.size() > MAX_RULES) rules_.erase(rules_.begin());
}

void DeviceControlEngine::remove_rule(const std::string& rule_id) {
    std::lock_guard lk(mtx_);
    rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
                                 [&rule_id](const DeviceRule& r) {
                                     return r.rule_id == rule_id;
                                 }),
                  rules_.end());
}

void DeviceControlEngine::whitelist_device(const std::string& serial_number) {
    std::lock_guard lk(mtx_);
    blacklist_.erase(serial_number);
    whitelist_.insert(serial_number);
}

void DeviceControlEngine::blacklist_device(const std::string& serial_number) {
    std::lock_guard lk(mtx_);
    whitelist_.erase(serial_number);
    blacklist_.insert(serial_number);
}

std::vector<DeviceEvent> DeviceControlEngine::recent_events(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, events_.size());
    return {events_.end() - static_cast<ptrdiff_t>(count), events_.end()};
}

std::vector<DeviceRule> DeviceControlEngine::rules() const {
    std::lock_guard lk(mtx_);
    return rules_;
}

std::vector<DeviceInfo> DeviceControlEngine::connected_devices() const {
    std::lock_guard lk(mtx_);
    std::vector<DeviceInfo> result;
    result.reserve(connected_.size());
    for (const auto& [id, dev] : connected_)
        result.push_back(dev);
    return result;
}

DevicePolicy DeviceControlEngine::default_policy() const {
    std::lock_guard lk(mtx_);
    return default_policy_;
}

void DeviceControlEngine::set_default_policy(DevicePolicy policy) {
    std::lock_guard lk(mtx_);
    default_policy_ = policy;
}

void DeviceControlEngine::scan_connected_devices() {
#ifdef GCAD_PLATFORM_WINDOWS
    char drives[256]{};
    DWORD len = GetLogicalDriveStringsA(sizeof(drives), drives);
    if (len == 0 || len >= sizeof(drives)) return;

    for (const char* p = drives; *p; p += std::strlen(p) + 1) {
        UINT type = GetDriveTypeA(p);
        if (type == DRIVE_REMOVABLE) {
            DeviceInfo info;
            info.device_id = p;
            info.drive_letter = p;
            info.friendly_name = std::string("Removable ") + p;
            info.type = DeviceType::DEV_USB_STORAGE;

            std::lock_guard lk(mtx_);
            if (!connected_.count(info.device_id)) {
                connected_[info.device_id] = info;
            }
        } else if (type == DRIVE_CDROM) {
            DeviceInfo info;
            info.device_id = p;
            info.drive_letter = p;
            info.friendly_name = std::string("CD-ROM ") + p;
            info.type = DeviceType::DEV_CDROM;

            std::lock_guard lk(mtx_);
            if (!connected_.count(info.device_id)) {
                connected_[info.device_id] = info;
            }
        }
    }
#endif
}

void DeviceControlEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 5000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        scan_connected_devices();
    }
}

} // namespace gcad
