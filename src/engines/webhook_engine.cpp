#include "gcad/engines/webhook_engine.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>

namespace gcad {

WebhookEngine::WebhookEngine() = default;

WebhookEngine::~WebhookEngine() {
    stop();
}

ErrorCode WebhookEngine::start() {
    if (running_.exchange(true)) return ErrorCode::OK;
    worker_thread_ = std::thread(&WebhookEngine::worker_loop, this);
    return ErrorCode::OK;
}

ErrorCode WebhookEngine::stop() {
    if (!running_.exchange(false)) return ErrorCode::OK;
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    return ErrorCode::OK;
}

EngineStatus WebhookEngine::status() const {
    EngineStatus st{};
    st.name = std::string(name());
    st.running = running_.load();
    st.events_processed = events_processed_.load();
    st.threats_detected = threats_detected_.load();
    return st;
}

void WebhookEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    threat_cb_ = std::move(cb);
}

void WebhookEngine::set_config(const WebhookConfig& cfg) {
    std::lock_guard<std::mutex> lock(mtx_);
    config_ = cfg;
}

WebhookConfig WebhookEngine::config() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return config_;
}

void WebhookEngine::enqueue_event(const ThreatEvent& event) {
    std::lock_guard<std::mutex> lock(mtx_);
    event_queue_.push(event);
    cv_.notify_one();
}

size_t WebhookEngine::queue_size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return event_queue_.size();
}

std::vector<std::string> WebhookEngine::recent_dispatches(size_t limit) const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (dispatched_payloads_.empty() || limit == 0) return {};
    size_t count = std::min(limit, dispatched_payloads_.size());
    return std::vector<std::string>(dispatched_payloads_.end() - count, dispatched_payloads_.end());
}

std::string WebhookEngine::format_generic_json(const ThreatEvent& event) {
    std::ostringstream oss;
    oss << "{\"alert\":{"
        << "\"level\":" << static_cast<int>(event.level) << ","
        << "\"category\":" << static_cast<int>(event.category) << ","
        << "\"description\":\"" << event.description << "\","
        << "\"process_name\":\"" << event.process_name << "\","
        << "\"process_id\":" << event.process_id
        << "}}";
    return oss.str();
}

std::string WebhookEngine::format_discord_payload(const ThreatEvent& event) {
    int color = (event.level == ThreatLevel::CRITICAL) ? 0xFF0000 :
                (event.level == ThreatLevel::HIGH) ? 0xFF8800 : 0xFFFF00;

    std::string title = event.process_name.empty() ? "System Security Alert" : event.process_name;

    std::ostringstream oss;
    oss << "{\"embeds\":[{"
        << "\"title\":\"GCAD Threat Alert: " << title << "\","
        << "\"description\":\"" << event.description << "\","
        << "\"color\":" << color << ","
        << "\"fields\":["
        << "{\"name\":\"Process\",\"value\":\"" << event.process_name << " (PID: " << event.process_id << ")\",\"inline\":true},"
        << "{\"name\":\"Severity\",\"value\":\"" << static_cast<int>(event.level) << "\",\"inline\":true}"
        << "]}]}";
    return oss.str();
}

std::string WebhookEngine::format_slack_payload(const ThreatEvent& event) {
    std::string tag = event.process_name.empty() ? "SECURITY" : event.process_name;
    std::ostringstream oss;
    oss << "{\"text\":\"[GCAD ALERT] " << tag << ": " << event.description << "\"}";
    return oss.str();
}

std::string WebhookEngine::format_splunk_hec_payload(const ThreatEvent& event) {
    std::ostringstream oss;
    oss << "{\"sourcetype\":\"gcad:edr\",\"event\":{"
        << "\"category\":" << static_cast<int>(event.category) << ","
        << "\"level\":" << static_cast<int>(event.level) << ","
        << "\"description\":\"" << event.description << "\","
        << "\"process\":\"" << event.process_name << "\","
        << "\"pid\":" << event.process_id
        << "}}";
    return oss.str();
}

std::string WebhookEngine::format_syslog_cef_payload(const ThreatEvent& event) {
    std::string src = event.source_ip.empty() ? "127.0.0.1" : event.source_ip;
    std::ostringstream oss;
    oss << "CEF:0|Galoisconnection|GCAD|1.0|ALERT|" << static_cast<int>(event.category)
        << "|" << static_cast<int>(event.level)
        << "|src=" << src
        << " dproc=" << event.process_name
        << " pid=" << event.process_id
        << " msg=" << event.description;
    return oss.str();
}

void WebhookEngine::worker_loop() {
    while (running_.load()) {
        ThreatEvent ev{};
        WebhookFormat fmt = WebhookFormat::JSON_GENERIC;
        bool has_item = false;

        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return !running_.load() || !event_queue_.empty();
            });

            if (!running_.load()) break;

            if (!event_queue_.empty()) {
                ev = event_queue_.front();
                event_queue_.pop();
                fmt = config_.format;
                has_item = true;
            }
        }

        if (has_item) {
            std::string payload;
            switch (fmt) {
                case WebhookFormat::DISCORD: payload = format_discord_payload(ev); break;
                case WebhookFormat::SLACK: payload = format_slack_payload(ev); break;
                case WebhookFormat::SPLUNK_HEC: payload = format_splunk_hec_payload(ev); break;
                case WebhookFormat::SYSLOG_CEF: payload = format_syslog_cef_payload(ev); break;
                case WebhookFormat::JSON_GENERIC:
                default: payload = format_generic_json(ev); break;
            }

            {
                std::lock_guard<std::mutex> lock(mtx_);
                dispatched_payloads_.push_back(std::move(payload));
                if (dispatched_payloads_.size() > 500) {
                    dispatched_payloads_.erase(dispatched_payloads_.begin(), dispatched_payloads_.begin() + 100);
                }
            }

            events_processed_.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

} // namespace gcad
