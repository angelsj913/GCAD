#include "gcad/engines/webhook_engine.hpp"
#include <functional>
#include <chrono>
#include <thread>

extern void register_test(const char* name, std::function<bool()> fn);

void register_webhook_engine_tests() {
    register_test("webhook_engine_name_and_lifecycle", [] {
        gcad::WebhookEngine engine;
        if (engine.name() != "WebhookEngine") return false;
        if (engine.running()) return false;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        if (!engine.running()) return false;
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        if (engine.running()) return false;
        return true;
    });

    register_test("webhook_engine_formats_discord", [] {
        gcad::ThreatEvent te{};
        te.level = gcad::ThreatLevel::CRITICAL;
        te.description = "Bypass attempt detected";
        te.process_name = "powershell.exe";
        te.process_id = 9999;

        std::string payload = gcad::WebhookEngine::format_discord_payload(te);
        return payload.find("embeds") != std::string::npos &&
               payload.find("powershell.exe") != std::string::npos;
    });

    register_test("webhook_engine_formats_slack", [] {
        gcad::ThreatEvent te{};
        te.level = gcad::ThreatLevel::HIGH;
        te.process_name = "ReflectiveInjection";
        te.description = "Hollowing attack";

        std::string payload = gcad::WebhookEngine::format_slack_payload(te);
        return payload.find("[GCAD ALERT]") != std::string::npos &&
               payload.find("Hollowing attack") != std::string::npos;
    });

    register_test("webhook_engine_formats_splunk", [] {
        gcad::ThreatEvent te{};
        te.level = gcad::ThreatLevel::MEDIUM;
        te.category = gcad::ThreatCategory::KERNEL_ATTACK;
        te.description = "DriverGuard BYOVD driver blocked";
        te.process_name = "gdrv.sys";
        te.process_id = 4;

        std::string payload = gcad::WebhookEngine::format_splunk_hec_payload(te);
        return payload.find("gcad:edr") != std::string::npos &&
               payload.find("DriverGuard") != std::string::npos;
    });

    register_test("webhook_engine_formats_syslog_cef", [] {
        gcad::ThreatEvent te{};
        te.level = gcad::ThreatLevel::HIGH;
        te.description = "Cobalt strike pipe detected";
        te.process_name = "beacon.exe";
        te.process_id = 5555;

        std::string payload = gcad::WebhookEngine::format_syslog_cef_payload(te);
        return payload.find("CEF:0|Galoisconnection|GCAD") != std::string::npos &&
               payload.find("beacon.exe") != std::string::npos;
    });

    register_test("webhook_engine_async_dispatch_queue", [] {
        gcad::WebhookEngine engine;
        gcad::WebhookConfig cfg{};
        cfg.enabled = true;
        cfg.format = gcad::WebhookFormat::JSON_GENERIC;
        engine.set_config(cfg);

        if (engine.start() != gcad::ErrorCode::OK) return false;

        gcad::ThreatEvent te{};
        te.level = gcad::ThreatLevel::CRITICAL;
        te.description = "Async test alert";
        te.process_name = "test.exe";
        te.process_id = 1;

        engine.enqueue_event(te);

        // Wait briefly for worker thread to process
        for (int i = 0; i < 20; ++i) {
            if (!engine.recent_dispatches().empty()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }

        auto dispatches = engine.recent_dispatches();
        bool ok = dispatches.size() >= 1 &&
                  dispatches.back().find("Async test alert") != std::string::npos;

        engine.stop();
        return ok;
    });
}
