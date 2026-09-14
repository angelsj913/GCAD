#include "gcad/common.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/scanner/deep_scanner.hpp"
#include "gcad/alert/alert_manager.hpp"
#include "gcad/platform/platform_compat.hpp"
#include "gcad/platform/service_manager.hpp"
#include "gcad/platform/service_ipc.hpp"
#include "gcad/ui/ui_manager.hpp"

#include <csignal>
#include <iostream>

static std::atomic<bool> g_running{true};
static gcad::ui::UIManager* g_active_ui{nullptr};

static void signal_handler(int sig) {
    (void)sig;
    g_running.store(false);
    if (g_active_ui) g_active_ui->request_close();
}

static void print_banner() {
    std::cout << R"(
  ╔═══════════════════════════════════════════╗
  ║   GCAD v1.0.0  —  지케드                  ║
  ║   Galoisconnection Antivirus & Defense    ║
  ║   Pure From-Scratch Security Engine       ║
  ╚═══════════════════════════════════════════╝
)" << std::endl;
}

static int run_daemon() {
    GCAD_LOG(INFO, "GCAD daemon mode started");

    gcad::EngineManager engine_mgr;
    gcad::DeepScanner scanner;
    gcad::AlertManager alert_mgr;
    gcad::platform::ServiceIpcServer ipc_server;

    ipc_server.start();

    engine_mgr.on_global_threat([&alert_mgr, &ipc_server](const gcad::ThreatEvent& ev) {
        GCAD_LOG(WARN, "THREAT [" + std::string(1, "SLMHC"[static_cast<int>(ev.level)]) +
                 "] " + ev.description);
        alert_mgr.push(ev);
        ipc_server.broadcast_threat(ev);
    });
    scanner.on_observation([&engine_mgr](gcad::security::SecurityObservation obs) {
        engine_mgr.publish_observation(std::move(obs));
    });

    auto rc = engine_mgr.start_all();
    if (rc != gcad::ErrorCode::OK) {
        GCAD_LOG(ERR, "Failed to start engines");
        ipc_server.stop();
        return 1;
    }

    GCAD_LOG(INFO, "All engines active — monitoring & IPC server online...");
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    GCAD_LOG(INFO, "Shutting down...");
    ipc_server.stop();
    engine_mgr.stop_all();
    return 0;
}

static int run_gui() {
    gcad::EngineManager engine_mgr;
    gcad::DeepScanner scanner;
    gcad::AlertManager alert_mgr;
    gcad::platform::ServiceIpcClient ipc_client;

    if (gcad::platform::ServiceIpcClient::is_service_running()) {
        if (ipc_client.connect(500)) {
            GCAD_LOG(INFO, "Connected to GCAD background service via Named Pipe IPC");
            ipc_client.on_threat([&alert_mgr](const gcad::ThreatEvent& ev) {
                alert_mgr.push(ev);
            });
        }
    }

    engine_mgr.on_global_threat([&alert_mgr](const gcad::ThreatEvent& ev) {
        GCAD_LOG(WARN, "THREAT [" + std::string(1, "SLMHC"[static_cast<int>(ev.level)]) +
                 "] " + ev.description);
        alert_mgr.push(ev);
    });
    scanner.on_observation([&engine_mgr](gcad::security::SecurityObservation obs) {
        engine_mgr.publish_observation(std::move(obs));
    });

    auto rc = engine_mgr.start_all();
    if (rc != gcad::ErrorCode::OK) {
        GCAD_LOG(ERR, "Failed to start engines");
        return 1;
    }

    gcad::ui::UIManager ui;
    rc = ui.init(&engine_mgr, &scanner, &alert_mgr);
    if (rc != gcad::ErrorCode::OK) {
        GCAD_LOG(ERR, "Failed to initialize UI");
        engine_mgr.stop_all();
        return 1;
    }

    g_active_ui = &ui;
    ui.main_loop();
    g_active_ui = nullptr;
    ipc_client.disconnect();
    engine_mgr.stop_all();
    return 0;
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto plat_rc = gcad::platform::init();
    if (plat_rc != gcad::ErrorCode::OK) {
        std::cerr << "Platform initialization failed" << std::endl;
        return 1;
    }

    gcad::platform::protect_own_process();

    print_banner();

    bool daemon_mode = false;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--daemon" || arg == "-d") daemon_mode = true;
        if (arg == "--scan" && i + 1 < argc) {
            std::filesystem::path target = argv[++i];
            std::cout << "[*] DeepScanner initiating scan on: " << target << std::endl;
            gcad::DeepScanner scanner;
            scanner.start_scan(gcad::ScanMode::CUSTOM, target);
            while (scanner.is_scanning()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            auto results = scanner.get_results();
            auto prog = scanner.progress();
            std::cout << "[+] Scan complete. Scanned files: " << prog.files_scanned
                      << ", Threats found: " << results.size() << std::endl;
            for (const auto& r : results) {
                std::cout << "  - [THREAT] " << r.file_path << " | " << r.signature_name
                          << " (" << r.description << ")" << std::endl;
            }
            gcad::platform::shutdown();
            return results.empty() ? 0 : 2;
        }
#ifdef GCAD_PLATFORM_WINDOWS
        if (arg == "--service-install" || arg == "-i") {
            bool ok = gcad::platform::WindowsServiceManager::install_service(argv[0]);
            std::cout << (ok ? "Service installed successfully." : "Failed to install service (requires Administrator).") << std::endl;
            gcad::platform::shutdown();
            return ok ? 0 : 1;
        }
        if (arg == "--service-remove" || arg == "-u") {
            bool ok = gcad::platform::WindowsServiceManager::remove_service();
            std::cout << (ok ? "Service removed successfully." : "Failed to remove service (requires Administrator).") << std::endl;
            gcad::platform::shutdown();
            return ok ? 0 : 1;
        }
        if (arg == "--service-start" || arg == "-s") {
            bool ok = gcad::platform::WindowsServiceManager::start_service();
            std::cout << (ok ? "Service started successfully." : "Failed to start service.") << std::endl;
            gcad::platform::shutdown();
            return ok ? 0 : 1;
        }
        if (arg == "--service-stop") {
            bool ok = gcad::platform::WindowsServiceManager::stop_service();
            std::cout << (ok ? "Service stopped successfully." : "Failed to stop service.") << std::endl;
            gcad::platform::shutdown();
            return ok ? 0 : 1;
        }
        if (arg == "--service-run") {
            int svc_ret = gcad::platform::WindowsServiceManager::run_service_dispatcher(run_daemon);
            gcad::platform::shutdown();
            return svc_ret;
        }
#endif
        if (arg == "--version" || arg == "-v") {
            std::cout << "GCAD v" << gcad::VERSION << std::endl;
            gcad::platform::shutdown();
            return 0;
        }
        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: gcad [options]\n"
                      << "  --daemon, -d          Run in daemon mode (no GUI)\n"
                      << "  --scan <path>         Scan file or directory with DeepScanner\n"
                      << "  --service-install, -i Install Windows Service (Admin)\n"
                      << "  --service-remove, -u  Remove Windows Service (Admin)\n"
                      << "  --service-start, -s   Start Windows Service\n"
                      << "  --service-stop        Stop Windows Service\n"
                      << "  --version, -v         Show version\n"
                      << "  --help, -h            Show this help\n";
            gcad::platform::shutdown();
            return 0;
        }
    }

    int ret;
    if (daemon_mode) {
        ret = run_daemon();
    } else {
        ret = run_gui();
    }

    gcad::platform::shutdown();
    GCAD_LOG(INFO, "GCAD exited cleanly");
    return ret;
}
