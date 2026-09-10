#include "gcad/common.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/scanner/deep_scanner.hpp"
#include "gcad/platform/platform_compat.hpp"
#include "gcad/ui/ui_manager.hpp"

#include <csignal>
#include <iostream>

static std::atomic<bool> g_running{true};

static void signal_handler(int sig) {
    (void)sig;
    g_running.store(false);
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

    engine_mgr.on_global_threat([](const gcad::ThreatEvent& ev) {
        GCAD_LOG(WARN, "THREAT [" + std::string(1, "SLMHC"[static_cast<int>(ev.level)]) +
                 "] " + ev.description);
    });

    auto rc = engine_mgr.start_all();
    if (rc != gcad::ErrorCode::OK) {
        GCAD_LOG(ERR, "Failed to start engines");
        return 1;
    }

    GCAD_LOG(INFO, "All engines active — monitoring...");
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    GCAD_LOG(INFO, "Shutting down...");
    engine_mgr.stop_all();
    return 0;
}

static int run_gui() {
    gcad::EngineManager engine_mgr;
    gcad::DeepScanner scanner;

    engine_mgr.on_global_threat([](const gcad::ThreatEvent& ev) {
        GCAD_LOG(WARN, "THREAT [" + std::string(1, "SLMHC"[static_cast<int>(ev.level)]) +
                 "] " + ev.description);
    });

    auto rc = engine_mgr.start_all();
    if (rc != gcad::ErrorCode::OK) {
        GCAD_LOG(ERR, "Failed to start engines");
        return 1;
    }

    gcad::ui::UIManager ui;
    rc = ui.init(&engine_mgr, &scanner);
    if (rc != gcad::ErrorCode::OK) {
        GCAD_LOG(ERR, "Failed to initialize UI");
        engine_mgr.stop_all();
        return 1;
    }

    ui.main_loop();
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
        if (arg == "--version" || arg == "-v") {
            std::cout << "GCAD v" << gcad::VERSION << std::endl;
            gcad::platform::shutdown();
            return 0;
        }
        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: gcad [options]\n"
                      << "  --daemon, -d    Run in daemon mode (no GUI)\n"
                      << "  --version, -v   Show version\n"
                      << "  --help, -h      Show this help\n";
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
