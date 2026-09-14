#pragma once
#include "../common.hpp"
#include <string>
#include <string_view>

namespace gcad::platform {

#ifdef GCAD_PLATFORM_WINDOWS

struct ServiceStatusInfo {
    bool installed{false};
    bool running{false};
    uint32_t win32_exit_code{0};
};

class WindowsServiceManager {
public:
    static constexpr std::string_view SERVICE_NAME = "GCADProtectionService";
    static constexpr std::string_view DISPLAY_NAME = "Galoisconnection Antivirus & Defense Service";

    static bool install_service(const std::string& binary_path);
    static bool remove_service();
    static bool start_service();
    static bool stop_service();
    static ServiceStatusInfo query_service();
    static int run_service_dispatcher(int (*daemon_entry)());
};

#endif

} // namespace gcad::platform
