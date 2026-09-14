#include "gcad/platform/service_manager.hpp"
#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_service_manager_tests() {
#ifdef GCAD_PLATFORM_WINDOWS
    register_test("service_manager_service_constants", [] {
        if (gcad::platform::WindowsServiceManager::SERVICE_NAME != "GCADProtectionService") return false;
        if (gcad::platform::WindowsServiceManager::DISPLAY_NAME != "Galoisconnection Antivirus & Defense Service") return false;
        return true;
    });

    register_test("service_manager_query_service", [] {
        auto info = gcad::platform::WindowsServiceManager::query_service();
        (void)info;
        return true;
    });
#endif
}
