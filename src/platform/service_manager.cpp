#include "gcad/platform/service_manager.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <windows.h>
#include <csignal>
#include <cstring>

namespace gcad::platform {

namespace {

SERVICE_STATUS        g_service_status{};
SERVICE_STATUS_HANDLE g_status_handle{nullptr};
int (*g_daemon_entry_fn)() = nullptr;

VOID WINAPI ServiceCtrlHandler(DWORD request) {
    switch (request) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_service_status.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_status_handle, &g_service_status);
            raise(SIGTERM);
            g_service_status.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(g_status_handle, &g_service_status);
            break;
        default:
            break;
    }
    SetServiceStatus(g_status_handle, &g_service_status);
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    (void)argc; (void)argv;
    g_status_handle = RegisterServiceCtrlHandlerA(WindowsServiceManager::SERVICE_NAME.data(), ServiceCtrlHandler);
    if (!g_status_handle) return;

    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwCurrentState = SERVICE_START_PENDING;
    g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_status_handle, &g_service_status);

    g_service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_status_handle, &g_service_status);

    if (g_daemon_entry_fn) {
        g_daemon_entry_fn();
    }

    g_service_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_status_handle, &g_service_status);
}

} // namespace

bool WindowsServiceManager::install_service(const std::string& binary_path) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;

    std::string bin_cmd = "\"" + binary_path + "\" --service-run";
    SC_HANDLE svc = CreateServiceA(
        scm,
        SERVICE_NAME.data(),
        DISPLAY_NAME.data(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        bin_cmd.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool WindowsServiceManager::remove_service() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME.data(), DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    BOOL ok = DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

bool WindowsServiceManager::start_service() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME.data(), SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    BOOL ok = StartServiceA(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

bool WindowsServiceManager::stop_service() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME.data(), SERVICE_STOP);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status{};
    BOOL ok = ControlService(svc, SERVICE_CONTROL_STOP, &status);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

ServiceStatusInfo WindowsServiceManager::query_service() {
    ServiceStatusInfo info{};
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return info;

    SC_HANDLE svc = OpenServiceA(scm, SERVICE_NAME.data(), SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return info;
    }

    info.installed = true;
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytes_needed = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes_needed)) {
        info.running = (ssp.dwCurrentState == SERVICE_RUNNING);
        info.win32_exit_code = ssp.dwWin32ExitCode;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return info;
}

int WindowsServiceManager::run_service_dispatcher(int (*daemon_entry)()) {
    g_daemon_entry_fn = daemon_entry;
    char name_buf[128];
    std::strncpy(name_buf, SERVICE_NAME.data(), sizeof(name_buf) - 1);
    name_buf[sizeof(name_buf) - 1] = '\0';

    SERVICE_TABLE_ENTRYA dispatch_table[] = {
        {name_buf, ServiceMain},
        {nullptr, nullptr}
    };

    if (!StartServiceCtrlDispatcherA(dispatch_table)) {
        return static_cast<int>(GetLastError());
    }
    return 0;
}

} // namespace gcad::platform
#endif
