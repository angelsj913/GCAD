#include "gcad/common.hpp"

namespace gcad {

// SHA256::K is constexpr, defined in header — no additional definitions needed.
// All utilities (shannon_entropy, chi_squared, secure_zero, SHA256, ThreadPool, Logger)
// are fully implemented inline/in-header. This TU ensures the header compiles cleanly
// and provides a place for any future non-inline helpers.

static bool g_platform_initialized = false;

ErrorCode global_init() {
#ifdef GCAD_PLATFORM_WINDOWS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return ErrorCode::ERR_NET_SOCKET;
#endif
    g_platform_initialized = true;
    GCAD_LOG(INFO, "GCAD global init complete");
    return ErrorCode::OK;
}

void global_shutdown() {
#ifdef GCAD_PLATFORM_WINDOWS
    if (g_platform_initialized)
        WSACleanup();
#endif
    g_platform_initialized = false;
    GCAD_LOG(INFO, "GCAD global shutdown complete");
}

} // namespace gcad
