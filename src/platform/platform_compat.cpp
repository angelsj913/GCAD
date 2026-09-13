#include "gcad/platform/platform_compat.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#include <psapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif
#endif

namespace gcad::platform {

ErrorCode init() {
#ifdef GCAD_PLATFORM_WINDOWS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return ErrorCode::ERR_NET_SOCKET;
#endif
    return ErrorCode::OK;
}

void shutdown() {
#ifdef GCAD_PLATFORM_WINDOWS
    WSACleanup();
#endif
}

uint32_t current_pid() {
#ifdef GCAD_PLATFORM_WINDOWS
    return GetCurrentProcessId();
#else
    return static_cast<uint32_t>(getpid());
#endif
}

bool is_elevated() {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD size = sizeof(elev);
    GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size);
    CloseHandle(token);
    return elev.TokenIsElevated != 0;
#else
    return geteuid() == 0;
#endif
}

std::vector<ProcessInfo> enumerate_processes() {
    std::vector<ProcessInfo> procs;
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return procs;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ProcessInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.ppid = pe.th32ParentProcessID;
            pi.name = pe.szExeFile;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                char path[MAX_PATH];
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameA(hProc, 0, path, &sz))
                    pi.path = path;
                PROCESS_MEMORY_COUNTERS pmc{};
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                    pi.memory_bytes = pmc.WorkingSetSize;
                CloseHandle(hProc);
            }
            procs.push_back(std::move(pi));
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
#else
    for (auto& entry : std::filesystem::directory_iterator("/proc")) {
        auto name = entry.path().filename().string();
        bool all_digits = !name.empty() && std::all_of(name.begin(), name.end(), ::isdigit);
        if (!all_digits) continue;
        ProcessInfo pi;
        pi.pid = static_cast<uint32_t>(std::stoul(name));
        std::ifstream comm(entry.path() / "comm");
        if (comm) std::getline(comm, pi.name);
        std::ifstream stat(entry.path() / "stat");
        if (stat) {
            std::string line;
            std::getline(stat, line);
            auto paren_end = line.rfind(')');
            if (paren_end != std::string::npos && paren_end + 4 < line.size()) {
                std::istringstream ss(line.substr(paren_end + 2));
                char state; ss >> state >> pi.ppid;
            }
        }
        std::error_code ec;
        auto exe = std::filesystem::read_symlink(entry.path() / "exe", ec);
        if (!ec) pi.path = exe.string();
        procs.push_back(std::move(pi));
    }
#endif
    return procs;
}

bool suspend_process(uint32_t pid) {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProc) return false;
    using fn_t = LONG(NTAPI*)(HANDLE);
    auto ntdll = GetModuleHandleA("ntdll.dll");
    bool ok = false;
    if (ntdll) {
        auto pSuspend = reinterpret_cast<fn_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtSuspendProcess")));
        if (pSuspend) ok = (pSuspend(hProc) >= 0);
    }
    CloseHandle(hProc);
    return ok;
#else
    return kill(pid, SIGSTOP) == 0;
#endif
}

bool resume_process(uint32_t pid) {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProc) return false;
    using fn_t = LONG(NTAPI*)(HANDLE);
    auto ntdll = GetModuleHandleA("ntdll.dll");
    bool ok = false;
    if (ntdll) {
        auto pResume = reinterpret_cast<fn_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtResumeProcess")));
        if (pResume) ok = (pResume(hProc) >= 0);
    }
    CloseHandle(hProc);
    return ok;
#else
    return kill(pid, SIGCONT) == 0;
#endif
}

bool terminate_process(uint32_t pid) {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) return false;
    bool ok = TerminateProcess(hProc, 1) != 0;
    CloseHandle(hProc);
    return ok;
#else
    return kill(pid, SIGKILL) == 0;
#endif
}

namespace {

#ifdef GCAD_PLATFORM_WINDOWS
bool creation_time_matches(HANDLE process, uint64_t expected) {
    if (expected == 0) return false;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return false;
    const uint64_t actual = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    return actual == expected;
}
#endif

} // namespace

bool resume_process_if_same_instance(uint32_t pid, uint64_t creation_time) {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    const bool matches = creation_time_matches(hProc, creation_time);
    using fn_t = LONG(NTAPI*)(HANDLE);
    auto ntdll = GetModuleHandleA("ntdll.dll");
    const auto resume = ntdll ? reinterpret_cast<fn_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtResumeProcess"))) : nullptr;
    const bool ok = matches && resume && resume(hProc) >= 0;
    CloseHandle(hProc);
    return ok;
#else
    (void)pid;
    (void)creation_time;
    return false;
#endif
}

bool terminate_process_if_same_instance(uint32_t pid, uint64_t creation_time) {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    const bool ok = creation_time_matches(hProc, creation_time) && TerminateProcess(hProc, 1) != 0;
    CloseHandle(hProc);
    return ok;
#else
    (void)pid;
    (void)creation_time;
    return false;
#endif
}

bool protect_own_process() {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    return true;
#else
    return true;
#endif
}

std::vector<uint8_t> read_process_memory(uint32_t pid, uintptr_t addr, size_t len) {
    std::vector<uint8_t> buf(len);
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), buf.data(), len, &read))
        buf.clear();
    else
        buf.resize(read);
    CloseHandle(hProc);
#else
    std::string mem_path = "/proc/" + std::to_string(pid) + "/mem";
    std::ifstream f(mem_path, std::ios::binary);
    if (!f) return {};
    f.seekg(addr);
    f.read(reinterpret_cast<char*>(buf.data()), len);
    auto actual = f.gcount();
    if (actual <= 0) buf.clear();
    else buf.resize(actual);
#endif
    return buf;
}

bool file_exists(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec);
}

uint64_t file_size(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::file_size(p, ec);
}

std::vector<std::filesystem::path> get_system_scan_paths() {
    std::vector<std::filesystem::path> paths;
#ifdef GCAD_PLATFORM_WINDOWS
    const char* user_profile = std::getenv("USERPROFILE");
    if (user_profile) {
        paths.push_back(std::string(user_profile) + "\\Desktop");
        paths.push_back(std::string(user_profile) + "\\Downloads");
        paths.push_back(std::string(user_profile) + "\\Documents");
        paths.push_back(std::string(user_profile) + "\\AppData\\Local\\Temp");
    }
    paths.push_back("C:\\Windows\\Temp");
#else
    paths.push_back("/tmp");
    paths.push_back("/home");
    paths.push_back("/var/tmp");
#endif
    return paths;
}

std::filesystem::path get_quarantine_dir() {
#ifdef GCAD_PLATFORM_WINDOWS
    const char* appdata = std::getenv("LOCALAPPDATA");
    std::filesystem::path dir;
    if (appdata) { dir = std::string(appdata) + "\\GCAD\\quarantine"; }
    else dir = "C:\\GCAD\\quarantine";
#else
    std::filesystem::path dir = "/var/lib/gcad/quarantine";
#endif
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

} // namespace gcad::platform
