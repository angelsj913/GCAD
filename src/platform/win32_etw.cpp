#include "gcad/platform/win32_etw.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#include <psapi.h>

namespace gcad::platform {

Win32Etw::Win32Etw() = default;
Win32Etw::~Win32Etw() { stop(); }

ErrorCode Win32Etw::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);
    trace_thread_ = std::thread(&Win32Etw::trace_loop, this);
    GCAD_LOG(INFO, "Win32 ETW monitor started");
    return ErrorCode::OK;
}

ErrorCode Win32Etw::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (trace_thread_.joinable()) trace_thread_.join();
    return ErrorCode::OK;
}

void Win32Etw::on_event(std::function<void(const EtwEvent&)> cb) {
    callback_ = std::move(cb);
}

std::vector<EtwEvent> Win32Etw::recent(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t start = events_.size() > n ? events_.size() - n : 0;
    return {events_.begin() + start, events_.end()};
}

void Win32Etw::trace_loop() {
    while (running_.load()) {
        std::vector<EtwEvent> batch;

        for (auto pid : find_suspicious_process_creation()) {
            EtwEvent ev{};
            ev.process_id = pid;
            ev.event_id = 1;
            ev.provider_name = "GCAD-ProcessMonitor";
            ev.description = "Suspicious process creation detected: PID " + std::to_string(pid);
            ev.timestamp = std::chrono::system_clock::now();
            batch.push_back(std::move(ev));
        }
        if (check_amsi_tampering()) {
            EtwEvent ev{};
            ev.event_id = 2;
            ev.provider_name = "GCAD-AMSIGuard";
            ev.description = "AMSI tampering detected (AmsiScanBuffer patched)";
            ev.timestamp = std::chrono::system_clock::now();
            batch.push_back(std::move(ev));
        }
        if (check_etw_tampering()) {
            EtwEvent ev{};
            ev.event_id = 3;
            ev.provider_name = "GCAD-ETWGuard";
            ev.description = "ETW tampering detected (EtwEventWrite patched)";
            ev.timestamp = std::chrono::system_clock::now();
            batch.push_back(std::move(ev));
        }

        if (!batch.empty()) {
            {
                std::lock_guard lk(mtx_);
                for (auto& ev : batch) events_.push_back(ev);
                if (events_.size() > 5000)
                    events_.erase(events_.begin(), events_.begin() + 2500);
            }
            if (callback_)
                for (auto& ev : batch) callback_(ev);   // outside the lock
        }

        for (int i = 0; i < 30 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool Win32Etw::check_amsi_tampering() {
    HMODULE amsi = GetModuleHandleA("amsi.dll");
    if (!amsi) return false;
    auto pScan = reinterpret_cast<uint8_t*>(GetProcAddress(amsi, "AmsiScanBuffer"));
    if (!pScan) return false;
    // Check if first bytes are patched (common: mov eax, 0x80070057; ret = B8 57 00 07 80 C3)
    if (pScan[0] == 0xB8 && pScan[5] == 0xC3) return true;
    // Check for ret (0xC3) at entry
    if (pScan[0] == 0xC3) return true;
    return false;
}

bool Win32Etw::check_etw_tampering() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto pEtw = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, "EtwEventWrite"));
    if (!pEtw) return false;
    // Patched EtwEventWrite: xor eax,eax; ret = 33 C0 C3
    if (pEtw[0] == 0x33 && pEtw[1] == 0xC0 && pEtw[2] == 0xC3) return true;
    if (pEtw[0] == 0xC3) return true;
    return false;
}

bool Win32Etw::detect_memory_write(uint32_t pid, uintptr_t addr, size_t size) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        CloseHandle(hProc);
        return (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
    }
    CloseHandle(hProc);
    (void)size;
    return false;
}

static uint64_t process_create_time(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    FILETIME c{}, e{}, k{}, u{};
    uint64_t out = 0;
    if (GetProcessTimes(h, &c, &e, &k, &u))
        out = (static_cast<uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    CloseHandle(h);
    return out;
}

std::vector<uint32_t> Win32Etw::find_suspicious_process_creation() {
    std::vector<uint32_t> suspicious;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return suspicious;

    std::vector<std::pair<uint32_t, uint32_t>> pid_ppid;   // (pid, claimed ppid)
    std::unordered_map<uint32_t, uint8_t> alive;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            alive.emplace(pe.th32ProcessID, 1);
            pid_ppid.emplace_back(pe.th32ProcessID, pe.th32ParentProcessID);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    // A genuine parent is always created strictly before its child. If the claimed
    // parent is still alive but was created *after* the child, the PPID was forged
    // (classic PROC_THREAD_ATTRIBUTE_PARENT_PROCESS spoof). An orphaned parent
    // (already exited) is normal and deliberately NOT flagged.
    for (auto& [pid, ppid] : pid_ppid) {
        if (ppid == 0 || pid == ppid) continue;
        if (alive.find(ppid) == alive.end()) continue;   // parent gone: normal
        uint64_t ct_child = process_create_time(pid);
        uint64_t ct_parent = process_create_time(ppid);
        if (ct_child && ct_parent && ct_parent > ct_child)
            suspicious.push_back(pid);
    }
    return suspicious;
}

bool Win32Etw::detect_ppid_spoofing(uint32_t pid) {
    auto s = find_suspicious_process_creation();
    return std::find(s.begin(), s.end(), pid) != s.end();
}

} // namespace gcad::platform

#endif
