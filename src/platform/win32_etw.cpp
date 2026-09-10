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
        auto suspicious = find_suspicious_process_creation();
        for (auto pid : suspicious) {
            EtwEvent ev{};
            ev.process_id = pid;
            ev.event_id = 1;
            ev.provider_name = "GCAD-ProcessMonitor";
            ev.description = "Suspicious process creation detected: PID " + std::to_string(pid);
            ev.timestamp = std::chrono::system_clock::now();
            {
                std::lock_guard lk(mtx_);
                events_.push_back(ev);
                if (events_.size() > 5000)
                    events_.erase(events_.begin(), events_.begin() + 2500);
            }
            if (callback_) callback_(ev);
        }

        if (check_amsi_tampering()) {
            EtwEvent ev{};
            ev.event_id = 2;
            ev.provider_name = "GCAD-AMSIGuard";
            ev.description = "AMSI tampering detected";
            ev.timestamp = std::chrono::system_clock::now();
            std::lock_guard lk(mtx_);
            events_.push_back(ev);
            if (callback_) callback_(ev);
        }

        if (check_etw_tampering()) {
            EtwEvent ev{};
            ev.event_id = 3;
            ev.provider_name = "GCAD-ETWGuard";
            ev.description = "ETW tampering detected";
            ev.timestamp = std::chrono::system_clock::now();
            std::lock_guard lk(mtx_);
            events_.push_back(ev);
            if (callback_) callback_(ev);
        }

        std::this_thread::sleep_for(std::chrono::seconds(3));
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

std::vector<uint32_t> Win32Etw::find_suspicious_process_creation() {
    std::vector<uint32_t> suspicious;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return suspicious;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (detect_ppid_spoofing(pe.th32ProcessID))
                suspicious.push_back(pe.th32ProcessID);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return suspicious;
}

bool Win32Etw::detect_ppid_spoofing(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{}, parent{};
    pe.dwSize = sizeof(pe);
    parent.dwSize = sizeof(parent);

    uint32_t claimed_ppid = 0;
    bool found = false;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                claimed_ppid = pe.th32ParentProcessID;
                found = true;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    if (!found) { CloseHandle(snap); return false; }

    bool parent_exists = false;
    PROCESSENTRY32 pe2{};
    pe2.dwSize = sizeof(pe2);
    if (Process32First(snap, &pe2)) {
        do {
            if (pe2.th32ProcessID == claimed_ppid) { parent_exists = true; break; }
        } while (Process32Next(snap, &pe2));
    }
    CloseHandle(snap);

    if (!parent_exists && claimed_ppid != 0) return true;
    return false;
}

} // namespace gcad::platform

#endif
