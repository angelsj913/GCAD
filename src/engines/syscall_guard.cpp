#include "gcad/engines/syscall_guard.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#include <psapi.h>
#endif

namespace gcad {

SyscallGuardEngine::SyscallGuardEngine() = default;
SyscallGuardEngine::~SyscallGuardEngine() { stop(); }

ErrorCode SyscallGuardEngine::start() {
    if (running_.load()) return ErrorCode::OK;
#ifdef GCAD_PLATFORM_WINDOWS
    if (!load_pristine_ntdll()) {
        GCAD_LOG(WARN, "SyscallGuard: could not load pristine ntdll.dll for comparison");
    }
#endif
    running_.store(true);
    monitor_thread_ = std::thread(&SyscallGuardEngine::monitor_loop, this);
    GCAD_LOG(INFO, "SyscallGuard engine started");
    return ErrorCode::OK;
}

ErrorCode SyscallGuardEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    secure_zero(pristine_ntdll_.data(), pristine_ntdll_.size());
    return ErrorCode::OK;
}

EngineStatus SyscallGuardEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void SyscallGuardEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

#ifdef GCAD_PLATFORM_WINDOWS
bool SyscallGuardEngine::load_pristine_ntdll() {
    char sys_dir[MAX_PATH];
    GetSystemDirectoryA(sys_dir, MAX_PATH);
    std::string ntdll_path = std::string(sys_dir) + "\\ntdll.dll";

    HANDLE hFile = CreateFileA(ntdll_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD size = GetFileSize(hFile, nullptr);
    if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(hFile); return false; }

    std::vector<uint8_t> file_data(size);
    DWORD read = 0;
    ReadFile(hFile, file_data.data(), size, &read, nullptr);
    CloseHandle(hFile);
    if (read != size) return false;

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file_data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(file_data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".text", 5) == 0) {
            ntdll_text_base_ = section->VirtualAddress;
            ntdll_text_size_ = section->Misc.VirtualSize;
            size_t raw_size = std::min<size_t>(section->SizeOfRawData, ntdll_text_size_);
            pristine_ntdll_.resize(raw_size);
            std::memcpy(pristine_ntdll_.data(),
                        file_data.data() + section->PointerToRawData, raw_size);
            return true;
        }
    }
    return false;
}
#endif

void SyscallGuardEngine::monitor_loop() {
    while (running_.load()) {
#ifdef GCAD_PLATFORM_WINDOWS
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe{};
            pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    if (detect_ntdll_unhook(pe.th32ProcessID)) {
                        emit_threat(ThreatCategory::EVASION_UNHOOK,
                            "ntdll.dll .text section modified in PID " +
                            std::to_string(pe.th32ProcessID) + " (" + pe.szExeFile + ")",
                            pe.th32ProcessID);
                    }
                    events_processed_.fetch_add(1);
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
#endif
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

bool SyscallGuardEngine::detect_ntdll_unhook(uint32_t pid) {
#ifdef GCAD_PLATFORM_WINDOWS
    if (pristine_ntdll_.empty()) return false;
    if (pid == GetCurrentProcessId()) return false;

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    HMODULE ntdll = nullptr;
    HMODULE mods[1024];
    DWORD needed;
    if (EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
        for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
            char name[MAX_PATH];
            if (GetModuleBaseNameA(hProc, mods[i], name, MAX_PATH)) {
                if (_stricmp(name, "ntdll.dll") == 0) {
                    ntdll = mods[i];
                    break;
                }
            }
        }
    }

    if (!ntdll) { CloseHandle(hProc); return false; }

    uintptr_t text_addr = reinterpret_cast<uintptr_t>(ntdll) + ntdll_text_base_;
    std::vector<uint8_t> remote_text(pristine_ntdll_.size());
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(text_addr),
                           remote_text.data(), remote_text.size(), &bytes_read)) {
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hProc);

    if (bytes_read < pristine_ntdll_.size()) return false;
    bool modified = std::memcmp(remote_text.data(), pristine_ntdll_.data(), pristine_ntdll_.size()) != 0;
    return modified;
#else
    (void)pid;
    return false;
#endif
}

bool SyscallGuardEngine::validate_caller_stack(uint32_t pid, uintptr_t caller_ip) {
    (void)pid;
#ifdef GCAD_PLATFORM_WINDOWS
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return true;
    MODULEINFO mi{};
    GetModuleInformation(GetCurrentProcess(), ntdll, &mi, sizeof(mi));
    uintptr_t base = reinterpret_cast<uintptr_t>(ntdll);
    uintptr_t end  = base + mi.SizeOfImage;
    return (caller_ip >= base && caller_ip < end);
#else
    (void)caller_ip;
    return true;
#endif
}

bool SyscallGuardEngine::detect_direct_syscall(uintptr_t caller_ip, uint32_t pid) {
#ifdef GCAD_PLATFORM_WINDOWS
    return !validate_caller_stack(pid, caller_ip);
#else
    (void)caller_ip; (void)pid;
    return false;
#endif
}

void SyscallGuardEngine::emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid) {
    threats_detected_.fetch_add(1);
    std::lock_guard lk(mtx_);
    SyscallRecord rec{};
    rec.pid = pid;
    rec.legitimate = false;
    rec.timestamp = std::chrono::steady_clock::now();
    suspicious_records_.push_back(rec);
    if (suspicious_records_.size() > 1000)
        suspicious_records_.erase(suspicious_records_.begin(), suspicious_records_.begin() + 500);

    if (threat_cb_) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::CRITICAL;
        ev.category = cat;
        ev.process_id = pid;
        ev.description = desc;
        threat_cb_(std::move(ev));
    }
}

std::vector<SyscallRecord> SyscallGuardEngine::get_suspicious_records(size_t n) const {
    std::lock_guard lk(const_cast<std::mutex&>(mtx_));
    size_t start = suspicious_records_.size() > n ? suspicious_records_.size() - n : 0;
    return {suspicious_records_.begin() + start, suspicious_records_.end()};
}

} // namespace gcad
