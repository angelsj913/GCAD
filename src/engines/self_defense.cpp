#include "gcad/engines/self_defense.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#endif

namespace gcad {

SelfDefenseEngine::SelfDefenseEngine() = default;
SelfDefenseEngine::~SelfDefenseEngine() { stop(); }

ErrorCode SelfDefenseEngine::start() {
    if (running_.load()) return ErrorCode::OK;
#ifdef GCAD_PLATFORM_WINDOWS
    own_pid_ = GetCurrentProcessId();
    HMODULE hmod = GetModuleHandleA(nullptr);
    if (hmod) {
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hmod);
        auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(hmod) + dos->e_lfanew);
        auto section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            if (std::memcmp(section->Name, ".text", 5) == 0) {
                text_base_ = reinterpret_cast<uintptr_t>(hmod) + section->VirtualAddress;
                text_size_ = section->Misc.VirtualSize;
                original_text_section_.resize(text_size_);
                std::memcpy(original_text_section_.data(),
                            reinterpret_cast<const void*>(text_base_), text_size_);
                break;
            }
        }
    }
#else
    own_pid_ = getpid();
#endif
    running_.store(true);
    guard_thread_ = std::thread(&SelfDefenseEngine::guard_loop, this);
    GCAD_LOG(INFO, "SelfDefense engine started for PID " + std::to_string(own_pid_));
    return ErrorCode::OK;
}

ErrorCode SelfDefenseEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (guard_thread_.joinable()) guard_thread_.join();
    secure_zero(original_text_section_.data(), original_text_section_.size());
    return ErrorCode::OK;
}

EngineStatus SelfDefenseEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void SelfDefenseEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void SelfDefenseEngine::guard_loop() {
    while (running_.load()) {
        if (!check_handle_integrity()) {
            emit_threat(ThreatCategory::EVASION_UNHOOK,
                "Unauthorized handle access to GCAD process detected");
        }
        if (!check_memory_integrity()) {
            emit_threat(ThreatCategory::MEMORY_INJECTION,
                "GCAD .text section tampered — possible code injection");
        }
        if (!check_module_integrity()) {
            emit_threat(ThreatCategory::DLL_INJECTION,
                "Unexpected module loaded into GCAD process");
        }
        events_processed_.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

bool SelfDefenseEngine::check_handle_integrity() {
#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return true;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    bool ok = true;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == own_pid_) continue;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            HANDLE hTest = nullptr;
            BOOL dup = DuplicateHandle(hProc, GetCurrentProcess(), GetCurrentProcess(),
                                        &hTest, PROCESS_ALL_ACCESS, FALSE, 0);
            if (dup && hTest) {
                CloseHandle(hTest);
                ok = false;
            }
            CloseHandle(hProc);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return ok;
#else
    return true;
#endif
}

bool SelfDefenseEngine::check_memory_integrity() {
#ifdef GCAD_PLATFORM_WINDOWS
    if (original_text_section_.empty() || text_base_ == 0) return true;
    auto current = reinterpret_cast<const uint8_t*>(text_base_);
    bool intact = std::memcmp(current, original_text_section_.data(), text_size_) == 0;
    if (!intact) threats_detected_.fetch_add(1);
    return intact;
#else
    return true;
#endif
}

bool SelfDefenseEngine::check_module_integrity() {
#ifdef GCAD_PLATFORM_WINDOWS
    static std::vector<std::string> known_modules;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, own_pid_);
    if (snap == INVALID_HANDLE_VALUE) return true;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    std::vector<std::string> current_modules;
    if (Module32First(snap, &me)) {
        do {
            current_modules.push_back(me.szModule);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);

    if (known_modules.empty()) {
        known_modules = current_modules;
        return true;
    }

    bool ok = true;
    for (auto& m : current_modules) {
        if (std::find(known_modules.begin(), known_modules.end(), m) == known_modules.end()) {
            ok = false;
            threats_detected_.fetch_add(1);
            GCAD_LOG(WARN, "SelfDefense: unexpected module loaded: " + m);
        }
    }
    known_modules = current_modules;
    return ok;
#else
    return true;
#endif
}

void SelfDefenseEngine::emit_threat(ThreatCategory cat, const std::string& desc) {
    threats_detected_.fetch_add(1);
    if (threat_cb_) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::CRITICAL;
        ev.category = cat;
        ev.process_id = own_pid_;
        ev.description = desc;
        threat_cb_(std::move(ev));
    }
}

} // namespace gcad
