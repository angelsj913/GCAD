#include "gcad/engines/self_defense.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#endif

namespace gcad {

#ifdef GCAD_PLATFORM_WINDOWS
namespace {

// NtQuerySecurityObject/NtSetSecurityObject are the native NT calls that
// GetSecurityInfo/SetSecurityInfo/SetKernelObjectSecurity themselves resolve
// to; GCAD calls them directly (resolved the same way arhs_engine.cpp
// resolves NtSuspendProcess) instead of going through those higher-level
// wrappers, which build/merge the ACL and SID on the caller's behalf.
using NtQuerySecurityObject_t = LONG(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
using NtSetSecurityObject_t   = LONG(NTAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);

// MS-DTYP self-relative SECURITY_DESCRIPTOR header: NtQuerySecurityObject
// always returns this form (offsets, not pointers) so the buffer is
// self-contained. GCAD parses it directly instead of asking an API to hand
// back a ready-made PACL.
#pragma pack(push, 1)
struct SelfRelativeSdHeader {
    uint8_t  Revision;
    uint8_t  Sbz1;
    uint16_t Control;
    uint32_t OwnerOffset;
    uint32_t GroupOffset;
    uint32_t SaclOffset;
    uint32_t DaclOffset;
};
#pragma pack(pop)
constexpr uint16_t kSelfRelativeFlag = 0x8000; // SE_SELF_RELATIVE

constexpr DWORD kDangerousProcessAccessMask =
    PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD |
    PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION | PROCESS_TERMINATE |
    PROCESS_DUP_HANDLE;

// Reads the current DACL of `handle` as raw ACL bytes (header + concatenated
// ACEs), bounds-checking every offset against the buffer NtQuerySecurityObject
// actually returned. Refuses a handle with no DACL present rather than
// treating "implicit allow-all" as zero existing entries to extend -- turning
// that into a DACL containing only our new deny ACE would make the process
// far more restricted than intended, since a non-null DACL denies by default
// anything not explicitly allowed.
bool query_dacl_bytes(HANDLE handle, NtQuerySecurityObject_t query_fn, std::vector<uint8_t>& out_acl_bytes) {
    ULONG needed = 0;
    query_fn(handle, DACL_SECURITY_INFORMATION, nullptr, 0, &needed);
    if (needed == 0 || needed > (16u * 1024 * 1024)) return false;

    std::vector<uint8_t> sd_buffer(needed);
    ULONG needed2 = 0;
    if (query_fn(handle, DACL_SECURITY_INFORMATION, sd_buffer.data(), needed, &needed2) != 0) return false;
    if (sd_buffer.size() < sizeof(SelfRelativeSdHeader)) return false;

    const auto* header = reinterpret_cast<const SelfRelativeSdHeader*>(sd_buffer.data());
    if ((header->Control & kSelfRelativeFlag) == 0) return false;
    if (header->DaclOffset == 0) return false;
    if (header->DaclOffset >= sd_buffer.size() ||
        header->DaclOffset + sizeof(ACL) > sd_buffer.size()) return false;

    const auto* acl_header = reinterpret_cast<const ACL*>(sd_buffer.data() + header->DaclOffset);
    if (static_cast<size_t>(header->DaclOffset) + acl_header->AclSize > sd_buffer.size()) return false;

    out_acl_bytes.assign(sd_buffer.begin() + header->DaclOffset,
                         sd_buffer.begin() + header->DaclOffset + acl_header->AclSize);
    return true;
}

// Escape hatch for development/debugging: a debugger (WinDbg, gdb via a
// remote stub, Process Hacker) needs PROCESS_VM_WRITE/SUSPEND_RESUME/
// DUP_HANDLE on GCAD itself, exactly the rights the protection DACL denies to
// everyone else. Checked once at start(), not cached, so it always reflects
// how the process was actually launched.
bool self_protection_disabled_by_env() {
    char value[8]{};
    const DWORD len = GetEnvironmentVariableA("GCAD_DISABLE_SELF_PROTECT", value, sizeof(value));
    return len > 0 && len < sizeof(value) && value[0] != '0';
}

std::pair<NtQuerySecurityObject_t, NtSetSecurityObject_t> resolve_security_object_functions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return {nullptr, nullptr};
    auto query_fn = reinterpret_cast<NtQuerySecurityObject_t>(
        reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQuerySecurityObject")));
    auto set_fn = reinterpret_cast<NtSetSecurityObject_t>(
        reinterpret_cast<void*>(GetProcAddress(ntdll, "NtSetSecurityObject")));
    return {query_fn, set_fn};
}

} // namespace
#endif

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
#ifdef GCAD_PLATFORM_WINDOWS
    // Best-effort: a process launched without rights to change its own DACL
    // (rare, but possible under a locked-down policy) still starts, it just
    // has nothing to verify later -- check_handle_integrity() only flags a
    // problem once protection was actually applied and then found missing.
    if (self_protection_disabled_by_env()) {
        GCAD_LOG(WARN, "SelfDefense: process-protection DACL disabled via "
                       "GCAD_DISABLE_SELF_PROTECT (debuggers and management tools can attach)");
        protection_applied_ = false;
    } else {
        protection_applied_ = apply_process_protection_dacl();
        if (!protection_applied_)
            GCAD_LOG(WARN, "SelfDefense: could not apply process-protection DACL");
    }
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
                "GCAD process-protection ACL was weakened or removed after being applied");
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
        for (int i = 0; i < 20 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool SelfDefenseEngine::is_dangerous_process_access(unsigned long granted_access) noexcept {
#ifdef GCAD_PLATFORM_WINDOWS
    return (granted_access & kDangerousProcessAccessMask) != 0;
#else
    (void)granted_access;
    return false;
#endif
}

#ifdef GCAD_PLATFORM_WINDOWS
std::vector<SelfDefenseEngine::RawAclEntry> SelfDefenseEngine::parse_acl_entries(
    const uint8_t* acl_bytes, size_t size) noexcept {
    std::vector<RawAclEntry> entries;
    if (!acl_bytes || size < sizeof(ACL)) return entries;

    const auto* header = reinterpret_cast<const ACL*>(acl_bytes);
    size_t offset = sizeof(ACL);
    for (uint16_t i = 0; i < header->AceCount; ++i) {
        if (offset + sizeof(ACE_HEADER) > size) break; // truncated/corrupt: stop, keep what parsed cleanly
        const auto* ace_header = reinterpret_cast<const ACE_HEADER*>(acl_bytes + offset);
        if (ace_header->AceSize < sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) ||
            offset + ace_header->AceSize > size) {
            break;
        }
        ACCESS_MASK mask = 0;
        std::memcpy(&mask, acl_bytes + offset + sizeof(ACE_HEADER), sizeof(mask));
        entries.push_back({ace_header->AceType, static_cast<uint32_t>(mask)});
        offset += ace_header->AceSize;
    }
    return entries;
}

std::vector<uint8_t> SelfDefenseEngine::build_acl_with_prepended_deny(
    const uint8_t* existing_acl_bytes, size_t existing_size, uint32_t deny_mask) {
    if (!existing_acl_bytes || existing_size < sizeof(ACL)) return {};

    const auto* existing_header = reinterpret_cast<const ACL*>(existing_acl_bytes);
    if (existing_header->AclSize != existing_size) return {}; // caller's slice must match the header exactly
    if (existing_header->AceCount == 0xFFFFu) return {};       // would overflow AceCount on +1

    // S-1-1-0 (Everyone): Revision=1, one sub-authority, World authority
    // {0,0,0,0,0,1}. Hand-built rather than obtained from AllocateAndInitializeSid.
    struct SidOneSubAuthority {
        uint8_t  Revision;
        uint8_t  SubAuthorityCount;
        uint8_t  IdentifierAuthority[6];
        uint32_t SubAuthority[1];
    };
    SidOneSubAuthority everyone_sid{1, 1, {0, 0, 0, 0, 0, 1}, {0}};

    const auto deny_ace_size = static_cast<uint16_t>(sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sizeof(everyone_sid));
    const size_t total_size = existing_size + deny_ace_size;
    if (total_size > 0xFFFFu) return {}; // would not fit in ACL::AclSize (a USHORT)

    std::vector<uint8_t> buffer(total_size, 0);
    auto* new_header = reinterpret_cast<ACL*>(buffer.data());
    new_header->AclRevision = ACL_REVISION;
    new_header->Sbz1 = 0;
    new_header->AclSize = static_cast<uint16_t>(total_size);
    new_header->AceCount = static_cast<uint16_t>(existing_header->AceCount + 1);
    new_header->Sbz2 = 0;

    size_t offset = sizeof(ACL);
    auto* deny_header = reinterpret_cast<ACE_HEADER*>(buffer.data() + offset);
    deny_header->AceType = ACCESS_DENIED_ACE_TYPE;
    deny_header->AceFlags = 0;
    deny_header->AceSize = deny_ace_size;
    const ACCESS_MASK mask_value = static_cast<ACCESS_MASK>(deny_mask);
    std::memcpy(buffer.data() + offset + sizeof(ACE_HEADER), &mask_value, sizeof(mask_value));
    std::memcpy(buffer.data() + offset + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK),
               &everyone_sid, sizeof(everyone_sid));
    offset += deny_ace_size;

    std::memcpy(buffer.data() + offset, existing_acl_bytes + sizeof(ACL), existing_size - sizeof(ACL));
    return buffer;
}
#endif

bool SelfDefenseEngine::check_handle_integrity() {
#ifdef GCAD_PLATFORM_WINDOWS
    // Nothing to verify if we never managed to protect ourselves in the first
    // place -- that is a startup-time limitation, not evidence of tampering.
    if (!protection_applied_) return true;
    return verify_process_protection_dacl();
#else
    return true;
#endif
}

#ifdef GCAD_PLATFORM_WINDOWS
bool SelfDefenseEngine::apply_process_protection_dacl() {
    // Prepend a hand-built DENY ACE for dangerous process-manipulation rights
    // (write/execute memory, create threads, suspend, terminate, duplicate
    // handles) to Everyone, ahead of the OS-assigned default ACEs -- so
    // another process cannot inject into or kill GCAD even with an open
    // handle. The existing DACL is read and extended rather than replaced
    // wholesale, since fully reinventing Windows' default process ACL from
    // scratch risks locking out rights the OS itself depends on.
    const auto [query_fn, set_fn] = resolve_security_object_functions();
    if (!query_fn || !set_fn) return false;

    std::vector<uint8_t> existing_dacl;
    if (!query_dacl_bytes(GetCurrentProcess(), query_fn, existing_dacl)) return false;

    const auto new_acl = build_acl_with_prepended_deny(
        existing_dacl.data(), existing_dacl.size(), kDangerousProcessAccessMask);
    if (new_acl.empty()) return false;

    SECURITY_DESCRIPTOR sd{};
    sd.Revision = SECURITY_DESCRIPTOR_REVISION;
    sd.Sbz1 = 0;
    sd.Control = SE_DACL_PRESENT;
    sd.Owner = nullptr;
    sd.Group = nullptr;
    sd.Sacl = nullptr;
    sd.Dacl = const_cast<PACL>(reinterpret_cast<const ACL*>(new_acl.data()));

    return set_fn(GetCurrentProcess(), DACL_SECURITY_INFORMATION, &sd) == 0; // STATUS_SUCCESS
}

bool SelfDefenseEngine::verify_process_protection_dacl() {
    const auto [query_fn, set_fn] = resolve_security_object_functions();
    (void)set_fn;
    if (!query_fn) return false;

    std::vector<uint8_t> dacl;
    if (!query_dacl_bytes(GetCurrentProcess(), query_fn, dacl)) return false;

    for (const auto& entry : parse_acl_entries(dacl.data(), dacl.size())) {
        if (entry.ace_type == ACCESS_DENIED_ACE_TYPE && is_dangerous_process_access(entry.mask))
            return true;
    }
    return false;
}
#endif

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
