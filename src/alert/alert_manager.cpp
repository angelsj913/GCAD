#include "gcad/alert/alert_manager.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace gcad {

namespace {

const char* map_category_source(ThreatCategory cat) {
    switch (cat) {
        case ThreatCategory::MEMORY_INJECTION:
        case ThreatCategory::PROCESS_HOLLOW:
        case ThreatCategory::DLL_INJECTION:
        case ThreatCategory::APC_INJECTION:
        case ThreatCategory::REFLECTIVE_LOAD:
        case ThreatCategory::SHELLCODE:
        case ThreatCategory::FILELESS_EXEC:
            return "PMSR";
        case ThreatCategory::DNS_TUNNEL:
        case ThreatCategory::DGA_DOMAIN:
            return "DnsMon";
        case ThreatCategory::RANSOMWARE:
        case ThreatCategory::FILE_ENCRYPT:
        case ThreatCategory::BACKDOOR_ACCOUNT:
            return "ARHS";
        case ThreatCategory::NETWORK_SCAN:
        case ThreatCategory::SYN_FLOOD:
        case ThreatCategory::UDP_FLOOD:
        case ThreatCategory::ARP_POISON:
        case ThreatCategory::ICMP_COVERT:
        case ThreatCategory::RAW_SOCKET_PROBE:
            return "ZRGP";
        case ThreatCategory::REGISTRY_TAMPER:
            return "RegMon";
        case ThreatCategory::EVASION_AMSI:
        case ThreatCategory::EVASION_ETW:
        case ThreatCategory::EVASION_UNHOOK:
        case ThreatCategory::DIRECT_SYSCALL:
            return "SyscallGuard";
        case ThreatCategory::PPID_SPOOF:
        case ThreatCategory::KERBEROS_ATTACK:
        case ThreatCategory::NTLM_COERCE:
        case ThreatCategory::CREDENTIAL_DUMP:
            return "KernelMon";
        case ThreatCategory::ENTROPY_ANOMALY:
        case ThreatCategory::SUSPICIOUS_BINARY:
            return "DeepScan";
        case ThreatCategory::ANTI_FORENSIC:
            return "SelfDefense";
        case ThreatCategory::FILE_INTEGRITY_VIOLATION:
            return "FIM";
        case ThreatCategory::YARA_RULE_MATCH:
            return "YARA";
        default:
            return "GCAD";
    }
}

} // namespace

// --- Platform: Windows tray + balloon + sound ---
#ifdef GCAD_PLATFORM_WINDOWS

struct AlertManager::TrayState {
    HWND  hwnd{nullptr};
    NOTIFYICONDATAW nid{};
    bool  initialized{false};
    ATOM  wc_atom{0};
};

void AlertManager::init_tray() {
    if (!tray_) tray_ = std::make_unique<TrayState>();

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = DefWindowProcW;
    wc.hInstance      = GetModuleHandleW(nullptr);
    wc.lpszClassName  = L"GCAD_AlertTray";
    tray_->wc_atom = RegisterClassExW(&wc);
    if (!tray_->wc_atom) return;

    tray_->hwnd = CreateWindowExW(0, L"GCAD_AlertTray", L"", 0,
                                  0, 0, 0, 0, HWND_MESSAGE, nullptr,
                                  wc.hInstance, nullptr);
    if (!tray_->hwnd) return;

    auto& nid      = tray_->nid;
    nid.cbSize      = sizeof(NOTIFYICONDATAW);
    nid.hWnd        = tray_->hwnd;
    nid.uID         = 1;
    nid.uFlags      = NIF_ICON | NIF_TIP;
    nid.hIcon       = LoadIconW(nullptr, reinterpret_cast<LPCWSTR>(IDI_APPLICATION));
    lstrcpynW(nid.szTip, L"GCAD — Security Monitor", 64);

    if (Shell_NotifyIconW(NIM_ADD, &nid))
        tray_->initialized = true;
}

void AlertManager::cleanup_tray() {
    if (!tray_) return;
    if (tray_->initialized) {
        Shell_NotifyIconW(NIM_DELETE, &tray_->nid);
        tray_->initialized = false;
    }
    if (tray_->hwnd) {
        DestroyWindow(tray_->hwnd);
        tray_->hwnd = nullptr;
    }
    if (tray_->wc_atom) {
        UnregisterClassW(L"GCAD_AlertTray", GetModuleHandleW(nullptr));
        tray_->wc_atom = 0;
    }
}

void AlertManager::show_balloon(const AlertRecord& rec) {
    if (!tray_ || !tray_->initialized) return;

    auto& nid    = tray_->nid;
    nid.uFlags   = NIF_INFO;

    DWORD flags = NIIF_NONE;
    if (rec.level >= ThreatLevel::HIGH)        flags = NIIF_ERROR;
    else if (rec.level >= ThreatLevel::MEDIUM)  flags = NIIF_WARNING;
    else                                        flags = NIIF_INFO;
    nid.dwInfoFlags = flags;

    static const wchar_t* titles[] = {
        L"GCAD — Safe", L"GCAD — Low", L"GCAD — Medium",
        L"GCAD — High", L"GCAD — Critical"
    };
    lstrcpynW(nid.szInfoTitle,
              titles[std::min(static_cast<int>(rec.level), 4)], 64);

    int len = MultiByteToWideChar(CP_UTF8, 0, rec.description.c_str(), -1,
                                  nullptr, 0);
    if (len > 0 && len < 256)
        MultiByteToWideChar(CP_UTF8, 0, rec.description.c_str(), -1,
                            nid.szInfo, 256);
    else
        lstrcpynW(nid.szInfo, L"Threat detected", 256);

    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void AlertManager::play_sound(ThreatLevel level) {
    UINT type = MB_ICONASTERISK;
    if (level >= ThreatLevel::CRITICAL)       type = MB_ICONHAND;
    else if (level >= ThreatLevel::MEDIUM)    type = MB_ICONEXCLAMATION;
    MessageBeep(type);
}

#endif // GCAD_PLATFORM_WINDOWS

// --- Core logic (platform-independent) ---

AlertManager::AlertManager() {
#ifdef GCAD_PLATFORM_WINDOWS
    tray_ = std::make_unique<TrayState>();
    init_tray();
#endif
}

AlertManager::~AlertManager() {
#ifdef GCAD_PLATFORM_WINDOWS
    cleanup_tray();
#endif
}

const char* AlertManager::category_source(ThreatCategory cat) {
    return map_category_source(cat);
}

void AlertManager::push(const ThreatEvent& ev) {
    if (ev.level < min_level_) return;

    AlertRecord rec;
    rec.id           = next_id_.fetch_add(1);
    rec.timestamp    = ev.timestamp.time_since_epoch().count()
                           ? ev.timestamp
                           : std::chrono::system_clock::now();
    rec.level        = ev.level;
    rec.category     = ev.category;
    rec.source       = map_category_source(ev.category);
    rec.description  = ev.description;
    rec.process_name = ev.process_name;
    rec.process_id   = ev.process_id;

    {
        std::lock_guard lk(mtx_);
        history_.push_back(rec);
        while (history_.size() > MAX_HISTORY)
            history_.pop_front();
    }

#ifdef GCAD_PLATFORM_WINDOWS
    if (toast_enabled_.load()) show_balloon(rec);
    if (sound_enabled_.load()) play_sound(rec.level);
#endif
}

std::vector<AlertRecord> AlertManager::recent(size_t n) const {
    std::lock_guard lk(mtx_);
    std::vector<AlertRecord> out;
    out.reserve(std::min(n, history_.size()));
    size_t start = history_.size() > n ? history_.size() - n : 0;
    for (size_t i = start; i < history_.size(); ++i)
        out.push_back(history_[i]);
    return out;
}

size_t AlertManager::total_count() const {
    std::lock_guard lk(mtx_);
    return history_.size();
}

size_t AlertManager::unacknowledged_count() const {
    std::lock_guard lk(mtx_);
    size_t count = 0;
    for (const auto& r : history_)
        if (!r.acknowledged) ++count;
    return count;
}

void AlertManager::acknowledge(uint64_t id) {
    std::lock_guard lk(mtx_);
    for (auto& r : history_) {
        if (r.id == id) { r.acknowledged = true; return; }
    }
}

void AlertManager::acknowledge_all() {
    std::lock_guard lk(mtx_);
    for (auto& r : history_) r.acknowledged = true;
}

void AlertManager::clear() {
    std::lock_guard lk(mtx_);
    history_.clear();
}

void AlertManager::set_min_level(ThreatLevel level) {
    std::lock_guard lk(mtx_);
    min_level_ = level;
}

ThreatLevel AlertManager::min_level() const {
    std::lock_guard lk(mtx_);
    return min_level_;
}

void AlertManager::set_sound_enabled(bool on)  { sound_enabled_.store(on); }
bool AlertManager::sound_enabled()       const { return sound_enabled_.load(); }
void AlertManager::set_toast_enabled(bool on)  { toast_enabled_.store(on); }
bool AlertManager::toast_enabled()       const { return toast_enabled_.load(); }

} // namespace gcad
