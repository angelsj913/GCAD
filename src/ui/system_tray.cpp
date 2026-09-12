#include "gcad/ui/system_tray.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/alert/alert_manager.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace gcad {

uint32_t SystemTrayManager::threat_color_rgb(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::SAFE:     return 0x00C800;
        case ThreatLevel::LOW:      return 0x88CC00;
        case ThreatLevel::MEDIUM:   return 0xFFAA00;
        case ThreatLevel::HIGH:     return 0xFF4400;
        case ThreatLevel::CRITICAL: return 0xFF0000;
        default:                    return 0x00C800;
    }
}

TrayAction SystemTrayManager::map_menu_id(int id) {
    switch (id) {
        case MENU_RESTORE:   return TrayAction::RESTORE_WINDOW;
        case MENU_DASHBOARD: return TrayAction::OPEN_DASHBOARD;
        case MENU_ALERTS:    return TrayAction::OPEN_ALERTS;
        case MENU_SETTINGS:  return TrayAction::OPEN_SETTINGS;
        case MENU_TOGGLE:    return TrayAction::TOGGLE_PROTECTION;
        case MENU_EXIT:      return TrayAction::EXIT;
        default:             return TrayAction::NONE;
    }
}

#ifdef GCAD_PLATFORM_WINDOWS

static constexpr UINT WM_TRAYICON = WM_APP + 100;
static SystemTrayManager* g_tray = nullptr;

struct SystemTrayManager::Impl {
    HWND msg_hwnd{nullptr};
    NOTIFYICONDATAW nid{};
    ATOM wc_atom{0};
    bool initialized{false};
    HICON icon_safe{nullptr};
    HICON icon_warn{nullptr};
    HICON icon_danger{nullptr};
    ThreatLevel current_level{ThreatLevel::SAFE};
};

static HICON create_status_icon(COLORREF fill, COLORREF border) {
    const int sz = 16;
    HDC sdc = GetDC(nullptr);
    HDC cdc = CreateCompatibleDC(sdc);
    HDC mdc = CreateCompatibleDC(sdc);
    HBITMAP hbm_c = CreateCompatibleBitmap(sdc, sz, sz);
    HBITMAP hbm_m = CreateBitmap(sz, sz, 1, 1, nullptr);

    auto old_c = (HBITMAP)SelectObject(cdc, hbm_c);
    auto old_m = (HBITMAP)SelectObject(mdc, hbm_m);

    RECT rc = {0, 0, sz, sz};
    FillRect(cdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));

    HBRUSH br = CreateSolidBrush(fill);
    HPEN pn = CreatePen(PS_SOLID, 1, border);
    auto ob = SelectObject(cdc, br);
    auto op = SelectObject(cdc, pn);
    Ellipse(cdc, 1, 1, sz - 1, sz - 1);
    SelectObject(cdc, ob);
    SelectObject(cdc, op);
    DeleteObject(br);
    DeleteObject(pn);

    FillRect(mdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
    SelectObject(mdc, GetStockObject(BLACK_BRUSH));
    SelectObject(mdc, GetStockObject(BLACK_PEN));
    Ellipse(mdc, 1, 1, sz - 1, sz - 1);

    SelectObject(cdc, old_c);
    SelectObject(mdc, old_m);
    DeleteDC(cdc);
    DeleteDC(mdc);
    ReleaseDC(nullptr, sdc);

    ICONINFO ii{};
    ii.fIcon = TRUE;
    ii.hbmMask = hbm_m;
    ii.hbmColor = hbm_c;
    HICON icon = CreateIconIndirect(&ii);
    DeleteObject(hbm_c);
    DeleteObject(hbm_m);
    return icon;
}

static LRESULT CALLBACK tray_wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_TRAYICON && g_tray) {
        UINT ev = LOWORD(lp);
        if (ev == WM_RBUTTONUP)
            g_tray->show_context_menu();
        else if (ev == WM_LBUTTONDBLCLK)
            g_tray->restore_window();
        return 0;
    }
    if (msg == WM_COMMAND && g_tray) {
        g_tray->handle_menu_command(LOWORD(wp));
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

SystemTrayManager::SystemTrayManager() : impl_(std::make_unique<Impl>()) {}

SystemTrayManager::~SystemTrayManager() { cleanup(); }

bool SystemTrayManager::init(void* main_hwnd, EngineManager* em, AlertManager* am) {
    main_hwnd_ = main_hwnd;
    engine_mgr_ = em;
    alert_mgr_ = am;
    g_tray = this;

    impl_->icon_safe   = create_status_icon(RGB(0, 200, 0),   RGB(200, 255, 200));
    impl_->icon_warn   = create_status_icon(RGB(255, 170, 0), RGB(255, 220, 100));
    impl_->icon_danger = create_status_icon(RGB(220, 30, 0),  RGB(255, 100, 100));

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = tray_wnd_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"GCAD_SystemTray";
    impl_->wc_atom = RegisterClassExW(&wc);
    if (!impl_->wc_atom) return false;

    impl_->msg_hwnd = CreateWindowExW(0, L"GCAD_SystemTray", L"", 0,
                                       0, 0, 0, 0, HWND_MESSAGE, nullptr,
                                       wc.hInstance, nullptr);
    if (!impl_->msg_hwnd) return false;

    auto& nid = impl_->nid;
    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = impl_->msg_hwnd;
    nid.uID = 2;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = impl_->icon_safe;
    lstrcpynW(nid.szTip, L"GCAD — Protection Active", 128);

    if (Shell_NotifyIconW(NIM_ADD, &nid)) {
        impl_->initialized = true;
        nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
    return impl_->initialized;
}

void SystemTrayManager::cleanup() {
    if (!impl_) return;
    if (impl_->initialized) {
        Shell_NotifyIconW(NIM_DELETE, &impl_->nid);
        impl_->initialized = false;
    }
    if (impl_->msg_hwnd) { DestroyWindow(impl_->msg_hwnd); impl_->msg_hwnd = nullptr; }
    if (impl_->wc_atom) {
        UnregisterClassW(L"GCAD_SystemTray", GetModuleHandleW(nullptr));
        impl_->wc_atom = 0;
    }
    if (impl_->icon_safe)   { DestroyIcon(impl_->icon_safe);   impl_->icon_safe = nullptr; }
    if (impl_->icon_warn)   { DestroyIcon(impl_->icon_warn);   impl_->icon_warn = nullptr; }
    if (impl_->icon_danger) { DestroyIcon(impl_->icon_danger); impl_->icon_danger = nullptr; }
    g_tray = nullptr;
}

void SystemTrayManager::update_icon(ThreatLevel level) {
    if (!impl_ || !impl_->initialized) return;
    if (impl_->current_level == level) return;
    impl_->current_level = level;

    HICON new_icon;
    const wchar_t* tip;
    if (level >= ThreatLevel::HIGH) {
        new_icon = impl_->icon_danger;
        tip = L"GCAD — Threat Detected!";
    } else if (level >= ThreatLevel::MEDIUM) {
        new_icon = impl_->icon_warn;
        tip = L"GCAD — Warning";
    } else {
        new_icon = impl_->icon_safe;
        tip = L"GCAD — Protection Active";
    }

    auto& nid = impl_->nid;
    nid.uFlags = NIF_ICON | NIF_TIP;
    nid.hIcon = new_icon;
    lstrcpynW(nid.szTip, tip, 128);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void SystemTrayManager::show_notification(const std::string& title,
                                           const std::string& msg,
                                           ThreatLevel level) {
    if (!impl_ || !impl_->initialized) return;

    auto& nid = impl_->nid;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = (level >= ThreatLevel::HIGH)   ? NIIF_ERROR
                    : (level >= ThreatLevel::MEDIUM)  ? NIIF_WARNING
                    :                                   NIIF_INFO;

    int tl = MultiByteToWideChar(CP_UTF8, 0, title.c_str(), -1, nullptr, 0);
    if (tl > 0 && tl < 64)
        MultiByteToWideChar(CP_UTF8, 0, title.c_str(), -1, nid.szInfoTitle, 64);
    else
        lstrcpynW(nid.szInfoTitle, L"GCAD Alert", 64);

    int ml = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, nullptr, 0);
    if (ml > 0 && ml < 256)
        MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, nid.szInfo, 256);
    else
        lstrcpynW(nid.szInfo, L"Threat detected", 256);

    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void SystemTrayManager::on_minimize() {
    if (!main_hwnd_) return;
    ShowWindow(static_cast<HWND>(main_hwnd_), SW_HIDE);
    window_hidden_.store(true);
}

void SystemTrayManager::restore_window() {
    if (!main_hwnd_) return;
    ShowWindow(static_cast<HWND>(main_hwnd_), SW_SHOW);
    ShowWindow(static_cast<HWND>(main_hwnd_), SW_RESTORE);
    SetForegroundWindow(static_cast<HWND>(main_hwnd_));
    window_hidden_.store(false);
}

TrayAction SystemTrayManager::poll_action() {
    return static_cast<TrayAction>(pending_action_.exchange(0));
}

void SystemTrayManager::show_context_menu() {
    if (!impl_ || !impl_->msg_hwnd) return;

    bool all_running = engine_mgr_ && engine_mgr_->all_running();
    size_t unacked = alert_mgr_ ? alert_mgr_->unacknowledged_count() : 0;

    HMENU menu = CreatePopupMenu();

    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0,
                all_running ? L"GCAD — Protection Active"
                            : L"GCAD — Protection Paused");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, MENU_RESTORE, L"Open GCAD");
    AppendMenuW(menu, MF_STRING, MENU_DASHBOARD, L"Dashboard");

    wchar_t alert_buf[64];
    if (unacked > 0)
        _snwprintf(alert_buf, 64, L"Alerts (%u)", static_cast<unsigned>(unacked));
    else
        lstrcpynW(alert_buf, L"Alerts", 64);
    AppendMenuW(menu, MF_STRING, MENU_ALERTS, alert_buf);

    AppendMenuW(menu, MF_STRING, MENU_SETTINGS, L"Settings");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, MENU_TOGGLE,
                all_running ? L"Pause Protection" : L"Resume Protection");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, MENU_EXIT, L"Exit");

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(impl_->msg_hwnd);
    TrackPopupMenu(menu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y,
                   0, impl_->msg_hwnd, nullptr);
    DestroyMenu(menu);
}

void SystemTrayManager::handle_menu_command(int id) {
    TrayAction action = map_menu_id(id);
    if (action == TrayAction::NONE) return;

    pending_action_.store(static_cast<int>(action));

    if (action == TrayAction::OPEN_DASHBOARD ||
        action == TrayAction::OPEN_ALERTS ||
        action == TrayAction::OPEN_SETTINGS ||
        action == TrayAction::RESTORE_WINDOW) {
        restore_window();
    }
}

#else // Non-Windows stubs

SystemTrayManager::SystemTrayManager() = default;
SystemTrayManager::~SystemTrayManager() = default;
bool SystemTrayManager::init(void*, EngineManager*, AlertManager*) { return false; }
void SystemTrayManager::cleanup() {}
void SystemTrayManager::update_icon(ThreatLevel) {}
void SystemTrayManager::show_notification(const std::string&, const std::string&, ThreatLevel) {}
void SystemTrayManager::on_minimize() {}
void SystemTrayManager::restore_window() {}
TrayAction SystemTrayManager::poll_action() { return TrayAction::NONE; }

#endif

} // namespace gcad
