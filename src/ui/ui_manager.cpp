#include "gcad/ui/ui_manager.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/scanner/deep_scanner.hpp"
#include "gcad/engines/etg_ri_engine.hpp"
#include "gcad/engines/arhs_engine.hpp"
#include "gcad/ui/views/dashboard_view.hpp"
#include "gcad/ui/views/scan_view.hpp"
#include "gcad/ui/views/network_view.hpp"
#include "gcad/ui/views/quarantine_view.hpp"
#include "gcad/ui/views/forensics_view.hpp"
#include "gcad/ui/views/alert_view.hpp"
#include "gcad/ui/views/settings_view.hpp"
#include "gcad/alert/alert_manager.hpp"
#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui.h"
#include "imgui_internal.h"

#ifdef GCAD_PLATFORM_WINDOWS
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#ifdef _MSC_VER
#pragma comment(lib, "d3d11.lib")
#endif

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace gcad::ui {

struct UIManager::DX11State {
    ID3D11Device*           device = nullptr;
    ID3D11DeviceContext*    ctx    = nullptr;
    IDXGISwapChain*         swap   = nullptr;
    ID3D11RenderTargetView* rtv    = nullptr;
    HWND                    hwnd   = nullptr;
    WNDCLASSEXW             wc{};
    bool                    imgui_win32_ready = false;
    bool                    imgui_dx11_ready = false;
};

static UIManager* g_ui = nullptr;
// (width<<16)|height of a pending swap-chain resize; 0 = none. Set from wnd_proc,
// consumed in run_frame so the resize happens on the render thread.
static std::atomic<uint32_t> g_pending_resize{0};

static LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp)) return true;
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    if (msg == WM_SIZE && wp != SIZE_MINIMIZED) {
        UINT w = LOWORD(lp), h = HIWORD(lp);
        if (w && h) g_pending_resize.store((w << 16) | h);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

UIManager::UIManager() : dx_(std::make_unique<DX11State>()) {}
UIManager::~UIManager() { shutdown(); }

ErrorCode UIManager::init(EngineManager* em, DeepScanner* sc, AlertManager* am) {
    engine_mgr_ = em;
    scanner_ = sc;
    alert_mgr_ = am;
    g_ui = this;

    dx_->wc = {sizeof(WNDCLASSEXW), CS_CLASSDC, wnd_proc, 0L, 0L,
               GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
               L"GCAD_WC", nullptr};
    if (!RegisterClassExW(&dx_->wc)) return ErrorCode::ERR_INIT_FAIL;

    const int client_width = 1360;
    const int client_height = 860;
    const DWORD window_style = WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME);
    RECT window_rect{0, 0, client_width, client_height};
    AdjustWindowRect(&window_rect, window_style, FALSE);
    const int width = window_rect.right - window_rect.left;
    const int height = window_rect.bottom - window_rect.top;
    const int left = std::max(0, (GetSystemMetrics(SM_CXSCREEN) - width) / 2);
    const int top = std::max(0, (GetSystemMetrics(SM_CYSCREEN) - height) / 2);

    dx_->hwnd = CreateWindowW(L"GCAD_WC", L"GCAD v1.0.0 — Galoisconnection Antivirus & Defense",
                              window_style, left, top, width, height,
                              nullptr, nullptr, dx_->wc.hInstance, nullptr);
    if (!dx_->hwnd) { shutdown(); return ErrorCode::ERR_INIT_FAIL; }

    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = dx_->hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                    nullptr, 0, D3D11_SDK_VERSION, &sd, &dx_->swap, &dx_->device, &fl, &dx_->ctx);
    if (FAILED(hr) || !dx_->swap || !dx_->device || !dx_->ctx) {
        shutdown();
        return ErrorCode::ERR_INIT_FAIL;
    }

    ID3D11Texture2D* back_buf = nullptr;
    hr = dx_->swap->GetBuffer(0, IID_PPV_ARGS(&back_buf));
    if (FAILED(hr) || !back_buf) {
        shutdown();
        return ErrorCode::ERR_INIT_FAIL;
    }
    hr = dx_->device->CreateRenderTargetView(back_buf, nullptr, &dx_->rtv);
    back_buf->Release();
    if (FAILED(hr) || !dx_->rtv) {
        shutdown();
        return ErrorCode::ERR_INIT_FAIL;
    }

    ShowWindow(dx_->hwnd, SW_SHOWNORMAL);
    UpdateWindow(dx_->hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Crisp anti-aliased UI font. Falls back to the built-in atlas if no TTF is found.
    ImGuiIO& io = ImGui::GetIO();
    const char* font_candidates[] = {
        "C:\\Windows\\Fonts\\consola.ttf",
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
    };
    for (const char* path : font_candidates) {
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            g_font_body = io.Fonts->AddFontFromFileTTF(path, 17.0f);
            g_font_heading = io.Fonts->AddFontFromFileTTF(path, 21.0f);
            g_font_large = io.Fonts->AddFontFromFileTTF(path, 27.0f);
        }
        if (g_font_body)
            break;
    }
    if (!g_font_body) g_font_body = io.Fonts->AddFontDefault();
    if (!g_font_heading) g_font_heading = g_font_body;
    if (!g_font_large) g_font_large = g_font_heading;

    apply_dark_theme();

    if (!ImGui_ImplWin32_Init(dx_->hwnd)) {
        ImGui::DestroyContext();
        shutdown();
        return ErrorCode::ERR_INIT_FAIL;
    }
    dx_->imgui_win32_ready = true;
    if (!ImGui_ImplDX11_Init(dx_->device, dx_->ctx)) {
        shutdown();
        return ErrorCode::ERR_INIT_FAIL;
    }
    dx_->imgui_dx11_ready = true;

    initialized_ = true;
    start_time_ = std::chrono::steady_clock::now();
    return ErrorCode::OK;
}

void UIManager::shutdown() {
    if (!dx_) return;
    if (dx_->imgui_dx11_ready) ImGui_ImplDX11_Shutdown();
    if (dx_->imgui_win32_ready) ImGui_ImplWin32_Shutdown();
    if (ImGui::GetCurrentContext()) ImGui::DestroyContext();
    dx_->imgui_dx11_ready = false;
    dx_->imgui_win32_ready = false;

    if (dx_->rtv) { dx_->rtv->Release(); dx_->rtv = nullptr; }
    if (dx_->swap) { dx_->swap->Release(); dx_->swap = nullptr; }
    if (dx_->ctx) { dx_->ctx->Release(); dx_->ctx = nullptr; }
    if (dx_->device) { dx_->device->Release(); dx_->device = nullptr; }
    if (dx_->hwnd) { DestroyWindow(dx_->hwnd); dx_->hwnd = nullptr; }
    if (dx_->wc.lpszClassName) UnregisterClassW(dx_->wc.lpszClassName, dx_->wc.hInstance);
    initialized_ = false;
    g_ui = nullptr;
}

void UIManager::run_frame() {
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (msg.message == WM_QUIT) { should_close_ = true; return; }
    }

    if (uint32_t packed = g_pending_resize.exchange(0)) {
        UINT w = packed >> 16, h = packed & 0xFFFF;
        if (dx_->rtv) { dx_->rtv->Release(); dx_->rtv = nullptr; }
        dx_->ctx->OMSetRenderTargets(0, nullptr, nullptr);
        if (SUCCEEDED(dx_->swap->ResizeBuffers(0, w, h, DXGI_FORMAT_UNKNOWN, 0))) {
            ID3D11Texture2D* back_buf = nullptr;
            if (SUCCEEDED(dx_->swap->GetBuffer(0, IID_PPV_ARGS(&back_buf))) && back_buf) {
                dx_->device->CreateRenderTargetView(back_buf, nullptr, &dx_->rtv);
                back_buf->Release();
            }
        }
        if (!dx_->rtv) return; // skip this frame if the RTV could not be rebuilt
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    render_menubar();

    const float menu_height = ImGui::GetFrameHeight();
    const float status_height = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos({0, menu_height});
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize - ImVec2(0, menu_height + status_height));
    ImGui::Begin("##main", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (ImGui::BeginTabBar("##tabs")) {
        if (ImGui::BeginTabItem("Dashboard", nullptr, active_tab_ == 0 ? ImGuiTabItemFlags_SetSelected : 0))
            { active_tab_ = 0; render_dashboard(); ImGui::EndTabItem(); }

        char alert_label[32];
        size_t unacked = alert_mgr_ ? alert_mgr_->unacknowledged_count() : 0;
        if (unacked > 0)
            std::snprintf(alert_label, sizeof(alert_label), "Alerts (%zu)", unacked);
        else
            std::snprintf(alert_label, sizeof(alert_label), "Alerts");
        if (ImGui::BeginTabItem(alert_label, nullptr, active_tab_ == 1 ? ImGuiTabItemFlags_SetSelected : 0))
            { active_tab_ = 1; render_alerts(); ImGui::EndTabItem(); }

        if (ImGui::BeginTabItem("Deep Scan", nullptr, active_tab_ == 2 ? ImGuiTabItemFlags_SetSelected : 0))
            { active_tab_ = 2; render_scan(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Network", nullptr, active_tab_ == 3 ? ImGuiTabItemFlags_SetSelected : 0))
            { active_tab_ = 3; render_network(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Quarantine", nullptr, active_tab_ == 4 ? ImGuiTabItemFlags_SetSelected : 0))
            { active_tab_ = 4; render_quarantine(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Forensics", nullptr, active_tab_ == 5 ? ImGuiTabItemFlags_SetSelected : 0))
            { active_tab_ = 5; render_forensics(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Settings", nullptr, active_tab_ == 6 ? ImGuiTabItemFlags_SetSelected : 0))
            { active_tab_ = 6; render_settings(); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    ImGui::End();
    render_statusbar();

    ImGui::Render();
    const float clear[4] = {0.051f, 0.067f, 0.090f, 1.0f};
    dx_->ctx->OMSetRenderTargets(1, &dx_->rtv, nullptr);
    dx_->ctx->ClearRenderTargetView(dx_->rtv, clear);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

    HRESULT pr = dx_->swap->Present(1, 0);
    if (pr == DXGI_ERROR_DEVICE_REMOVED || pr == DXGI_ERROR_DEVICE_RESET) {
        // GPU was reset (TDR / driver update / sleep). Nothing to recover to
        // without rebuilding the device; log once and close cleanly.
        GCAD_LOG(CRIT, "D3D11 device lost (0x" + std::format("{:08x}",
                 static_cast<uint32_t>(dx_->device->GetDeviceRemovedReason())) + ") — closing UI");
        should_close_ = true;
    }
}

void UIManager::main_loop() {
    while (!should_close_) run_frame();
}

#else // Linux stub — placeholder for GLFW+OpenGL
UIManager::UIManager() {}
UIManager::~UIManager() { shutdown(); }
ErrorCode UIManager::init(EngineManager* em, DeepScanner* sc) {
    engine_mgr_ = em; scanner_ = sc; initialized_ = true; return ErrorCode::OK;
}
void UIManager::shutdown() { initialized_ = false; }
void UIManager::run_frame() { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }
void UIManager::main_loop() { while (!should_close_) run_frame(); }
#endif

// View dispatchers — these call into the static view instances
static views::DashboardView  s_dashboard;
static views::AlertView      s_alerts;
static views::ScanView       s_scan;
static views::NetworkView    s_network;
static views::QuarantineView s_quarantine;
static views::ForensicsView  s_forensics;
static views::SettingsView   s_settings;

void UIManager::render_menubar() {
    if (ImGui::BeginMainMenuBar()) {
        ImGui::TextUnformatted("GCAD");
        ImGui::SameLine();
        ImGui::TextDisabled("v%s", std::string(VERSION).c_str());
        ImGui::Separator();

        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Exit")) should_close_ = true;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Scan")) {
            if (ImGui::MenuItem("Open Scan Console")) active_tab_ = 2;
            ImGui::Separator();
            const bool scan_available = scanner_ && !scanner_->is_scanning();
            ImGui::BeginDisabled(!scan_available);
            if (ImGui::MenuItem("Start Quick Scan")) scanner_->start_scan(ScanMode::QUICK);
            if (ImGui::MenuItem("Start Memory Scan")) scanner_->start_scan(ScanMode::MEMORY);
            ImGui::EndDisabled();
            if (scanner_ && scanner_->is_scanning() && ImGui::MenuItem("Cancel Active Scan")) scanner_->cancel_scan();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Protection")) {
            if (ImGui::MenuItem("Operations Dashboard")) active_tab_ = 0;
            if (ImGui::MenuItem("Alert History")) active_tab_ = 1;
            if (ImGui::MenuItem("Forensic Timeline")) active_tab_ = 5;
            if (ImGui::MenuItem("Protection Settings")) active_tab_ = 6;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About GCAD")) ImGui::OpenPopup("About GCAD");
            ImGui::EndMenu();
        }
        auto level = engine_mgr_ ? engine_mgr_->current_threat_level() : ThreatLevel::SAFE;
        push_threat_color(static_cast<uint8_t>(level));
        ImGui::Text("Shield: %s", threat_level_label(static_cast<uint8_t>(level)));
        pop_threat_color();
        ImGui::EndMainMenuBar();
    }

    if (ImGui::BeginPopupModal("About GCAD", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("GCAD — Galoisconnection Antivirus & Defense");
        ImGui::TextDisabled("Local security telemetry and incident review console.");
        ImGui::Spacing();
        if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void UIManager::render_statusbar() {
    const ImGuiIO& io = ImGui::GetIO();
    const float height = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos({0.0f, io.DisplaySize.y - height});
    ImGui::SetNextWindowSize({io.DisplaySize.x, height});
    constexpr ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                       ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::Begin("##statusbar", nullptr, flags);
    const auto statuses = engine_mgr_ ? engine_mgr_->statuses() : std::vector<EngineStatus>{};
    const auto stopped = engine_mgr_ ? engine_mgr_->stopped_engines() : std::vector<std::string>{};
    ImGui::Text("Engines %zu/%zu", statuses.size() - stopped.size(), statuses.size());
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    ImGui::Text("Scan %s", scanner_ && scanner_->is_scanning() ? "ACTIVE" : "IDLE");
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    if (engine_mgr_) {
        ImGui::Text("Events %llu", static_cast<unsigned long long>(engine_mgr_->total_engine_events()));
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
        ImGui::Text("Threats %zu", engine_mgr_->total_threats());
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
    }
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time_).count();
    ImGui::TextDisabled("Uptime %lldm %02llds", static_cast<long long>(uptime / 60), static_cast<long long>(uptime % 60));
    ImGui::End();
}

void UIManager::render_dashboard()  { if (engine_mgr_) s_dashboard.render(*engine_mgr_); }
void UIManager::render_alerts()     { if (alert_mgr_) s_alerts.render(*alert_mgr_); }
void UIManager::render_scan()       { if (scanner_) s_scan.render(*scanner_); }
void UIManager::render_network()    { if (engine_mgr_) s_network.render(dynamic_cast<ETGRIEngine*>(engine_mgr_->engine("ETG-RI"))); }
void UIManager::render_quarantine() { if (engine_mgr_) s_quarantine.render(dynamic_cast<ARHSEngine*>(engine_mgr_->engine("ARHS"))); }
void UIManager::render_forensics()  { if (engine_mgr_) s_forensics.render(*engine_mgr_); }
void UIManager::render_settings()   { if (engine_mgr_) s_settings.render(*engine_mgr_, alert_mgr_); }

} // namespace gcad::ui
