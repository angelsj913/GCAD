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
#include "gcad/ui/views/settings_view.hpp"
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
};

static UIManager* g_ui = nullptr;

static LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp)) return true;
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    if (msg == WM_SIZE && g_ui) return 0;
    return DefWindowProcW(hwnd, msg, wp, lp);
}

UIManager::UIManager() : dx_(std::make_unique<DX11State>()) {}
UIManager::~UIManager() { shutdown(); }

ErrorCode UIManager::init(EngineManager* em, DeepScanner* sc) {
    engine_mgr_ = em;
    scanner_ = sc;
    g_ui = this;

    dx_->wc = {sizeof(WNDCLASSEXW), CS_CLASSDC, wnd_proc, 0L, 0L,
               GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
               L"GCAD_WC", nullptr};
    RegisterClassExW(&dx_->wc);

    dx_->hwnd = CreateWindowW(L"GCAD_WC", L"GCAD v1.0.0 — Galoisconnection Antivirus & Defense",
                              WS_OVERLAPPEDWINDOW, 100, 100, 1400, 900,
                              nullptr, nullptr, dx_->wc.hInstance, nullptr);

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
    if (FAILED(hr)) return ErrorCode::ERR_INIT_FAIL;

    ID3D11Texture2D* back_buf = nullptr;
    dx_->swap->GetBuffer(0, IID_PPV_ARGS(&back_buf));
    dx_->device->CreateRenderTargetView(back_buf, nullptr, &dx_->rtv);
    back_buf->Release();

    ShowWindow(dx_->hwnd, SW_SHOWDEFAULT);
    UpdateWindow(dx_->hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    apply_dark_theme();

    ImGui_ImplWin32_Init(dx_->hwnd);
    ImGui_ImplDX11_Init(dx_->device, dx_->ctx);

    initialized_ = true;
    return ErrorCode::OK;
}

void UIManager::shutdown() {
    if (!initialized_) return;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    if (dx_->rtv)  dx_->rtv->Release();
    if (dx_->swap) dx_->swap->Release();
    if (dx_->ctx)  dx_->ctx->Release();
    if (dx_->device) dx_->device->Release();
    DestroyWindow(dx_->hwnd);
    UnregisterClassW(dx_->wc.lpszClassName, dx_->wc.hInstance);
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

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    render_menubar();

    ImGui::SetNextWindowPos({0, ImGui::GetFrameHeight()});
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize - ImVec2(0, ImGui::GetFrameHeight()));
    ImGui::Begin("##main", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (ImGui::BeginTabBar("##tabs")) {
        if (ImGui::BeginTabItem("Dashboard"))  { active_tab_ = 0; render_dashboard();  ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Deep Scan"))  { active_tab_ = 1; render_scan();       ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Network"))    { active_tab_ = 2; render_network();    ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Quarantine")) { active_tab_ = 3; render_quarantine(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Forensics"))  { active_tab_ = 4; render_forensics();  ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Settings"))   { active_tab_ = 5; render_settings();   ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    ImGui::End();

    ImGui::Render();
    const float clear[4] = {0.051f, 0.067f, 0.090f, 1.0f};
    dx_->ctx->OMSetRenderTargets(1, &dx_->rtv, nullptr);
    dx_->ctx->ClearRenderTargetView(dx_->rtv, clear);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    dx_->swap->Present(1, 0);
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
void UIManager::run_frame() {}
void UIManager::main_loop() { while (!should_close_) std::this_thread::sleep_for(std::chrono::seconds(1)); }
#endif

// View dispatchers — these call into the static view instances
static views::DashboardView  s_dashboard;
static views::ScanView       s_scan;
static views::NetworkView    s_network;
static views::QuarantineView s_quarantine;
static views::ForensicsView  s_forensics;
static views::SettingsView   s_settings;

void UIManager::render_menubar() {
    if (ImGui::BeginMainMenuBar()) {
        ImGui::Text("GCAD v%s", std::string(VERSION).c_str());
        ImGui::Separator();
        auto level = engine_mgr_ ? engine_mgr_->current_threat_level() : ThreatLevel::SAFE;
        push_threat_color(static_cast<uint8_t>(level));
        ImGui::Text("  Shield: %s", threat_level_label(static_cast<uint8_t>(level)));
        pop_threat_color();
        ImGui::EndMainMenuBar();
    }
}

void UIManager::render_dashboard()  { if (engine_mgr_) s_dashboard.render(*engine_mgr_); }
void UIManager::render_scan()       { if (scanner_) s_scan.render(*scanner_); }
void UIManager::render_network()    { if (engine_mgr_) s_network.render(dynamic_cast<ETGRIEngine*>(engine_mgr_->engine("ETG-RI"))); }
void UIManager::render_quarantine() { if (engine_mgr_) s_quarantine.render(dynamic_cast<ARHSEngine*>(engine_mgr_->engine("ARHS"))); }
void UIManager::render_forensics()  { if (engine_mgr_) s_forensics.render(*engine_mgr_); }
void UIManager::render_settings()   { if (engine_mgr_) s_settings.render(*engine_mgr_); }

} // namespace gcad::ui
