#include "gcad/ui/views/settings_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#include "imgui.h"

namespace gcad::ui::views {

void SettingsView::render(EngineManager& em) {
    ImGui::Text("GCAD Settings");
    ImGui::Separator();

    if (ImGui::CollapsingHeader("Engine Controls", ImGuiTreeNodeFlags_DefaultOpen))
        render_engine_controls(em);
    if (ImGui::CollapsingHeader("Scan Settings"))
        render_scan_settings();
    if (ImGui::CollapsingHeader("Network Settings"))
        render_network_settings();
    if (ImGui::CollapsingHeader("General"))
        render_general_settings();
}

void SettingsView::render_engine_controls(EngineManager& em) {
    auto stats = em.statuses();
    for (auto& s : stats) {
        ImGui::PushID(s.name.c_str());
        bool running = s.running;
        push_threat_color(running ? 0 : 4);
        ImGui::Text("%s: %s", s.name.c_str(), running ? "ACTIVE" : "STOPPED");
        pop_threat_color();
        ImGui::SameLine();
        auto* eng = em.engine(s.name);
        if (eng) {
            if (running) {
                if (ImGui::SmallButton("Stop")) eng->stop();
            } else {
                if (ImGui::SmallButton("Start")) eng->start();
            }
        }
        ImGui::PopID();
    }

    ImGui::Separator();
    if (ImGui::Button("Start All", {100, 28})) em.start_all();
    ImGui::SameLine();
    if (ImGui::Button("Stop All", {100, 28})) em.stop_all();

    ImGui::Separator();
    ImGui::SliderFloat("PMSR Sensitivity", &pmsr_sensitivity_, 0.1f, 1.0f, "%.2f");
    if (ImGui::Checkbox("Self-Defense", &self_defense_enabled_)) {
        auto* eng = em.engine("SelfDefense");
        if (eng) {
            if (self_defense_enabled_) eng->start();
            else eng->stop();
        }
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("Syscall Guard", &syscall_guard_enabled_)) {
        auto* eng = em.engine("SyscallGuard");
        if (eng) {
            if (syscall_guard_enabled_) eng->start();
            else eng->stop();
        }
    }
}

void SettingsView::render_scan_settings() {
    ImGui::SliderFloat("ARHS Backup Interval (s)", &arhs_backup_interval_, 1.0f, 30.0f, "%.1f");
    ImGui::Checkbox("Auto-Quarantine on Detection", &auto_quarantine_);
    ImGui::Checkbox("Auto-Rollback on Ransomware", &auto_rollback_);
}

void SettingsView::render_network_settings() {
    ImGui::SliderFloat("ETG Entropy Threshold", &etg_entropy_thresh_, 5.0f, 8.0f, "%.2f");
    ImGui::SliderInt("ZRGP Max Honey Ports", &zrgp_max_ports_, 4, 64);
}

void SettingsView::render_general_settings() {
    ImGui::Checkbox("Minimize to System Tray", &minimize_to_tray_);
    ImGui::Separator();
    ImGui::Text("GCAD v%s", std::string(VERSION).c_str());
    ImGui::Text("Build: C++20 | Platform: %s",
#ifdef GCAD_PLATFORM_WINDOWS
                "Windows (DX11)"
#else
                "Linux (OpenGL)"
#endif
    );
    ImGui::TextDisabled("Galoisconnection Antivirus & Defense");
}

} // namespace gcad::ui::views
