#include "gcad/ui/views/settings_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/engine_manager.hpp"
#include "gcad/report/report_generator.hpp"
#include "gcad/alert/alert_manager.hpp"
#include "imgui.h"

namespace gcad::ui::views {

void SettingsView::render(EngineManager& em, AlertManager* am) {
    ImGui::Text("GCAD Settings");
    ImGui::Separator();

    if (ImGui::CollapsingHeader("Engine Controls", ImGuiTreeNodeFlags_DefaultOpen))
        render_engine_controls(em);
    if (ImGui::CollapsingHeader("Scan Settings"))
        render_scan_settings();
    if (ImGui::CollapsingHeader("Network Settings"))
        render_network_settings();
    if (ImGui::CollapsingHeader("Report Generation"))
        render_report_settings(em, am);
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

void SettingsView::render_report_settings(EngineManager& em, AlertManager* am) {
    const char* formats[] = {"HTML", "Plain Text"};
    ImGui::Combo("Format", &report_format_, formats, 2);

    if (ImGui::Button("Generate Report", {160, 28})) {
        auto data = report::ReportGenerator::collect(em, am);
        std::string content;
        std::string ext;
        if (report_format_ == 0) {
            content = report::ReportGenerator::generate_html(data);
            ext = ".html";
        } else {
            content = report::ReportGenerator::generate_text(data);
            ext = ".txt";
        }

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
        localtime_s(&tm_buf, &t);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm_buf);

        auto path = std::filesystem::current_path() / ("gcad_report_" + std::string(ts) + ext);
        if (report::ReportGenerator::save_to_file(content, path))
            report_status_ = "Saved: " + path.filename().string();
        else
            report_status_ = "Failed to save report";
    }

    if (!report_status_.empty()) {
        ImGui::SameLine();
        ImGui::TextColored({0.4f, 0.9f, 0.4f, 1.0f}, "%s", report_status_.c_str());
    }
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
