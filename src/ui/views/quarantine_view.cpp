#include "gcad/ui/views/quarantine_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/platform/platform_compat.hpp"
#include "imgui.h"

namespace gcad::ui::views {

static const char* category_name(ThreatCategory cat) {
    switch (cat) {
        case ThreatCategory::RANSOMWARE:      return "Ransomware";
        case ThreatCategory::FILE_ENCRYPT:    return "File Encryption";
        case ThreatCategory::MEMORY_INJECTION: return "Memory Injection";
        case ThreatCategory::PROCESS_HOLLOW:  return "Process Hollowing";
        case ThreatCategory::DLL_INJECTION:   return "DLL Injection";
        case ThreatCategory::APC_INJECTION:   return "APC Injection";
        case ThreatCategory::REFLECTIVE_LOAD: return "Reflective Load";
        case ThreatCategory::SHELLCODE:       return "Shellcode";
        case ThreatCategory::CREDENTIAL_DUMP: return "Credential Dump";
        default: return "Suspicious Activity";
    }
}

void QuarantineView::render(ARHSEngine* engine) {
    if (!engine) {
        ImGui::TextDisabled("ARHS engine not available.");
        return;
    }

    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##qlist", {w * 0.5f, 0}, true);
    render_sandboxed_list(engine);
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##qdetail", {0, 0}, true);
    auto& sandboxed = engine->sandboxed_processes();
    if (selected_item_ >= 0 && selected_item_ < static_cast<int>(sandboxed.size())) {
        render_detail_panel(sandboxed[selected_item_]);
        ImGui::Separator();
        render_action_buttons(engine, sandboxed[selected_item_].pid);
    } else {
        ImGui::TextDisabled("Select a quarantined process.");
    }
    ImGui::EndChild();
}

void QuarantineView::render_sandboxed_list(ARHSEngine* engine) {
    ImGui::Text("Quarantined Processes");
    ImGui::Separator();

    auto& sandboxed = engine->sandboxed_processes();
    for (int i = 0; i < static_cast<int>(sandboxed.size()); i++) {
        ImGui::PushID(i);
        bool sel = (i == selected_item_);
        auto& sp = sandboxed[i];
        char label[256];
        snprintf(label, sizeof(label), "PID %u - %s [%s]",
                 sp.pid, sp.name.c_str(), category_name(sp.reason));
        if (ImGui::Selectable(label, sel)) selected_item_ = i;
        ImGui::PopID();
    }
    if (sandboxed.empty()) ImGui::TextDisabled("No quarantined processes.");
}

void QuarantineView::render_detail_panel(const SandboxedProcess& proc) {
    ImGui::Text("Process Details");
    ImGui::Separator();
    ImGui::Text("PID: %u", proc.pid);
    ImGui::Text("Name: %s", proc.name.c_str());
    ImGui::Text("Reason: %s", category_name(proc.reason));
    ImGui::Text("Snapshots: %zu", proc.snapshots.size());

    push_threat_color(4);
    ImGui::Text("Status: SUSPENDED");
    pop_threat_color();

    if (!proc.snapshots.empty()) {
        ImGui::Separator();
        ImGui::Text("Snapshot Files:");
        for (size_t i = 0; i < std::min(proc.snapshots.size(), size_t(10)); i++) {
            ImGui::BulletText("%s (%s)", proc.snapshots[i].path.filename().string().c_str(),
                              proc.snapshots[i].sha256_hash.substr(0, 12).c_str());
        }
    }
}

void QuarantineView::render_action_buttons(ARHSEngine* engine, uint32_t pid) {
    ImGui::Text("Actions");
    if (ImGui::Button("Rollback Files", {120, 28})) {
        engine->rollback_process(pid);
    }
    ImGui::SameLine();
    if (ImGui::Button("Resume Process", {120, 28})) {
        platform::resume_process(pid);
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.1f, 0.1f, 1));
    if (ImGui::Button("Terminate", {120, 28})) {
        platform::terminate_process(pid);
    }
    ImGui::PopStyleColor();
}

} // namespace gcad::ui::views
