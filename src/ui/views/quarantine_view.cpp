#include "gcad/ui/views/quarantine_view.hpp"
#include "gcad/ui/theme.hpp"
#include "gcad/platform/platform_compat.hpp"
#include "imgui.h"

namespace gcad::ui::views {

namespace {

const char* incident_action_label(IncidentAction action) {
    switch (action) {
        case IncidentAction::ROLLBACK_FILES: return "Rollback Files";
        case IncidentAction::RESUME_PROCESS: return "Resume Process";
        case IncidentAction::TERMINATE_PROCESS: return "Terminate Process";
        case IncidentAction::NONE: return "No action";
    }
    return "Unknown action";
}

const char* incident_action_consequence(IncidentAction action) {
    switch (action) {
        case IncidentAction::ROLLBACK_FILES:
            return "Restores captured files associated with this process.";
        case IncidentAction::RESUME_PROCESS:
            return "Allows the suspended process to continue running.";
        case IncidentAction::TERMINATE_PROCESS:
            return "Ends the process immediately. Unsaved work may be lost.";
        case IncidentAction::NONE:
            return "No system change will be made.";
    }
    return "No system change will be made.";
}

} // namespace

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

    const auto sandboxed = engine->sandboxed_processes();
    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##qlist", {w * 0.5f, 0}, true);
    render_sandboxed_list(sandboxed);
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##qdetail", {0, 0}, true);
    if (selected_item_ >= 0 && selected_item_ < static_cast<int>(sandboxed.size())) {
        render_detail_panel(sandboxed[selected_item_]);
        ImGui::Separator();
        render_action_buttons(sandboxed[selected_item_]);
    } else {
        ImGui::TextDisabled("Select a quarantined process.");
    }
    ImGui::EndChild();

    render_confirmation_modal(*engine);
}

void QuarantineView::render_sandboxed_list(const std::vector<SandboxedProcess>& sandboxed) {
    ImGui::Text("Quarantined Processes");
    ImGui::Separator();

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

void QuarantineView::render_action_buttons(const SandboxedProcess& proc) {
    ImGui::Text("Actions");
    if (ImGui::Button("Rollback Files", {120, 28})) {
        pending_action_ = {IncidentAction::ROLLBACK_FILES, proc.pid, proc.creation_time, proc.name};
        ImGui::OpenPopup("Confirm incident action");
    }
    ImGui::SameLine();
    if (ImGui::Button("Resume Process", {120, 28})) {
        pending_action_ = {IncidentAction::RESUME_PROCESS, proc.pid, proc.creation_time, proc.name};
        ImGui::OpenPopup("Confirm incident action");
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.1f, 0.1f, 1));
    if (ImGui::Button("Terminate", {120, 28})) {
        pending_action_ = {IncidentAction::TERMINATE_PROCESS, proc.pid, proc.creation_time, proc.name};
        ImGui::OpenPopup("Confirm incident action");
    }
    ImGui::PopStyleColor();
}

void QuarantineView::render_confirmation_modal(ARHSEngine& engine) {
    if (!pending_action_) return;

    ImGui::SetNextWindowSize({460.0f, 0.0f}, ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Confirm incident action", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    const auto& pending = *pending_action_;
    ImGui::TextUnformatted("Confirm manual incident action");
    ImGui::Separator();
    ImGui::Text("Action: %s", incident_action_label(pending.action));
    ImGui::Text("Process: %s", pending.process_name.c_str());
    ImGui::Text("PID: %u", pending.pid);
    ImGui::Spacing();
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + 410.0f);
    ImGui::TextUnformatted(incident_action_consequence(pending.action));
    ImGui::PopTextWrapPos();
    ImGui::Spacing();

    if (ImGui::Button("Cancel", {120, 0})) {
        pending_action_.reset();
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.1f, 0.1f, 1));
    if (ImGui::Button("Confirm", {120, 0})) {
        execute_pending_action(engine);
        ImGui::CloseCurrentPopup();
    }
    ImGui::PopStyleColor();
    ImGui::EndPopup();
}

void QuarantineView::execute_pending_action(ARHSEngine& engine) {
    if (!pending_action_ || !requires_confirmation(pending_action_->action)) return;

    const auto action = pending_action_->action;
    const uint32_t pid = pending_action_->pid;
    if (action == IncidentAction::ROLLBACK_FILES) {
        engine.rollback_process(pid);
    } else if (action == IncidentAction::RESUME_PROCESS) {
        platform::resume_process_if_same_instance(pid, pending_action_->creation_time);
    } else if (action == IncidentAction::TERMINATE_PROCESS) {
        platform::terminate_process_if_same_instance(pid, pending_action_->creation_time);
    }
    pending_action_.reset();
}

} // namespace gcad::ui::views
