#include "gcad/ui/views/quarantine_view.hpp"
#include "gcad/engine_manager.hpp"
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
    render(nullptr, engine);
}

void QuarantineView::render(EngineManager* engine_mgr, ARHSEngine* engine) {
    if (ImGui::BeginTabBar("##QuarantineMainTabBar")) {
        if (ImGui::BeginTabItem("Quarantined Files Vault")) {
            render_vault_tab(engine_mgr);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Active Process Sandboxes (ARHS)")) {
            render_sandboxed_tab(engine);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void QuarantineView::render_vault_tab(EngineManager* engine_mgr) {
    if (!engine_mgr) {
        ImGui::TextDisabled("Engine manager not connected.");
        return;
    }

    const auto records = engine_mgr->recent_quarantine_records(100);
    float w = ImGui::GetContentRegionAvail().x;
    ImGui::BeginChild("##vault_file_list", {w * 0.48f, 0}, true);
    ImGui::Text("Vaulted Files (%zu)", records.size());
    ImGui::Separator();

    for (int i = 0; i < static_cast<int>(records.size()); i++) {
        ImGui::PushID(i);
        const auto& rec = records[i];
        bool sel = (i == selected_record_);

        std::string tag;
        if (rec.shredded) {
            tag = "[SHREDDED]";
        } else if (rec.restored) {
            tag = "[RESTORED]";
        } else {
            tag = "[VAULTED]";
        }

        std::filesystem::path p(rec.original_path);
        std::string label = std::to_string(rec.id) + ". " + tag + " " + p.filename().string();

        if (rec.shredded) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.6f, 1.0f));
        } else if (rec.restored) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.8f, 0.4f, 1.0f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.2f, 1.0f));
        }

        if (ImGui::Selectable(label.c_str(), sel)) selected_record_ = i;
        ImGui::PopStyleColor();
        ImGui::PopID();
    }
    if (records.empty()) ImGui::TextDisabled("No files currently in quarantine vault.");
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##vault_file_detail", {0, 0}, true);
    if (selected_record_ >= 0 && selected_record_ < static_cast<int>(records.size())) {
        const auto& rec = records[selected_record_];
        ImGui::Text("Quarantine Record #%llu", static_cast<unsigned long long>(rec.id));
        ImGui::Separator();
        ImGui::Text("Finding ID: %llu", static_cast<unsigned long long>(rec.finding_id));
        ImGui::Spacing();
        ImGui::TextWrapped("Original Path: %s", rec.original_path.c_str());
        ImGui::Spacing();
        ImGui::TextWrapped("Vault Path: %s", rec.vault_path.c_str());
        ImGui::Spacing();
        ImGui::TextWrapped("SHA-256: %s", rec.sha256_at_quarantine.c_str());
        ImGui::Spacing();

        if (rec.shredded) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
            ImGui::Text("Status: PERMANENTLY SHREDDED (0x00 Wiped)");
            ImGui::PopStyleColor();
        } else if (rec.restored) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.8f, 0.4f, 1.0f));
            ImGui::Text("Status: RESTORED TO ORIGINAL LOCATION");
            ImGui::PopStyleColor();
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.2f, 1.0f));
            ImGui::Text("Status: SECURED IN ISOLATION VAULT");
            ImGui::PopStyleColor();

            ImGui::Separator();
            ImGui::Text("Remediation Actions");
            if (ImGui::Button("Restore File", {140, 28})) {
                pending_file_action_ = FileVaultAction::RESTORE;
                pending_record_id_ = rec.id;
                pending_record_path_ = rec.original_path;
                ImGui::OpenPopup("Confirm Vault Action");
            }
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.15f, 0.15f, 1.0f));
            if (ImGui::Button("Secure Shred (0x00)", {160, 28})) {
                pending_file_action_ = FileVaultAction::SHRED;
                pending_record_id_ = rec.id;
                pending_record_path_ = rec.original_path;
                ImGui::OpenPopup("Confirm Vault Action");
            }
            ImGui::PopStyleColor();
        }
    } else {
        ImGui::TextDisabled("Select a quarantined record to view details.");
    }
    ImGui::EndChild();

    render_vault_modal(*engine_mgr);
}

void QuarantineView::render_vault_modal(EngineManager& engine_mgr) {
    if (pending_file_action_ == FileVaultAction::NONE) return;

    ImGui::SetNextWindowSize({480.0f, 0.0f}, ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Confirm Vault Action", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    const bool is_shred = (pending_file_action_ == FileVaultAction::SHRED);
    ImGui::TextUnformatted(is_shred ? "Confirm Permanent File Shredding" : "Confirm File Restoration");
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextWrapped("Target: %s", pending_record_path_.c_str());
    ImGui::Spacing();
    if (is_shred) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
        ImGui::TextWrapped("WARNING: The quarantined file will be securely overwritten with 0x00 zeros before deletion. This operation cannot be undone.");
        ImGui::PopStyleColor();
    } else {
        ImGui::TextWrapped("The quarantined file will be restored from the vault back to its original location.");
    }
    ImGui::Spacing();

    if (ImGui::Button("Cancel", {120, 0})) {
        pending_file_action_ = FileVaultAction::NONE;
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (is_shred) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.15f, 0.15f, 1.0f));
    if (ImGui::Button(is_shred ? "Confirm Shred" : "Confirm Restore", {140, 0})) {
        if (is_shred) {
            engine_mgr.shred_quarantine(pending_record_id_);
        } else {
            engine_mgr.restore_quarantine(pending_record_id_);
        }
        pending_file_action_ = FileVaultAction::NONE;
        ImGui::CloseCurrentPopup();
    }
    if (is_shred) ImGui::PopStyleColor();

    ImGui::EndPopup();
}

void QuarantineView::render_sandboxed_tab(ARHSEngine* engine) {
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
        action_gate_.request({IncidentAction::ROLLBACK_FILES, proc.pid, proc.creation_time, proc.name});
        ImGui::OpenPopup("Confirm incident action");
    }
    ImGui::SameLine();
    if (ImGui::Button("Resume Process", {120, 28})) {
        action_gate_.request({IncidentAction::RESUME_PROCESS, proc.pid, proc.creation_time, proc.name});
        ImGui::OpenPopup("Confirm incident action");
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.1f, 0.1f, 1));
    if (ImGui::Button("Terminate", {120, 28})) {
        action_gate_.request({IncidentAction::TERMINATE_PROCESS, proc.pid, proc.creation_time, proc.name});
        ImGui::OpenPopup("Confirm incident action");
    }
    ImGui::PopStyleColor();
}

void QuarantineView::render_confirmation_modal(ARHSEngine& engine) {
    const auto* pending = action_gate_.pending();
    if (!pending) return;

    ImGui::SetNextWindowSize({460.0f, 0.0f}, ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("Confirm incident action", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;

    ImGui::TextUnformatted("Confirm manual incident action");
    ImGui::Separator();
    ImGui::Text("Action: %s", incident_action_label(pending->action));
    ImGui::Text("Process: %s", pending->process_name.c_str());
    ImGui::Text("PID: %u", pending->pid);
    ImGui::Spacing();
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + 410.0f);
    ImGui::TextUnformatted(incident_action_consequence(pending->action));
    ImGui::PopTextWrapPos();
    ImGui::Spacing();

    if (ImGui::Button("Cancel", {120, 0})) {
        action_gate_.cancel();
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.1f, 0.1f, 1));
    if (ImGui::Button("Confirm", {120, 0})) {
        action_gate_.confirm([&engine, this](const PendingIncidentAction& action) {
            execute_pending_action(engine, action);
        });
        ImGui::CloseCurrentPopup();
    }
    ImGui::PopStyleColor();
    ImGui::EndPopup();
}

void QuarantineView::execute_pending_action(ARHSEngine& engine, const PendingIncidentAction& pending) {
    const auto action = pending.action;
    const uint32_t pid = pending.pid;
    if (action == IncidentAction::ROLLBACK_FILES) {
        engine.rollback_process(pid);
    } else if (action == IncidentAction::RESUME_PROCESS) {
        platform::resume_process_if_same_instance(pid, pending.creation_time);
    } else if (action == IncidentAction::TERMINATE_PROCESS) {
        platform::terminate_process_if_same_instance(pid, pending.creation_time);
    }
}

} // namespace gcad::ui::views
