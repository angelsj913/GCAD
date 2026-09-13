# GCAD Minimal Operator UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace GCAD's tabbed desktop UI with the approved Minimal Operator shell while preserving existing security-engine behavior and requiring explicit confirmation for manual containment actions.

**Architecture:** `UIManager` owns a six-destination shell backed by pure navigation types that unit tests can compile without Dear ImGui. Existing views remain presentation owners, with Alerts and Quarantine composed under Incidents. Quarantine actions move behind a local pending-action state and confirmation modal; no engine, scanner, or policy API changes.

**Tech Stack:** C++20, Dear ImGui 1.91, Win32/DX11, existing GCAD unit-test executable and CTest.

## Global Constraints

- Work only in `codex/ui-overhaul`; do not alter `master` or untracked `.agents/`.
- Do not add a UI library, telemetry, persistence format, automatic remediation, or new network call.
- Render from snapshots; invoke rollback, resume, or terminate only after an explicit Confirm click.
- Keep the application as a normal window: allow resizing, keep maximize disabled, and never start maximized.
- Keep `build-make` single-threaded: `cmake --build build-make --target gcad gcad_tests --parallel 1`.
- Preserve existing tray/menu actions and map Alerts to `PrimaryView::INCIDENTS` with `IncidentPane::ALERTS`.

---

### Task 1: Navigation contract and Minimal Operator shell

**Files:**
- Create: `include/gcad/ui/navigation.hpp`, `tests/test_ui_navigation.cpp`
- Modify: `include/gcad/ui/ui_manager.hpp`, `src/ui/ui_manager.cpp`, `CMakeLists.txt`, `tests/test_main.cpp`, `src/ui/theme.cpp`, `include/gcad/ui/theme.hpp`

**Interfaces:**
- Produces `enum class PrimaryView { OVERVIEW, SCAN, NETWORK, INCIDENTS, FORENSICS, SETTINGS }` and `enum class IncidentPane { ALERTS, QUARANTINE }` in `gcad::ui`.
- Produces `primary_view_label(PrimaryView)`, `primary_view_count()`, and `legacy_tab_target(int)`; the latter maps 0→Overview, 1/4→Incidents, 2→Scan, 3→Network, 5→Forensics, 6→Settings.
- `UIManager` replaces `active_tab_` with `active_view_` and `incident_pane_`; `set_active_tab(int)` stays public and delegates to `legacy_tab_target` for compatibility.

- [ ] **Step 1: Write navigation contract tests**

```cpp
register_test("ui_primary_navigation_contract", [] {
    using namespace gcad::ui;
    return primary_view_count() == 6 &&
           primary_view_label(PrimaryView::INCIDENTS) == "Incidents" &&
           legacy_tab_target(1).incident_pane == IncidentPane::ALERTS &&
           legacy_tab_target(4).view == PrimaryView::INCIDENTS &&
           legacy_tab_target(4).incident_pane == IncidentPane::QUARANTINE;
});
```

- [ ] **Step 2: Build `gcad_tests` and confirm the contract fails because `navigation.hpp` is absent.**

Run: `cmake --build build-make --target gcad_tests --parallel 1`

- [ ] **Step 3: Add the pure navigation header and register its test source.**

```cpp
struct NavigationTarget { PrimaryView view; IncidentPane incident_pane; };
constexpr size_t primary_view_count() noexcept { return 6; }
constexpr NavigationTarget legacy_tab_target(int tab) noexcept;
```

Add `tests/test_ui_navigation.cpp` to `gcad_tests` and call `register_ui_navigation_tests()` from `tests/test_main.cpp`.

- [ ] **Step 4: Replace the `BeginTabBar` shell.**

Implement `render_navigation_rail()`, `render_top_header()`, and `render_active_view()` in `UIManager`. Use six compact ImGui buttons with two-letter glyphs (`OV`, `SC`, `NW`, `IN`, `FR`, `ST`) and tooltips, not an icon-font dependency. Draw Overview/Scan/Network/Incidents/Forensics/Settings from `active_view_`; Incidents renders its in-page Alert/Quarantine selector. In the Win32 window style, remove the existing `WS_THICKFRAME` exclusion so the normal window is resizeable, while retaining the `WS_MAXIMIZEBOX` exclusion and normal-show startup.

- [ ] **Step 5: Apply the C visual system.**

Update `ThemeColors` and `apply_dark_theme()` to use a midnight-navy background, cyan interactive accent, restrained panel borders, and semantic safe/warn/critical colors. Keep existing font loading and resize handling unchanged. Update the status bar to show the six-shell state without changing its engine, scan, event, threat, or uptime data.

- [ ] **Step 6: Run focused and full verification; commit.**

Run: `cmake --build build-make --target gcad gcad_tests --parallel 1`; `build-make\gcad_tests.exe`; `ctest --test-dir build-make --output-on-failure`.

Commit: `feat(ui): add minimal operator shell`

### Task 2: Recompose Overview, Scan, Network, and Settings

**Files:**
- Modify: `src/ui/views/dashboard_view.cpp`, `include/gcad/ui/views/dashboard_view.hpp`, `src/ui/views/scan_view.cpp`, `src/ui/views/network_view.cpp`, `src/ui/views/settings_view.cpp`

**Interfaces:**
- Consumes existing `EngineManager`, `DeepScanner`, `ETGRIEngine`, `FirewallEngine`, and `AlertManager` snapshot APIs only.
- Produces no new engine or scanner API and no new persistent state.

- [ ] **Step 1: Run the navigation regression before page edits.**

Run: `cmake --build build-make --target gcad_tests --parallel 1 && build-make\gcad_tests.exe`

Expected: `ui_primary_navigation_contract` passes before view-only edits begin.

- [ ] **Step 2: Make Overview attention-first.**

Retain `render_kpi_cards`, engine status, findings, and activity data, but reduce the first viewport to: protection posture, engines online, active threats, last scan/event rate, category health, and recent activity. Hide empty timeline/resource plots behind compact detail sections rather than showing decorative zero-state graphs. Do not mutate the dashboard's history indices during a render solely to create animation.

- [ ] **Step 3: Make Scan a single work area.**

Keep the existing Quick/Memory/Custom modes and their current `DeepScanner` calls. Render one mode selector, one context-aware Start/Cancel button, progress, then the existing result table. The Custom path behavior remains exactly as implemented; no path is selected or scanned automatically.

- [ ] **Step 4: Simplify Network and Settings without changing controls.**

Use compact local selectors for Traffic/Firewall and firewall subviews. Group Settings visually as Engines, Scan, Alerts & Reports, and General, while preserving every existing control and its authority. Do not make Auto-Quarantine operational if it was not operational before this work.

- [ ] **Step 5: Build, test, and commit.**

Run the Task 1 verification commands and inspect `git diff --check`.

Commit: `feat(ui): redesign operator work areas`

### Task 3: Safe Incidents composition and readable forensics flow

**Files:**
- Create: `include/gcad/ui/incident_actions.hpp`
- Modify: `include/gcad/ui/views/quarantine_view.hpp`, `src/ui/views/quarantine_view.cpp`, `src/ui/views/forensics_view.cpp`, `tests/test_ui_navigation.cpp`, `CMakeLists.txt`, `tests/test_main.cpp`

**Interfaces:**
- Produces `enum class IncidentAction { NONE, ROLLBACK_FILES, RESUME_PROCESS, TERMINATE_PROCESS }` and `requires_confirmation(IncidentAction)`.
- `QuarantineView` owns `std::optional<PendingIncidentAction> pending_action_`; `PendingIncidentAction` contains the action, PID, and process name copied from a snapshot.

- [ ] **Step 1: Write confirmation-policy tests.**

```cpp
register_test("ui_incident_actions_require_confirmation", [] {
    using namespace gcad::ui;
    return !requires_confirmation(IncidentAction::NONE) &&
           requires_confirmation(IncidentAction::ROLLBACK_FILES) &&
           requires_confirmation(IncidentAction::RESUME_PROCESS) &&
           requires_confirmation(IncidentAction::TERMINATE_PROCESS);
});
```

- [ ] **Step 2: Verify the test fails because the action policy is absent.**

Run: `cmake --build build-make --target gcad_tests --parallel 1`

- [ ] **Step 3: Implement the action policy and confirmation modal.**

```cpp
if (ImGui::Button("Terminate"))
    pending_action_ = {IncidentAction::TERMINATE_PROCESS, proc.pid, proc.name};

if (pending_action_ && ImGui::BeginPopupModal("Confirm incident action")) {
    // Render copied process name, PID, action label, and consequence.
    if (ImGui::Button("Cancel")) pending_action_.reset();
    if (ImGui::Button("Confirm")) execute_pending_action(engine);
    ImGui::EndPopup();
}
```

`execute_pending_action` calls `ARHSEngine::rollback_process`, `platform::resume_process`, or `platform::terminate_process` only in the Confirm branch, then clears the pending action. Cancel always clears it without calling an engine/platform function. Preserve snapshot-copy access; never hold an engine lock while rendering the modal.

- [ ] **Step 4: Replace PID-circle forensics layout.**

Keep the existing event snapshot input and selection behavior. Lay out rounded rectangular nodes in deterministic left-to-right lanes by event order, draw directional Bezier arrows behind nodes, label nodes with process name/PID and severity, and retain the right detail/timeline panels. Remove render-time rotation or mutation of graph ordering.

- [ ] **Step 5: Build, test, smoke-test modal cancellation, and commit.**

Run the Task 1 verification commands. In the GUI, open a Quarantine action modal and press Cancel; confirm no rollback/resume/terminate side effect occurs. Then inspect Forensics at normal and narrow window widths.

Commit: `feat(ui): add confirmed incident actions`

### Task 4: Documentation and final visual verification

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`

**Interfaces:**
- Documents the six primary destinations, Incidents' two panes, and confirmation-only manual incident actions; does not claim automatic remediation.

- [ ] **Step 1: Update UI documentation.**

Replace the old seven-tab description with the six-destination shell and state that Alerts and Quarantine live under Incidents. State that Rollback Files, Resume Process, and Terminate require a confirmation modal and remain manual operations.

- [ ] **Step 2: Verify documentation matches code.**

Run: `rg -n "Dashboard, Deep Scan|Quarantine.*primary|automatic" README.md ARCHITECTURE.md`.

Expected: no obsolete primary-tab claim; every remaining automatic-action
reference explicitly says that GCAD does not perform the action automatically.

- [ ] **Step 3: Perform final build and GUI smoke.**

Run the single-threaded build, direct `gcad_tests.exe`, CTest, and `git diff --check`. Launch `build-make\bin\gcad.exe`, resize its window, visit all six destinations, switch both Incidents panes, exercise Quick/Memory/Custom start-cancel controls, complete one safe Quick scan, cancel a Quarantine confirmation modal, and inspect the labeled Forensics flow. Do not confirm a destructive action, approve remediation, or execute quarantine.

- [ ] **Step 4: Commit and hand off.**

Commit: `docs(ui): document operator console navigation`

Report the four implementation commits, exact test counts, GUI observations, and any UI-automation blocker. Do not push or merge without a fresh explicit instruction.
