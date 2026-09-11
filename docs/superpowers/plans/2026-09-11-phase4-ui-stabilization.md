# GCAD Phase 4 UI Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete and verify GCAD's interrupted Phase 4 UI without regressing the Phase 1-3 protection engine work.

**Architecture:** UIManager owns only the platform window, frame lifecycle, menus, tab selection, and status bar. Each view consumes immutable EngineManager snapshots. The forensic graph is built from the current threat-event snapshot and carries its own pan, zoom, and selection state; it must never mutate engine state during rendering.

**Tech Stack:** C++20, CMake, Ninja, Dear ImGui, Win32, Direct3D 11, existing GCAD unit-test executable.

## Global Constraints

- Preserve all Phase 1-3 behavior and existing public engine interfaces.
- Keep the application windowed, fixed-size, and centered at launch; do not use `SW_SHOWMAXIMIZED`.
- Do not add dependencies or push a remote branch.
- Preserve warning-free C++20 builds under the repository's `-Werror` configuration.
- UI render methods may read snapshots and update view-local interaction state only.

---

### Task 1: Recover a coherent UI compilation boundary

**Files:**
- Modify: `include/gcad/ui/views/dashboard_view.hpp`
- Modify: `src/ui/views/dashboard_view.cpp`
- Modify: `include/gcad/ui/theme.hpp`
- Modify: `src/ui/theme.cpp`
- Modify: `src/ui/ui_manager.cpp`

**Interfaces:**
- Consumes: `EngineManager::statuses()`, `EngineManager::recent_events(size_t)`, and `EngineManager::current_threat_level()`.
- Produces: `DashboardView::render(EngineManager&)` with declarations matching all private helpers.

- [ ] **Step 1: Establish the current failure**

Run: `cmake --build build --target gcad --parallel`

Expected: compilation fails because the interrupted `DashboardView` header and implementation expose different private member functions.

- [ ] **Step 2: Reconcile the DashboardView interface**

Declare exactly the helpers implemented by the view, or replace obsolete implementations with the approved KPI, engine-card, gauge, resource-monitor, and activity-feed helpers. Keep the public interface exactly:

```cpp
void render(EngineManager& em);
```

- [ ] **Step 3: Make frame lifecycle failure-safe**

Use `SW_SHOWNORMAL`, set `start_time_` after successful initialization, and ensure each DX11 failure path releases already-created resources through `shutdown()` or a local release helper before returning `ERR_INIT_FAIL`.

- [ ] **Step 4: Verify build**

Run: `cmake --build build --target gcad --parallel`

Expected: `gcad` builds with no warnings or errors.

### Task 2: Complete navigation and status affordances

**Files:**
- Modify: `include/gcad/ui/ui_manager.hpp`
- Modify: `src/ui/ui_manager.cpp`

**Interfaces:**
- Consumes: `active_tab_`, `EngineManager` snapshots, and `DeepScanner::start_scan/cancel_scan` existing APIs.
- Produces: menu actions that select tabs or invoke only existing, explicit scan actions.

- [ ] **Step 1: Add menu behavior without engine side effects in rendering**

Implement File (Exit), Scan (open scan tab), Protection (open dashboard/forensics), and Help (About popup) using stable tab indices. File Exit only sets `should_close_`; it must not stop engines directly.

- [ ] **Step 2: Add status bar**

Render engine count, current threat label, scan state, and elapsed UI uptime at the bottom of the main content area. Read all values from snapshots; do not retain references to engine-owned collections.

- [ ] **Step 3: Verify UI compilation**

Run: `cmake --build build --target gcad --parallel`

Expected: `gcad` builds with no warnings or errors.

### Task 3: Rebuild the forensic card DAG safely

**Files:**
- Modify: `include/gcad/ui/views/forensics_view.hpp`
- Modify: `src/ui/views/forensics_view.cpp`

**Interfaces:**
- Consumes: `std::vector<ThreatEvent>` returned by `EngineManager::recent_events(200)`.
- Produces: selected PID/card information, a deterministic layered layout, and only index-safe directed edges.

- [ ] **Step 1: Define deterministic graph invariants**

Each node is keyed by nonzero PID, carries process label, highest observed severity, event count, and outgoing node indices. Edges are added only between valid node indices. Rebuild when snapshot identity/content changes, not solely when count changes.

- [ ] **Step 2: Render readable process cards**

Draw rounded rectangular nodes with process name, PID, event count, severity dot, directional Bezier edges, clipping, pan, zoom, and hit-testing after drawing the canvas button. Render selection details and event timeline from the same snapshot.

- [ ] **Step 3: Verify UI compilation**

Run: `cmake --build build --target gcad --parallel`

Expected: `gcad` builds with no warnings or errors.

### Task 4: Stabilize remaining view presentation and documentation

**Files:**
- Modify: `src/ui/views/network_view.cpp`
- Modify: `src/ui/views/quarantine_view.cpp`
- Modify: `src/ui/views/scan_view.cpp`
- Modify: `src/ui/views/settings_view.cpp`
- Create: `README.md`
- Create: `ARCHITECTURE.md`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: existing snapshot-returning view APIs.
- Produces: responsive layouts and documentation that distinguishes implemented telemetry from planned functionality.

- [ ] **Step 1: Audit fixed-width layout only where it clips at 1100px**

Replace only confirmed fixed-pixel panels with `GetContentRegionAvail()` proportions and preserve each view's existing actions and data flow.

- [ ] **Step 2: Document current verified behavior**

README must contain build/run/test commands. ARCHITECTURE must describe engine boundaries, event flow, scanner modes, and platform differences without claiming unverified protection coverage.

- [ ] **Step 3: Ignore local runtime artifacts**

Add `imgui.ini` and other confirmed local UI runtime files only; do not ignore source, test, or configuration files.

### Task 5: End-to-end verification and controlled commit

**Files:**
- Verify: all files changed by Tasks 1-4

- [ ] **Step 1: Build and test**

Run:

```powershell
cmake --build build --parallel
& .\build\gcad_tests.exe
```

Expected: warning-free build and all tests passing.

- [ ] **Step 2: GUI smoke test**

Launch `gcad.exe` normally. Confirm: initial fixed-size, centered window, menu access, six tabs, status bar, Quick Scan start/cancel, and a selectable forensic node when PID-bearing events exist.

- [ ] **Step 3: Review staged diff and commit only Phase 4 files**

Run `git diff --check`, inspect `git status --short`, and stage only verified Phase 4 files. Use commit message:

```text
feat(ui): complete windowed operations console
```

Do not push.

## Plan Self-Review

- Spec coverage: Tasks 1-3 cover windowed launch, menus/status, dashboard, and forensic cards. Task 4 covers the requested remaining presentation and docs. Task 5 covers build, tests, GUI smoke, and a local-only commit.
- Placeholder scan: no implementation step depends on an unspecified dependency or future task.
- Type consistency: all views retain existing `render(EngineManager&)` ownership and consume snapshots rather than raw cross-thread references.
