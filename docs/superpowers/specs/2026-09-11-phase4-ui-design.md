# GCAD Phase 4 UI Stabilization Design

## Goal

Finish the interrupted Phase 4 user interface work without changing the Phase 1-3 protection-engine behavior. GCAD must open as a normal window, expose meaningful navigation and status information, and render forensic process relationships as readable cards rather than decorative dots.

## Scope

- Start in a normal, fixed-size centered window; do not maximize at launch.
- Add a functional File, Scan, Protection, and Help menu bar plus a non-interactive status bar.
- Reconcile `DashboardView` declarations and definitions, then present engine health, threat level, resource data, and recent events with responsive ImGui layout.
- Rebuild the forensic graph from the event snapshot into PID-backed node cards, directed links, selection details, pan, and zoom.
- Keep rendering pure: graph and dashboard state is updated from event snapshots or resource samples, not by mutating protection-engine state.

## Non-goals

- No modification to security-engine detection logic, signatures, or platform telemetry.
- No claims of a production-quality EDR from visual changes alone.
- No external network calls, dependency additions, or automatic push.

## Verification

- Add an automated test for extracted forensic graph construction if it can be isolated from ImGui.
- Build with the existing CMake/Ninja configuration and run all existing tests.
- Run the Windows GUI and verify windowed launch, menus, tabs, Quick Scan controls, dashboard, and forensic graph interaction manually.
