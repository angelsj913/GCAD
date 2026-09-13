# GCAD Minimal Operator UI Design

## Summary

GCAD's current tabbed desktop console becomes a compact, operator-first shell.
The redesign keeps all existing security and scan behavior intact, but changes
how snapshots and explicit actions are arranged: a narrow icon rail, a single
work area, an always-visible protection state, and fewer competing panels.

The visual direction is **C — Minimal Operator**: midnight-navy surfaces,
cyan as the single interactive accent, and semantic green/amber/coral only for
security state. Typography stays on the existing Segoe UI family. The primary
window remains resizeable; below the normal desktop width, the rail is reduced
to icons and content stacks instead of clipping.

## Shell and navigation

`UIManager` owns the shell, navigation state, menu commands, and bottom status
bar. Its current seven tab slots are replaced by six primary destinations:

1. **Overview** — Dashboard and current protection posture.
2. **Scan** — Quick, Memory, and Custom scan launch, progress, cancellation,
   and results.
3. **Network** — Traffic monitor and firewall data.
4. **Incidents** — An in-page selector for **Alerts** and **Quarantine**;
   Quarantine is no longer a primary navigation destination.
5. **Forensics** — Process/event relationship exploration.
6. **Settings** — Engine, scan, alert/report, and general settings.

The top header shows the destination, current GaloisShield/engine availability,
and one context-safe primary action. On Overview and Scan that action opens or
starts a scan; other pages have no invented destructive action. The bottom bar
continues to show engine availability, scan state, event count, threat count,
and uptime.

The File, Scan, Protection, and Help menus remain keyboard-accessible. Their
targets are remapped to the six destinations. Existing tray commands retain
their behavior and map Alerts and Quarantine to the Incidents destination.

## Page content

- **Overview:** one protection-health summary, concise engine-category status,
  active threat count, and a bounded recent-activity list. A clean system
  emphasizes the health state rather than decorative empty charts; detail is
  revealed only when a user selects an activity or category.
- **Scan:** a three-mode selector and one prominent start/cancel control above
  progress and a result table. Results retain the existing severity and file
  data without adding automatic quarantine.
- **Network:** a compact traffic summary with the existing packet, blocked-IP,
  and firewall views as secondary in-page choices.
- **Incidents:** Alerts is the default pane. Quarantine remains a review pane
  for existing ARHS sandbox snapshots; it does not approve, quarantine, delete,
  restore, or terminate anything.
- **Forensics:** replace decorative PID circles with a readable left-to-right
  process/event flow. Nodes are labeled rounded rectangles, relationship lines
  are directional, and the right detail pane remains a snapshot-only inspector.
- **Settings:** replace one long accordion with four visual groups. Existing
  settings controls retain their present implementation and authority.

## Boundaries and safety

This is a presentation-layer change. `EngineManager`, `DeepScanner`,
`AlertManager`, ARHS, the remediation approval API, and engine state ownership
are not changed. Render functions consume value snapshots only. No rendering
path starts engines, changes policy, writes files, or performs remediation
unless the user uses an existing explicit control.

No new telemetry, network call, persistence format, or third-party UI library
is introduced. Existing Dear ImGui/DX11 ownership and `WM_SIZE` resize handling
remain the rendering foundation.

## Acceptance checks

- Build `gcad` and `gcad_tests` with the single-threaded `build-make` path;
  direct tests and CTest have zero failures.
- Verify no side effects from opening each of the six destinations or changing
  the Incidents selector.
- GUI smoke: resize the window, navigate all six destinations, open both
  Incidents panes, run and cancel Quick/Memory/Custom scans, then complete one
  safe Quick scan. No automatic remediation is approved or executed.
- Confirm Forensics has labeled directional nodes and no PID-only dot layout.
- Run `git diff --check`; commit only source, headers, tests, and the design
  document. Exclude `.agents/`, worktree internals, and build artifacts.
