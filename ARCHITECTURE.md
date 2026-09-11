# GCAD Architecture

`EngineManager` owns the security engines and collects immutable `ThreatEvent` snapshots. UI views consume copies returned by `statuses()` and `recent_events()`; they do not retain references to engine-owned collections.

## Runtime flow

1. Security engines emit `ThreatEvent` values through `EngineManager`.
2. `EngineManager` assigns IDs and retains a bounded event history.
3. `UIManager` owns the Win32/DX11 frame loop, menu actions, tab selection, and status bar.
4. Dashboard, network, quarantine, scan, settings, and forensics views render snapshot data.
5. The forensic view derives a PID-keyed graph from visible event records. Its arrows visualize event sequence relationships, not proven process-parentage or causal attribution.

## Components

- `PMSR`, `ETG-RI`, `ARHS`, `ZRGP`, `SelfDefense`, `SyscallGuard`, and `KernelMonitorEngine` are security-engine implementations.
- `DeepScanner` performs Quick, Deep, Memory, and Custom-path scans.
- `platform/` contains Windows ETW and Linux monitoring adapters.
- `ui/` contains the presentation layer. It must not update engine state except from explicit user actions such as scan commands or settings controls.

## Platform boundary

The full interactive console is currently implemented for Windows with Win32, Direct3D 11, and Dear ImGui. Linux retains a stub UI loop; engine availability and telemetry differ by platform.
