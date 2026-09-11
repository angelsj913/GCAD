# GCAD Architecture

`EngineManager` owns the security engines and collects immutable `ThreatEvent` snapshots. UI views consume copies returned by `statuses()` and `recent_events()`; they do not retain references to engine-owned collections.

## Runtime flow

1. Security engines emit `ThreatEvent` values through `EngineManager`.
2. `EngineManager` assigns IDs and retains a bounded event history.
3. `UIManager` owns the Win32/DX11 frame loop, menu actions, tab selection, and status bar.
4. Dashboard, network, quarantine, scan, settings, and forensics views render snapshot data.
5. The forensic view derives a PID-keyed graph from visible event records. Its arrows visualize event sequence relationships, not proven process-parentage or causal attribution.

## Security decision pipeline

`security/` normalizes raw signals into immutable `SecurityObservation` values.
`TelemetryBus` is a bounded, closeable FIFO; it rejects invalid observations and
drops new observations at capacity instead of blocking producers. `CorrelationEngine`
suppresses same-source duplicates for thirty seconds and raises a finding only when
score or severity grows within its five-minute target window. `PolicyEngine` is pure
and only marks non-protected critical deterministic signatures as data-only
quarantine candidates.

`ArtifactTrustEngine` inspects bounded PE data and offline Authenticode state.
`ProcessBehaviorEngine` uses documented user-mode APIs to observe executable-writable
memory and impossible live-parent creation order. Access denial is unavailable
evidence, not a threat verdict.

`EtwKernelProcessEngine` is GCAD's first genuine ETW consumer: it opens a
real-time session against the manifested `Microsoft-Windows-Kernel-Process`
provider (`StartTrace`/`EnableTraceEx2`/`OpenTrace`/`ProcessTrace`) and decodes
`ProcessStart`/`ProcessStop` records with TDH, publishing a `PROCESS_LINEAGE`
observation directly to the pipeline when a process's claimed live parent was
created after it. It requires administrator or "Performance Log Users"
privilege; `EngineManager::etw_kernel_process_active()` reports the live state
honestly instead of assuming success. GCAD still does not consume any other ETW
provider or claim kernel-driver visibility.

## Components

- `PMSR`, `ETG-RI`, `ARHS`, `ZRGP`, `SelfDefense`, `SyscallGuard`, and `KernelMonitorEngine` are security-engine implementations.
- `DeepScanner` performs Quick, Deep, Memory, and Custom-path scans.
- `platform/` contains Windows ETW and Linux monitoring adapters.
- `ui/` contains the presentation layer. It must not update engine state except from explicit user actions such as scan commands or settings controls.

## Platform boundary

The full interactive console is currently implemented for Windows with Win32, Direct3D 11, and Dear ImGui. Linux retains a stub UI loop; engine availability and telemetry differ by platform.
