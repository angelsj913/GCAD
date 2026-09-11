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
score or severity grows within its five-minute target window. It also marks a
finding `deterministic_signature` when any contributing observation was an exact
or structural check rather than a statistical guess, which is what lets
`PolicyEngine` -- pure, and otherwise report-only -- mark a non-protected
critical deterministic signature as a data-only quarantine candidate.

`legacy_adapter.hpp`/`.cpp` converts each of PMSR, ETG-RI, ARHS, ZRGP,
SelfDefense, SyscallGuard, and KernelMon's `ThreatEvent` callbacks into a
`SecurityObservation`, keyed on `(engine_name, ThreatCategory)` rather than
`ThreatLevel` alone. The pair matters because the same category can mean
different things per engine: `EVASION_UNHOOK` is an exact `memcmp` of a remote
process's live ntdll `.text` against an on-disk pristine copy in SyscallGuard,
but only "an OS query on GCAD's own token/DACL failed" in SelfDefense -- a much
weaker signal. `source_id` is now the emitting engine's own name, so two
categories from the same engine no longer look like two independent sources to
`CorrelationEngine`'s multi-source bonus. An unrecognized (engine, category)
pair falls back to the original level-only confidence and is never marked
deterministic. `SelfDefense`'s `EVASION_UNHOOK` handle-integrity check remains
low-confidence and non-deterministic by design: it is scoped honestly rather
than fixed, since strengthening the underlying check is separate follow-up work.

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
