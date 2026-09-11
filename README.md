# GCAD

GCAD (Galoisconnection Antivirus & Defense) is a C++20 security-monitoring prototype with a local Direct3D 11 operations console on Windows.

## Build

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

## Run

```powershell
.\build\bin\gcad.exe
```

The Windows console opens as a fixed-size, centered window. It provides Dashboard, Deep Scan, Network, Quarantine, Forensics, and Settings tabs. Elevated permissions may be required for some process and raw-network telemetry.

## Test

```powershell
.\build\gcad_tests.exe
```

The test suite covers selected engine and scanner contracts. Passing tests do not establish complete malware-detection coverage or replace deployment validation on a controlled machine.

## Engine foundation

GCAD's local security pipeline accepts bounded, structured observations from its
engines, correlates independent signals, and records an explainable finding. It is
Windows user-mode and offline: no cloud reputation, kernel driver, remote policy,
or sample upload is used. A full telemetry queue drops new observations and exposes
drop metrics rather than blocking a protection engine.

Findings are report-only by default. A critical deterministic signature can create
a quarantine *candidate*, but nothing moves a file, terminates a process, or blocks
traffic without going through `SecurityPipeline::approve_candidate()` first --
and even then, only `QuarantineExecutor` acts on it, and only `EngineManager`
would decide when to call that; today nothing does, so quarantine execution is a
tested, standalone capability, not a live path. The component named `Win32Etw`
is not an ETW event consumer; it provides limited user-mode polling and
integrity observations.

`LocalSecurityPolicy` can persist to a small key=value text file via
`PolicyStore`; `EngineManager` loads `%PROGRAMDATA%\GCAD\policy.txt` at
startup and falls back to safe built-in defaults for a missing, unreadable, or
partially corrupt file (each field degrades independently). A candidate stays
`PENDING_APPROVAL` until `approve_candidate()`/`reject_candidate()` is called
explicitly; `QuarantineExecutor` then re-validates the target (not a symlink,
not a protected path, size-bounded, and hash-matched against the evidence
captured at detection time) before moving it into a vault it can restore from
later. See `ARCHITECTURE.md` for the full workflow.

PMSR, ETG-RI, ARHS, ZRGP, SelfDefense, SyscallGuard, and KernelMon still report
through the legacy `ThreatEvent`/`on_threat` path for the UI, but `EngineManager`
now adapts each one into the observation pipeline with per-(engine, category)
confidence and determinism instead of a blanket per-severity guess -- see
`ARCHITECTURE.md` for exactly which detections are exact/structural checks and
which are statistical thresholds. This does not by itself enable automatic
quarantine for these engines: `PolicyEngine` still requires a non-empty target
file path, and most of these six report a process anomaly, not a file.

`security::EtwKernelProcessEngine` is a genuine ETW consumer: it opens a real-time
session against the manifested `Microsoft-Windows-Kernel-Process` provider with
`StartTrace`/`EnableTraceEx2`/`OpenTrace`/`ProcessTrace` and decodes each
`ProcessStart`/`ProcessStop` record with TDH. Creating a real-time session
requires administrator privilege (or membership in "Performance Log Users"); when
that privilege is absent, `start()` returns `ErrorCode::ERR_ENGINE_START` and the
sensor reports itself as not running rather than fabricating telemetry. When
active, it emits a `SecurityObservation` only when a process's claimed live
parent was created strictly after it -- the same deterministic anomaly
`ProcessBehaviorEngine` reports on demand, observed continuously instead of
through periodic snapshot polling. It does not claim to unmask every
EPROCESS-level parent-spoofing technique.

## Safety

Run only on systems where you are authorized to inspect processes and files. GCAD performs local monitoring and may expose process metadata in its interface.
