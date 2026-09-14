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

The Windows console opens as a centered, resizable window with maximization
disabled. Its six primary destinations are **Overview**, **Scan**,
**Network**, **Incidents**, **Forensics**, and **Settings**. Incidents contains
the Alerts and Quarantine panes. Quarantine's Rollback Files, Resume Process,
and Terminate controls are manual operations: GCAD shows the target process,
the selected action, and its consequence in a confirmation modal before it
calls an existing action. Cancelling the modal changes nothing. Elevated
permissions may be required for some process and raw-network telemetry.

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
traffic without an explicit external call: `EngineManager::approve_remediation()`
must run first, and only then does a second, separate call to
`execute_quarantine()` let `QuarantineExecutor` act. No engine and no automatic
logic calls either one -- this is a reachable API surface for a future UI/CLI
action, not something GCAD triggers on its own. The component named `Win32Etw`
is not an ETW event consumer; it provides limited user-mode polling and
integrity observations.

`LocalSecurityPolicy` can persist to a small key=value text file via
`PolicyStore`; `EngineManager` loads `%PROGRAMDATA%\GCAD\policy.txt` at
startup and falls back to safe built-in defaults for a missing, unreadable, or
partially corrupt file (each field degrades independently). A candidate stays
`PENDING_APPROVAL` until `EngineManager::approve_remediation()`/
`reject_remediation()` is called explicitly; `QuarantineExecutor` then
re-validates the target (not a symlink,
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
`ProcessStart`/`ProcessStop` record's raw `UserData` bytes itself
(`EtwKernelProcessEngine::decode_process_start()`), against the provider's
documented manifest field order, instead of calling TDH
(`TdhGetProperty`/`TdhFormatProperty`) to extract named fields on GCAD's
behalf. That field-order assumption has not been verified against a live
capture -- no administrator session was available in the environment this was
built in to start a real-time trace and inspect actual bytes -- so
`decode_process_start()` fails closed (drops the event) rather than guess when
a buffer does not fit the expected shape; an elevated verification pass is
still open. Creating a real-time session
requires administrator privilege (or membership in "Performance Log Users"); when
that privilege is absent, `start()` returns `ErrorCode::ERR_ENGINE_START` and the
sensor reports itself as not running rather than fabricating telemetry. When
active, it emits a `SecurityObservation` only when a process's claimed live
parent was created strictly after it -- the same deterministic anomaly
`ProcessBehaviorEngine` reports on demand, observed continuously instead of
through periodic snapshot polling. It does not claim to unmask every
EPROCESS-level parent-spoofing technique.

## Batch 4 engines and GaloisShield

The Batch 4 engines add local user-mode signals for ransomware behavior,
credential-access activity, network beaconing, and device policy. They emit
structured observations with their own source IDs (`RansomwareShield`,
`CredentialGuard`, `NetworkDPI`, and `DeviceControl`) so the same bounded
pipeline can correlate their evidence without treating unrelated events from
one engine as independent sources.

- `RansomwareShield` tracks file writes, renames, entropy trends, shadow-copy
  deletion reports, and honeyfile changes. Ransomware extensions are compared
  case-insensitively.
- `CredentialGuard` aggregates suspicious LSASS access, token manipulation,
  lateral-movement, and SAM-access signals per process.
- `NetworkDPI` analyzes packet metadata and flags stable repeated connections as
  `C2_BEACON`; a reported connection timeline is suppressed until it no longer
  meets the beacon threshold.
- `DeviceControl` evaluates local USB/device policy and reports a block as
  `DEVICE_POLICY`. Audit-only device activity remains an observation, not a
  block.

`GaloisShield` is not a twenty-third detection engine. It is a thin management
facade over an application-owned `EngineManager`: it starts or stops the same
engines, presents their snapshots, groups them into seven categories (Memory
Protection, Process Defense, Network Security, File Protection, System
Integrity, Threat Analysis, and Endpoint Control), and exposes one health
report. Its health score is the running-engine ratio minus a current-threat
penalty (0/5/15/30/50 points for Safe through Critical), clamped to 0–100%.
It neither owns a telemetry loop nor grants any remediation authority.

## Troubleshooting

The normal Windows build uses Ninja. On this PC, if Ninja stalls while CMake
regenerates compiler checks, use this diagnostic fallback instead of treating a
stalled build as a successful one:

```powershell
cmake -S . -B build-make -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_SOURCE_DIR_IMGUI="C:/Users/angel/GCAD/build/_deps/imgui-src"
cmake --build build-make --target gcad gcad_tests --parallel 1
ctest --test-dir build-make --output-on-failure
```

This is a local troubleshooting route, not a replacement for the project's
normal Ninja configuration.

## Safety

Run only on systems where you are authorized to inspect processes and files. GCAD performs local monitoring and may expose process metadata in its interface.
