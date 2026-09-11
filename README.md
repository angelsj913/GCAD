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
a quarantine *candidate*, but this version never moves files, terminates processes,
or blocks traffic automatically. The component named `Win32Etw` is not an ETW event
consumer; it provides limited user-mode polling and integrity observations.

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
