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

## Safety

Run only on systems where you are authorized to inspect processes and files. GCAD performs local monitoring and may expose process metadata in its interface.
