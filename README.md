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

## Safety

Run only on systems where you are authorized to inspect processes and files. GCAD performs local monitoring and may expose process metadata in its interface.
