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
and a hand-parsed check that GCAD's own process-protection DACL is still
present in SelfDefense -- two different exact checks, independently
calibrated (0.92 and 0.88). `source_id` is now the emitting engine's own name,
so two categories from the same engine no longer look like two independent
sources to `CorrelationEngine`'s multi-source bonus. An unrecognized (engine,
category) pair falls back to the original level-only confidence and is never
marked deterministic.

`SelfDefenseEngine` applies that DACL itself at `start()`: it reads its own
process security descriptor via `NtQuerySecurityObject`, hand-builds a new ACL
that prepends a DENY ACE for `PROCESS_VM_WRITE`/`VM_OPERATION`/
`CREATE_THREAD`/`SUSPEND_RESUME`/`SET_INFORMATION`/`TERMINATE`/`DUP_HANDLE`
against the ACL/ACE/SID byte layout documented in MS-DTYP (no
`SetEntriesInAcl`/`AllocateAndInitializeSid`/`SetSecurityInfo` -- those would
build the structure on GCAD's behalf), and writes it back with
`NtSetSecurityObject`. `check_handle_integrity()` then periodically re-parses
the live DACL to confirm that ACE is still present, firing only once
protection was actually applied and later found missing. Setting
`GCAD_DISABLE_SELF_PROTECT=1` before launch skips applying it, for a debugger
or management tool that needs the same rights this DACL denies to everyone
else.

`ArtifactTrustEngine` inspects bounded PE data and offline Authenticode state.
`ProcessBehaviorEngine` uses documented user-mode APIs to observe executable-writable
memory and impossible live-parent creation order. Access denial is unavailable
evidence, not a threat verdict.

## Policy persistence and the approval workflow

`PolicyStore` loads and saves `LocalSecurityPolicy` as a small key=value text
file (not JSON -- GCAD adds no third-party parser for a handful of scalar
fields). `EngineManager` loads `%PROGRAMDATA%\GCAD\policy.txt` at construction
and falls back to `LocalSecurityPolicy{}` defaults for a missing file, an
unreadable file, or any individual out-of-range field; nothing currently calls
`PolicyStore::save()` automatically, since no UI yet edits the policy.

`SecurityPipeline::approve_candidate()`/`reject_candidate()` are the only way a
`RemediationCandidate` leaves `PENDING_APPROVAL`, and they only ever change
that in-memory state -- they never touch a file or a process. The opposite
terminal state is refused (`ERR_INVALID_TRANSITION`); reaching the same
terminal state again is idempotent; an unknown finding id is `ERR_NOT_FOUND`.

`QuarantineExecutor` is the only component that acts on a candidate's target
file, and only when `approval_state == APPROVED`. It re-validates at execution
time rather than trusting the candidate: the target must not be a symlink,
must be a regular file under a size bound, must not fall under a protected
path in the policy given to the executor (which may differ from the policy in
effect when the candidate was created), and -- when the candidate carries an
`expected_sha256` captured at detection time -- its current hash must still
match, so a file that changed after detection is never quarantined on stale
evidence. Quarantining moves (never deletes) the file into a vault directory
(`%PROGRAMDATA%\GCAD\Quarantine`) and appends a pipe-delimited ledger line next
to it so `restore()` can move it back after a process restart; `restore()`
refuses to overwrite anything now occupying the original path.

`EngineManager` owns the one `QuarantineExecutor` instance and exposes the
full workflow as a single API surface: `find_remediation_candidate()`,
`approve_remediation()`/`reject_remediation()` (pure state transitions,
delegating to `SecurityPipeline`), and `execute_quarantine()`/
`restore_quarantine()`/`recent_quarantine_records()`. No engine and no
automatic logic ever calls `approve_remediation()` or `execute_quarantine()`
-- both require an explicit external caller naming a finding id, and they are
two separate calls (approve, then execute), so nothing in GCAD can move a file
on its own. This surface exists for a future UI/CLI action to call; none
exists yet.

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
