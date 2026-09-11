# GCAD Windows User-Mode Engine Foundation Design

## Goal

Build an offline, Windows-first defensive-engine foundation that turns independent
sensor signals into deterministic, explainable, and safely actionable security
decisions. GCAD remains a user-mode product: this release does not claim kernel
telemetry, signed-driver enforcement, cloud reputation, or guaranteed malware
prevention.

## Product Boundary

- Platform: Windows is the supported implementation target. Linux keeps its
  existing compatibility stubs and is not part of this release's acceptance gate.
- Connectivity: all decisions are local. No sample upload, cloud lookup, remote
  policy service, or automatic signature download is added.
- Action policy: detections are reported by default. Only a policy-approved,
  deterministic signature match can become a quarantine candidate; no file move,
  process termination, or network block runs without an explicit approval path.
- Compatibility: existing `ISecurityEngine` implementations keep their lifecycle
  contract while their findings are adapted into the new observation pipeline.
- Safety: no callback executes while an engine-owned mutex is held. All queues,
  histories, and correlation caches are bounded.

## Current-State Findings

GCAD has seven independently started engines and a `DeepScanner`, each of which
can publish a `ThreatEvent`. There is no common evidence model, event deduplication,
risk-scoring contract, local policy boundary, or remediation decision record.
The component named `Win32Etw` currently polls processes and checks the current
process's AMSI/ETW entry points; it is not an ETW consumer and must not be presented
as one. The redesign preserves it as a sensor with accurately scoped evidence.

## Alternatives Considered

### A. Add rules directly to the existing engines

This has the smallest initial diff but leaves each engine with its own severity,
deduplication, and action semantics. It cannot establish reliable global policy or
explain why multiple weak signals formed one verdict. Rejected.

### B. Observation bus, correlation engine, and policy engine

Sensors emit immutable observations. A single-threaded correlation worker derives
findings and action candidates under an explicit local policy. This adds clear
boundaries, deterministic test seams, and a migration path for existing engines.
Selected.

### C. Kernel-driver-first EDR

This offers deeper visibility but requires code-signing, compatibility testing,
installer/rollback design, and an isolated test lab. It exceeds the selected
user-mode/offline release. Deferred behind future platform interfaces.

## Architecture

```text
existing engines / scanner / new user-mode sensors
                     |
                     v
            SecurityObservation (immutable value)
                     |
                     v
      TelemetryBus (bounded queue, drop metrics)
                     |
                     v
 CorrelationEngine (dedup + time-window risk accumulation)
                     |
                     v
       PolicyEngine (local decision and action eligibility)
                     |
                     +--> Finding history for EngineManager/UI
                     +--> RemediationCandidate history for explicit approval
```

### SecurityObservation

`SecurityObservation` is an immutable value with:

- stable source identifier and observation kind;
- event timestamp;
- process ID and process image name when available;
- normalized file path and SHA-256 when available;
- network tuple when available;
- evidence text, confidence in the inclusive range `[0.0, 1.0]`, and a suggested
  severity;
- a deterministic correlation key derived from observation kind and the strongest
  available process/artifact identity, excluding source so independent sensors can
  correlate on the same target.

Observations do not contain raw file contents, credentials, or unbounded binary
blobs. Invalid observations are rejected at the publishing boundary and counted.

### TelemetryBus

The bus is process-local and bounded. Publishers use a non-blocking, short critical
section to enqueue a value copy. When full, the observation is dropped, the drop
counter increments, and no producer waits. One correlation worker drains the queue
in FIFO order. `stop()` closes publishing, wakes the worker, and drains accepted
items before destruction.

### CorrelationEngine

The correlator maintains bounded per-key state over a five-minute window. It:

1. suppresses duplicate observations of the same key for thirty seconds;
2. aggregates distinct source signals by the same process or artifact;
3. computes a capped risk score from policy-owned weights and confidence;
4. emits one `SecurityFinding` only when its score or severity increases;
5. expires stale keys and retains a bounded finding history.

The output contains the contributing source IDs, a human-readable rationale, score,
severity, correlation key, and source observation IDs. This is the only path that
creates an actionable finding from an observation.

### PolicyEngine

`LocalSecurityPolicy` is an in-memory, explicit configuration with secure defaults:

- weak isolated heuristic signal: report at `LOW` or `MEDIUM`;
- two independent sources in the window: raise score and report one correlated
  finding;
- known deterministic signature at `CRITICAL`: mark a quarantine candidate;
- all other findings: `REPORT_ONLY`;
- protected process names and trusted signed system paths are never automatically
  remediated.

The policy engine is pure: the same policy and finding always produce the same
decision. Persisted policy files and admin UI editing are excluded from this release;
the interface is designed so they can be added without changing sensor code.

### New Sensors

1. `ArtifactTrustEngine` calculates a cached SHA-256, validates PE basics, checks
   Authenticode with `WinVerifyTrust`, and emits separate observations for an invalid
   PE, unsigned executable in a risky location, invalid signature, and suspicious
   entropy. A valid signature is evidence, not an automatic allow-list.
2. `ProcessBehaviorEngine` uses documented user-mode Windows APIs to snapshot process
   lineage, executable paths, memory protections, and TCP ownership. It emits
   observations only for concrete conditions such as executable-writable committed
   memory, a child whose claimed live parent was created later, or an untrusted image
   with an unusual network connection. It does not claim API-hook or kernel-event
   visibility it cannot establish.
3. Existing `DeepScanner`, ARHS, PMSR, ETG-RI, SyscallGuard, and KernelMon are adapted
   one at a time. Their old direct `ThreatEvent` callbacks remain temporarily
   compatible, but their raw signals enter the bus with source-specific confidence.

### Remediation Candidates

`RemediationCandidate` stores finding ID, target kind, target path or PID, requested
action, rationale, and an approval state. Candidate creation is data-only. A later
explicit approval API will validate the candidate against current policy and target
identity before executing an action. This release builds and tests candidate creation
and state transitions only; it does not silently modify user files or terminate
processes.

## Error Handling and Concurrency

- Public APIs return `ErrorCode` or an empty optional for invalid data; no sensor
  exception can terminate the correlation worker.
- Every callback is copied under lock and invoked after lock release.
- Queues, event/finding history, dedup state, and per-artifact caches have documented
  maximum capacities and eviction rules.
- Shutdown order is publisher stop, bus close, worker join, then owned-state
  destruction. Tests cover shutdown with queued observations.
- Access-denied Windows API results are treated as unavailable evidence and counted;
  they are never converted into an infection verdict.

## Test Strategy and Acceptance Criteria

Unit tests precede each production component and prove:

1. observation validation rejects invalid confidence and empty source IDs;
2. a full telemetry queue drops rather than blocks;
3. duplicate suppression emits one finding while distinct sources correlate;
4. correlation score and policy decision are deterministic;
5. only the explicit critical-signature case creates a quarantine candidate;
6. protected targets stay report-only;
7. shutdown drains accepted work without use-after-free or deadlock;
8. ArtifactTrust and ProcessBehavior classify supplied, controlled fixtures without
   touching arbitrary user data.

Every task must pass strict C++20 compilation with the repository's warning-as-error
policy, the complete `gcad_tests` suite, and a controlled Windows smoke run. A passing
test suite demonstrates the specified local behavior only; it does not certify
malware-detection coverage or equivalence to a commercial endpoint product.

## Delivery Sequence

1. Core domain values, bounded telemetry bus, and deterministic correlation tests.
2. Local policy and remediation-candidate state machine.
3. EngineManager integration and migration adapter for existing engine findings.
4. ArtifactTrust sensor with controlled file fixtures.
5. ProcessBehavior sensor with documented user-mode collection and synthetic tests.
6. Documentation, capacity metrics, full build/test, and controlled smoke evidence.

Each sequence is independently buildable and reviewable. No kernel driver, automatic
remediation, cloud service, or UI redesign is included.
