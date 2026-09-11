# GCAD User-Mode Engine Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Build a deterministic offline Windows user-mode security pipeline that converts sensor observations into explainable findings and safe remediation candidates.

**Architecture:** New security domain types define immutable observations, a bounded in-process bus, pure policy evaluation, correlation state, and candidate records. EngineManager owns the pipeline and adapts legacy ThreatEvent emissions into observations without changing existing engine lifecycles. New artifact and process sensors publish only documented user-mode evidence.

**Tech Stack:** C++20, standard library synchronization and containers, Win32, WinVerifyTrust, IP Helper API, existing CMake/Ninja and native test registry.

## Global Constraints

- Windows user mode is the acceptance target; Linux remains a compile-safe compatibility stub.
- All policy and detection decisions are offline. No remote lookup, upload, or network service is introduced.
- No callback is invoked while an engine-owned mutex is held.
- Queues and histories are bounded. Producers do not wait on a full telemetry queue.
- Detection is report-only except that a deterministic CRITICAL signature may create a data-only quarantine candidate. No task moves files, terminates processes, or blocks traffic.
- Existing uncommitted changes in EngineManager and DeepScanner are outside the planned commit scopes unless their owner explicitly incorporates them.
- Compile GCAD-owned code with C++20 and warnings-as-errors. Do not add a third-party dependency.

---

## File Structure

- include/gcad/security/observation.hpp: immutable input/output domain values, validation, correlation-key helper.
- include/gcad/security/telemetry_bus.hpp and src/security/telemetry_bus.cpp: bounded closeable FIFO with metrics.
- include/gcad/security/policy.hpp and src/security/policy.cpp: pure local risk/action policy and candidate eligibility.
- include/gcad/security/correlation_engine.hpp and src/security/correlation_engine.cpp: time-window aggregation, duplicate suppression, finding history.
- include/gcad/security/security_pipeline.hpp and src/security/security_pipeline.cpp: bus-draining worker, safe shutdown, snapshot APIs.
- include/gcad/security/artifact_trust_engine.hpp and src/security/artifact_trust_engine.cpp: Windows Authenticode and artifact observations.
- include/gcad/security/process_behavior_engine.hpp and src/security/process_behavior_engine.cpp: documented user-mode process and connection observations.
- EngineManager: pipeline ownership and legacy-event adapter only.
- tests/test_security_pipeline.cpp, tests/test_artifact_trust.cpp, tests/test_process_behavior.cpp: native registry tests.

### Task 1: Security values and bounded telemetry bus

**Files:**
- Create: include/gcad/security/observation.hpp
- Create: include/gcad/security/telemetry_bus.hpp
- Create: src/security/telemetry_bus.cpp
- Create: tests/test_security_pipeline.cpp
- Modify: CMakeLists.txt
- Modify: tests/test_main.cpp

**Interfaces:**
- Produces ObservationKind, PublishResult, SecurityObservation, TelemetryMetrics, and TelemetryBus.
- SecurityObservation::valid() requires non-empty source ID/evidence, finite confidence in [0.0, 1.0], and non-safe suggested level.
- SecurityObservation::correlation_key() deterministically uses kind, PID, SHA-256 if present, otherwise normalized path, otherwise process name.
- TelemetryBus exposes publish(SecurityObservation), try_pop(SecurityObservation&), close(), metrics(), and closed().

- [ ] **Step 1: Write failing validation and queue tests**

~~~
TEST(observation_rejects_invalid_confidence) {
    auto o = fixture_observation();
    o.confidence = 1.01;
    ASSERT_FALSE(o.valid());
    return true;
}

TEST(telemetry_bus_drops_when_capacity_is_reached) {
    gcad::security::TelemetryBus bus(1);
    ASSERT_EQ(bus.publish(fixture_observation()), gcad::security::PublishResult::ACCEPTED);
    ASSERT_EQ(bus.publish(fixture_observation()), gcad::security::PublishResult::DROPPED_FULL);
    ASSERT_EQ(bus.metrics().dropped_full, 1u);
    return true;
}
~~~

- [ ] **Step 2: Verify RED**

Run: cmake --build build --target gcad_tests --parallel 1

Expected: compilation fails because the security observation header does not exist.

- [ ] **Step 3: Implement the minimal queue contract**

~~~
class TelemetryBus final {
public:
    explicit TelemetryBus(size_t capacity);
    PublishResult publish(SecurityObservation observation);
    bool try_pop(SecurityObservation& out);
    void close();
    TelemetryMetrics metrics() const;
private:
    const size_t capacity_;
    mutable std::mutex mtx_;
    std::deque<SecurityObservation> queue_;
    bool closed_{false};
    TelemetryMetrics metrics_{};
};
~~~

publish rejects invalid input, returns CLOSED after close, and returns DROPPED_FULL without waiting at capacity.

- [ ] **Step 4: Register register_security_pipeline_tests and verify GREEN**

Run: .\build\gcad_tests.exe

Expected: validation, FIFO, full-queue, and closed-bus tests pass.

- [ ] **Step 5: Commit**

~~~
git add -- include/gcad/security/observation.hpp include/gcad/security/telemetry_bus.hpp src/security/telemetry_bus.cpp tests/test_security_pipeline.cpp tests/test_main.cpp CMakeLists.txt
git commit -m "feat(engine): add bounded security telemetry bus"
~~~

### Task 2: Local policy and remediation candidates

**Files:**
- Create: include/gcad/security/policy.hpp
- Create: src/security/policy.cpp
- Modify: tests/test_security_pipeline.cpp

**Interfaces:**
- Produces ResponseAction { REPORT_ONLY, QUARANTINE_CANDIDATE }, SecurityFinding, RemediationCandidate, LocalSecurityPolicy, and PolicyEngine.
- PolicyEngine::decide(const SecurityFinding&, const LocalSecurityPolicy&) is pure.
- PolicyEngine::candidate_for(const SecurityFinding&, const LocalSecurityPolicy&) returns a value only for a non-protected, critical deterministic signature target.

- [ ] **Step 1: Write failing policy tests**

~~~
TEST(policy_only_candidates_critical_deterministic_signatures) {
    gcad::security::PolicyEngine policy;
    auto finding = critical_signature_finding("C:/Temp/sample.exe");
    ASSERT_EQ(policy.decide(finding, {}), gcad::security::ResponseAction::QUARANTINE_CANDIDATE);
    ASSERT_TRUE(policy.candidate_for(finding, {}).has_value());
    return true;
}

TEST(policy_keeps_protected_target_report_only) {
    gcad::security::PolicyEngine policy;
    auto finding = critical_signature_finding("C:/Windows/System32/notepad.exe");
    ASSERT_EQ(policy.decide(finding, {}), gcad::security::ResponseAction::REPORT_ONLY);
    ASSERT_FALSE(policy.candidate_for(finding, {}).has_value());
    return true;
}
~~~

- [ ] **Step 2: Verify RED**

Run: cmake --build build --target gcad_tests --parallel 1

Expected: compilation fails because PolicyEngine is not defined.

- [ ] **Step 3: Implement pure policy defaults**

Use a critical threshold of 90, a five-minute finding age, and protected prefixes C:/Windows/ and C:/Program Files/. Qualify only a deterministic signature with CRITICAL level, non-empty target file, and no case-insensitive protected-prefix match.

- [ ] **Step 4: Verify GREEN**

Run: .\build\gcad_tests.exe

Expected: report-only, protected-target, critical-signature, and previous bus tests pass.

- [ ] **Step 5: Commit**

~~~
git add -- include/gcad/security/policy.hpp src/security/policy.cpp tests/test_security_pipeline.cpp
git commit -m "feat(engine): add deterministic local response policy"
~~~

### Task 3: Correlation engine with deduplication

**Files:**
- Create: include/gcad/security/correlation_engine.hpp
- Create: src/security/correlation_engine.cpp
- Modify: tests/test_security_pipeline.cpp

**Interfaces:**
- Produces CorrelationEngine::ingest(const SecurityObservation&, system_clock::time_point), expire(system_clock::time_point), and recent(size_t).
- Duplicate window: thirty seconds per source and correlation key. Aggregation window: five minutes per process/artifact key. Scores cap at 100.

- [ ] **Step 1: Write failing correlation tests**

~~~
TEST(correlation_suppresses_same_source_duplicate) {
    gcad::security::CorrelationEngine engine({});
    auto first = engine.ingest(observation("artifact", 0.60), fixed_time());
    auto duplicate = engine.ingest(observation("artifact", 0.60), fixed_time() + 10s);
    ASSERT_TRUE(first.has_value());
    ASSERT_FALSE(duplicate.has_value());
    return true;
}

TEST(correlation_raises_finding_for_independent_sources) {
    gcad::security::CorrelationEngine engine({});
    engine.ingest(observation("artifact", 0.60), fixed_time());
    auto correlated = engine.ingest(observation("process", 0.65), fixed_time() + 1s);
    ASSERT_TRUE(correlated.has_value());
    ASSERT_EQ(correlated->contributing_sources.size(), 2u);
    ASSERT_TRUE(correlated->risk_score > 60);
    return true;
}
~~~

- [ ] **Step 2: Verify RED**

Run: cmake --build build --target gcad_tests --parallel 1

Expected: compilation fails because CorrelationEngine is not defined.

- [ ] **Step 3: Implement bounded state**

Store at most 4096 active keys and 2000 findings. Evict the oldest active state before accepting a new key at capacity. Score each independent source once per window as round(confidence * 50), add a 20 point multi-source bonus, and map 0-24/25-49/50-74/75-89/90-100 to safe/low/medium/high/critical.

- [ ] **Step 4: Verify GREEN**

Run: .\build\gcad_tests.exe

Expected: duplicate, multi-source, expiration, score cap, policy, and previous tests pass.

- [ ] **Step 5: Commit**

~~~
git add -- include/gcad/security/correlation_engine.hpp src/security/correlation_engine.cpp tests/test_security_pipeline.cpp
git commit -m "feat(engine): correlate bounded security observations"
~~~

### Task 4: Pipeline worker and EngineManager adapter

**Files:**
- Create: include/gcad/security/security_pipeline.hpp
- Create: src/security/security_pipeline.cpp
- Modify: include/gcad/engine_manager.hpp
- Modify: src/engine_manager.cpp
- Modify: tests/test_security_pipeline.cpp
- Modify: CMakeLists.txt

**Interfaces:**
- Produces SecurityPipeline::start(), stop(), publish(SecurityObservation), recent_findings(size_t), recent_candidates(size_t), and telemetry_metrics().
- EngineManager::push_event(ThreatEvent) retains its public behavior and additionally converts the event through a private adapt_legacy_event helper.

- [ ] **Step 1: Write failing worker lifecycle test**

~~~
TEST(pipeline_drains_accepted_observation_on_stop) {
    gcad::security::SecurityPipeline pipeline(8, {});
    ASSERT_EQ(pipeline.start(), gcad::ErrorCode::OK);
    ASSERT_EQ(pipeline.publish(fixture_observation()), gcad::security::PublishResult::ACCEPTED);
    ASSERT_EQ(pipeline.stop(), gcad::ErrorCode::OK);
    ASSERT_TRUE(!pipeline.recent_findings(1).empty());
    return true;
}
~~~

- [ ] **Step 2: Verify RED**

Run: cmake --build build --target gcad_tests --parallel 1

Expected: compilation fails because SecurityPipeline is not defined.

- [ ] **Step 3: Implement lifecycle**

The worker waits on a condition variable, drains accepted FIFO entries through CorrelationEngine, records eligible candidates, and copies callbacks before lock release. stop closes publishing, wakes the worker, joins it, and is idempotent. EngineManager starts the pipeline before sensors and stops it after sensor callbacks quiesce.

- [ ] **Step 4: Verify GREEN**

Run: .\build\gcad_tests.exe

Run: git diff --check

Expected: all tests pass and no whitespace errors are reported.

- [ ] **Step 5: Commit**

~~~
git add -- include/gcad/security/security_pipeline.hpp src/security/security_pipeline.cpp include/gcad/engine_manager.hpp src/engine_manager.cpp tests/test_security_pipeline.cpp CMakeLists.txt
git commit -m "feat(engine): connect pipeline to engine manager"
~~~

### Task 5: Artifact trust sensor

**Files:**
- Create: include/gcad/security/artifact_trust_engine.hpp
- Create: src/security/artifact_trust_engine.cpp
- Create: tests/test_artifact_trust.cpp
- Modify: CMakeLists.txt
- Modify: tests/test_main.cpp

**Interfaces:**
- Produces ArtifactTrustEngine::inspect(const filesystem::path&) returning observations.
- Windows inspection uses offline WinVerifyTrust, SHA-256, bounded PE header reads, and documented file attributes. Non-Windows returns an empty vector.

- [ ] **Step 1: Write failing controlled-fixture test**

~~~
TEST(artifact_trust_reports_invalid_pe_fixture) {
    auto fixture = write_invalid_pe_fixture();
    gcad::security::ArtifactTrustEngine engine;
    auto observations = engine.inspect(fixture);
    ASSERT_TRUE(has_kind(observations, gcad::security::ObservationKind::INVALID_PE));
    return true;
}
~~~

- [ ] **Step 2: Verify RED**

Run: cmake --build build --target gcad_tests --parallel 1

Expected: compilation fails because ArtifactTrustEngine is not defined.

- [ ] **Step 3: Implement bounded inspection**

Read at most 4 MiB for inspection, use SHA256::hash_file for the full-file digest, validate PE offsets before each read, and emit INVALID_PE, UNSIGNED_RISKY_LOCATION, INVALID_SIGNATURE, or HIGH_ENTROPY separately. Access failures report unavailable evidence rather than infection.

- [ ] **Step 4: Verify GREEN**

Add wintrust and crypt32 only on Windows in CMakeLists.txt.

Run: .\build\gcad_tests.exe

Expected: fixture tests pass without inspecting arbitrary user files.

- [ ] **Step 5: Commit**

~~~
git add -- include/gcad/security/artifact_trust_engine.hpp src/security/artifact_trust_engine.cpp tests/test_artifact_trust.cpp tests/test_main.cpp CMakeLists.txt
git commit -m "feat(engine): add offline artifact trust sensor"
~~~

### Task 6: Process behavior sensor and release verification

**Files:**
- Create: include/gcad/security/process_behavior_engine.hpp
- Create: src/security/process_behavior_engine.cpp
- Create: tests/test_process_behavior.cpp
- Modify: CMakeLists.txt
- Modify: tests/test_main.cpp
- Modify: README.md
- Modify: ARCHITECTURE.md

**Interfaces:**
- Produces ProcessBehaviorEngine::inspect_pid(uint32_t) returning observations.
- Windows uses OpenProcess, QueryFullProcessImageName, GetProcessTimes, VirtualQueryEx, and GetExtendedTcpTable. It never reads or writes another process's memory.

- [ ] **Step 1: Write failing current-process test**

~~~
TEST(process_behavior_does_not_flag_current_process_without_concrete_signal) {
    gcad::security::ProcessBehaviorEngine engine;
    auto observations = engine.inspect_pid(GetCurrentProcessId());
    ASSERT_FALSE(has_high_confidence_injection_claim(observations));
    return true;
}
~~~

- [ ] **Step 2: Verify RED**

Run: cmake --build build --target gcad_tests --parallel 1

Expected: compilation fails because ProcessBehaviorEngine is not defined.

- [ ] **Step 3: Implement concrete conditions only**

Emit EXECUTABLE_WRITABLE_MEMORY only for MEM_COMMIT with executable-writable protection. Emit parent-order evidence only when both live process creation timestamps are available and the parent was created later. Emit connection evidence only when a documented TCP table row maps to the inspected PID. Never treat access denial as infection.

- [ ] **Step 4: Run release verification**

Run: cmake -S . -B build -DFETCHCONTENT_FULLY_DISCONNECTED=ON

Run: cmake --build build --target gcad gcad_tests --parallel 1

Run: .\build\gcad_tests.exe

Run: ctest --test-dir build --output-on-failure

Expected: configuration, build, direct tests, and CTest complete with no warnings or failures.

- [ ] **Step 5: Document and commit**

Document user-mode/offline scope, no-automatic-remediation policy, telemetry drop metrics, and the non-ETW limitation in README.md and ARCHITECTURE.md.

~~~
git add -- include/gcad/security/process_behavior_engine.hpp src/security/process_behavior_engine.cpp tests/test_process_behavior.cpp tests/test_main.cpp CMakeLists.txt README.md ARCHITECTURE.md
git commit -m "feat(engine): add user-mode process behavior sensor"
~~~

## Plan Self-Review

- Spec coverage: Tasks 1-4 implement immutable observations, bounded delivery, correlation, policy, candidate records, legacy adaptation, and shutdown safety. Tasks 5-6 add the two selected user-mode sensors. Task 6 documents scope and runs required verification.
- Placeholder scan: every task names exact files, interfaces, red/green test steps, verification commands, and commit scope.
- Type consistency: later tasks consume the SecurityObservation, SecurityFinding, RemediationCandidate, LocalSecurityPolicy, PolicyEngine, and SecurityPipeline types introduced by earlier tasks.

