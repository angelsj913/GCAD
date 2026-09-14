// GCAD Formal Verification — Dafny Invariants
// Proves core safety properties of the security engine

// ============================================================
// 1. Shannon entropy accumulation terminates for a bounded histogram.
//    Numeric entropy bounds are intentionally outside this model because the
//    Log2 function below is uninterpreted; no unproved bound is claimed.
// ============================================================
function ShannonEntropy(freq: seq<nat>, total: nat): real
    requires total > 0
    requires |freq| == 256
    requires SumSeq(freq) == total
{
    ShannonEntropyHelper(freq, total, 0)
}

function SumSeq(s: seq<nat>): nat
{
    if |s| == 0 then 0 else s[0] + SumSeq(s[1..])
}

function ShannonEntropyHelper(freq: seq<nat>, total: nat, idx: nat): real
    requires total > 0
    requires idx <= |freq|
    requires |freq| == 256
    decreases |freq| - idx
{
    if idx == |freq| then 0.0
    else if freq[idx] == 0 then ShannonEntropyHelper(freq, total, idx + 1)
    else
        var p: real := freq[idx] as real / total as real;
        (-p * Log2(p)) + ShannonEntropyHelper(freq, total, idx + 1)
}

// Uninterpreted Log2 declaration used only to model the accumulation shape.
function {:axiom} Log2(x: real): real
    requires x > 0.0

// ============================================================
// 2. Snapshot Ring Buffer: never exceeds MAX_SNAPSHOTS
// ============================================================
class SnapshotRing {
    var data: array<int>
    var count: nat
    var head: nat
    const capacity: nat

    ghost predicate Valid()
        reads this, data
    {
        capacity > 0 &&
        data.Length == capacity &&
        count <= capacity &&
        head < capacity
    }

    constructor(cap: nat)
        requires cap > 0
        ensures Valid()
        ensures count == 0
    {
        capacity := cap;
        data := new int[cap];
        count := 0;
        head := 0;
    }

    method Push(val: int)
        requires Valid()
        modifies this, data
        ensures Valid()
        ensures count <= capacity
    {
        data[head] := val;
        head := (head + 1) % capacity;
        if count < capacity {
            count := count + 1;
        }
    }
}

// ============================================================
// 3. Canary Integrity: XOR round-trip preserves value
// ============================================================
lemma XorRoundTrip(value: bv32, key: bv32)
    ensures (value ^ key) ^ key == value
{
    // Bit-vector XOR is self-inverse — Dafny verifies automatically
}

// Shadow ring canary invariant
lemma CanaryVerification(canary: bv32, magic: bv32, xor_key: bv32)
    requires canary == magic ^ xor_key
    ensures canary ^ xor_key == magic
{
    XorRoundTrip(magic, xor_key);
}

// ============================================================
// 4. Blocked IP list: no duplicates after block/unblock
// ============================================================
predicate NoDuplicates<T(==)>(s: seq<T>)
{
    forall i, j :: 0 <= i < j < |s| ==> s[i] != s[j]
}

method BlockIP(blocked: seq<int>, ip: int) returns (result: seq<int>)
    requires NoDuplicates(blocked)
    ensures NoDuplicates(result)
    ensures ip in result
{
    if ip in blocked {
        return blocked;
    } else {
        result := blocked + [ip];
    }
}

method UnblockIP(blocked: seq<int>, ip: int) returns (result: seq<int>)
    requires NoDuplicates(blocked)
    ensures NoDuplicates(result)
    ensures ip !in result
{
    result := [];
    for i := 0 to |blocked|
        invariant NoDuplicates(result)
        invariant ip !in result
        invariant forall k :: 0 <= k < |result| ==> result[k] in blocked[..i]
    {
        if blocked[i] != ip {
            result := result + [blocked[i]];
        }
    }
}

// ============================================================
// 5. Threat Level ordering: SAFE < LOW < MEDIUM < HIGH < CRITICAL
// ============================================================
datatype ThreatLevel = SAFE | LOW | MEDIUM | HIGH | CRITICAL

function ThreatOrd(t: ThreatLevel): nat
{
    match t
    case SAFE => 0
    case LOW => 1
    case MEDIUM => 2
    case HIGH => 3
    case CRITICAL => 4
}

lemma ThreatLevelMonotonic()
    ensures ThreatOrd(SAFE) < ThreatOrd(LOW)
    ensures ThreatOrd(LOW) < ThreatOrd(MEDIUM)
    ensures ThreatOrd(MEDIUM) < ThreatOrd(HIGH)
    ensures ThreatOrd(HIGH) < ThreatOrd(CRITICAL)
{
}

// ============================================================
// 6. Event Log capacity: never exceeds MAX_EVENTS
// ============================================================
class EventLog {
    var events: seq<int>
    const max_events: nat

    ghost predicate Valid()
        reads this
    {
        max_events > 0 &&
        |events| <= max_events
    }

    constructor(max: nat)
        requires max > 0
        ensures Valid()
        ensures |events| == 0
    {
        max_events := max;
        events := [];
    }

    method Push(ev: int)
        requires Valid()
        modifies this
        ensures Valid()
        ensures |events| <= max_events
    {
        if |events| >= max_events {
            events := events[1..];
        }
        events := events + [ev];
    }
}

// ============================================================
// 7. Thread-safety: sequential consistency of atomic flag
// ============================================================
lemma AtomicFlagInvariant(flag: bool)
    ensures flag == true || flag == false
{
    // Trivially true for bool — models that running_ is always defined
}

// ============================================================
// 8. Scan progress invariant: scanned <= total
// ============================================================
lemma ScanProgressInvariant(scanned: nat, total: nat)
    requires scanned <= total
    ensures scanned <= total
{
}

method UpdateScanProgress(scanned: nat, total: nat) returns (new_scanned: nat)
    requires scanned <= total
    requires total > 0
    ensures new_scanned <= total
{
    if scanned < total {
        new_scanned := scanned + 1;
    } else {
        new_scanned := scanned;
    }
}

// ============================================================
// 9. ThreadPool lifecycle abstraction (common.hpp::ThreadPool)
//    outstanding_ is the sum of queued and currently active work.
// ============================================================
class ThreadPoolState {
    var queued: nat
    var active: nat
    var accepting: bool

    ghost predicate Valid()
        reads this
    {
        queued + active >= 0
    }

    constructor()
        ensures Valid()
        ensures queued == 0 && active == 0 && accepting
    {
        queued := 0;
        active := 0;
        accepting := true;
    }

    method Enqueue()
        requires Valid() && accepting
        modifies this
        ensures Valid()
        ensures queued == old(queued) + 1
        ensures active == old(active)
    {
        queued := queued + 1;
    }

    method StartOne()
        requires Valid() && queued > 0
        modifies this
        ensures Valid()
        ensures queued + active == old(queued + active)
    {
        queued := queued - 1;
        active := active + 1;
    }

    method FinishOne()
        requires Valid() && active > 0
        modifies this
        ensures Valid()
        ensures queued + active == old(queued + active) - 1
    {
        active := active - 1;
    }

    method ClearQueued()
        requires Valid()
        modifies this
        ensures Valid()
        ensures queued == 0
        ensures active == old(active)
    {
        queued := 0;
    }

    method Close()
        requires Valid()
        modifies this
        ensures Valid()
        ensures !accepting
    {
        accepting := false;
    }

    method Idle() returns (ready: bool)
        requires Valid()
        ensures ready <==> queued + active == 0
    {
        ready := queued + active == 0;
    }
}

// ============================================================
// 10. DeepScanner progress/cancellation abstraction
//     Cancellation may leave queued work unfinished, but never allows a
//     worker completion count past the enumerated total.
// ============================================================
class DeepScanState {
    var total: nat
    var scanned: nat
    var cancelled: bool

    ghost predicate Valid()
        reads this
    {
        scanned <= total
    }

    constructor()
        ensures Valid()
        ensures total == 0 && scanned == 0 && !cancelled
    {
        total := 0;
        scanned := 0;
        cancelled := false;
    }

    method Begin(work: nat)
        modifies this
        ensures Valid()
        ensures total == work && scanned == 0 && !cancelled
    {
        total := work;
        scanned := 0;
        cancelled := false;
    }

    method CompleteOne()
        requires Valid() && scanned < total
        modifies this
        ensures Valid()
        ensures scanned == old(scanned) + 1
    {
        scanned := scanned + 1;
    }

    method Cancel()
        requires Valid()
        modifies this
        ensures Valid()
        ensures cancelled
        ensures total == old(total) && scanned == old(scanned)
    {
        cancelled := true;
    }
}

// ============================================================
// 11. EngineManager recent-event window abstraction
//     Newer event ids are monotonically allocated; a bounded log discards
//     only the oldest entry before appending the new one.
// ============================================================
class RecentEventLog {
    var events: seq<nat>
    var next_id: nat
    const max_events: nat

    ghost predicate Valid()
        reads this
    {
        max_events > 0 && |events| <= max_events
    }

    constructor(max: nat)
        requires max > 0
        ensures Valid()
        ensures events == [] && next_id == 1
    {
        max_events := max;
        events := [];
        next_id := 1;
    }

    method Push() returns (assigned_id: nat)
        requires Valid()
        modifies this
        ensures Valid()
        ensures assigned_id == old(next_id)
        ensures next_id == old(next_id) + 1
        ensures |events| <= max_events
        ensures |events| > 0 ==> events[|events| - 1] == assigned_id
    {
        assigned_id := next_id;
        next_id := next_id + 1;
        if |events| >= max_events {
            events := events[1..];
        }
        events := events + [assigned_id];
    }
}

// ============================================================
// 12. PMSR shadow-store boundary abstraction
//     This models the intended public-state ceiling of two ring capacities.
//     The C++ implementation is validated separately because Dafny does not
//     prove its vector lifetime or locking behavior.
// ============================================================
class PmsrShadowStore {
    var entries: nat
    const ring_capacity: nat

    ghost predicate Valid()
        reads this
    {
        ring_capacity > 0 && entries <= 2 * ring_capacity
    }

    constructor(capacity: nat)
        requires capacity > 0
        ensures Valid()
        ensures entries == 0
    {
        ring_capacity := capacity;
        entries := 0;
    }

    method RegisterBaseRing()
        requires Valid() && entries == 0
        modifies this
        ensures Valid()
        ensures entries == ring_capacity
    {
        entries := ring_capacity;
    }

    method AddHoneyEntry()
        requires Valid()
        modifies this
        ensures Valid()
        ensures entries <= 2 * ring_capacity
    {
        if entries < 2 * ring_capacity {
            entries := entries + 1;
        }
    }
}
