# Operational store resource measurement

The recorded distinct-frame, exact-25-identity quota workload passed native and
race-instrumented tests before the later typed-busy classifier. Baseline
measurements, including the earlier instrumented concurrency failure, and the
newer busy-handling test contract are preserved separately below.

## Scope and reproducibility

This is a disposable, synthetic cloud-workspace measurement of the current
`managed-operations-v1` candidate. It does not sample a real machine, run a
collector, contact an endpoint, deploy a credential or service, or publish data.
The fixtures reuse the normal enrollment proof/certificate/activation helpers
and enter observations through `SaveObservation`; validators and quotas are not
relaxed and no database rows are injected.

Measured on 2026-10-03 UTC, Linux amd64, Go 1.27.1, with benchmark
`GOMAXPROCS=9`. These results describe the current candidate, not a released
revision. Source: `internal/enrollmentstore/operational_budget_test.go`.

With Go 1.27.1 on `PATH`, run from the repository root:

```sh
go test -buildvcs=false ./internal/enrollmentstore \
  -run '^TestTwentyFiveOperationalRetainedBudget$' -count=1 -v
go test -buildvcs=false ./internal/enrollmentstore \
  -run '^$' -bench '^BenchmarkTwentyFiveOperationalRetainedBudget$' \
  -benchtime=5x -count=1 -benchmem
go test -race -buildvcs=false ./internal/enrollmentstore \
  -run '^TestTwentyFiveOperationalRetainedBudget$' -count=1 -v
```

Run heavy store measurements separately from other dense/race workloads.
`5x` limits the measured benchmark loop to five iterations per sub-benchmark;
Go also performs its initial calibration invocation. Fixture construction and
new-ingress frame construction are excluded from the measured loop. Allocation
figures are allocation traffic per operation, not peak heap or steady-state RSS.

## Maximum admitted logical footprint

Exactly 25 retained identities are enrolled and activated for the explicit
operational profile. Six successive accepted generations populate all six
last-good sections, retaining their original generation IDs and collection times.
Each device has the same generated record shape, with unique enrollment IDs
and fixed-width, per-device/per-observation generation IDs:

- 32 volume records, 32 interfaces, 64 services, 32 processes, 32 event groups,
  and 128 software records across its last-good cache
- Latest generation: healthy software and explicitly unavailable other sections
- Latest snapshot JSON: **49,151 bytes**, one byte below the 48 KiB limit
- Last-good record JSON, including its wrapper: **81,921 bytes**
- Logical operational bytes per device: **131,072 bytes**, exactly 128 KiB
- Logical operational bytes across 25 devices: **3,276,800 bytes**
- Every admitted exact frame: **73,728 bytes**, exactly 72 KiB

Long, allowed synthetic package/version/service/mount fields fill the logical
budget. Valid trailing JSON whitespace fills the *frame* budget; it does not
inflate the reported logical snapshot or cache sizes. The logical calculation is
exactly the store's snapshot-JSON-plus-last-good-record-JSON calculation.
These figures are not SQLite file size, WAL size, credential-row/base64 size,
response size, or process memory. Last-good software duplicates the latest
software intentionally; the other retained sections originate in earlier
accepted generations.

At the current 25-device and 128-KiB-per-device limits, all devices can reach
only 3.125 MiB of logical operational data, below the 4 MiB global limit.
Consequently this workload cannot independently drive the global quota into
rejection without first violating another configured limit. It does not claim
that the global quota was saturated.

## Baseline admission, age and concurrency evidence

The native test passed in **20.619 seconds**, including fixture construction.
It also submitted a fully valid 49,152-byte operational snapshot in a valid
72-KiB frame. Replacing the latest and cached software would require **131,074
logical bytes**, two bytes over the device quota. Admission returned the
store's storage/quota error. Readback verified unchanged sequence 6, receipt
and collection timestamps, generation IDs, all retained sections, and total
logical bytes. The view became stale at the original age; the rejected update
did not refresh it. The original accepted exact frame remained retryable.

One concurrent native run used three independent store handles to the same
SQLite database. The read and ingress targeted identity 25; revocation targeted
identity 24, keeping all 25 retained identities including the tombstone.
End-to-end times include transaction work and SQLite lock wait:

| Operation | One observed duration |
| --- | ---: |
| Operational read | 285.102 ms |
| New observation ingress | 878.935 ms |
| Revocation | 585.770 ms |

All three succeeded, and the revoked read model was verified afterward. A
separate cancellation check held the store's only SQL connection, verified that
an operational read entered the connection queue, then canceled its context.
It returned `context.Canceled` in **6.4 microseconds after cancellation**, while
the connection was still held. The five-second test watchdog is a hang detector,
not a cancellation-latency guarantee. This tests the `database/sql` connection
queue; it does not claim that SQLite busy-lock waits or arbitrary filesystem
calls have the same cancellation behavior.

## Baseline five-iteration benchmark

| Operation | ns/op | Approx. ms/op | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Operational read | 241,742,183 | 241.742 | 130,135,710 | 434,194 |
| Exact observation retry | 232,927,749 | 232.928 | 129,386,326 | 430,397 |
| New observation ingress | 236,611,809 | 236.612 | 130,969,678 | 437,907 |

The baseline reused generation IDs across identities. The fixture now gives
every device distinct frame bytes and verifies distinct stored payload hashes,
so transaction-local exact-frame reuse cannot artificially collapse the dataset.
Generation labels retain exactly the same width and all byte counts above stay
unchanged. The baseline implementation reparsed every row, even when two frames
were identical; it had no exact-frame parse reuse.

The benchmark passed in **20.321 seconds**, including fixture construction and
Go's calibration. All rows report the same exact 25-device footprint above.
The store loads and validates the retained ledger/credentials/operational data
inside serialized transactions, so a single-device operation still incurs
substantial full-store decode, validation, and allocation work. The results
provide a regression baseline, not a throughput, p95/p99, slow-disk, burst,
production-capacity, or hard-deadline guarantee. There is no claimed broad
latency improvement or safety margin from this small synthetic run.

## Baseline race instrumentation

The baseline exact-quota race-instrumented command **failed** after 293.622
seconds. Dataset construction and the quota/age/replay subtest passed; queued
read cancellation passed in 20.681 microseconds after cancellation. The
cross-handle concurrency subtest returned `ErrStorage` after 15.65 seconds.
No race-detector data-race diagnostic was emitted. The first version of the
test stopped before printing individual operation durations on failure, so the
failing operation and its exact lock-wait time were not captured in this run.
Subsequent runs log all three durations and errors before checking success.

This is an observed instrumented-contention failure, not a passing race test.
The store has an existing five-second SQLite busy timeout, which has not been
raised for this workload. An `ErrStorage` alone does not prove the precise
internal failure site. Race instrumentation is diagnostic and is not
representative latency evidence.

## After transaction-local parse reuse

A subsequent candidate reuses strict frame parsing only within a single durable
transaction, keyed by exact-frame SHA-256 and receipt time. Returned mutable
values are detached from the cached parse. Authority, revocation, replay and
freshness remain transaction decisions; this measurement does not substitute
for their separate correctness tests. Neither the quota nor the SQLite busy
timeout was increased.

The corrected, distinct-frame exact-quota workload passed natively on
2026-10-04 UTC in **13.332 seconds**. Its same footprint and quota-rejection
assertions passed, along with exact retry receipt/age checks and readback of
both concurrent ingress and revocation. One concurrent run observed:

| Operation | One observed duration |
| --- | ---: |
| Operational read | 313.492 ms |
| New observation ingress | 467.155 ms |
| Revocation | 133.430 ms |

Queued read cancellation returned in **10.966 microseconds after cancellation**
while the occupied connection remained held, and released the read-admission
slot. The five-iteration benchmark then passed in **13.959 seconds**:

| Operation | ns/op | Approx. ms/op | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Operational read | 131,497,900 | 131.498 | 63,610,712 | 145,103 |
| Exact observation retry | 133,848,865 | 133.849 | 63,687,523 | 145,127 |
| New observation ingress | 139,071,414 | 139.071 | 64,266,920 | 148,876 |

These are five-iteration local observations, not broad latency or allocation
bounds. Full-command times include fixture generation, which now constructs
and validates distinct frames for each device, and are not direct per-operation
comparisons. Concurrency order and waiting can vary between runs. The latest
race-instrumented result is recorded separately below.


### Recorded strict first-attempt race result, before typed-busy classification

The same corrected, distinct-frame exact-quota test **passed** under `-race`
on 2026-10-04 UTC: **190.83 seconds** for the test and **191.854 seconds** for
the command. No race-detector diagnostic was emitted. Dataset/quota/age/replay
assertions and both post-concurrency readbacks passed. All three concurrent
operations succeeded on their first attempt, with no retries or relaxed limits:

| Operation | Instrumented end-to-end duration |
| --- | ---: |
| Operational read | 4.239880 s |
| New observation ingress | 6.403774 s |
| Revocation | 2.121716 s |

Canceled occupied-connection admission returned `context.Canceled` in
**18.588 microseconds after cancellation** and released its admission slot.
These diagnostic durations include waiting and execution. The SQLite busy
timeout is not an end-to-end transaction deadline; in particular, successful
ingress taking more than five seconds does not imply that its lock wait alone
exceeded five seconds. This single passing instrumented workload establishes
its tested outcome, not a bound for other loads, machines, or schedules.


## Later typed-busy admission contract

The subsequent runtime change distinguishes `ErrBusy` only when the real SQLite
driver reports `SQLITE_BUSY` or `SQLITE_LOCKED` at the initial `BEGIN IMMEDIATE`.
The existing five-second busy timeout is unchanged. Failures after admission,
commit uncertainty, other driver/storage errors, and permission/path failures
must not become retryable busy results. Context cancellation retains its own
error. This classification does not change the non-busy parsing/transaction
work measured by the preceding benchmarks; those numbers remain explicitly
pre-classifier evidence.

The cross-handle capacity test now keeps two separate outcomes visible:

- Native builds still require all three operations to succeed on their first
  attempt. Any first-attempt error, including `ErrBusy`, fails the test.
- Race builds permit only the exact `ErrBusy` sentinel on a first attempt.
  Every contender must return before inspection or retry. For each busy ingress
  or revocation, complete canonical target-state copies must match their
  pre-contention versions: enrollment authority snapshot, credential including
  exact frame and replay/receipt timestamps, and retained operational cache.
  The unchanged request is then retried **exactly once**, serially after
  contention ends. The retry must succeed; there is no retry loop, backoff,
  changed control, altered payload or acceptance of arbitrary `ErrStorage`.

Every run logs first-attempt successes, first-attempt busy results, and explicit
retry counts. A passing run with zero busy results does not exercise the retry
branch. A passing run that required a retry is busy-handling evidence, not a
strict first-attempt latency result. Post-operation readbacks still require the
expected new observation and revoked authority. Shared-store runtime tests are
separate and keep their strict first-attempt assertions.

The revised capacity test and its race/non-race build-tag constants compile in
both native and race modes. Their final aggregate execution is a separate gate;
no new dense-run result is claimed here. The historical 293.622-second failing
baseline and 191.854-second strict first-attempt passing run above remain
unchanged and are not relabeled as results of the newer busy-handling contract.
Use verbose or JSON test output when recording the aggregate run so its explicit
first-attempt/busy/retry counts remain reviewable.
