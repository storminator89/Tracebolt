# Complete Go race coverage across separate runners

Routine PR/main checks now use the separate [focused source tier](two-tier-ci.md).
This full Validate workflow runs manually/nightly and remains mandatory exact-source
release evidence; its coverage and aggregate check retain their original meaning.

The Validate workflow keeps the required check name **Go tests and build-only
platform checks**. It now aggregates three race runners plus the unchanged
build/runtime checks and the existing four-case dense race gate. It runs with
`always()` and fails unless every prerequisite explicitly succeeds and every
shard supplies valid completion evidence. Failed, cancelled, skipped, missing,
extra and duplicate shards cannot produce a successful aggregate.

## Coverage contract

Each shard and the aggregate independently run `go list -race -buildvcs=false ./...`
for Linux/amd64, with the same race build tags as execution. Historical timing weights only determine placement; they never
select packages. New packages are included automatically. The deterministic
partition must contain every discovered package exactly once. The unchanged
Go-source allowlist digest is verified before discovery, and each report is
bound to the actual checkout SHA (including a PR merge SHA), source digest,
workflow run, attempt, shard and complete partition digest.

Each runner keeps `-race`, `-p 1`, `-buildvcs=false`, `-count=1` and the existing
15-minute per-package, per-invocation test timeout and 60-minute job budget.
Enrollmentstore remains on its original shard, with a default invocation and
source-bound exact-root groups for full services, full software, full processes,
network context and retention/capacity. Each moved root is excluded only from
the default invocation and must run and pass exactly once in its selected group;
missing, skipped, duplicate or overlapping moved-root evidence fails closed.
Other roots, examples and fuzz seeds remain in the default invocation.
Only the same anchored dense and guided root tests remain excluded: their
existing dedicated race jobs, timeouts and positive-completion gates are pinned
byte-for-byte by the coverage contract. All existing vet, build, CLI, native
runtime, support-bundle, cross-build and API checks remain in the build/runtime
job. The frontend/browser dependency chain is unchanged.

The retention/capacity group contains only these four unchanged roots:

- `TestTwentyFiveOperationalRetainedBudget`
- `TestCompleteOverviewSteadyMinuteCadenceRetainsPagesAndCleans`
- `TestCompleteInventoryQuotaPreservesPreviousAndReservation`
- `TestTwentyFiveNearMaxConcurrentTransactionWait`

In successful PR54 job `114579549324`, these roots took 316.99 seconds of the
613.496-second default enrollmentstore invocation. PR55 and PR56 later exhausted
that invocation's 15-minute budget at different roots. Splitting the measured
heavy roots removes cumulative pressure without changing assertions, workloads,
race flags or either timeout. It is not evidence of a standalone deadlock or a
runtime speed guarantee. Each root creates its own temporary database and fixture;
none relies on another root's state. The operational-budget subtests and their
shared fixture remain together. Similar future names stay in the default run;
removing or renaming a listed root requires updating the exact partition.

A successful process exit is necessary but insufficient. Every selected package
must start and have exactly one valid terminal event; any test or build failure
fails the shard. Package-level skips are accepted only for packages for which Go
reported no test files. Root-test platform/environment skips retain their existing
meaning. At the source baseline, discovery finds 141 packages: 126 with tests and
15 with no test files.

The aggregate independently recomputes the package universe and partition. It
requires exactly three current-attempt artifacts, one expected file in each,
matching source/run/attempt/partition bindings, and exactly the corresponding
normalized package records. Re-running only failed jobs cannot reuse successful
shards from an earlier attempt; use a complete workflow rerun so all proofs belong
to the same attempt. This deliberately fails closed rather than silently mixing
attempts.

## Privacy and progress

Raw Go JSONL and stderr remain in private temporary files, are never uploaded,
and are removed when the runner finishes normally. Existing source-allowlisted
bounded failure/timing reporting remains available. A once-per-minute progress
line includes only shard number, a fixed invocation label and elapsed seconds. Artifacts contain only
source/run identifiers, digests, fixed statuses, allowlisted package names and
selected root names and bounded elapsed numbers; no raw output, subtest names,
private paths or telemetry.
Artifacts expire after one day.

## Why three runners

The original weights came from the successful main run
[38058537360, Go job 114231878636](https://github.com/storminator89/Tracebolt/actions/runs/38058537360/job/114231878636)
at source `f3b85720ceee2508b110bbcd3feccb8306a7fcf5`. Its Go command took 2,025
seconds. The two largest package durations were approximately 593 seconds
(enrollmentstore) and 352 seconds (security). The preceding two successful runs
took 2,194 and 2,238 seconds for the Go command. Only the twenty largest package
durations were exported; the remainder includes both smaller-package execution
and build/orchestration work. It is not an isolated cold-build measurement.

Three runners originally balanced those measured package weights plus a 3-second scheduling
estimate for each unmeasured test package. At that baseline the estimated loads
are approximately 689/688/689 seconds. Those numbers are scheduling inputs, not
runtime forecasts. The slowest indivisible package imposes a floor. A fourth
runner lowers the idealized floor by less than two minutes in these samples,
while the unchanged frontend/browser chain already takes roughly 15–18 minutes.
Three is therefore the bounded first experiment, not a speed guarantee.

### Refreshed scheduling weights

The current weights use already-recorded normalized completion artifacts from
two runs of the same tested merge commit
`504c0c4c15691bd8563cf424ed9b4a5d24f47db0`, with Go-source digest
`e7de16b14b87a0f317d9bfb556ee4eb38425a1b9de26e0287fa3f6bc26613471`:

- [Run 38278986648, shard 0](https://github.com/storminator89/Tracebolt/actions/runs/38278986648/job/114911351164), attempt 1, artifact `11760799455`
- [Run 38278986648, shard 1](https://github.com/storminator89/Tracebolt/actions/runs/38278986648/job/114911351155), attempt 1, artifact `11760827513`
- [Run 38273976221, shard 2](https://github.com/storminator89/Tracebolt/actions/runs/38273976221/job/114894841403), attempt 1, artifact `11760242346`

The schema-v2 weights file records these exact identities plus each artifact ZIP
and normalized completion file's SHA-256. Its provenance is pinned by the reader.
These historical reports supply scheduling measurements only: mixing runs here
does not authorize mixing runs or attempts in current completion evidence. They
are not a complete successful workflow run or proof that current source passed.

The reports cover 227 distinct packages, including 196 positive test-package
weights. Each weight is the recorded package elapsed time in integer milliseconds;
enrollmentstore additionally includes all five inventory groups. Its combined
1,588,821ms replaces the old 592,837ms weight. API and lanclient become 605,923ms
and 586,978ms respectively. No-test packages retain zero cost through discovery;
new unmeasured test packages retain the 3,000ms estimate. Weights never select tests.

Only enrollmentstore's scheduling weight may exceed 900,000ms, bounded by six
times 900,000ms for its default invocation and five groups. Every individual
invocation still has the same 15-minute timeout; the job budget stays 60 minutes.
The package remains on shard 0 with all of its exact root groups unchanged.

Arithmetic replay of the unchanged partition algorithm on those recorded
packages changes the modeled workloads from 1,770.164 / 779.512 / 2,102.651 seconds
to 1,588.821 / 1,531.753 / 1,531.753 seconds. The modeled longest workload falls by
513.830 seconds (24.4%). This is a scheduling estimate, not a benchmark or measured
new run. It omits compilation, setup and orchestration overhead, and mixes samples
from two runs; runner variation and newer packages can change actual results.

There is a runner-cost tradeoff: the former single backend job becomes one
build/runtime job, three race jobs and one aggregate job. Compared with baseline,
that adds four job setups/checkouts, repeats module preparation, and duplicates
some compilation on separate cold runners. Total billed runner time can rise
even if wall time falls. No cache, test reduction or timeout change is included.
After reviewed publication and authorized CI, compare exact-commit total wall
time, individual shard duration and summed job runtime against these baselines
before considering further changes.

## Inert verification

`python3 -B tests/security/test_go_race_shards.py` exercises malformed/overlapping
partitions, missing/foreign/duplicate reports, failed/skipped/cancelled needs,
source/run binding, no-test packages, normalization and mocked-process failure
propagation without executing Go tests. A temporary metadata-only module also proves that
race-only packages and race-tagged test files are discovered. Run it and the coverage/timing tests
normally and with `-O`. The coverage test pins the full workflow integration and
runner implementation as well as the unchanged dedicated exclusion gates; a
contract change requires an explicit coverage review and updated digest.
