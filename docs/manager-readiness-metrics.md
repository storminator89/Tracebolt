# Manager readiness and operational metrics (TB-26 source candidate)

This separate source candidate extends the reviewed session slice of
[#153](https://github.com/storminator89/Tracebolt/issues/153). It does not close
that issue or its remaining #136 dependency gate. The independently closed #145
does not extend the pilot limits below. No host was deployed, credential or
endpoint grant changed, endpoint release published, or security setting relaxed.
The LAN manager remains a Linux pilot with its existing profile and device caps.

## Surfaces and meaning

The existing operator listener and its exact TLS/HTTP-test, Host, Origin,
canonical-path, no-store and session rules remain in force. No new listener,
reverse-proxy identity trust, monitor credential or external exporter is created.

| Route | Admission | Result |
| --- | --- | --- |
| `GET /livez`, `HEAD /livez` | Existing operator transport/Host/path checks; no login | Minimal process liveness only. GET returns exactly `{"live":true}`. It does not inspect databases, certificates, endpoints or targets. |
| `GET /api/manager/readiness` | Current authenticated read session | `200` only for a fresh successful sample of every configured component; otherwise `503` with `ready:false` and fixed component states. |
| `GET /api/manager/metrics` | Current authenticated read session | Cached operational snapshot, bounded counters, queue/capacity and Go-process aggregates, including when unready. |

Other methods and query-bearing metric URLs are rejected. Readiness/metrics do
not add capabilities or admit a named administrative write. Revocation/expiry is
rechecked before responding; this is short read admission, not a promise to recall
bytes already sent over a network. The public liveness result remains minimal
when a database is closed or unavailable. A process responding is not readiness.

This is a bounded JSON contract, not an unauthenticated Prometheus endpoint or an
automatic load-balancer/deployment configuration. Any external monitor, credential
custody, exposure, host-service or deployment change needs its separate authority.

## Components and sampling

Only configured components appear, drawn from a fixed list:

- application and manual-trust storage;
- Linux, Windows, macOS basic and macOS inventory enrollment domains, including
  an already-retained macOS inventory domain that still requires maintenance;
- dedicated issuer/root validity and server TLS leaf validity;
- private-state filesystem-write observation;
- authentication occupancy;
- Linux complete-inventory, Windows inventory/content and macOS inventory
  maintenance loops when those existing loops are configured.

Startup is **starting/unready**. One background owner refreshes about every five
seconds. HTTP handlers only read cached snapshots/counters: they do not execute
SQL, write the canary, sign, collect endpoint data or run target checks. Go runtime
memory collection also occurs at construction/background sampling, not per API
request. A sample older than 15 seconds, a backward sample clock or a stopped
monitor cannot report ready. Shutdown stops status before closing the stores.

Each callback has a 500 ms observation budget and a refresh has a six-second
budget. There is at most **one active probe callback**, including a callback that
outlives cancellation. Its occupied slot is not replaced by new goroutines;
subsequent observations report busy until it actually returns. This is essential:
a real fixture measured the existing SQLite five-second busy handler taking
**5.022 seconds despite a 20 ms context deadline**. Filesystem sync can also
outlive cancellation. These limits bound status-response work and outstanding
probe count; they are not a claim that every OS/database operation is forcibly
interrupted within 500 ms.

A conservative full retained-record domain is unready even though existing read
or report operations may still be useful. No automatic deletion, compaction,
limit increase, enrollment retry, identity reset or replay-floor reset follows.
This readiness is configured core-operation evidence, not an exhaustive promise
that every independently scoped application operation will succeed.

## Storage and filesystem truth

A database probe uses the real existing pool and `BEGIN IMMEDIATE`, validates
expected table access and bounded package-owned state, then rolls back. Enrollment
restores and validates its actual trusted ledger/credentials without persisting
anything; recorded lifecycle states are counted without advancing expiry.
Application/trust production probes bind their fixed private paths and original
file inodes before/after the read; enrollment retains its existing package-owned
path/inode checks. Unsafe permissions, links or replacement are not repaired or
adopted. Restore quarantine remains deny-only and makes the filesystem component
unready; status never clears it or purports to fence already admitted work.
A structurally valid older backup cannot be detected from that same local state
alone. A ready result is not rollback/freshness proof and never authorizes
transparent restore or recovery; the existing independent restore/quarantine
procedure and consumed-authority guarantees still apply.

Success establishes **read validity and writer admission at sampling**, not a
successful future write, commit, available SQLite growth, power-loss durability,
complete schema-integrity audit or every feature's availability. In particular,
DB byte count at its maximum is not proof every write is impossible: free pages
may be reusable. Byte/capacity metrics do not silently override an explicit probe
state. A failed rollback discards the uncertain connection. Reconnect DSNs now
preserve exactly the already-required per-connection settings (foreign keys,
FULL synchronization and the existing enrollment trusted-schema/cache-spill/page
caps); no value is weakened and no authority/schema state is migrated.

The Linux filesystem observation reserves only:

- `.manager-filesystem-write` — one completed, zero-only 4 KiB diagnostic;
- `.manager-filesystem-write-next` — at most one zero-only partial/4 KiB next file.

Construction writes nothing. Each sample validates the private original directory
and existing reserved files, rejects symlinks/hardlinks/foreign ownership/public
modes/nonzero content, recreates the next inode exclusively, writes/syncs it,
renames and syncs the directory. A recognized crash prefix may be reclaimed; an
unrecognized object is left untouched and makes the component invalid. Normal
footprint is 4 KiB, transiently at most 8 KiB logical file data, with two fixed
names. Existing identity/trust/receipt files are never used as canaries.

This observes the **exact create/write/fsync operation only**. Compression,
deduplication, allocation policy, quotas and subsequent writes can differ; it is
not physical-block reservation, SQLite-commit proof or an assurance against
future disk exhaustion. Available bytes/inode counts are filesystem aggregates,
not an endpoint storage scope. Zero/omitted inode information can mean unavailable
or zero; creation errors remain authoritative for that operation. Source tests
inject ENOSPC/EDQUOT at file-operation boundaries and produce real SQLite FULL in
a disposable capped database; no real production disk was filled.

## Operational metrics and privacy

Labels are closed enums, never device, user, actor, customer, recipient, address,
path, certificate, request URI, SQL text or error strings. There is no raw log,
telemetry, report, journal content, token, cookie, CSRF value, verifier or provider
key in these DTOs. No diagnostic data is exported to AI or another service.

- Two fixed HTTP surfaces (`operator`, `agent`): requests, in-flight count, status
  classes and duration buckets. Classes are `1xx,2xx,3xx,4xx,5xx,other`; disjoint
  duration buckets are `<=10ms,<=100ms,<=1s,<=5s,>5s`. Paths/headers/bodies are not
  retained. These are observations, not a new HTTP admission-limit policy.
- Per-component fixed **probe observation** outcome counters, not counts of every
  runtime write failure or distinct incidents. Classes include busy, full,
  readonly, denied, I/O, resource exhaustion, invalid, timeout and unavailable.
  Diagnostic classification never turns an uncertain COMMIT into retry-safe busy.
- Database/WAL bytes, known existing caps, pool occupancy and cumulative pool
  waits. A cumulative `WaitCount` is not instantaneous queue depth.
- Retained record/session occupancy and existing limits; active/pending/terminal
  enrollment counts; hashing/signing/proof permit occupancy and retained challenge
  count. No per-actor/device series or enrollment secret is returned.
- Separate Linux alarm and Windows notification outbox aggregates, each with its
  existing bounds and queued/in-flight/failed/uncertain/suppressed/dropped truth.
  They do not imply delivery, recipient consent, notification enablement or retry.
- Boolean existing journal-AI cancellation/unconfirmed-capture fences. Successful
  reads never clear them, authorize a capture/model call or prove every feature
  is available.
- Go-process goroutines, heap/system bytes, objects, next-GC target, GC count and
  cumulative pause time. These help observe process/GC pressure, not host RAM,
  container headroom, native endpoint health or an OOM guarantee.

## Maintenance evidence

Observers see every actual existing step start and completion, including busy
results suppressed by warning throttling and later successful recovery. No
warning silence is treated as health. Counts/times are manager-owned operational
metadata; no target/source content crosses the observer seam. Stopped loops stay
stopped. Freshness bounds are twice the configured cadence plus five seconds
(seven seconds for one-second loops, 125 seconds for the minute macOS loop).

The macOS loop retains its minute cadence but now gives each step a 500 ms
context, matching the existing bounded Linux/Windows model. Actual driver/OS
cancellation limitations above still apply. It may remain starting/unready until
its first real minute tick; no startup success or warning absence is fabricated
as a maintenance completion. Cancellation tests preserve existing identity,
ledger, credential, content and clock-floor bytes and permit ordinary recovery.
No native macOS collection or new endpoint permission is implied.

## Evidence and remaining gates

Source and real-loopback fixture checks are reported separately from native
execution. Coverage includes cached authenticated surfaces, TLS/Host/Origin/query
and session expiry/revocation, liveness versus unavailable stores, restart with
reserved diagnostic files, fixed-label/privacy-negative metrics, stale/stopped
and recovered loops, bounded blocked probes, real DB busy/FULL, corrupted
schema/authority, unchanged authority bytes, and safe reconnect settings.

The finite `TestManagerStatusNearCapacityConcurrentReportsAndCachedReads` uses
real SQLite at the unchanged 25-record Linux complete-profile cap: 1 activated
identity and 23 retained canceled invitations, then the final pending slot. It
accepts 64 synthetic primary reports without concurrent diagnostics, then 64
with 64 background probes and 256 cached metrics reads. An increase in actual
pool wait count proves contention; merely starting concurrent goroutines does
not pass. It checks bounded identifier-free JSON, final recovery, byte-identical
authority around read-only probes, restart-retained terminal records, exact
original receipt/replay floor, and an existing report at full enrollment capacity.

One Linux amd64 Go 1.27.1 race run (`GOMAXPROCS=2`) measured 2,941-byte reports,
baseline/concurrent report p95 114/193 ms, probe p95 201 ms and cached-read p95
171 microseconds, with 127 pool waits and all 67 sampled outcomes `ok`. Pre-restart
DB/WAL sizes were 4,096/3,497,912 bytes. These are shared-container measurements,
not SLOs or native collector/HTTP-ingress/browser/fleet-scale acceptance; cached
read timing includes JSON encoding but no production HTTP/auth/network path.
The reproducible test logs current timings and pre-restart pool counters on each
run, rather than treating restart-reset counters as load evidence.

Before any production claim, validate native filesystem exhaustion and I/O
behavior, shutdown on supported hosts, and unchanged real endpoint/browser
operation. These source probes are not complete runtime-write-error
instrumentation for every application path. #136 endpoint/support status remains
an independent requirement. Unsupported 100/500/1000-device scale is not promoted.
#153 remains open; no release, host acceptance or complete-security-audit claim
is made by this local candidate.
