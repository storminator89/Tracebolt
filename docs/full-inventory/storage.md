# Complete package inventory storage foundation

Status: isolated candidate package and synthetic tests only. This does not add a
runtime route, a collection profile, an enrollment identity, an agent collector,
a manager migration, a UI, or a deployment. The baseline remains the frozen
556-file release source. Existing basic/operational/package profile, identity and
replay policy remains authoritative and unchanged.

## Authority transaction boundary

`internal/inventoryledger` deliberately has no `Open`, `*sql.DB` owner, private
second database, authentication cache, background collector or network handler.
Its `Transaction` interface contains only `ExecContext`, `QueryContext` and
`QueryRowContext`. The existing authority owner must supply the same already-open
SQLite `BEGIN IMMEDIATE` connection/transaction used for:

1. Current manager binding, fresh complete-collection profile and device identity
2. Current enrollment state, revocation, expiry, replay and request admission
3. Inventory mutation/read, authority-state persistence and eventual COMMIT

The caller must roll back the entire authority transaction on **any** error.
None of the package methods begins, commits or rolls back that transaction.
Every returned value is provisional until COMMIT succeeds. `CommitResult[T]`
accepts the authority owner's transaction runner and returns a zero `T` for any
callback, authority-persistence or COMMIT error. It does not create a second
transaction or authenticate the runner. Publishing inside the callback would
violate the precondition and cannot be undone by this helper.

This is a structural seam, not a claim that an arbitrary implementation of the
interface is safe. In particular, a database pool or autocommit connection must
never be passed as a transaction. Authorization from a previous request must not
be reused. The device key must be derived from the fresh approved identity or
credential scope, not trusted from request JSON or silently reused to attach old
inventory to a replacement identity/profile. A display device name is not that
authority binding. The caller rechecks revocation even for an idempotent retry or
a valid cursor. Client timestamps do not supply `now`: every operation takes a trusted
manager clock value. `CollectedAt` stays the original observed client timestamp
and remains untrusted provenance, subject to the authority owner's freshness
checks.

The isolated `Initialize` creates fresh `fi_*` tables inside the caller's schema
transaction. It neither adopts a legacy database nor changes the existing
runtime's schema allowlist/version. Configuration limits are durably recorded and
must match on every handle. Future integration needs explicit review of the
fresh-profile schema, authority runner, database opener and API adapter.

## Generations and promotion

The contract in `internal/fullinventory` declares all selected installed or
incomplete binary package rows from a successful supported dpkg source parse.
Residual-only source data can legitimately produce an empty selected inventory;
that generation has zero rows, zero chunks and the defined empty domain hash.
Source read/parse failure is not equivalent to that empty generation.

- `Begin` stores one immutable canonical manifest and starts a fixed 15-minute
  staging lifetime. A device can have one active staging generation. An exact
  retry returns the original start/expiry without refreshing either.
- `Append` accepts the next chunk only. The shared validator checks generation and
  manifest binding, chunk self-hash and chain, ordinal and row offset, strict
  package-name/architecture order, duplicate rejection, per-chunk limits and
  aggregate counts/bytes/hash progress.
- Exact canonical retries of an accepted ordinal return the original chunk
  receipt. Changed canonical content is a conflict and cannot overwrite the
  accepted chunk. Equivalent whitespace/key order normalized by the separate
  wire decoder has identical canonical content; original raw ingress is not
  stored by this typed seam.
- A versioned private-manager checkpoint persists the SHA-256 state, manifest
  binding, last key/hash and counts in the same transaction as the canonical
  chunk and page rows. Resume checks the contract's strict checkpoint format and
  separately compares accepted row/chunk/canonical-byte counters. Checkpoint bytes
  can contain a partial hash block's row data; never expose them to a client,
  diagnostic log or artifact.
- `Promote` restores the bounded checkpoint and obtains a valid `Finish` receipt
  only after every declared chunk, row count, installed count, canonical row-byte
  total and final hash matches. It atomically changes the current-generation
  pointer, retiring the old complete generation. It performs no row copy,
  whole-generation reload or cascading delete.
- Failed, conflicting, incomplete, expired, interrupted or quota-rejected staging
  never replaces the old complete generation. A COMMIT failure also leaves it
  unchanged. The original collection, initial receipt, per-chunk receipt and
  completion timestamps are retained rather than synthesized on retry.

A trusted checkpoint is continuity state, not authentication against arbitrary
local database rewriting. Bounded strict decoding, counter consistency and page
row validation detect specified corruption classes; they do not prove integrity
of a database that an attacker can coherently replace. Filesystem protections,
backup/rollback policy and any authenticated-state requirement remain the
existing authority owner's responsibility.

## Complete, bounded pagination and search

`Page` returns at most 100 matches after examining at most 2,048 indexed rows.
Rows are in the generation's immutable package-name/architecture order, stored
with contiguous ordinal keys. Search is case-insensitive literal substring
matching across the retained row fields, with a maximum 128-byte printable ASCII
query. It does not use an unbounded SQL `LIKE`, total-match `COUNT`, whole-ledger
load or JavaScript-safe-number conversion.

Every continuation binds device, generation, normalized query, page limit, next
scan ordinal and a fixed expiry using a domain-separated HMAC-SHA-256. The
caller supplies a durable 32-byte key through a private pointer-backed opaque
handle; diagnostic and JSON formatting is redacted. Verification is constant-time
for the MAC, canonical and byte-bounded for the payload. Cross-device, changed
query, changed generation, changed limit and modified cursors fail explicitly.
Rotating the caller's key intentionally invalidates existing cursors.

Pagination never switches silently to a newly promoted generation. A retired
generation is retained for 15 minutes after retirement, allowing existing cursors
whose original expiry remains valid to finish. Subsequent pages preserve that
original expiry. Current observations become unavailable after 24 hours from the
original `CollectedAt`; this does not claim fresh source data for 24 hours and
does not weaken the authority owner's shorter freshness policy.

An empty page with `Exhausted=false` and `SearchIncomplete=true` means more
indexed rows must be examined using `NextCursor`. It does **not** mean zero
matches. `TotalRows` is the complete immutable inventory size, not an invented
search-match total. A scan-bound cursor always advances, so matching rows after
2,048 nonmatches remain reachable. Only `Exhausted=true` establishes that this
scan reached the end. Missing terminal rows or ordinal gaps return a zero result
and a fixed storage error; no partial page escapes an error.

## Accounting and physical work

All limits are ceilings, optionally configurable downward and persisted in the
same database. Hitting one rejects admission; no prefix is promoted as complete.

| Resource | Generation | Device, all retained states | Global |
|---|---:|---:|---:|
| Declared rows reserved | 100,000 | 300,000 | 2,000,000 |
| Declared chunks reserved | 1,024 | 3,072 | 32,768 |
| Canonical row stream | 32 MiB | covered by stored-byte budget | covered by stored-byte budget |
| Canonical manifest + chunk wire encodings | 48 MiB | covered by stored-byte budget | covered by stored-byte budget |
| Retained manifest + checkpoint + chunk + page-row BLOBs | 96 MiB | 288 MiB | 512 MiB |
| Retained generation slots | 1 | 3 | 4,096 |

Chunk calls are bounded to 128 rows and 64 KiB of canonical chunk data. Manifest
input is at most 4 KiB and a trusted checkpoint at most 2 KiB. A page query examines
at most 2,048 page-row BLOBs, returns at most 100 matches and has at most a
1,024-byte cursor. A cleanup call deletes at most 256 page rows and 16 chunk BLOBs
through indexed key ranges. Promotion updates only bounded generation metadata
and the device pointer. There are no cascading deletes, `VACUUM`, global table
scans or full inventory materializations in request operations.

There are two distinct accounting classes:

- **Held declarations:** `Begin` reserves the manifest's full row and chunk
  counts and a generation slot. These remain held across abandonment and partial
  cleanup, until every physical row and chunk belonging to that generation has
  actually been deleted in the same transaction.
- **Actually retained canonical BLOB bytes:** inserted manifest, checkpoint,
  canonical chunk and separate page-row BLOB lengths are charged. Checkpoint
  replacement charges its exact byte delta. Bounded deletion releases only the
  bytes actually deleted; remaining manifest/checkpoint bytes are released with
  final generation removal. Per-device and global counters are updated under
  the same serialized authority transaction, not independently cached in memory.

Three slots can briefly mean current plus two retired generations. A subsequent
`Begin` is rejected until eligible cleanup frees a slot. Cleanup never deletes
the current generation, even if observation age has expired. `Abandon` marks only
matching staging data and releases no budget. The caller must continue eligible
`Cleanup` calls until `Done` so abandoned reservations cannot remain stranded.
Empty device/budget metadata is removed at final cleanup if no generations remain.
There is intentionally no hidden autonomous cleanup scheduler in this package.

These are **logical retained canonical-byte and bounded-row-work limits**, not
claims of maximum process memory, physical database size, raw network traffic,
SQLite CPU steps or elapsed time. The separate wire decoder permits bounded
noncanonical whitespace/key order; a 48-MiB canonical sum is not a 48-MiB raw
transfer guarantee. Repeated exact retries also consume ingress/CPU while adding
no stored bytes. A future runtime must independently enforce raw-body limits,
cumulative/raw retry/rate and in-flight admission, deadlines, authorized request
sequencing and client connection limits. It must also enforce protected database
paths, page-count/file/WAL/journal limits, checkpoint policy, disk admission and
bounded concurrency, reconciling these new budgets with existing authority
storage limits. The 512-MiB number excludes indexes, SQLite metadata, free pages,
WAL/journal and the rest of the existing authority database.

## Errors and validation evidence

Fixed package errors distinguish invalid input, conflict, quota, storage,
incomplete generation, not found, expired stage, invalid cursor and expired
cursor. Internal SQL errors/raw metadata are not returned. A canceled context may
return its ordinary context error. No method returns partial rows/counts alongside
an error. The caller's authority runner may return its own fixed authorization or
COMMIT error through `CommitResult`.

Synthetic temporary-SQLite tests cover:

- Restart and exact retry timestamps; zero-row complete generation
- Every row in a 100,000-row source fixture, including a match at the final ordinal
- Scan continuation beyond 2,048 nonmatches, fixed cursor expiry and generation pin
- Cursor modification and cross-device/query/generation/limit rejection
- Incomplete/conflicting/expired staging preserving prior current data
- Concurrent independent-handle quota reservations, promotion and bounded cleanup;
  rollback of losing quota handles
- Actual deferred-foreign-key COMMIT failure suppressing provisional completion
- Caller revocation denial, checkpoint counter mismatch and corrupt page zero-output
- Logical byte quota rejection without partially persisted chunks
- Bounded cleanup, held reservations until last physical deletion, deletion fault
  rollback and retained-generation slot limits
- Opaque cursor-key formatting, missing-terminal-row failure, trusted-clock
  reversal rejection and indexed query-plan checks

One ordinary local synthetic run of the full-ceiling test stored 100,000 rows in
782 chunks, reached the final search result in 49 bounded scan pages, and charged
37,826,106 retained canonical BLOB bytes. Ingest plus scan took about 3.16 seconds
in that run. These are fixture measurements, not production latency, physical
storage or memory guarantees.

Validation command (Go 1.27.1 on PATH, with locked dependencies already cached
for offline use):

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test ./internal/inventoryledger
```

No test reads real inventory, uses a network, loads credentials, changes existing
runtime files or performs enrollment/deployment.
