# Complete inventory authority-store contract

This source candidate adds only a fresh `managed-operations-v3` authority store
with SQLite `user_version=3`. It neither migrates nor adopts basic schema1 or
managed-v1/v2 schema2. Existing public binding, path ownership, mode, inode,
issuer, canonical authority and schema checks remain mandatory before mutable
reopen pragmas. At most 25 identities are allowed for this profile.

The transport must establish possession and bind the exact purpose, independent
inventory sequence, deterministic `inventorywire.GenerationID(serverDeviceID,
sequence)` label, manifest digest and chunk/body fields. The agent methods do not
provide transport authentication. They require trusted certificate-hash identity
and trusted manager time, rechecking the current activated Linux profile,
certificate, expiry, revocation, clock and durable inventory floor in the SAME
`BEGIN IMMEDIATE` transaction as chunk writes and promotion. No body device ID or
cached authorization supplies authority. A single nonblocking store inventory
admission slot prevents an unbounded SQLite wait queue for this seam. Initial
BEGIN-busy retains the existing typed result; later errors are never reclassified
as retryable busy. No provisional result escapes a failed COMMIT.

Each identity has one independent durable inventory floor, retained separately
from ledger chunks/rows. Cleanup never deletes that floor or the private cursor
key. Per-retained-generation bindings stay bounded by ledger reservations and
are deleted only when matching bounded cleanup finishes. Deterministic labels
make a higher sequence use a different identity without historical tombstones.
An exact retry retains original start, receipt, completion and collection ages.

`InventoryFailure` separately records authenticated source failure before a
valid manifest exists. Allowed reasons are source_missing, source_invalid,
source_changed, resource_limit and collection_failed. It has no manifest, rows
or count. A failed or expired new transfer preserves the previous current
complete generation. Operator status keeps both independent. Manifest counts in
a pending transfer are declarations, not committed completeness. A completed
zero-row inventory is explicit and distinct from failure/unavailable.

`InventoryPage` returns indexed, generation-pinned bounded pages, including the
completed sequence/hash binding. Cursor expiry, observation expiry and absent
inventory remain errors; none becomes a successful empty result. Status retains
expired complete metadata with its original observation age. Complete metadata
expires at original collection+24h, staging at original begin+15m, and cursors
at15m at most. Future collection/attempt time is rejected (zero future skew).
Operator status/page methods require server-assigned device IDs and current
authority too.
Routine authority transactions validate only bounded generation metadata,
per-generation bindings and exact logical-budget totals. They do not restore
all rows/chunks. Cleanup deletes at most256 rows and16 chunks per transaction,
never current complete inventory; row/chunk reservations survive until cleanup
finishes. Deleting/pruning inventory cannot reset its replay floor.

`InventoryCleanup` is a distinct privileged operator-maintenance seam, never an
agent endpoint or body-supplied lifecycle override. Inside the same transaction,
it resolves the immutable issued device/profile binding from freshly restored
authority. It permits eligible non-current cleanup after revocation, certificate
expiry, or an expired lifecycle state. It preserves the ledger's original staging
and cursor-retention eligibility windows; revocation is not early-delete consent.
Its separate persisted trusted maintenance clock cannot go backward and never
rewrites credential-era receipt timestamps, the sequence floor, certificate,
activation state or current complete pointer. Agent operations and operator reads
continue to require activated, unexpired current authority.

Current complete data is deliberately retained even after revocation/expiry and
continues consuming the fixed logical and physical budgets. This API does not
provide deletion of the last complete generation, identity retirement/recycling,
or floor reset. Reclaiming such data requires a separately designed and reviewed
explicit retention/deletion policy; unavailable identities must not be silently
represented as complete empty inventories.

## Fixed runtime ceilings

These are fail-closed admission ceilings, not supported-size guarantees:

- Logical retained BLOB bytes:48MiB generation,96MiB device,128MiB global
- Reserved rows:200,000 device and400,000 global
- Reserved chunks:2,048 device and4,096 global
- Retained generations:3 device and75 global
- Database:512MiB,4096-byte pages, max_page_count131072
- WAL:640MiB; SHM:2MiB; unexpected nonempty rollback journal rejected
- Old profiles retain their existing192MiB/file and49152-page limits

The pure ledger default512MiB logical budget is intentionally NOT used by the
runtime profile. A maximum-size pure-contract generation can exceed the lower
runtime generation ceiling and must fail without truncation or prefix promotion.

SQLite autocheckpoint and journal_size_limit do not guarantee a physical WAL
bound. The complete-profile actual transaction connection disables and verifies
cache_spill, verifies WAL/FULL synchronization and4096-page geometry, and before
COMMIT reserves existing WAL bytes+32+page_count*4120+72KiB<=640MiB while holding
BEGIN IMMEDIATE. With spill disabled, the commit writes each dirty final DB page
at most once; the additional72KiB covers pinned SQLite sector padding, including
its65536-byte maximum sector and one4120-byte frame. The full current page count
is reserved rather than estimating dirty pages. Capacity rejection rolls back.

The proof applies to these bounded authority-store transactions, not arbitrary
SQL supplied by callers. No public SQL/transaction handle is exposed.

This conservative reservation is an availability tradeoff: a pinned reader or
retained WAL physical high-water mark can make all committing authority calls,
including status, revocation and cleanup, fail closed with ErrStorage. There is
no automatic checkpoint/truncation recovery path in this seam, and the tests do
not establish acceptance under runtime checkpoint starvation or a near-cap live
WAL. Operational recovery must be reviewed before runtime capacity acceptance;
never delete, truncate or replace a live DB/WAL/SHM file to bypass admission.
Quiescing all owners and protected SQLite checkpoint/reopen procedures require
their own recovery test and deployment runbook.

The actual transaction connection reapplies cache_spill=OFF and max_page_count,
then verifies WAL, FULL synchronization and page geometry. This is not a claim
that every startup safety pragma is reinstalled after pool replacement:
foreign_keys and trusted_schema remain startup-only inherited store settings.
A reconnect with changed synchronization or WAL geometry fails closed; broader
connection-replacement acceptance is not established by the capacity sample.

## Synthetic evidence

Go1.27.1 linux/amd64,2026-10-04, pinned offline modules. No host collection:

- Real authority fixtures approve, issue and activate ephemeral certificates;
  enumerate769 complete rows exactly once; check retry ages, restart, revocation,
  generation/hash/sequence binding, rollback, real deferred-FK COMMIT failure,
  initial-BEGIN busy and revocation/finalize races.
- Integrated75,000-row synthetic generation exceeds its48MiB runtime quota;
  byte accounting and declared reservations remain intact and previous complete
  inventory stays current. Partial promotion fails.
- Opt-in isolated physical measurement used maximal128-byte ledger device keys.
  Three100,000-row generations completed, then a fourth stopped at51,072 rows
  on the128MiB logical ceiling. Stored logical bytes134,201,384; maximum DB bytes
  285,040,640; WAL4,280,712; SHM32,768; pages69,590; elapsed11.36s.
  The rejection preserved exact accounting and blocked incomplete promotion.
  This standalone ledger fixture sets wal_autocheckpoint and journal_size_limit
  explicitly; it is not an authority-store high-WAL or starvation measurement.
  Its file-size assertions match the runtime's 2 MiB SHM rejection ceiling.
- Revoked, certificate-expired and lifecycle-expired real authority fixtures
  reclaim only eligible retired/expired-staging reservations. Current data,
  replay floor, identity and credential-era timestamps survive cleanup/reopen;
  maintenance-clock reversal and all agent/read attempts remain rejected.

Run focused tests with `go test ./internal/enrollmentstore -run
'^TestCompleteInventory' -count=1`. Run the explicit capacity measurement with
`TRACEBOLT_INVENTORY_CAPACITY_TEST=1 go test ./internal/enrollmentstore -run
TestCompleteInventorySyntheticPhysicalCapacity -count=1 -v`.

These source/fixture checks do not establish production capacity, authenticated
HTTP/TLS transport acceptance, native source collection, installation, service
lifecycle, restart/reboot acceptance, or real-device consent.
