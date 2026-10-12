# Fresh manager MSI package catalogue

Source candidate only. No runtime setup, credential, permission, service or MSI
installation is performed or authorized by the source fixtures.

## Explicit fresh setup

The manager prepare/finalize source CLI adds `--package-catalogue` alongside
`--fleet --reusable-jobs`. Both apply phases additionally require the unchecked,
explicit `--ack-package-catalogue` acknowledgement and the existing exact plan and
managed-MSI acknowledgement. Keep the same flags and protected inputs through
both phases. Optional `--scheduled-jobs` retains its separate fresh scheduling
profile and approval requirements.

The catalogue uses new manager-only registry/config/setup versions (v5 manual,
v6 scheduled), a reciprocal immutable catalogue setup marker, manager records
v5/v6, and saved worklist v2. Endpoint offers, grants, signed v3/v4 permits and
reports, IPC, local executor and paired mutation fences are unchanged. There is
no migration or promotion of an existing singleton registry, even an unused one.
Manager startup only opens existing matching state; missing or contradictory used
state is never repaired. Original identity, leaf, grant expiry, schedule windows
and operator capabilities remain authoritative.

## Four retained payloads, one shared budget

A fresh catalogue retains at most four payload entries sharing the existing
128 MiB manager payload budget. It reserves the entire declared reviewed size
before accepting bytes. Partial uploads, pending writes and uncertain custody
continue to consume the slot and declared-byte quota. Package bytes stay outside
the database. The existing 192 MiB database and 256 KiB artifact-metadata record
bounds are unchanged; four sets of at most 25 compact assignments fit in that
same record. Each delivered endpoint still has its separate original payload cap.

Every reserve creates a monotonically increasing immutable custody occurrence,
independent of the content-derived artifact ID and each device's grant-wide job
sequence. A repeated A payload has the same content identity and a new occurrence.
A request cannot select a slot or supply a path. Four fixed server-selected spool
namespaces reuse the original protected-parent, single-link, current inode/owner,
exact pending chunk and digest guards. No arbitrary or recursive deletion exists.

An unresolved job for A prevents retiring A; it does not prevent retaining B or
explicitly delivering B to another eligible device. Each endpoint still has one
active job. It must finish the existing result-bound retirement before choosing
another package. An older retained entry that the endpoint has never received
can be selected after retirement of a later one. Per-entry assignment tombstones
prevent a second delivery of the same occurrence to that endpoint, even after its
bounded recent-job history has rolled over. There is no deferred queue.

Assignment plus exact transfer/job sequence is persisted atomically with delivery.
The verified result and signed retirement digests are recorded atomically with the
retirement report and remain with the entry. Scoped manager retirement considers
only that entry's assignments and rejects any unresolved one, including offline or
revoked endpoints. Its durable deletion intent serializes with assignment issuance.
A retired slot is reused only after any active worklist for it has been explicitly
archived. The old entry is committed into a bounded rolling retirement digest;
its occurrence is never reused. An uncertain shared SQLite commit or integrity
failure still fails the manager closed; unrelated availability does not weaken a
shared-storage safety boundary.

## Deliberate package and device choice

The compact catalogue shows each entry's reviewed name/version, size, state and
aggregate reserved storage. Select an exact entry, then use the existing explicit
upload, saved target choice, Deliver, Review, Approve and package-cleanup controls.
Each stage starts unchecked. Saving never grants delivery or execution. One active
worklist per retained entry is allowed; the existing total nine worklists, 25
registered targets and nine batches per worklist remain unchanged. Archive changes
presentation only. Historical outcomes stay inspectable, including after slot reuse.

Reload, selection changes and uncertain responses reconcile with GET only. They
do not replay a POST, resume a batch, schedule, install, retire or acknowledge risk.
Existing pending scheduled approvals keep every original occurrence, device, actor,
leaf, readiness and window pin. Central cancellation stops only unsent work.

## Private API

- GET `/api/windows-managed-msi/catalogue`: explicit enabled/disabled profile,
  revision, four-entry limit, reserved bytes and bounded entry views.
- POST `/api/windows-managed-msi/catalogue/reserve`: reviewed exact package,
  native/publisher review references and current catalogue revision.
- Catalogue-only GETs of the existing artifact and per-device MSI endpoints require
  the canonical query `artifactRetiredCount=N`. Old singleton endpoints still reject
  query selection. Existing mutation bodies pin the occurrence and exact job as
  before. A schedule cancellation continues to pin its exact schedule digest.
- Saved worklist v2 uses the same strict request fields and foreground stage API;
  it permits independent active selections for the different retained entries.

All operations retain private named-operator HTTPS, session, CSRF and final live
capability checks. The catalogue creates no endpoint permission or publisher trust.

## Source verification boundary

Focused tests cover SQLite reservation bounds/restart, original assignment evidence,
A-to-B-to-fresh-A replay fences, older-unused occurrence selection, two independent
protected spool deliveries, scoped retirement with another incomplete payload,
active-worklist slot retention, strict GET routing, fresh setup flags and compact
EN/DE UI interruption/uncertainty flows. Inert fixture bytes and signed synthetic
reports never establish native Windows installer, NTFS, SCM or deployment acceptance.
