# Enrollment-v2 durable transaction boundary

`internal/enrollmentstore` is a Linux-only, private SQLite adapter for the
isolated enrollment lifecycle. It does not generate invitation secrets or
signing keys, install services, change trust, expose endpoints, or deploy a
manager. Tests use disposable generated keys held in memory.

## Transaction authority

Each command acquires SQLite `BEGIN IMMEDIATE` before reading authority. It
restores a complete bounded private ledger into a transaction-local state
engine, applies the command, writes the new ledger and any certificate,
delivery or observation metadata, and commits before returning success.
Independent handles and processes use the same SQLite serialization boundary.
There is no process-local authorization cache and no in-memory transition
followed by an independent, later database write.

The private binary ledger has its own version and framing. Public snapshot JSON
is still inspection-only. Restoration checks exact manager/profile/origin/
issuer/configuration binding, chronology, exact revisions, quotas, all retained
request/identity/serial/verifier uniqueness, canonical approved public keys, and
complete intent metadata. Tombstones are retained; no implicit eviction or
resurrection occurs. Unknown schemas, added triggers/tables, partial state,
missing issued certificates, malformed bodies, and incompatible configuration
fail closed.

`BeginIssuance` commits an immutable intent before `SigningIntent` returns it.
An external signer must use that intent's identity and serial and must reconcile
uncertain outcomes. `CommitIssued` validates the concrete verified certificate
against that intent and atomically retains its exact DER with lifecycle state.
Retries retain the same identity, serial and DER. Signing alone cannot authorize
delivery, and a cancellation/revocation that wins the transaction race prevents
later issuance or delivery.

`StatusContext` and `CertificateForVerification` are privileged local lookups
for proof verification. Their return values must never be exposed directly as
unauthenticated HTTP responses. `ReadStatus` and `DeliverCredential` recheck the
purpose-separated verified proof against current stored binding, key, time and
state inside the final transaction. Terminal status is inspectable by the bound
key but never authorizes delivery. A pending approval deadline continues to
limit delivery until activation; activated identities use certificate expiry.

Delivery metadata retains first delivery time, last delivery time/request ID and
a bounded count. Only the most recent request ID has metadata-level exact-retry
idempotency. A fresh older request ID may replace that last entry after a newer
request, but every permitted request returns the same stored certificate; no
identity or credential is recreated. Repeated delivery never establishes
activation, updates a telemetry receipt, or proves a running service.

## Observations and replay

`SaveObservation` accepts a transport-authenticated certificate hash and one
bounded v1/basic frame. It checks current activated state, exact committed
certificate, expiry and sequence/time ordering in the same database transaction
that persists the latest exact frame and replay floor. It derives sequence and
observation fields from strictly validated frame bytes, not separate caller
metadata. The mapped identity comes from durable approval.

An exact previously committed frame may be retried after its normal sample-age
window, while the identity remains active and unexpired. It returns the original
receipt and does not refresh connection or collection timestamps. A new frame
must satisfy the ordinary freshness contract and advance sequence, generated
time and collected time. Revocation is checked even for exact retries. Status,
certificate retrieval and telemetry are distinct operations.

## Filesystem, recovery and limits

The direct directory must already be private to the runtime UID or be newly
created privately. Ancestors must be owned by the runtime UID or root and not
be replaceable by another account (ordinary sticky directories are permitted).
Existing insecure directories/files are rejected rather than chmodded or
adopted. Database and SQLite sidecars must be private, owned regular files with
one hard link; symlinked paths are rejected. File identity and protections are
rechecked per transaction. The policy excludes compromise by the same runtime
UID or root; it is not an encrypted store or a sandbox against its own owner.
Existing databases are inspected read-only before any mutable SQLite pragma.
When no WAL is present, an immutable-main preflight avoids creating sidecars;
that preflight is never current authorization, and the final transaction always
loads current SQLite state. Live WAL reads may update transient shared-memory
reader bookkeeping, but rejection does not change journal mode, schema or
checkpoint database contents. SQLite uses WAL and FULL synchronous mode. The new
database directory is synced before initial Open returns.

The configured record capacity includes terminal tombstones. DER, ledger,
credential records, frame bytes and database/sidecar sizes have finite bounds.
Every transaction currently restores and verifies the whole ledger, including
stored certificates and latest frames. The first exposed integration must cap
retained records at 25 pending a normalized-storage/performance review. A
25-record credential-plus-small-frame benchmark is included. One measured Linux/amd64
cloud run (10 iterations) took approximately 14.1 ms per read transaction and
allocated 2.93 MB in 29,261 allocations per operation. This is a local measurement,
not a worst-case measurement or a production latency, throughput or peak-memory
guarantee. A separate dense-evidence fixture padded with valid JSON whitespace
uses exactly 73,728 bytes, the current 72 KiB wire cap. With 25 stored frames,
one five-iteration run measured 52.2 ms, 36.3 MB allocated and 64,408 allocations
per read transaction. One simultaneous status/observation/revocation run took
134.8/238.2/55.7 ms including lock wait (lock-acquisition order varies). Allocation is cumulative per operation,
not peak live memory; these particular fixtures do not establish a universal
worst case. Tests cover rollback on a SQLite write failure; they do not claim
injected COMMIT-failure or process-crash recovery evidence.

A structurally valid complete older backup cannot be distinguished from current
state by this local database alone. Restore must be an explicit security recovery
event with quarantine/reconciliation or a new manager epoch before accepting
existing agents. Partial backups fail closed. Automatic backup rollback recovery,
renewal, key rotation and production signer custody remain separate gates.
