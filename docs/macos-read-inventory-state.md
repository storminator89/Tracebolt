# macOS inventory sender-state foundation (inactive source)

`internal/macosinventorystate` adds pure checkpoint validation and serialized
sender transitions around a fake-testable durable-commit interface. The reviewed
[wire contract](macos-read-inventory-wire.md) remains authoritative and unchanged,
as do the [collector files](macos-read-inventory-source.md). There is no native
filesystem adapter, collector invocation, transport, profile registration, CLI,
manager store, service, listener or UI. Linux, Windows, basic macOS, old telemetry
budgets and release pins are untouched. Source tests are not native acceptance.

## Original identity and initialization

`InitializeFresh` and `Restore` are deliberately different entry points. Fresh
initialization requires a valid canonical enabled v1 control and a successful
create-only commit of a `used: true` checkpoint. This is not authentication:
the future initializer must establish explicit fresh local consent, unpredictable
fresh grant creation and protected original identity provenance first. The exact
original enable bytes are immutable across every transition and reopen. They
include the original device, sender binding and independent grant, not the current
renewable leaf. A different original enable, even with otherwise valid syntax,
cannot reopen this state.

The future adapter must preserve an independent irreversible used marker, like
the primary Windows full-process used fence, before exposing any fresh initialized
state. If that marker exists, missing/invalid/interrupted checkpoint creation is
a blocker. `CreateFresh` must reject it, and it must never be cleared to retry.
`Restore` rejects empty/missing, invalid, foreign, noncanonical or stale checkpoint
bytes; it does not call the initializer. The interface and its test fake do not
establish authentic freshness, primary-marker custody or real disk integrity.

Initialization exposes only the exact pending enable control. A canonical receipt
bound to those exact bytes, with original `receivedAt` no later than caller time,
must be durably acknowledged before any capture lease is returned. Receipt syntax
and digests are not proof that a manager is authentic or actually committed.

## Reserved captures and exact pending bytes

All state transitions on one `State` hold one mutex through compare-and-commit.
`Reserve` consumes an independent bounded sequence and original UTC capture time,
then commits the entire next checkpoint before returning an immutable lease.
The next reservation is at least one minute after the last reserved capture,
including failed or lost attempts. Sequence zero, unsafe integers, wraparound,
clock regression and unrepresentable original 24-hour expiry are rejected.
Only the lease's originating live state can settle its exact reservation.

`Stage` accepts one already-canonical report matching the original enable and
lease's sequence, generation and original time. It never calls a collector,
repairs a binding, changes source status, truncates a body or creates fresh retry
bytes. The report becomes sendable only after the checkpoint commits. A pending
report blocks another reservation until acknowledgement, expiry or terminal
disable. `Fail` records only the closed `collection_failed` or `interrupted`
reason; source/provider text is never accepted as an error or failure reason.

A reopen turns a reserved capture into a durably recorded lost attempt before
returning a usable state. The reservation floor and original time remain consumed.
It never returns another lease or recaptures that sequence. An invalid/expired
completion also cannot release its reservation; the owner records failure/loss or
reopens under exclusive ownership. The latest failure remains distinct from the
latest successful source generation and its age. This is bounded latest-state
metadata, not an unbounded attempt history.

`PendingReport` and `PendingControl` return detached copies of the exact committed
request bytes. Receipt verification binds the pending request, identity, grant,
control revision, sequence, generation, digest and capture time, and checks receipt
time against caller time. First acknowledgement stores the original canonical
receipt bytes. An exact duplicate is idempotent; a regenerated receipt with a new
`receivedAt` conflicts. Reopen and same-key renewal retain exact pending bytes,
original receipt times, floor and capture age. There is no current-certificate field
or renewal operation that could silently rebind them. See
[automatic renewal](automatic-certificate-renewal.md).

## Latest state, quality and original expiry

At most one latest report is retained. A newer completed report replaces the
previous latest report/receipt record; there is no pending queue or historical
source inventory. Failed captures preserve the previous completed report for
its original remaining lifetime. `Inspect` reports `full`, `partial` or `unknown`
source coverage independently from `fresh`, `stale` or `expired` original age.
A source-unknown report never becomes a known empty inventory. Stale begins at
one minute; expiry begins exactly 24 hours after original capture.

On an admitted time-advancing transition, including `Inspect` and `Restore`,
expired source bytes are removed from the next checkpoint. Request/source digests,
original capture/generation metadata and the latest original receipt remain as
bounded replay tombstones until a newer completed report replaces that record.
The permanent used flag, original controls/receipts, final floor and terminal
decision are never pruned or reset. Validation checks expired receipt tombstones
against those exact saved fields; it cannot re-hash payload bytes already removed.
Future protected storage must supply integrity and rollback resistance.

There is no internal clock, scheduler, background expiry task, physical erasure
or disk-retention proof. A future owner must regularly drive `Inspect`/maintenance
with a trusted time, including when disabled, and apply the real storage cleanup
policy. Pausing all callers can leave previously committed bytes on disk; the
package does not promise wall-clock deletion. Expired reports cannot be returned
as pending, acknowledged anew or given a refreshed timestamp. `CheckpointBytes`
is a private adapter/testing copy of already committed state, not a transport or
operator-read API, and does not itself advance time.

## Terminal disable and durable uncertainty

`Disable` commits control revision 2 with the exact final locally reserved floor,
including failed, lost and pending attempts. A live reservation becomes lost;
a pending report becomes abandoned. There is no reenable, grant replacement or
new revision workflow in v1. Every later reservation, stage, report retry and
report acknowledgement fails closed. Disable retry returns the original control
bytes and time. Its original acknowledgement is retained without re-aging, and
the used/replay tombstones survive reopen and expiry.

`DurableCommitter` has only create-only initialization and exact
compare-and-commit operations. Even identical-byte transitions must verify that
the expected durable checkpoint still exists; an adapter may implement this as
a verified no-op. A failed or uncertain commit permanently poisons that live
owner. Poisoning begins before entering the adapter callback, so even an adapter
panic recovered by its caller leaves that owner unusable; panic text is not
converted into a public error. No report/control bytes, capture lease or success are returned from the
failed operation or a later operation on that owner. A commit may have succeeded
before returning an error: reopen requires inspecting the actual durable bytes
under protected exclusive ownership, never resetting to the old in-memory copy.
Restore itself performs compare-and-commit before exposing a usable state.

The real adapter must still prove protected paths/ownership/ACLs, bounded reads,
atomic replacement, sync/durability, crash behavior, the independent primary used
fence, exact expected-byte checks and exclusive single-owner/process locking.
Restoring an old complete private-state backup is not a supported rollback fix.
The test fake models before-write and after-write uncertainty, but proves none
of these native storage properties.

A returned lease or byte copy cannot be recalled by a mutex. A future integration
must recheck authentic current identity, TLS/current-leaf validity, revocation,
profile/grant authority and trusted clock at the actual collection/send edge.
It must cancel and join old collectors/senders, serialize report admission with
terminal disable, and prevent an already-returned copy from being transmitted
after disable or credential cutover. `Close` only invalidates this in-memory owner;
it does not release an adapter lock or cancel/join anything. Receipt publication
also needs the receiver's separately reviewed authenticated durable transaction.
Neither this interface, fake, lease nor caller-supplied clock proves these gates.

## Bounds and verification

The checkpoint's exact typed canonical JSON representation is capped at 768 KiB,
including base64 expansion of its one at-most-520-KiB report, two bounded controls,
three bounded receipts and metadata. Input size is checked before decoding.
Duplicate/unknown/wrong-case keys, alternate JSON spellings, malformed UTF-8,
trailing documents, inconsistent phases/floors/times and mismatched nested wire
bytes are rejected. Returned arrays are independent copies. Errors use a fixed
safe vocabulary and state formatting is redacted.

Pure/fake tests cover maximum snapshot/base64 custody, canonical nested mutation,
used-marker loss, changed original binding, immutable copies, enable-before-capture,
interruption, pacing, exact reopen/renewal retry, receipt binding/time, original
expiry and quality, terminal disable, before/after-write uncertainty, clock/sequence
bounds and concurrent reserve/disable/ack transitions. Race checks establish only
this source's in-process synchronization. No test authorizes or establishes a
native macOS read, protected disk adapter, running service, real sender/receiver,
installation, credential, TCC/privilege change or release acceptance.
