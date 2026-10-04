# Native complete-inventory spool candidate

This is an isolated Linux local-storage implementation. It does not authorize or
perform host inventory collection, enrollment, networking, service installation,
credential changes, or deployment. The current release is unchanged. All tests
use invented rows and temporary directories. This package is not a credential
store; its bounded package data and exact receipts are private plaintext files.

## Public integration contract

`internal/inventorystate` exposes:

- `InitializeNew(dir, bindingSHA256, agentID)` for the enroller only. A missing or
  empty private directory is required. Existing files are never adopted,
  repaired, migrated, or overwritten. A prior lock without a ledger is not new.
- `OpenExisting(dir, bindingSHA256, agentID)` for senders. It never creates a
  missing path, lock, ledger, or fresh sequence domain.
- `ValidateExisting(dir, bindingSHA256, agentID)` for read-only preflight under
  the same exclusive lock. It verifies the entire retained generation but makes
  no writes and removes nothing, including a recognized recovery phase.
- `Allocate(ctx, attemptedAt)` durably reserves the independent sequence before
  any capture. The sequence range is 1 through MaxInt64; exhaustion fails closed.
  `inventorywire.GenerationID(agentID, sequence)` is the only generation-ID
  construction. The UTC attempt time is also the eventual manifest's original
  collection time. Neither retry nor receipt arrival may refresh it.
- `Stage(ctx, allocation, manifestRaw, chunkRaws)` verifies every raw object with
  the strict fullinventory decoders and the complete streaming validator before
  publishing any generation. Exact input payload bytes are preserved inside the
  immutable wire requests, including harmless whitespace. Validation failures
  cannot promote a prefix or a fabricated zero-row inventory.
- `StageFailure(ctx, allocation, reason)` stages one fixed wire failure. The
  allowed reasons are `source_missing`, `source_invalid`, `source_changed`,
  `resource_limit`, and `collection_failed`. It never carries exception text.
- `NextWork()` returns a detached exact begin/append/finalize/failure/abort work
  snapshot. `Body()` returns a copy. It never consumes work or changes timestamps.
- `Acknowledge(work, receiptRaw)` validates the exact request operation, sequence,
  generation, manifest, raw-body SHA-256, and purpose-specific receipt with
  `inventorywire.DecodeReceipt`. Append ordinal/row count, failure time/reason,
  and final collection time must match. Begin start/expiry and subsequent
  receipt chronology are retained; upload acknowledgments cannot fall outside
  the original staging interval. Only then is the cursor durably advanced.
- `StatusWork()` returns an exact purpose-bound status request for the current
  manifest. `ValidateStatus(work, receiptRaw)` additionally checks the retained
  manifest's chunk count and exact accepted row-prefix count. Status does not
  advance the cursor, clear bytes, or refresh the collection time.
- `RequestAbortAfterStatus(work, receiptRaw)` atomically validates the status and
  permits an abort transition only for `expired` or `failed` with no
  `CompletedAt`. The lower-level `RequestAbort()` requires the caller to establish
  those same facts; the sender should use the atomic wrapper. The original generation is retained until its exact
  abort receipt is acknowledged. An expired completed generation still has a
  nonzero completion time; it is not an interrupted collection to discard.
- `SequenceFloor()`, `LastAttemptedAt()`, and `Close()` inspect the floor/original
  latest attempt time and release the lifetime lock. Attempt time survives terminal
  cleanup so restart cannot erase the runtime cooldown.
  All copied `State` handles share one mutex, state, poisoned/closed flag and lock.

The caller computes a canonical lowercase SHA-256 binding over the exact local
configuration, enrollment instance, agent identity, configured origins, fresh
complete-inventory consent/profile, and key/certificate identity. The package
stores that digest and agent ID immutably and compares both on every open.
It does not create credentials or infer permission from an old profile.

The caller owns transport/server identity verification. Receipt consistency is
not authentication. In particular, HTTP-test receipts remain unauthenticated;
this local state machine cannot confer TLS confidentiality or server identity.

## Journal and recovery

There is one small canonical ledger and at most one immutable packed generation.
The packed file contains the exact begin, ordered append, and finalize request
bodies. A ledger cursor identifies the next body. Only one generation can be
allocated or retained at a time; there is no queue of old generations.

Phases are `idle`, `allocated`, `failure`, `ready`, `abort`, and `retiring`:

1. `idle -> allocated` commits the raised sequence floor, generation ID, original
   timestamp, and deterministic `collection_failed` fallback body before capture.
2. A live, unexported allocation permit allows `allocated -> ready` or `failure`.
   Reopening never recreates that permit. After a crash during capture, the sender
   offers the original fallback report; it must not recollect under that ID.
   Calling `NextWork` on a live unfinished allocation also irrevocably revokes its
   collection permit before offering that fallback.
3. `ready` retains all generation bytes while acknowledgments advance the cursor.
   Acknowledgment failure never allows the caller to skip to the next operation.
4. Finalize/abort acknowledgment first commits `retiring` with the exact terminal
   request and server receipt. Only then is the verified generation file removed
   and its directory synced. Finally, an `idle` ledger preserves the floor, original attempt time, and
   last exact terminal request/receipt. A failure acknowledgment goes directly
   to `idle` because it has no generation file.
5. A validated `retiring` state can finish that specific deletion after restart.
   Its absent pack represents already completed cleanup, not permission to reset
   a ready generation. Read-only validation deliberately does not finish cleanup.

Both ledger and pack publication use an exclusively created private temporary,
fsync of its directory to publish an uncertainty marker, complete bounded writes,
file fsync, atomic rename, and directory fsync. All errors poison the shared live
handle. Once a pack has finished writing, cancellation completes its bounded
publication/journal transition rather than introducing a needless split state.
Cancellation after the marker but before complete writing leaves uncertainty.

An unexpected `.ledger.tmp` or `.generation.tmp`, or a published pack beside an
allocated ledger, fails closed as `ErrUncertain`. No open path deletes, promotes,
or resets these artifacts. This conservative blocker intentionally requires a
separately reviewed recovery procedure; this package offers no reset/repair API.
If a complete ledger rename took effect but its final directory fsync returned an
error, a later successful open may verify and use the published sequence/body.
Either outcome retains the floor/pending bytes rather than guessing at success.

A repeated acknowledgment of the most recent operation succeeds only with the
same operation, request identity/digest, and exact original receipt bytes. It is
idempotent across restart and after terminal cleanup. A different receipt for
that operation is refused. Older acknowledgments cannot clear later work.

## Linux protection and privacy

The implementation follows the native telemetry state's tested anchored-FD
pattern: open directories from `/`, reject symlink traversal, retain each
ancestor's identity, use no-follow/nonblocking/close-on-exec file and directory
opens, and recheck ownership, permissions, type, link count, identity, size and
stable content. The leaf directory must be owned by the current effective UID
with exact mode 0700. State, lock, and pack files must be regular, current-UID,
mode 0600, and have one hard link. Trusted root/current-UID ancestors may be
non-writable or sticky. The lock is held for the entire sender lifetime, including
transmission and acknowledgment. A read-only validator also requires that lock.

A removed/replaced lock, ledger, live directory, or retained generation fails
closed. Neither missing state nor changed bindings authorize fresh initialization.
No unrelated file is removed; schema and binding are checked before deciding
anything about temporary artifacts. Existing insecure paths are never chmodded.
A hostile current-UID process or root can replace/rollback the whole private
store between lifetimes; protection against that actor needs an external trust
anchor. This package does not claim one.

Errors contain fixed sanitized text with no OS paths, package rows or binding.
Public `State`, `Allocation`, and `Work` formatting and JSON methods redact
contents. Payloads and state bindings are pointer-backed so even formatting verbs
that bypass custom formatting, such as invalid `%p` on a value, cannot dump raw
package metadata, private binding or retained receipts. Only intentionally
public bounded work/allocation metadata may appear in that fallback. The sole
intentional payload accessor is `Work.Body()`, which returns a selected copy.
Non-Linux builds return `ErrUnsupported` without touching the target path.

## Explicit limits

- 1 allocated/ready/failure/abort generation; no retained old generation packs
- Full pure contract: up to 1024 chunks, each at most 64 KiB raw, manifest at most
  4 KiB, at most 100,000 rows, canonical row bytes at most 32 MiB, and aggregate
  canonical manifest/chunk bytes at most 48 MiB
- Aggregate original raw payloads at most 64 MiB + 4 KiB, independently of the
  canonical-byte budget; whitespace does not bypass the raw limit
- Each complete request respects the separate 72 KiB inventory wire envelope
- Packed generation ceiling: `MaxRawBytes + (1024 + 2) * 1024` bytes, including
  fixed framing and envelopes; the protocol is not silently reduced to 256 rows
- Ledger at most 16 KiB; one exact receipt at most 4 KiB; a retained terminal
  request at most 2 KiB
- Managed spool content ceiling: `MaxPackBytes + 2 * MaxStateBytes`; only one pack
  or pack temporary can exist under normal publication, plus old/new ledger
  and the zero-byte lock. Filesystem allocation-unit overhead is additional.
- Open validates the whole bounded pack once; work selection uses the retained
  immutable bytes and checks file identity/stability. Caller-owned source/chunk
  buffers and construction/validation memory are additional bounded working memory,
  not an unbounded process-global cache.

## Synthetic verification

Tests cover exact payload/receipt restart retries over 513 rows, no missing or
duplicate chunks, zero rows, source-age preservation, fixed failure reports,
1024 chunks including an exactly 64 KiB raw chunk, explicit byte limits,
changed/unknown receipt fields, append counts, final collection times, status
prefix consistency, private modes/symlinks/hardlinks/FIFOs, lifetime locks,
missing/replaced state, refusal preserving unrelated/temporary bytes, copy aliasing,
concurrent snapshot reads, MaxInt64 exhaustion, allocation and pack/ledger
marker/file/rename/directory-sync faults, cancellation phases, and acknowledged
retirement recovery/cleanup. Darwin and Windows checks are cross-builds only;
they do not establish native runtime/service acceptance.

Run with Go 1.27.1 on PATH and the locked dependencies already cached:

```sh
GOPROXY=off GOSUMDB=off go test ./internal/inventorystate
GOPROXY=off GOSUMDB=off go test -race ./internal/inventorystate
```

No synthetic result establishes real dpkg capture, installer lifecycle, systemd
restart/reboot, transport deployment, or data-directory migration acceptance.
