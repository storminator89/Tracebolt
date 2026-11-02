# Offline backup manifest integrity contract (TB-16 source slice)

`internal/backupmanifest` implements a bounded **manifest-verification part** of
the planned PR 1 in [TB-16 / #143](https://github.com/storminator89/Tracebolt/issues/143).
It is a source library, **not a backup CLI, a complete snapshot implementation or
a restore/release workflow**. No manager startup or other production call site
uses it. #143 remains open.

## Exact contract

`Verify(context, rawManifest, independentlyExpected, readOnlyObjectStreams)`
checks all of the following before reading any object stream:

- A maximum 256 KiB v1 JSON manifest, with exact required keys at every level;
  duplicate, unknown, case-alias, missing, null, partial and trailing values fail.
- SHA-256 of the **exact manifest bytes**, matched to an independently protected
  capture receipt. A digest copied from the same untrusted backup is not that
  receipt. Receipt authentication and custody are the caller's responsibility.
- Exact equality of the declared manager build-artifact, protected configuration,
  issuer and immutable-instance digests, transport profile, nonroot runtime UID
  and GID with the independent recovery plan. The eventual capture adapter must
  derive these declarations from the actual selected bytes; `Verify` does not
  derive them or prove their semantic association with individual object streams.
- An independently expected, closed inventory of at most 32 databases and 1,024
  objects. Each database has an exact expected schema identifier and explicit
  present/absent entries for `-wal`, `-shm` and `-journal`. A declared present
  sidecar must be an inventoried sidecar object; an absent one must not appear.
  Duplicate objects/databases, unlinked sidecars and database-kind objects not
  listed as databases fail. The full expected roster and actual stream roster
  must agree; omitted or extra objects fail.

Every stream must then have exactly its declared length and SHA-256. Processing
uses a 32 KiB buffer, limits one object to 64 GiB and all objects to 256 GiB,
rejects short/extra/corrupt/error/no-progress streams, and checks cancellation
between reads and before returning success. An arbitrary blocking `io.Reader`
cannot be interrupted by context alone: the eventual storage adapter must own
its read deadlines/cancellation. Readers are not closed or retained.

Object names are bounded lowercase logical keys, **not filesystem paths**.
Kinds distinguish database, sidecar, other state, configuration and separately
protected credential objects. Credential streams remain under their custodian's
controls; this contract neither bundles them with ordinary state nor provides
encryption, secret provisioning, logs or public diagnostic exports. All errors
are fixed strings without names, raw data, digests or underlying reader errors.
The manifest and receipt are themselves private security/telemetry metadata.

The capture-mode label `stopped-writers-offline-v1` admits only that planned
capture contract. It **cannot prove** that writers were stopped, that capture
was atomic, or that a database/schema is internally valid. Schema identifiers
are compared, not extracted from SQLite. Likewise, the caller's expected roster
must actually include every configured external ledger, custody path, profile
marker, fence, setting and secret: this library cannot discover an omission
shared by both the manifest and its expected inventory. A successful comparison
must not be described as complete consistency, permissions or migration proof.

## Integrity is never freshness

An authentic old capture receipt and its old files can pass every integrity
check. No time, hash, schema match or success result here authenticates *current*
revocations, consumed actions, replay/renewal floors or consent. The library has
no release, reset, rearm, migration or authority-writing API; it does not read or
remove the existing [deny-only quarantine](restore-quarantine.md).

Keep restored state quarantined and all writers/automatic starts disabled.
Missing independent current-authority evidence still forbids reconnecting
endpoints or releasing quarantine. Never manufacture freshness by accepting
the old receipt as an external monotonicity anchor.

## Next integration steps and remaining gates

The concrete [stopped-writer/inventory architecture](backup-capture-architecture.md)
maps existing loader boundaries, writer entry points and independently testable
integration steps. The package-controller pure parser is now reused by its real
load/init paths; complete inventory and the common fence remain unimplemented.
The optional [manager runtime ownership guard](manager-writer-exclusion.md) now
excludes another cooperating updated same-root manager where locking is
available, but is not the complete capture fence.

1. Inventory the **actual selected manager configuration**, including externally
   configured action/package/update/MSI custody, all enrollment domains,
   `agents.db`, `operator.db`, sidecars, markers and optional settings/fences.
   Freeze that full inventory and independently protected receipt under a
   reviewed stopped-writer capture transaction. This source does not supply an
   inventory generator, writer fence, atomic copier or receipt signer.
2. Implement separately reviewed protected-descriptor storage adapters and an
   atomic capture/materialization protocol. Preserve private UID/GID/modes,
   reject links/aliases/changed objects, verify real schema/build compatibility
   and ensure crash/disk-full outcomes remain quarantined. Never interpret
   logical object keys as trusted destination paths. Do not add a convenience
   auto-discovery fallback when the expected roster or receipt is unavailable.
3. Specify and implement an independently authenticated freshness/monotonicity
   anchor **outside the rollback domain**, plus revocation, action-consumption,
   replay/renewal and consent reconciliation. Preserve higher floors and original
   identity/expiry; uncertainty keeps quarantine. Only a separately reviewed
   release transaction may make authority usable again.
4. Perform separately authorized isolated native old-snapshot, interruption,
   corruption, missing-sidecar, wrong issuer/schema/UID and empty-host drills,
   including the same snapshot after revocation, action use **and** consent
   withdrawal. Measure RTO/RPO. Source/stream fixtures are not these drills.

No live backup/restore, database opening, credentials, endpoint/provider calls,
listeners, host/security changes, GUI tests or release are required or performed
by this source slice. Record the exact revision, platform and actually executed
checks separately; neither written tests nor this contract closes #143.
