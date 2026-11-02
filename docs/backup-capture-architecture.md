# TB-16: minimal stopped-writer capture architecture

This is a **proposed integration design**, not an implemented capture/fence or
restore feature. It follows the [manifest integrity contract](backup-manifest-contract.md).
Implemented source increments are the shared pure `packagecontroller.ParseConfig`
boundary used by `Load`/`Initialize`, and optional
[same-directory manager runtime ownership](manager-writer-exclusion.md) with
HTTP-drain-safe lifetime. No snapshot or complete cross-domain capture fence is
implemented, and #143 remains open.

## Why not call existing loaders or walk one directory?

`cmd/lan-manager.prepareWithApplicationChecks` opens `agents.db`, enrollment
domains and `operator.db`, prepares mode/profile markers and constructs optional
controllers. These are not an inventory interface. In particular:

- `packagecontroller.Load` reads the separate `StateFile` and `PrivateKeyFile`.
  `packageupdatestore.OpenExisting` opens read/write, starts a transaction and
  commits `active=1`; even opening this existing store changes durable state.
- Action/update/software/MSI loaders open enrollment-ledger domains.
  `windowsmanagedmsimanager.LoadRegistry` selects singleton versus versioned
  fleet configurations and opens singleton/catalogue spool/artifact state.
- Enrollment, alarm and application-check configurations are separate CLI
  inputs; alarm configuration may reference an external bearer-token file.
- State directories can contain credential-bearing saved AI/alarm settings.
  Treating all unknown files as ordinary nonsecret state would be unsafe.

Therefore neither `prepare`/`Load` nor a recursive `StateDirectory` walk proves
complete, side-effect-free inventory. Per-database locks and the package-store
flock are not a common capture transaction. The existing restore-quarantine
marker remains a voluntary startup guard, not a live-writer fence.

## 1. One pure, profile-bound dependency graph

Each domain must expose its **existing strict parser**, reused by the real
runtime loader, without opening credentials, ledgers or native/provider APIs.
The offline planner accepts exact protected configuration bytes and returns
descriptors, not hydrated `Manager`/`Store` objects. Unknown versions, absent
required descriptors or unsupported enabled domains stop planning; there is no
"state-directory-only" fallback.

| Domain / existing integration point | Required dependency inventory | State of pure boundary |
| --- | --- | --- |
| `lanconfig.Parse`, `cmd/lan-manager` CLI inputs | exact LAN/enrollment/alarm/application-check inputs; TLS/auth/trust files; manager state root; artifact/UI binding | LAN parser exists; complete graph pending |
| `enrollmentconfig.Load` / mode preparation | exact selected Linux/Windows/macOS domains, issuer/root/bootstrap material, profile markers and each DB/sidecar | pending; do not invoke mode preparation |
| `alarmdelivery.Load`, `applicationcheck.Load` | external config plus applicable bearer reference; saved settings/fences under state | pending |
| `actionmanager.Load`, `windowsactionmanager.Load` | exact domain config/key plus associated enrollment-ledger binding | pending |
| `windowsupdatemanager`, `windowssoftwaremanager` registries | every enabled registry/member config, key and setup receipt, version-specific retained state | pending |
| `windowsmanagedmsimanager.LoadRegistry` | singleton/fleet/catalogue configs, receipts, keys, bounded slots/custody/artifact ledgers | pending; all supported versions must be covered explicitly |
| `packagecontroller.Load` and `Initialize` | exact config, external `StateFile`, separate `PrivateKeyFile`, original binding | **shared `ParseConfig` integrated**; no operational admission or complete inventory claim |

Freeze a canonical graph only after validating the selected profile, exact raw
config digests, original instance/issuer, expected schema identifiers, build/UI
artifacts and runtime UID/GID. Derive metadata from actual selected bytes, not
manifest declarations. Every DB has explicit present/absent `-wal`, `-shm` and
`-journal` descriptors. Retained disabled-domain state is not silently dropped.
Per-domain classification must identify credential-bearing objects and separate
custody; unknown file/type/classification fails rather than guessing.

## 2. A common lifetime writer fence, before capture exists

The source now supplies only the same-directory cooperating `lan-manager` part.
Its ordinary-startup compatibility fallback on unavailable locking must **not**
be used by capture. The complete multi-root/standalone-writer protocol below
remains a proposal.

Use one fixed, protected coordination object per **mutable authority root**,
derived from the frozen graph rather than a new runtime setting. Both a runtime
writer and a future offline capture require exclusive, nonblocking ownership of
the complete graph's lock set. Shared external ledgers must map to the same
coordination object even when manager roots differ. Overlapping roots/aliases
must not manufacture independent locks.

Canonical root ownership and nested-root overlap rejection must be specified
and fixture-tested before implementing this lease protocol; do not assume that
locking two different directory paths coordinates their overlapping descendants.

- Acquire via protected directory descriptors; reject links, multiple links,
  wrong owner/mode, replaced coordination objects/ancestors and unsupported
  filesystems. Use a deterministic object-identity order, release partial lock
  sets on conflict and fail; no background waits, TTL unlock or "repair".
- After acquisition, reread/revalidate the frozen descriptor graph and config
  hashes. Any changed/new dependency aborts. Do not expand the lock set after
  opening stores or silently retry a mutated operation.
- `lan-manager` must acquire ownership **before its first store/schema/worker
  preparation** and retain it through worker shutdown, all store closes and
  package-session settlement. Existing quarantine checks still precede authority
  use; fence failure never removes or bypasses quarantine.
- Standalone manager writers, initially `package-manager-init` and manager-side
  `action-setup apply`, must acquire the same applicable ownership before writes.
  In-process API/setup/maintenance work uses the runtime's already-held lease;
  it must not reacquire a conflicting independent lease.
- Existing package-store `active=1`, uncertainty and one-use floors remain
  authoritative. An OS lock released after crash is **not** permission to clear
  those records, recover a journal, reset state or reopen uncertain authority.

This only excludes cooperating, verified compatible writers. Old binaries,
manual DB tools, administrator writes and raw volume rollback do not obey it.
Before enabling capture, qualify every supported writer entry point and
artifact. A missing/unlocked coordination object does not prove freshness or
that an old/noncooperating writer is absent.

Root-owned configuration/secret custody is a separate boundary: an unprivileged
manager must not gain permission to create lock files in credential directories.
A reviewed custodian snapshot/freeze protocol must supply stable selected
objects, or those profiles remain unsupported for capture. Mere repeated hashes
or a caller boolean do not prove a cross-custody atomic snapshot.

## 3. Only then add capture, tied to `backupmanifest.Verify`

With the full graph frozen, all participating writer leases held and the
custodian snapshot established, open every source using protected descriptors.
Preserve and record actual UID/GID/modes and original binding metadata; reject
aliasing, special files, changed objects, unbounded input and incomplete rosters.
Schema/internal SQLite validity is a separate exact-build gate, not a declaration
accepted from the manifest. Do not invoke ordinary store startup as validation.

Write only into a new protected staging area; never overwrite a backup or source.
Credential objects stay in their separate reviewed custody. Hash while copying,
then run the existing verifier against the independently frozen expected graph
and freshly opened captured streams. Separately custodied generations must be
sealed durably and referenced exactly before publishing the final manifest;
there is no claim of an atomic rename across custody domains/filesystems. Sync
capture outputs, manifest and containing directories before a create-only
same-filesystem atomic publication of that completed capture, then sync the
destination parent **after** publication before durably issuing/reporting its
completed receipt. Publication/receipt sync failure is an uncertain outcome,
never automatic overwrite, rollback or success. Interrupted or disk-full stages
must never appear as completed captures. The independently
protected capture receipt must bind exact final manifest bytes; receipt custody
and crash reconciliation must be designed before adding a public capture CLI.

This produces integrity/consistency evidence only within the qualified frozen
capture boundary. It creates no restore destination, listener, credential/grant,
current-authority anchor or quarantine-release command.

## Small, independently checkable implementation order

1. **This step:** extract package-controller parsing and reuse it in both real
   consumers. Inert tests accept valid config with absent key/state dependencies,
   reject malformed/oversized config and preserve existing admission semantics.
2. Extract the remaining domain parsers; add exact dependency fixtures for every
   supported profile/version, including external state and secret-containing
   settings. Unsupported/unknown domains must fail before any store/key read.
3. Implement protected lease mechanics and integrate all supported writer entry
   points. Same-directory runtime ownership is implemented; the common complete
   capture lease is not. Non-GUI subprocess tests must prove writer↔writer/capture exclusion,
   startup/shutdown ordering, partial-acquisition cleanup, alias/replacement
   rejection and crash release **without** clearing durable uncertainty.
4. Add custodian freeze and descriptor snapshot/atomic publication. Non-GUI
   fault-injection fixtures must cover config/dependency changes, missing/new
   sidecars, retained domains, credentials separation and every write/sync/rename
   interruption. No successful partial publication or source mutation is allowed.
5. Separately authorize native isolated capture/restore drills on qualified
   filesystems/artifacts. Measure RTO/RPO. Independently implement and test the
   outside-rollback-domain revocation/action/replay/renewal/consent anchor and
   reviewed reconciliation/release; full #143 cannot close without those gates.

Steps 2–4 are remaining engineering work, not an authorization denial. Actual
host/custody changes and native drills remain outside this source-only work.
No source test establishes that a real manager is stopped or recoverable.
