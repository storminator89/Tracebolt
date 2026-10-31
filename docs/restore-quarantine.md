# Deny-only manager restore quarantine (TB-16 source slice)

This source adds an **explicit, voluntary startup quarantine**, not a backup or
restore implementation. It does not close [TB-16 / #143](https://github.com/storminator89/Tracebolt/issues/143).
An internally valid old snapshot can contain approvals revoked later, unconsumed
copies of already-used actions/replay floors, or consent withdrawn later. A hash
proves neither freshness nor permission to reuse that authority.

## What this slice enforces

`manager-restore-quarantine mark` exclusively creates the fixed nonsecret
`restore-quarantine` marker in an **existing** protected manager state directory.
It syncs the marker and directory before reporting `created:true`. It never
creates a directory, copies backup files, opens SQLite, changes ownership/modes,
creates credentials, contacts an endpoint, or changes existing state bytes.

The updated `lan-manager` checks that directory before loading credential
material, opening stores, initializing schemas, creating listeners or admitting
background workers. Its internal preparation entry point repeats the check.
**Any object** at the marker path denies startup: valid, malformed, empty or
partially written file, directory, FIFO, hardlink, symlink or dangling symlink.
No marker content, age, checksum or purported approval can release it. Errors
inspecting the protected state path also fail closed.

There is deliberately **no release, clear, reset, rearm, resume or automatic
reauthorization command**. Quarantined state remains unavailable until an
independently reviewed reconciliation/release implementation exists. Do not
remove the marker to make an old snapshot run. Do not point a development manager
or another tool at the quarantined state to bypass this guard.

### Boundaries that remain open

- Only this updated `lan-manager` startup is guarded. Older binaries, direct
  storage APIs, separate setup/maintenance tools and filesystem administrators
  are not fenced by the marker.
- Marking is **not a live transition or process lock**. An active manager, or a
  concurrent startup already past its check, can continue admitted work. Stop all
  writers and disable **all automatic/concurrent starts** before marking; keep
  them disabled through confirmed marker establishment and inspection.
- A raw whole-volume/directory rollback can remove the marker along with newer
  revocations. Missing marker state is **not** proof of current authority. This
  local mechanism cannot detect an unannounced replacement with an old complete
  snapshot; it requires deliberate restore handling.
- Marker presence is not a backup manifest, integrity/consistency check, schema
  compatibility decision, current revocation/consent source, monotonic floor
  anchor, audit trail, RTO/RPO measurement or native restore acceptance.
- This tool does not provide an independent freshness anchor or authorize its
  provisioning. Missing current authority evidence must keep recovery stopped;
  do not manufacture a new identity, erase used state or infer consent.
- The native CLI is built separately. Its inclusion in an existing published
  image/package is not established by this source change.

## Source-only operational contract

Follow [installation](installation.md#10-stop-back-up-restore-update-uninstall)
for the complete private snapshot, separate credential custody and required
host/exposure approvals. The commands below are a contract for a separately
approved isolated recovery, **not authorization to restore a real system**.

1. Select the exact reviewed manager build/profile, intended existing nonroot
   runtime UID and original state target. Preserve every retained identity,
   revocation, consumed-action/replay floor, consent receipt and sidecar.
2. Stop every writer; disable supervisors, scheduled work and concurrent starts.
   Keep endpoints and all outbound dispatch disconnected. Do not change host
   security settings or credentials just to make recovery proceed.
3. Materialize the separately authorized complete backup in its protected target
   using the site's approved offline procedure. No backup-copy command is shipped
   here. Do not start any manager, setup command or helper against that target.
4. From the matching source, with the pinned Go toolchain available, build only:

   ```sh
   go build -buildvcs=false -trimpath -o bin/lan-manager ./cmd/lan-manager
   go build -buildvcs=false -trimpath -o bin/manager-restore-quarantine ./cmd/manager-restore-quarantine
   ```

5. As the original intended runtime UID in the intended filesystem namespace,
   explicitly mark the **existing** target. Substitute the locally reviewed UID
   and absolute target; the example does not select a host or grant permission:

   ```sh
   ./bin/manager-restore-quarantine mark \
     --state-directory /srv/tracebolt/state \
     --runtime-uid 65532 \
     --ack-stopped-writers
   ./bin/manager-restore-quarantine status \
     --state-directory /srv/tracebolt/state \
     --runtime-uid 65532
   ```

`--ack-stopped-writers` includes stopped automatic/concurrent starts. The tool
requires Linux, the explicit matching nonroot effective UID, absolute canonical
paths, a private runtime-owned direct directory and protected non-symlink
ancestors. It rejects insecure paths rather than repairing them. Supply **paths
only**, never invitation values, passwords, verifier strings, key contents or
backup bytes. Diagnostics are static JSON and do not echo arguments or raw errors.

A successful new mark reports schema `tracebolt.restore-quarantine-status.v1`,
`code:"quarantined"`, `markerPresent:true` and `created:true`. Only that new-write
success confirms marker/directory sync. Repeated mark/status can report presence
but do not claim past durability, freshness or reconciliation. Every report keeps
`freshnessVerified:false` and `authorityReleased:false`.

A missing, mistyped or inaccessible CLI target fails instead of creating it.
Status on an existing unmarked directory reports
`marker_absent_not_freshness_proof`; `ok:true` there means only that this inspection
succeeded. It is never approval to resume a restore. Invalid arguments, wrong UID,
path failures or unconfirmed writes exit nonzero, with `markerPresent:null`
where presence was not established (never a false absence claim). Preserve partial marker/state
on any write/sync failure, keep writers stopped and inspect locally; do not delete,
overwrite or blindly retry an uncertain write.

## Remaining full backup/recovery contract

A future complete implementation must capture all manager state consistently,
not just one enrollment database. In this revision that includes `agents.db`,
`operator.db`, the configured Linux/Windows/macOS enrollment domains and every
present SQLite `-wal`, `-shm` and `-journal`, profile/enrollment mode markers,
settings/fences and any separately configured action/update/MSI/package ledgers
or custody paths. The complete protected configuration and referenced external
state must be inventoried from the actual selected profile; this list is not an
exhaustive copy allowlist. Secrets remain separately protected under custodian
control; a public report must not contain backup data or secret values.

The manifest needs exact schema/build/profile/UID/config/issuer/immutable-instance
bindings and bounded file integrity metadata, with interrupted/partial capture
rejected. It must distinguish **integrity** from independently authenticated
**freshness**. A release mechanism needs current revocation, action-consumption,
replay/renewal and consent comparisons against a trusted anchor outside the
rollback domain, preserving higher floors and original identity/expiry. Missing,
stale, inconsistent or unavailable evidence must not release quarantine. A new
identity/authorization is a separate reviewed workflow, never an implicit reset.

Mandatory remaining acceptance includes the same old snapshot after revocation,
action consumption **and** consent withdrawal; missing sidecars; wrong issuer,
schema or UID; partial/corrupt snapshots; crash/disk-full at every transition;
and empty-host isolated drills with measured RTO/RPO. Neither old source tests,
a matching hash nor this startup marker satisfies those gates.

## Verification classification

New source fixtures cover deny-only file/object behavior, retained invented old
approval/consumption/consent bytes, protected/missing/symlink paths, exclusive
concurrent creation, explicit acknowledgement/UID and diagnostic redaction. The
manager tests use deliberately missing credential files and invalid material to
verify quarantine wins before loading or preparing anything. They do not create
credentials, perform a real restore, call a provider, start listeners or modify a
host service/security setting.

Record exact final revision, platform and actual pass/fail/not-run results before
publication. Native Linux/Docker recovery, cross-platform endpoint behavior,
external-anchor reconciliation, full product acceptance and #143 closure remain
separate gates. Do not count merely written tests as passed.
