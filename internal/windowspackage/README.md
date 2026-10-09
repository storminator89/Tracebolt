# Fresh Windows package payload (source candidate)

`Preflight(ctx)` is read-only. `Provision(ctx, payload, manifest, publicBootstrap)`
performs only the fresh create-only file phase. The caller must validate the public
bootstrap with `enrollmentclient.ParseBootstrap` first, obtain the actual local
setup approval, and invoke the existing fresh disabled-service coordinator next.
This package never accepts an invitation, enrolls, writes grants, changes SCM,
repairs an ACL, adopts an object, overwrites an object, retries a mutation, or
removes even a partial creation. Native use requires separate authorization.

The embedded `Manifest` schema is `tracebolt.windows-setup-package.v1` with exact
`schemaVersion`, `version`, `sourceCommit`, `architecture`, and `sha256` fields.
Version is a v-prefixed strict SemVer (at most 80 ASCII bytes), sourceCommit is
lowercase full 40-hex, and SHA256 is lowercase full 64-hex. `ParseManifest` rejects
unknown/duplicated/missing/trailing fields. `Validate` enforces a 128 MiB payload
cap, its digest, PE32+ executable/image sections, and exact amd64/arm64 machine.
Provenance binds package bytes, not a publisher signature or release approval.
The runtime architecture must also match before writes.

Only machine KnownFolders define paths. Every ancestor is pinned through the
physical local-volume handle and component-relative no-reparse opens. Native
NTFS/persistent ACLs, trusted owners, replacement-capable ACL rights, final names,
case-insensitive directories, object types and IDs are checked and rechecked.
The resolved ProgramData shared ancestor alone admits unrelated add-file/EA/
attribute rights; DELETE, DELETE_CHILD, generic write/all, WRITE_DAC and
WRITE_OWNER remain forbidden. This is path-integrity admission, not proof of the
future LocalService token's effective access. No existing ACL is changed.

Both Tracebolt app roots and the fixed SCM service must be absent before the first
write. Only direct-child-not-found counts as filesystem absence. Existing, denied,
reparse, wrong-type or uncertain objects fail closed. A competing creator can
cause a retained partial installation, never adoption or replacement.

Created objects receive atomic, explicit protected ACLs:

- ProgramFiles/Tracebolt and the service image: SYSTEM/Administrators full control;
  LocalService read and execute
- ProgramData/Tracebolt: SYSTEM/Administrators full control; LocalService directory
  list, read-attributes, traverse, read-control and synchronization, no writes
- ProgramData/Tracebolt/windows-setup, bootstrap.json and payload-manifest.json:
  SYSTEM/Administrators only

The separate windows-agent runtime, installer and extension stores remain for
existing protected-store APIs to create with their identity-specific policies.
The public bootstrap is bounded to 64 KiB. Each file is flushed, hashed back,
checked for single-link/default-stream-only identity, and reopened by its pinned
parent. Payload bytes are snapshotted before validation to prevent a caller-owned
buffer changing between hash validation and write.

Keep `Result` until the coordinator finishes and then call `Close`. It releases
pins only. The bootstrap content pin alone is released after final verification
so the existing exclusive `ReadProtectedInstaller` reader can acquire it; its
protected parent remains pinned. Executable, provenance and all directory pins
remain held. `Retained` indicates a create was attempted, including an uncertain
failure; an error never authorizes a retry or cleanup. `Code(err)` exposes finite
classifications without native paths/error strings.

Portable injected tests cover manifest/PE bounds, exact sequencing, every
create/write/final-verification failure, cancellation, retained partial results,
input snapshots, and pin lifetime. Windows tests only build in-memory descriptors
and inspect request-independent values; they do not inspect or mutate host ACLs,
SCM, keys, grants or files. Cross-builds are not native installation acceptance.
