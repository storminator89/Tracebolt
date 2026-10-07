# Windows protected local-state source candidate

This package is a **source/fixture candidate**, not native service acceptance.
No test creates a service, identity, key, file ACL, persistent store or host
permission. Windows-specific tests only convert in-memory security descriptors
and check ABI layout. Running a real create/write/lifecycle gate requires
separate action-time approval on a disposable Windows target.

## API and fail-closed contract

- `Open(path, Options)` opens an existing store. `Create: true` creates only a
  new final directory; parents must already exist. Existing empty directories
  are never adopted. Failure leaves evidence in place, without cleanup/reset.
- `Options` binds `RuntimeSID`, `InstallerOnly`, file `Names`, child
  `Directories`, `LockName`, `TempName`, and `MaxBytes` permanently to a store.
  Names are canonical lowercase single components, 1–32 files and 0–4 children.
  The lock, temp, file and child names are disjoint. `MaxBytes` is in
  `(0, 16 MiB]`, per data file. The manifest is independently limited to 64 KiB.
- Runtime mode requires one canonical service SID of the form
  `S-1-5-80-A-B-C-D-E`. Explicit `InstallerOnly: true` instead requires an empty
  `RuntimeSID` and permits only SYSTEM and Administrators.
- `Read`, `Write`, `Verify`, `Entries`, `CreateDirectoryStore`, and `Close` are
  serialized. Storage/integrity failures permanently poison the handle. Invalid
  caller input is rejected without poisoning otherwise healthy state.
- `fs.ErrNotExist` from existing `Open` means only the final directory did not
  exist. Ancestor loss, missing lock/temp, malformed ledger and missing used data
  never mean freshness. `Read` returns that sentinel only for a configured name
  durably recorded as never initialized. Writing zero bytes still initializes it.
- `Entries` returns sorted initialized data/child names, omitting metadata.
  `CreateDirectoryStore(name, Options{Create:true, ...})` initializes and records a
  new child with the same security policy. Its identity and ACL stay bound into
  the parent, while its own contents may change. Creation interrupted before the
  parent's final manifest commit blocks that parent; there is no auto-adoption.
- `ReadProtected(path, runtimeSID, private, maxBytes)` is a non-mutating standalone
  file read. `ReadProtectedInstaller` is its explicit admin-only equivalent.
  Both require a protected containing directory, pinned ancestors, protected
  file, one link, no alternate streams, and bounded stable reads. `private=false`
  does not relax protection. These helpers do **not** consult a store manifest
  or establish persistent freshness; use `Store` for that purpose.

## Native boundary

Canonical uppercase-drive, ASCII paths up to 240 characters are accepted.
UNC/network, relative/root-relative, device/extended syntax, environment
expansion, DOS reserved names, 8.3 aliases, alternate-stream syntax, empty/dot
components, trailing dot/space and noncanonical resolved case are rejected.
Only fixed local NTFS volumes with persistent ACLs are supported. SUBST and
unrecognized DOS-device mappings are rejected. Every directory must support
`FileCaseSensitiveInformation` and have that flag disabled; unsupported systems
fail closed. There is no permissions or path fallback.

The native implementation resolves the drive to a local volume device, then uses
`NtCreateFile` with one relative component per pinned directory handle,
`OBJ_DONT_REPARSE` and `FILE_OPEN_REPARSE_POINT`. Ancestors stay open without
`FILE_SHARE_DELETE`. Every operation rechecks their IDs and normalized paths.
Ancestors need not have the store's exact DACL; they are pinned against rename
and checked for type, reparse and case-sensitive status. Store roots, tracked
children and regular files must satisfy the exact protected policy.

Protected objects must have an explicit protected nondefault DACL with exactly
three allow ACEs (runtime service SID, SYSTEM, Administrators), or exactly two in
installer-only mode. Each ACE is non-inherited/nonconditional full file access.
No other ACE, owner, principal, inherited ACE, null/absent DACL or generic-access
mask is accepted. The owner must be one of those trusted principals. LocalService
(`S-1-5-19`) is never an accepted owner or ACE: its shared identity must not obtain
implicit owner `WRITE_DAC` authority over another service's state.

Creation chooses SYSTEM if it is the token user; otherwise an owner-enabled,
non-deny-only service SID or Administrators group actually present in the
effective token. SERVICE_SID_TYPE_UNRESTRICTED supplies `SE_GROUP_OWNER`, and
RESTRICTED includes UNRESTRICTED. No token/privilege/owner changes are attempted.
The new object's explicit descriptor is supplied atomically with creation. If
that token cannot assign a trusted owner, creation fails rather than granting
extra authority.

Regular files use exclusive handles, require one hard link, and reject reparse
points and alternate data streams. Reads are size-bounded, repeated and compared,
then revalidated by handle. Directory enumeration rejects unknown entries.
The durable lock file is opened exclusively and range-locked; an already-used
lock is never recreated. Store formatting and errors never include file bytes,
private keys, invitation input, raw native paths or raw OS error arguments.

## Write transaction and limits

The exclusive lock contains a bounded canonical, checksummed manifest binding
schema, root/lock/temp IDs, initialized names, content hashes and generation.
A write durably records `pending` first. It then rewrites the existing empty temp,
flushes it, verifies its bytes, renames it relative to the pinned root with
`NtSetInformationFile(FileRenameInformation)`, flushes the renamed handle,
creates and flushes a fresh protected empty temp, and commits the new manifest.
A partial manifest, pending transaction, stale identity/hash, missing temp,
extra file or interrupted child initialization is an integrity failure. There
is intentionally no best-effort recovery, counter reset, deletion, repair or
re-enrollment API.

This protects against untrusted pathname substitution and accidental/partial
state loss, within Windows' access-control model. SYSTEM, Administrators and the
authorized service identity are trusted. It does not defend against a hostile
administrator/kernel, complete-volume rollback, replay of a complete valid
snapshot, a compromised authorized service, privileged offline edits, or a disk
controller that lies about flush completion. File `FlushFileBuffers` and
write-through handles are used, but arbitrary storage stacks' power-loss and
directory-entry ordering are **not** claimed as verified. A separate approved
native crash/power-loss gate is required before stronger durability claims.

All source checks, in-memory failure injection, cross-compilation and ABI checks
must be reported separately from actual Windows file, service, enrollment,
network, key-creation and reboot lifecycle acceptance.

## Official API references

- [NtCreateFile: relative RootDirectory, sharing and no-reparse options](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
- [FILE_RENAME_INFORMATION: native relative rename ABI and replacement](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
- [FlushFileBuffers: access and storage flushing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [GetSecurityInfo: handle-based security descriptors](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
- [Security descriptors for new objects: protected DACL inheritance](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors-for-new-objects)
- [SERVICE_SID_INFO: service SID owner attributes](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [CreatePrivateObjectSecurityEx: creation owner eligibility](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createprivateobjectsecurityex)
- [FILE_ID_INFO: volume and file identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)
- [FILE_ID_BOTH_DIR_INFO: bounded enumeration ABI](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_both_dir_info)
- [FILE_STREAM_INFO: alternate-stream enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_stream_info)
- [FILE_CASE_SENSITIVE_INFORMATION: directory case-sensitivity flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_case_sensitive_information)
