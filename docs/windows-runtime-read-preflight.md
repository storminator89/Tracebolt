# Windows executable runtime-read preflight

This correction is part of the fixed Windows basic-service source candidate.
It does not install a service, repair permissions, create a token or endpoint
identity, or establish native service acceptance.

## Why owner/writer trust was insufficient

An executable and its ancestors can be owned by SYSTEM with only SYSTEM and
Administrators access. That protects the bytes against an ordinary writer, but
an elevated installer's successful read does not show that LocalService can load
the image or read the ancestor descriptors during runtime self-validation.

The held-handle path check therefore applies two independent requirements:

- Existing owner, writer, reparse-point, fixed-drive, hard-link and path-locking
  checks are unchanged. Only SYSTEM, Administrators or TrustedInstaller may own
  or hold the checked replacement-capable rights.
- Effective ordinary allow ACEs naming `S-1-5-19` (LocalService) must together
  cover the required runtime file rights. Other allow trustees do not contribute.

This account-specific grant covers the public executable and ancestors only.
It neither grants LocalService access to private state nor replaces the separate
service-specific SID protection of enrollment and sender state.

## Exact finite DACL policy

The executable requires `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`, mask
`0x001200a9`: read data, read extended attributes, read attributes, execute,
`READ_CONTROL` and `SYNCHRONIZE`.

Each ancestor, including the drive root, requires mask `0x001200a0`:
`READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE`. Runtime
self-validation opens ancestors to read their descriptors and attributes.
Directory listing is not required. The policy deliberately requires traverse
rather than depending on `SeChangeNotifyPrivilege` bypass behavior.

The implementation maps generic rights using the Windows file-object mapping
before checking allow/deny intersections. A generic-write deny also denies
`READ_CONTROL` and `SYNCHRONIZE`, so it can defeat a read request even though it
looks like a write-only restriction. Bare data-write denial does not do that.
Microsoft documents these [generic file mappings and overlapping deny
rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
and the [individual file/directory rights, including
traverse](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants).

In this policy:

- One or multiple LocalService-specific allow ACEs may supply the required bits.
  An inherited effective allow is counted; an inherit-only allow is not.
- Any effective ordinary deny intersecting required rights causes refusal,
  regardless of its trustee and position in the DACL. This deliberately rejects
  some configurations Windows might allow: the future token's groups and logon
  SID are not inferred, and an allow-before-deny ordering is not used as proof.
- Object-specific, callback and other unsupported effective ACE types fail the
  existing trust check. They are not misread as ordinary allow/deny structures.
  Inherit-only ACEs do not affect the current object.
- NULL DACLs, unsafe owners and unrelated write/replacement grants still fail.
  An apparently sufficient LocalService read grant cannot hide an unsafe writer.

Microsoft's [ACE flag
definition](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header)
distinguishes inherited effective entries from inherit-only entries. Windows
[access checking](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
normally uses token trustees and ordered ACE evaluation; this deliberately
stricter source policy does not claim to reproduce that evaluation.

## Where refusal occurs

The check runs as part of `VerifyExecutable`, on the descriptors associated with
the same handles held through the executable digest:

- `Plan` rejects missing or denied grants before an install plan is returned.
- `ApplyInstall` repeats the check before service creation, catching changes
  since planning.
- `InspectOwned` repeats it before the coordinator's stopped-service enrollment
  admission and `ClaimOnly` operation.
- `ApplyStart` repeats it before requesting start.
- Runtime installation validation repeats it under the real service process.

Missing account grants or effective ordinary deny conflicts return
`ErrRuntimeReadAccess`. Unsafe ownership, writes or unsupported effective ACL
forms remain `ErrUnsafePath`. No branch changes an ACL, adds group membership,
impersonates LocalService, logs on a service account or falls back to the
installer identity for runtime work. A failed provisioning prerequisite needs
separately authorized administrator review.

## Verification boundaries

In-memory Windows SDDL fixtures cover administrator-only denial, missing each
required right, split and generic grants, LocalService/group denies, inherited
and inherit-only entries, object ACEs, and unchanged writer restrictions.
Portable injected-backend fixtures check refusal before SCM creation or start
and during owned inspection. Those checks do not create services, change host
ACLs, read process tokens or generate endpoint keys. Windows cross-compilation
does not execute the SDDL fixtures.

This is a sufficient grant check for the supported DACL forms, not complete
effective-token acceptance. The future SCM process token does not exist while a
new service is being planned. The implementation does not construct a pretend
token or claim to run `AccessCheck`; that API requires a real client
[impersonation token](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck).
Additional restrictions such as mandatory labels, encryption, target policy,
filters or changed permissions are not proved away by this DACL check.

A separately approved native disposable-VM gate must still verify exact
provisioned ancestor and executable descriptors, successful image load and
runtime self-check under the actual limited LocalService/service-SID token, and
failure for deliberately unreadable descriptors. The broader state, enrollment,
stop/shutdown and genuine reboot gates in the [service candidate
guide](windows-basic-service-candidate.md) remain outstanding.
