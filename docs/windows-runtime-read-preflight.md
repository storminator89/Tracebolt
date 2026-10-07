# Windows executable trust and runtime access

The fixed Windows basic-service source keeps path integrity separate from
runtime access. This correction does not install a service, repair permissions,
create a token or endpoint identity, or establish native service acceptance.

## Existing ancestors: trust first, native access later

An ancestor does not need an allow ACE naming LocalService specifically. Windows
evaluates the actual thread/process token, enabled groups and ACE ordering; group
or inherited grants can supply access. A scan that counts only LocalService and
aggregates every deny, including unrelated trustees, is not an effective-access
calculation. See Microsoft's [ordered access-check
semantics](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object).

The descriptor-only ancestor policy now checks integrity only:

- Trusted owner: SYSTEM, Administrators or TrustedInstaller.
- No untrusted replacement-capable writer, ownership/DACL change, delete or
  delete-child grant. The existing writer masks are unchanged.
- No NULL DACL or unsupported effective ACE shape; inherit-only entries do not
  affect the current object.
- Existing fixed-drive, canonical-path, reparse, hard-link and held-handle checks
  remain. Directory handles deny delete sharing while used.

Read-deny ACEs do not make a path writable. They remain in the original DACL and
Windows applies them during actual access, using their real trustees and order.
A trusted administrator-only ancestor can therefore pass this static integrity
policy without claiming that the future service can read it.

The native `CreateFile` and `NtCreateFile` access masks are unchanged. Executable
self-validation still requests descriptor/attribute read on ancestor handles;
protected-state traversal still requests `READ_CONTROL`, attributes, listing,
traverse and synchronization. Failure of any actual open fails closed. Nothing
retries as administrator, impersonates another token, enables a privilege or
changes a parent ACL. This change does not rely on guessed group membership or
on an assumed traverse-bypass privilege. Microsoft documents the [file mappings,
parent/child access and traversal
semantics](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

## Final executable and private state remain protected

The final public executable retains its conservative sufficient read policy:
LocalService-specific ordinary allow ACEs must cover
`FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` (`0x001200a9`). An inherited effective
allow counts; an inherit-only entry does not. Any ordinary effective deny
intersecting these rights fails this final-file policy, regardless of trustee or
order. Generic rights are mapped with the Windows file-object mapping, including
read/control/synchronize overlap. Administrator-only, unreadable or
non-executable final files still return `ErrRuntimeReadAccess` before install.
Unsafe owners, writers or unsupported effective ACE forms return `ErrUnsafePath`.

This sufficient final-file check is deliberately stricter than full native
access and still cannot establish future token access alone. The new app-owned
creation descriptors remain unchanged. Private enrollment/sender state keeps
its exact protected service-SID/SYSTEM/Administrators policy; the shared
LocalService SID receives no private-state grant. Protected-store open masks,
locking, schema, replacement, mutation and cleanup rules are unchanged.

## Where the checks execute

`Plan`, `ApplyInstall`, `InspectOwned`, `ApplyStart` and runtime installation
validation retain the same held-path and final-file checks. The installer's own
successful opens establish only installer access. Runtime installation
validation and the protected-store APIs perform their actual opens inside the
SCM process. A failure prevents runtime readiness/reporting.

There is no synthetic LocalService token and no simulated `AccessCheck` result.
That API requires a real client [impersonation
token](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck);
constructing guessed groups would not prove the later SCM token. Additional
mandatory-label, filesystem/filter, encryption or changed-permission restrictions
are handled by actual Windows access decisions, not asserted away by this policy.

## Evidence and remaining gate

The ordinary read-only prerequisite command reports only trusted-path/host-policy
readiness. A `supported` result always retains
`effectiveServiceTokenAccessVerified=false` and `nativeServiceAcceptance=false`.
The exact 5bd1340 source previously reported `blocked` at `ancestor-policy`; that
was the old sufficient policy's refusal, not an observed LocalService denial.
Never widen drive-root, Program Files or ProgramData ACLs to force a pass.

In-memory descriptor fixtures admit trusted ancestors with group/inherited
reads, missing named grants and read denies without claiming effective access.
They continue to reject unsafe owners, write/delete-child grants, NULL DACLs and
unsupported effective ACEs. Final-file missing/denied-read fixtures remain. These
fixtures neither create objects nor open process tokens; cross-building them
does not execute them on Windows.

The separately approved [native service acceptance
subset](windows-native-service-acceptance.md) must combine actual SCM image
startup, an observed limited LocalService/service-SID token, ordinary runtime
path/private-state opens, same-identity activation/reporting and real unrelated
service denial. Those observations supply the actual-token access evidence.
Read-only prerequisite success is never a substitute. Deliberately unreadable
runtime/path variants, human hidden-console input, production manager/dashboard
and genuine shutdown/reboot remain separately identified native coverage rather
than claims from this correction.
