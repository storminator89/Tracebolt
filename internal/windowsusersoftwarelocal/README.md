# Selected-user software foreground source candidate

This package is a distinct fixed local observation channel, not the action
broker and not machine software collection. The only executable entry is
`cmd/windows-user-software`: an explicitly launched, one-shot normal-session
console command. There is no unattended confirmation, account selector,
elevation, scheduled collection, native child, PowerShell or persistence.

The service is separately enabled under the existing observation identity.
`Serve` binds one first-instance, local-only, non-inheritable named pipe and
checks its own local primary token (LocalService plus dedicated service SID)
and exact live SCM own-process PID. During its own startup only, a read-only
10-second wait permits StartPending with the same or unspecified PID until
Running; token drift, a foreign PID, other state, cancellation or timeout fails
closed. The foreground client does not open the
service's token. It queries the fixed SCM service, holds a
PROCESS_QUERY_LIMITED_INFORMATION process handle, and verifies the public fixed
executable path, exact service configuration, LocalService account, SID
configuration and public installation marker. A bounded SCM owner/DACL check
rejects untrusted configuration, owner, DACL or deletion authority and binds
the descriptor throughout the conversation. The public registered hash is an
administrator-protected marker, not a client-measured binary digest. The service
retains its own existing protected-executable verification before the listener.
The narrow `windowsservice.OpenObservationPeer` proof reads no executable file,
private receipt, enrollment state or credential. Default SCM read-control and
query rights support normal users. Query-only process/image/SCM access still
requires native acceptance; denial never triggers an ACL or privilege fallback.

The server reads a bounded hello before identifying its kernel-provided client
PID/session. On a dedicated locked OS thread it calls ImpersonateNamedPipeClient
only to open an identification-level TOKEN_QUERY handle, then immediately calls
RevertToSelf and verifies the thread no longer has an impersonation token.
Only after verified revert does it inspect the token. Anonymous, impersonation
and delegation levels are rejected. No handler, state, registry, MSIX or other
source read occurs while the thread carries a client context. The first token
handle is retained, with OS pipe PID/session, authentication ID, SID, groups,
medium integrity and non-elevated interactive identity rechecked around each
operation. No foreign primary token or foreign-process session query is used.

A failed revert is fatal: the goroutine exits without unlocking, so Go destroys
that dedicated OS thread; Serve stops and no admission or cleanup handler is
called after the failure. The original reservation/floor is left for normal
restart reconciliation. There is no WTS provider dependency, user/domain name
lookup, account enumeration, privilege enablement or permission mutation.
The helper checks AppContainer on its own primary token. Server identification
proof rejects enabled app-container SID groups and low/high integrity; it does
not claim that TokenIsAppContainer=0 proves non-AppContainer for an identification
token. A SID never travels over the pipe or to the manager.

Begin issues a connection-bound 256-bit random nonce and original expiry. The
foreground prompt discloses the actual device, manager destination, selected
account label, metadata scope and HTTP-test warning if applicable. Only exact
`CAPTURE` input proceeds. The service must durably reserve that exact nonce
before any native capture starts. Every unsubmitted exit calls Abort, including
decline/disconnect before reservation and failures after a durable reservation.
Abort must preserve any consumed nonce and floor. Submit performs the final
live authority check and freezes exact retry bytes; uncertain delivery never
causes another native capture. Parent runtime supplies these Handler semantics.

Native reads are limited to the current process's own shared HKCU uninstall
subtree, exactly once, and WinRT
`PackageManager.FindPackagesForUser(string.Empty)`. HKCU ancestors and children
are opened read-only with `REG_OPTION_OPEN_LINK` and link targets are not read.
Only DisplayName, DisplayVersion and Publisher are fetched with fixed buffers.
MSIX uses fixed native IIDs and only package identity FullName (hashed locally),
Name, Publisher and Version getters. The reported MSIX name is its identity
name, not a localized Start menu label. No package location, install path,
uninstall command, manifest, application, dependency, license or user-list getter
is used. No package is launched or changed.

HKCU root count/last-write and per-registration before/after last-write checks
protect its single enumeration; two bounded MSIX enumerations must agree. These
checks detect observed source churn but does not turn a non-transactional OS enumeration into a global
installed-software snapshot. Each source's status remains explicit; failed
sources discard all prefixes, optional unavailable fields remain unavailable,
and zero complete rows remain distinguishable from failed/unknown coverage.
At most 4096 aggregate rows and 4 MiB canonical rows survive admission. Every
native string, enumeration and optional value has an independent bound.

The 15-second native deadline runs in the dedicated one-shot foreground
process. A blocked COM/registry thread cannot safely be forcibly terminated in
Go. At timeout/cancellation the client closes the held connection and immediately
returns to `main`, which exits the process; it does not wait for another IPC
response or retry. The service records the reserved attempt's failure through
Abort. `RunForeground` is process-lifetime one-shot and MUST NOT be used from the
long-lived agent, Setup, or another resident process. The process-exit boundary
and raw WinRT ABI need Windows amd64/arm64 acceptance; cross-compilation and
source fixtures are not that acceptance. Normal-user query-only access to the
observation process/image and public SCM configuration/descriptor, plus the
identification-token flow, must be demonstrated on the exact native profile.
Failure is surfaced rather than repaired by a wider ACL.

## Microsoft sources verified 2026-10-11

- [HKCU Software is shared across WOW64](https://learn.microsoft.com/windows/win32/winprog64/shared-registry-keys)
- [PackageManager.FindPackagesForUser: empty string means current user](https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.packagemanager.findpackagesforuser)
- [WinRT activation](https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-roactivateinstance)
- [Microsoft-generated native deployment ABI](https://github.com/microsoft/windows-rs/blob/master/crates/libs/windows/src/Windows/Management/Deployment/mod.rs)
- [Microsoft-generated package identity ABI](https://github.com/microsoft/windows-rs/blob/master/crates/libs/windows/src/Windows/ApplicationModel/mod.rs)
- [CreateNamedPipe flags and inheritance](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
- [GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
- [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)

- [Identification-level named-pipe authentication without impersonation privilege](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [SecurityIdentification cannot act as the client](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level)
- [OpenThreadToken and OpenAsSelf](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [Verified RevertToSelf is required](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself)
- [Token classes and identification-token AppContainer caveat](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [Pipe client session requires no foreign process handle](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientsessionid)
- [Query-limited process rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

- [Default normal-user SCM query and descriptor-read rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Bounded read-only SCM object descriptor](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceobjectsecurity)
