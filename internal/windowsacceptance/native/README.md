# Default-off native acceptance driver

This package prepares a **separately authorized, disposable Windows gate** for
the existing published fixed `TraceboltWindowsAgent` service. It is source only,
not evidence that any native gate ran. Its portable tests are inert guard and
redaction fixtures; Windows-only tests use in-memory descriptors, buffers and
injected observations. Cross-building those tests does not execute them.

`New` validates artifact names/digests without opening files. Every exported
mutating operation takes a live `Guard` supplied by the exact-source manual
controller. No package initialization performs native work, and no environment
variable, receipt or command argument is treated as approval. The controller
must independently bind its own build and the ordinary service binary to the
approved source. Approval must cover the fixed resources, temporary endpoint
identity, app-owned ACLs, bounded controls and owned cleanup. Only `Evidence`
(finite stages/reasons and booleans) is intended for reports.

## Read-only prerequisite

`Preflight` uses KnownFolder paths, requires an elevated administrator and fixed
local NTFS with persistent ACLs, holds the existing OS ancestor handles against
replacement, rejects reparse points and requires trusted owner/writer policy.
Ancestor descriptor admission does not claim effective read access and does not
require a named LocalService ACE. Windows applies group membership, inheritance
and ordered applicable denies during the actual service's unchanged native opens.
The ordinary read-only result always keeps effective service-token access false.
The later approved native run must observe real SCM startup, its limited token,
protected-state use and reporting. See
[the access-proof contract](../../../docs/windows-runtime-read-preflight.md).

The final executable's sufficient read policy and all creation descriptors remain
unchanged; private state remains service-SID protected. A blocked prerequisite
never authorizes changes to drive-root, Program Files, ProgramData, Users,
existing Tracebolt directories, groups, tokens or global policy. This package
contains no existing-object ACL repair API and no fabricated token.

## Fixed create-only resources

Both existing `ProgramFiles\Tracebolt` and `ProgramData\Tracebolt` cause refusal,
even if empty. Existing main or probe services cause refusal. `Provision` copies
only the controller-bound artifact bytes to the two fixed executable names,
using `CREATE_NEW`, explicit descriptors at creation and recorded file IDs and
hashes. Parent creation uses `CreateDirectoryW` with a protected descriptor; it
never calls `SetSecurityInfo`, `SetNamedSecurityInfo`, `icacls`, a shell or an
installer script. The public executable/app parent grants LocalService read and
execute; the new app data parent grants only its required ancestor read rights.
The shared LocalService SID is never placed on private state.

`Prepare` invokes the ordinary `windowsservice.Plan`/`ApplyInstall` path, writes
the protected intent before SCM creation, retains incomplete receipts on any
failure, and creates the ordinary protected runtime and empty enrollment stores
using the main service SID. No service is adopted, upgraded or overwritten.
`Claim` uses the existing `ClaimOnly` library operation with an in-memory secret
callback and public-trust callback. This deliberately does **not** establish
hidden-console or production-CLI input acceptance. It anchors the immutable
committed claim marker; the actual main service performs approval resumption,
activation and reporting with its ordinary `--run-service` mode.

`InspectToken` opens the actual running main service process with query-limited
rights and reads its token. It requires LocalService, the enabled owner-capable
service SID, no enabled Administrators group and exactly the permitted privilege.
SCM PID is checked again afterwards. It never enables debug/ownership privileges,
logs on, impersonates, or substitutes the controller's token.

## Independent real denial probe

`Probe` is permitted only after a stopped, ready main service and validated
initialized key/sender files. A separate admin-only acceptance store records its
intent and completed receipt. It creates `TraceboltWindowsAcceptanceProbe` as a
separate LocalService own-process service with its own unrestricted service SID,
only `SeChangeNotifyPrivilege`, demand startup, no recovery command or trigger,
and one fixed controller argument: `--internal-denial-probe`.

The controller admits this internal mode only through `ProbeContextValid` plus
its in-memory guard. The child verifies SCM origin, exact process argument,
image location/hash, fixed configuration and the actual token. It requires its
own SID and the absence of the main service SID, checks that the operating
thread is not impersonating, and attempts read-only `CreateFile` opens of the
actual main private key and sender state. No bytes are read. Only real Win32
`ERROR_ACCESS_DENIED` on **both** counts. Missing paths, sharing violations,
library policy sentinels, timeouts and other errors fail. A finite SCM-specific
exit code carries success; raw native errors and target paths are not reports.

## Continuity, stop, uninstall and cleanup

All waits are cancellation-aware and bounded at 45 seconds per transition.
Acceptance Stop additionally requires both SCM exit codes to be zero. A separate
receipt-bound `CleanupStop` permits removing an already-failed service only in
the controller failure defer; it cannot satisfy an acceptance check.
`Running` alone is not approval or reporting. `StateContinuity` requires a
stopped receipt-owned service, uses the existing protected-store validation,
checks the original immutable claim identity/deadline, and observes the existing
sender binding/counter floor. On outage observations it hashes the retained
pending body in memory and proves unchanged bytes at the same sequence on the
next stopped observation. No body, counter, identity or digest is exposed.

`Uninstall` uses the ordinary stopped receipt-owned SCM deletion and separately
waits for absence. It compares verified runtime-tree IDs and hashes before and
after deletion before reporting `UninstallStateRetained`. The probe is stopped
and deleted only from its same-process completed ownership receipt and exact
current configuration. Partial probe creation is retained for inspection.

`Cleanup` requires confirmed main-service absence and its protected receipt.
Only app parents created by this driver, their recorded IDs, the exact two
artifact hashes, validated protected store schemas/manifests and known entries
are eligible. Unknown entries, changed IDs/hashes/ACLs, unexpected services or
incomplete receipts stop cleanup. It freezes the bounded tree into handles and
uses `SetFileInformationByHandle(FileDispositionInfo)` on each exact owned object
bottom-up. It never uses recursive path deletion. A late unknown child prevents
parent removal; it is never discovered and deleted. Failed/partial work may be
retained and must not be reported as clean.

No shutdown/reboot API exists here. Handler fixtures can test shutdown control
semantics; genuine OS shutdown/reboot, desktop/ARM64 runtime, hidden-console
input and broader interrupted-write/power-loss acceptance remain separate gates.

## Microsoft contracts

- [CreateDirectoryW and creation-time security descriptors](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)
- [CreateServiceW fixed account, quoting and access](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
- [OpenProcessToken query requirements](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [GetTokenInformation bounded token queries](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [DeleteService deferred deletion](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice)
- [SetFileInformationByHandle access and exact-handle disposition](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
- [FILE_DISPOSITION_INFO one-BOOLEAN layout](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info)

## Separate ordinary-CI read-only observer

`InspectPrerequisites` is the only native entry referenced by the separate
`cmd/windows-prerequisites` executable. It invokes read-only Preflight and closes
its owned read handles without calling acceptance Cleanup. It cannot reach
Provision, Prepare, Claim, Start, Stop, Probe, Uninstall or any credential/ACL/token
grant operation. Finite supported/blocked/unverified observations describe the
current sufficient host policy, never actual effective SCM-token access. A
blocked ancestor policy does not prove a native permission denial or justify
changing OS-managed ACLs. Real service acceptance remains separately approved.
