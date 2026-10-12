# Cached Windows update executor adapter: source only

`internal/windowsupdateexecutor` implements the existing selected-update
`ExecutorAdapter`/`PreparedUpdate` boundary. The explicit
`windows-update-executor --run-foreground` command connects it to the dedicated
local IPC and observation relay described in [selected update jobs](windows-selected-update-jobs.md).
It requires separately provisioned protected keys, consent receipts and peer pins.
The default kernel still uses the inactive adapter; construction alone is inert.
There is no automatic installation or activation.

## Exact native scope

The first native call is an explicitly invoked `PrepareExact` for one validated
nonzero GUID and 31-bit revision. A dedicated goroutine owns one locked OS thread
from token inspection through COM release/uninitialization. No COM reference is
returned to another thread. On that thread, the adapter requires no impersonation
token, a primary process token, elevation, no token restrictions, High or System
integrity, and enabled non-deny-only `BUILTIN\\Administrators` membership. Token
query, bounds or close failures reject. Fixed errors distinguish unproven token,
impersonation, integrity, administrator membership and restriction prerequisites.
The code does not adjust a token, impersonate, request elevation or change a grant.
High integrity alone would not establish WUA installation rights.

Only system `ole32.dll`/`oleaut32.dll`, fixed Microsoft WUA CLSIDs and local
in-process activation are used. High/System integrity excludes per-user COM
registration. This relies on the normal protected Windows machine registration
and trusted OS boundary; it does not attest a machine already compromised by an
administrator or replace a future publisher/provisioning gate.

One generated query selects `Type='Software'`, `IsInstalled=0`, `IsHidden=0`,
exact `UpdateID` and `RevisionNumber`. `Online=false` and
`CanAutomaticallyUpgradeService=false` are set and read back. A successful
search must yield exactly one object with that identity. No search retry,
alternate revision, online fallback, source registration or upgrade is allowed.
That object remains retained through inspection and installation.

All contract readiness facts are reread. Unknown or malformed values never
become false. Any bundle count other than zero rejects; children are never
traversed. The adapter requires the update already downloaded and its EULA
already accepted, with no user input, source media or network requirement. It
reads reboot behavior and the installer's reboot-before-install and busy gates.
`IsInstalled` is a search-time snapshot; re-reading it is not a new applicability
scan, a global installation lock or a guarantee against external Windows activity.

The new collection must initially be empty. Exactly one retained update is added,
then the installer collection is read back and its sole object's COM `IUnknown`
identity is compared. `IUpdateInstaller2` support is mandatory. Source prompts and
forced installation are set false; `ForceQuiet` is true; all three are read back
again before installation. Missing quiet support rejects without falling back.
The engine requires a successful prior inspection, rechecks the same facts, and
makes at most one synchronous `Install` call. No code requests application closure,
uninstall, EULA acceptance, downloads or automatic restart. These safeguards do
not promise that WUA installation cannot interrupt applications.

Only the selected update's `GetUpdateResult(0)` supplies `ResultCode`, `HResult`
and `RebootRequired`. A successful COM method return does not by itself report
installation success. Partial, malformed, missing or canceled results remain
uncertain under the kernel's result rules.

## Ownership and duration

Preparation/inspection waits are bounded to 30 seconds, idle prepared ownership
to 60 seconds, and an installation caller's wait to 30 minutes. The signed
60-second start deadline belongs to the kernel, not to installation duration.
A private kernel context value carries that original deadline and the durable
clock floor, together with admitted consent/current-leaf expiries. The adapter rejects missing fences, expiry, rollback and cancellation
after final readiness. The native wrapper repeats the check immediately before
`Invoke(Install)`, after token checks, method-name resolution and another read
of the volatile busy/reboot gates. No blocking
preparation runs between that final check and the native call. The context value
is retained through the independent operation timeout; a caller cannot replace
the signed deadline by choosing a later context deadline.
Caller cancellation or timeout cannot stop a synchronous COM call or prove a
rollback. The caller returns uncertainty; the same owner keeps COM references
until the call really returns and only then releases them. The adapter is poisoned
against subsequent preparation after abandoned work or an installation error;
a late result never clears that uncertainty. Owner-side failure poison is saved
before result publication. A small response-settlement handshake keeps the busy
slot held until the caller has finalized timeout/close uncertainty, even if that
caller is descheduled after a buffered native reply. Failed preparation and
non-success native results likewise cannot briefly reopen admission. Cleanup
completion and admission release are atomic with timeout settlement: a delayed
Close timer prefers an already-completed owner, and an unfinished owner is
poisoned before its slot can be released. Stale handles cannot poison a later
owner after their own completed slot is reused. `Close` never releases an in-use
object and returns uncertainty if shutdown is not established within its bound.
A stuck native call can retain one owner thread indefinitely. No process kill,
rollback, repair or retry is attempted. Durable claim/attempt/result truth remains
the responsibility of the existing executor kernel.

## Unsupported and unverified

- Foreground invocation, protected-material validation, local IPC, observer relay
  and [fresh explicit setup](windows-selected-update-setup.md) are implemented in source.
  The foreground command itself cannot create, adopt or repair setup material.
- Native activation requires explicit approval, including the optional
  process-lifetime observer query permission. It has not been performed.
- Existing read-admin/service-broker rights are not promoted. Standard, filtered,
  restricted, impersonating or unproven tokens are rejected.
- Bundles, drivers, missing cache/EULA/readiness, prompting/network/source-media
  updates, busy installers and required prior restarts are rejected.
- The adapter has no authority to solve a failed prerequisite by changing Windows.
- Native Windows execution and disposable-host acceptance have not run. Inert
  COM/token fixtures and cross-builds do not establish actual installation,
  cache behavior, handler UI behavior, revocation propagation or native safety.

## Microsoft contracts reviewed

- [WUA installation interfaces require Administrators](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/secured-methods-and-properties-in-the-wua-api)
- [High-integrity COM ignores per-user registration](https://learn.microsoft.com/en-us/previous-versions/bb756926(v=msdn.10))
- [WUA fixed CLSID assignments](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/e839e7e0-1795-451b-94ef-abacd6cbecac)
- [Microsoft interface declarations, including Installer2 IID](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/wuapi.h)
- [Installation behavior fields](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iinstallationbehavior)
- [ForceQuiet and unsupported handlers](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdateinstaller2-put_forcequiet)
- [Source prompts](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdateinstaller-put_allowsourceprompts)
- [Forced installation semantics](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdateinstaller-put_isforced)
- [Synchronous Install and busy prerequisite](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdateinstaller-install)
- [Reboot-before-install prerequisite](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdateinstaller-get_rebootrequiredbeforeinstallation)
