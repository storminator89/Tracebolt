# Selected Windows service actions (source candidate)

This source adds manager-approved **start, stop and restart** of one explicitly
reviewed existing Windows application service. The Services view offers only the
locally granted exact target. Inventory visibility, service health, existing
observation grants and Linux `restart_service` authority confer no action rights.
Use the separate named-operator `windows_service_control` capability.

This is source/fixture evidence only. No Windows installation, account, ACL,
persistent key, grant, native service control or release was performed. A
separately approved disposable Windows gate must establish exact-byte native
acceptance before deployment. The published preview does not contain this path.

## Separate authority and setup

The observation service keeps its existing LocalService identity and service
SID. A different fixed own-process `TraceboltWindowsActionBroker` service runs
as the dedicated virtual account `NT SERVICE\TraceboltWindowsActionBroker`
with `SERVICE_SID_TYPE_RESTRICTED`, only
`SeChangeNotifyPrivilege`, no arguments, dependencies, triggers, recovery actions
or network client. Its fixed image is
`Program Files\Tracebolt\tracebolt-windows-action-broker.exe` (resolved by the
KnownFolder API). The source command takes no arguments and only enters SCM
service dispatch; it does not initialize authority at startup.

The create-only setup path **requires** an independently approved, already
installed, stopped broker with reviewed protected executable and explicit SCM
ACL. This increment does not install that service or apply any target ACL. If
those prerequisites are absent or cannot be inspected, setup fails closed.

The dedicated virtual account is an explicit setup prerequisite, not a runtime
account migration. Unlike LocalService, virtual accounts can authenticate to
network resources as the computer account. That tradeoff must be reviewed at the
separately authorized native setup gate. The broker has no network or manager
client and uses only fixed local IPC; this code does not change host networking
or assert an OS-enforced network sandbox. Target applications remain LocalService.

Before opening authority, ledger or action-capable target handles, runtime checks
the broker process and primary-token object owners/DACLs, every currently
enumerated thread, and the token default owner/DACL for future objects. Only
SYSTEM, Administrators and the dedicated broker SID may own or hold mutation,
injection, duplication, impersonation or permission-changing rights. Other
principals may have only narrow object-specific query rights; token defaults
permit them only READ_CONTROL. Checks are bounded and repeated before controls.
The documented restricted-token full-access ACE is accepted only on the token
object and only for the exact enabled logon SID derived from the verified broker
virtual-account token. Arbitrary logon SIDs and shared service principals remain
untrusted; this exception never reaches state, process, thread or default DACLs.
Unknown, inherited/callback, missing or unreadable descriptors fail closed. No
runtime ACL/account repair is attempted, and safe Windows defaults are not
assumed. The native gate must prove both isolation and the exact query access
needed for mutual peer inspection. Full process/token/thread/default checks run
inside the broker; the client proves fixed SCM PID and token identity without
opening the broker's threads. An observation worker must not inherit any
broker token or action-capable handle. Administrator changes are not atomically
excluded by these checks.

The broker SCM object must have a protected DACL, SYSTEM or Administrators owner,
and exactly these explicit allow ACEs: SYSTEM/Administrators full service access;
broker SID and observation-agent SID only QUERY_CONFIG, QUERY_STATUS and
READ_CONTROL (`0x20005`). LocalService and arbitrary groups get no ACE. This
prevents an observation process from replacing the broker command to inherit its
SID. Runtime, peer proof and the pre-control inspection check that boundary.

The target has a protected DACL and trusted owner. Only SYSTEM, Administrators,
TrustedInstaller and the dedicated broker SID may hold mutation rights. The
broker target ACE is exactly QUERY_CONFIG, QUERY_STATUS, ENUMERATE_DEPENDENTS,
START, STOP and READ_CONTROL (`0x2003d`). Other ACEs are limited to read/query
rights. No observation SID/account/group receives START/STOP, configuration,
owner or ACL rights. The target is an existing Win32 own-process standalone
application under LocalService, with a quoted protected `.exe` path and **no
arguments**. Drivers, shared-process services, Tracebolt, reviewed
security/connectivity/OS targets, dependencies, active dependents, triggers and
all recovery actions are rejected. Name exclusions supplement explicit local
review; they do not identify every security product or prove application safety.

An administrator separately prepares the canonical `windowsaction.Policy` with
one reviewed target/configuration/executable digest, review-record digest, public
manager action-key pin, activated endpoint/certificate incarnation, broker
installation identity and grant digest. Configuration and executable paths stay
local; only bounded binding metadata and digests reach the manager. The command
key is a distinct Windows key and signature domain. Linux permit bytes and
`.service`/`service.try-restart` semantics remain unchanged.

On the existing stopped owned observation installation, the source endpoint CLI
is:

```
tracebolt-windows-service.exe --service-actions-setup --policy-file C:\Reviewed\policy.json
```

The default is read-only planning under the existing protected receipt lease.
For an explicitly authorized setup, repeat with `--apply --approve sha256:...`,
using the exact printed policy digest. HTTP test enrollment additionally requires
`--insecure-http-test` and its displayed action/session risk acknowledgement.
The command creates only new broker authority and a separate agent relay grant;
it never starts the broker/agent or performs the first target action. Startup is
a separate authorized host action. The manager has a separate
`windows-action-manager-setup` source command and
`windowsServiceActionsConfigFile`; inspect its help before authorized setup.
Manager runtime opens already established authority only.

Endpoint apply persists a permanent `started.json` fence before creating the
separate ledger child, then exact policy, initialized ledger and completion
receipt. Policy, fence, receipt and ledger use the existing protected
`windowsstate` implementation with SYSTEM/Administrators/**broker SID only**.
The broker does not have enrollment private-key custody. Its root is separate
from observation stores. The relay grant uses observation custody and conveys
no SCM authority. Existing roots are never adopted, overwritten, promoted or
repaired. Losing a used ledger, fence, receipt or pending write hard-stops.
Partial cross-store setup is retained for intervention; no automatic cleanup or
second initialization is permitted. This does not resist administrator rollback
of the entire machine or deletion of every independent authority artifact.

## Approval, transport and recovery

A named live operator session supplies the server-derived actor under the
existing session lease, Origin and CSRF checks. Preview is bound to target,
operation, grant, key, endpoint incarnation, installation, sequence and expiry.
Approval atomically saves the exact approval/request and signed envelope in the
manager ledger. Claims release that envelope once. UI navigation, stale
responses, double clicks and uncertain approval do not create another effect;
results are read back from saved status. The UI never receives the envelope.
Manager revocation prevents new claims. It cannot retroactively withdraw an
already released, still-valid signed permit from a network-isolated broker;
local broker disable/stop or grant revocation is the independent host boundary.
No instantaneous remote revocation or atomic manager/SCM transaction is claimed.
A final manager rejection commits its exact observed clock in a separate
rejection-only floor, restoring the unchanged unclaimed job and envelope.
Successful final observations also advance time. The rejection floor can outlive
enrollment authority without extending it, capabilities, previews or deadlines.

The observer reports bounded broker capabilities and relays the original signed
bytes once over a fixed local pipe. The pipe is local-only, first-instance,
non-inheritable and protected by an explicit DACL. The agent's rights deliberately
exclude FILE_CREATE_PIPE_INSTANCE. Both sides verify the peer's current
own-process SCM PID in a held process handle and fixed token identity: the
broker virtual-account SID with its restricted SID, or the observation service
LocalService user with its enabled dedicated service SID. A shared account alone,
a different service and same-token collection workers are insufficient. The client requests identification-only security
quality of service. Identity-query denial never causes fallback to account-only
trust or impersonation. No broker token or action-capable handle is inherited.

There is one pipe instance and one mutation slot, canonical size-limited frames,
a 50-second connection budget and overlapped pipe I/O. Before disconnecting, the
server waits for a fixed response-digest consumed acknowledgement within the
original deadline so unread buffered results are not discarded prematurely.
A busy sole pipe may be retried only before connection or request bytes, within
that same original deadline. Cancellation drains pending I/O before releasing handles/buffers; no unbounded
FlushFileBuffers or background abandoned control is used. Failed or lost replies
remain uncertain and recover through **status only**, never resubmission.

The broker independently verifies signature and every local binding, preserves
its durable increasing sequence and wall-clock floor, and records admission,
dispatch and each attempted control before effects. Strictly increasing sequence
gaps are allowed because an earlier manager approval may expire before delivery.
An expired observed request advances the clock floor and cannot revive by a
subsequent clock rollback. Reopened admitted/dispatching work becomes terminal
intervention-required and cannot run or automatically clear itself.

## Exact native behavior and limits

One held service handle and protected executable/ancestor chain cover the whole
operation. The grant, original deadline, broker/target ACLs, exact configuration,
executable hash and current target state are rechecked immediately before each
control, including after synchronous persistence. This coordinates no arbitrary
administrator or SCM automatic action: Windows has no atomic
compare-configuration-and-control API. Privileged changes are not claimed to be
atomically excluded.

- Start: initially Stopped, zero arguments, one START, observe Running with PID
- Stop: initially Running with PID and STOP accepted, one STOP, observe Stopped
- Restart: initially Running only; one STOP, observe Stopped, one START, observe Running

Initially stopped restart never becomes start. Initial pending, paused and
unknown states are rejected. No recursion through dependents, shell, script,
custom arguments/environment, forced kill, automatic retry or compensation is
supported. State observations after effects can poll only the expected old,
pending or requested state, for at most 184 observations and 45 cooperative
seconds, also bounded by the original signed deadline. Native SCM/filesystem
calls are synchronous and can return late; late results remain uncertain. No hard
native-call cancellation guarantee is claimed.

Durable results retain separate attempted/requested/observed flags, last observed
state, operation, identity and original deadline. Attempted is persisted before
the native call, conservatively surviving a crash between persistence and call.
Requested means only that the call returned success. A partial restart, lost
result, late call, configuration drift, shutdown or post-effect storage/closure
failure retains intervention-required evidence. SCM Running/Stopped observations
are not application health, successful telemetry, reboot or delivery evidence.

## Source verification and remaining gate

Focused portable fixtures cover all three operations, manager/ingress/relay/broker
integration, signatures/bindings/domain isolation, old grants, claimonce/replay,
missing used state, crashes, expiry/clock rollback/revocation, partial restart,
config drift, pending state, access denial, no second control, response ACK,
broker SCM and process/token/thread/default-DACL isolation policies, named-session/Origin/CSRF and UI repeated/stale flows.
Windows amd64/arm64 compilation is source compatibility only. Real Windows token,
pipe DACL, SCM descriptor, protected file and application transition behavior must
still pass separately approved native gates. Linux contracts are unchanged.

Primary Windows contracts: [CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea),
[service object access](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
[DisconnectNamedPipe buffered-data behavior](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe),
[process rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights),
[thread rights](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights),
[token rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects),
[virtual-account network identity](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts#virtual-accounts),
and [file/directory access-right differences](https://learn.microsoft.com/en-us/windows/win32/wmisdk/file-and-directory-access-rights-constants).
