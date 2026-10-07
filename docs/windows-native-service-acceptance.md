# Manual Windows service acceptance candidate

This is **test infrastructure source**, not an installed-service acceptance result.
The workflow has no automatic trigger. No repository publication, successful
cross-build, source fixture, or read-only collector job authorizes its native
operations. The published Windows basic service contract remains in
[windows-basic-service-candidate.md](windows-basic-service-candidate.md).

## Separate ordinary-CI read-only measurement

`windows-prerequisites.yml` runs a separate `cmd/windows-prerequisites` executable
on the disposable hosted Windows image. It only reads KnownFolder/layout, local
filesystem facts, current administrator elevation, existing ancestor descriptors
and fixed resource absence. Its sole CLI mode cannot dispatch the manual native
controller or any service/ACL/identity mutation. It does not collect telemetry.
The clean checkout, GitHub SHA and compiled source are bound independently.

Its finite `tracebolt.windows-prerequisites.v1` result is `supported`, `blocked`
or `unverified`, with one finite check/reason. `supported` means only that the
current sufficient host policy is satisfied; actual SCM-token/effective access
and native service acceptance remain explicitly false. `blocked` at
`ancestor-policy` means the current descriptor policy rejected the prerequisite,
not that LocalService was experimentally denied. Completed blocked/unverified
measurements may finish their ordinary CI job successfully, while malformed or
failed measurement execution fails it. Neither outcome is a native service pass.

Read-only CI does not grant permission to launch the separate manual workflow.
If the policy rejects legitimate effective access, fix and review that access
policy and prove the real token at the later approved manual stage; never widen
OS-root or Program Files ACLs just to satisfy this conservative test. No public
statement of Windows service readiness should precede inspection of this result.

## What needs explicit approval

After reviewing an exact source commit, the operator must separately approve a
single run of `Manual disposable Windows native acceptance subset` on a fresh disposable
GitHub-hosted `windows-2025` x64 runner. The dispatch requires its full 40-character
commit SHA and **all five** scopes, each false by default:

1. `services`: create the fixed `TraceboltWindowsAgent` LocalService SCM
   service and the separate `TraceboltWindowsAcceptanceProbe` LocalService
   service; start/stop/restart them and delete their verified registrations.
2. `identity`: create one temporary endpoint enrollment identity and
   protected private state; deliberately approve its captured fingerprint and
   comparison value against a disposable fixture authority.
3. `app_acls`: create only new Tracebolt app directories/files with their
   explicit ACLs. Existing resources are never adopted or repaired.
4. `loopback_tls`: create temporary memory-only fixture authority and two
   local TLS listeners; send real basic Windows telemetry to that local fixture.
5. `cleanup`: delete only the newly owned test services and app files
   after receipt, object ID, content hash and manifest checks. Unexpected or
   incomplete resources are retained with a failed cleanup result.

The action-time request must name the exact commit, workflow and disposable
runner, the above objects/identity/permissions/telemetry, and bounded cleanup.
It must disclose the prerequisite below and that a failed run can retain test
resources until runner destruction. An earlier request to implement Windows
support is not approval to dispatch this gate. Never reuse an approval for a new
source commit. There are no user computer targets or external manager credentials
in this workflow. There is no dispatch command in this guide.

## Source and artifact binding

`.github/workflows/windows-native-acceptance.yml` permits `workflow_dispatch`
only. The Python wrapper and Go executable independently reject absent scopes,
automatic events, another repository, self-hosted/non-Windows runners, malformed
run IDs, or differing expected/GitHub/compiled source. The wrapper also checks the
clean checkout's HEAD before building the ordinary service and the controller
from that source. The controller's source is compiled in, and both artifact
hashes are checked again before copying. The main service is the unchanged
`cmd/windows-service --run-service`; no acceptance-only runtime shortcut, clock
or service timeout is injected into it.

The approval is in-memory, expires after twenty minutes and is rechecked on
mutating driver calls. Main work is bounded to ten minutes; failure cleanup has
its own two-minute cancellation window using the same still-valid scope. The
wrapper's process deadline includes that cleanup interval. Cancellation does not
grant permission to adopt incomplete state or erase an ownership fence.

## Read-only provisioning prerequisite: a real blocker

The current service deliberately uses a conservative sufficient-DACL policy,
not a general effective-access calculation. Its existing executable ancestors
require an explicit LocalService read/execute grant (`0x001200a0`), trusted owner
and no untrusted writer. The protected state's ancestors additionally need
`FILE_LIST_DIRECTORY` (`0x001200a1`). This includes the volume root, Program Files
and ProgramData. All effective ordinary deny entries intersecting required
rights are refused, even if they would not apply to this particular token.

**A stock GitHub-hosted runner may fail this prerequisite.** The gate checks it
before creating any fixture listener, identity, service or app directory. It
returns `blocked` with `ancestor-prerequisite`; this is not a native pass. It
never adds an ACE to a drive root, Program Files, ProgramData, Users or any other
existing directory, and never invokes an ACL-repair shell command. Do not change
OS-managed root ACLs merely to make this test pass. If the hosted image is
unsuitable, a separately reviewed provisioning/access-policy solution and a new
exact-source approval are required. Self-hosted dispatch is deliberately refused
by this candidate; no suitable image is assumed to exist.

Other prerequisites are elevated administration, supported physical local NTFS
paths, persistent ACLs, no reparse points or case-sensitive directory semantics,
and absence of both fixed services and both Tracebolt app parents. Preflight
pins existing ancestor handles. It neither adopts nor empties existing resources.

## What a successful native subset would prove

The controller emits exactly thirteen finite outcome checks:

1. Read-only prerequisites passed.
2. App-only create-new provisioning matched source-bound artifacts.
3. Ordinary service install and protected state preparation completed.
4. A single pending claim was committed with explicit TLS/basic public trust.
5. The actual main service process token was LocalService with its enabled,
   owner-capable service SID, no enabled Administrators group and only
   `SeChangeNotifyPrivilege`. The SCM PID is rechecked after querying it.
6. Each acceptance Stop requires zero ordinary and service-specific SCM exit
   codes; stopped failures cannot count as orderly shutdown. A real pending service ran for at least five seconds, then stopped while
   preserving the original claim identity and approval deadline.
7. On restart, explicit matching fixture approval activated the same identity;
   the ordinary service delivered a validated Windows basic frame over real TLS.
8. A separate real LocalService process with a different service SID, and no
   main service SID or impersonation, was denied read opens of the initialized
   main private key and sender state by Win32 `ERROR_ACCESS_DENIED`. Missing
   objects, sharing violations and policy sentinel errors cannot pass.
9. A fixture outage yielded a real unavailable request without receipt progress,
   and Stop retained the durable sender's pending generation.
10. Restart during the same outage retained exactly the same pending bytes and
    sequence, with no new claim or reset.
11. Recovery accepted progress from the same identity and durable counter floor;
    Stop left no pending generation.
12. Ordinary uninstall removed the SCM service while preserving verified state
    objects unchanged. Uninstall itself does not erase identity.
13. Only newly owned, unchanged app resources and the probe registration were
    cleaned. Cleanup freezes a bounded allowlisted tree and deletes exact opened
    handles bottom-up. Unknown children, altered IDs/hashes or partial receipts
    cause retained-state failure rather than wider deletion.

A success is named `passed_native_subset`. The finite report's current-state
fields require the services stopped/uninstalled, no pending generation and no
retained cleanup resources. It cannot be promoted to full deployment acceptance.

## Fixture boundaries and outstanding gates

The native peer in `internal/windowsacceptance/fixture` uses real enrollment
proofs, state transitions, issuance and v1 frame/receipt validation. It holds its
issuer and invitation only in process memory and listens only on IPv4 loopback,
TLS 1.3. The ordinary Windows service uses its actual protected identity, real
collector and sender. Raw telemetry is validated but never printed or uploaded.

This peer is **not the production Linux manager**. The latter's durable enrollment
store is Linux-only; this candidate neither weakens it nor calls a synthetic
Windows server equivalent. No dashboard/browser, durable Linux manager receipt,
manager restart/persistence, external network or released-installer result follows.
An eventual Windows-to-real-Linux-manager/dashboard gate is still required.

The initial claim uses the existing enrollment library with an in-memory secret
callback and explicit public trust callback. It does not exercise the human
hidden-console prompt or prove those CLI input mechanics on Windows.

The workflow separately runs the existing deterministic pending coordinator and
SCM-handler fixtures: approval after a simulated first fifteen-minute session,
original thirty-minute expiry, state/authority failure concurrent with Stop,
cancellation and Shutdown during initialization. Those use injected clocks or
memory backends. The native service keeps real time and waits seconds before
approval; the report never labels this as a real fifteen/thirty-minute wait.

No actual OS Shutdown or reboot is requested. Real shutdown/reboot persistence,
power loss, interrupted writes, desktop Windows and ARM64 runtime remain pending.
The report always keeps `productionManagerExercised`, `hiddenConsoleExercised`,
`osShutdownExercised` and `osRebootExercised` false. Source cross-builds are not
native proof. Persistent Event Log diagnostics remain separate from finite SCM
and console codes.

## Safe evidence and failure handling

Only a strictly validated bounded JSON report with exact source, finite stages,
finite reasons, booleans and the thirteen outcome names is retained. The wrapper
rejects unknown fields, duplicates, malformed types, missing checks and false
success claims. It captures but never publishes raw controller output. Binaries,
private stores, invitation/key material, fingerprints, object paths, raw native
errors and telemetry are excluded from artifacts. No CI secret is needed.

A failed or blocked result fails the job; a skipped operation is never a pass.
On a failure after complete installation, the controller attempts receipt-bound
cleanup-only Stop, Uninstall and owned Cleanup within the separate cleanup deadline. Partial
installations without a completed durable receipt remain fenced. Reported cleanup
failure means resources were retained; it must not be relabelled as successful
because the hosted runner will later be destroyed.

## Microsoft API references

The API contracts were checked against current Microsoft documentation:

- [LocalService account](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account)
- [Service SID token attributes](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [SCM required-privilege removal](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow)
- [OpenProcessToken query rights](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [SetFileInformationByHandle disposition](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)

The implementation never enables debug/ownership privileges, logs on as another
identity, repairs an ACL, installs a trust root, changes a firewall, or exposes
arbitrary shell commands. Those omissions are enforced source boundaries; their
runtime correctness still needs the separately approved native run.
