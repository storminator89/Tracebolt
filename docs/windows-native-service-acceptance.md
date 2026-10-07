# Manual Windows service acceptance candidate

This is **test infrastructure source**, not an installed-service acceptance result.
The workflow has no automatic trigger. No repository publication, successful
cross-build, source fixture, or read-only collector job authorizes its native
operations. The basic service contract remains in
[windows-basic-service-candidate.md](windows-basic-service-candidate.md); the separate
[Windows inventory profile](windows-inventory-dashboard.md) is the default manual
gate selection. Selecting it is not approval to run it.

## Separate ordinary-CI read-only measurement

`windows-prerequisites.yml` runs a separate `cmd/windows-prerequisites` executable
on the disposable hosted Windows image. It only reads KnownFolder/layout, local
filesystem facts, current administrator elevation, existing ancestor descriptors
and fixed resource absence. Its sole CLI mode cannot dispatch the manual native
controller or any service/ACL/identity mutation. It does not collect telemetry.
The clean checkout, GitHub SHA and compiled source are bound independently.

Its finite `tracebolt.windows-prerequisites.v2` result is `supported`, `blocked`
or `unverified`, with one finite check/reason and a closed first-failure
[ancestor diagnostic](windows-prerequisite-diagnostics.md) when that check blocks. `supported` means only that the
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
commit SHA, an exact `collection_profile` and `transport_profile`, and every
applicable scope below. All seven approval booleans default to false. The only
valid pairs are `basic-readonly-v1` + `tls`, `windows-inventory-v1` + `tls`
(the default selection), and `windows-inventory-v1` + `http-test`. No automatic
matrix, transport fallback or existing-identity reuse is supported.

The five shared approvals are:

1. `services`: create the fixed `TraceboltWindowsAgent` LocalService SCM
   service and the separate `TraceboltWindowsAcceptanceProbe` LocalService
   service; start/stop/restart them and delete their verified registrations.
2. `identity`: create one temporary endpoint enrollment identity and
   protected private state; deliberately approve its captured fingerprint and
   comparison value against a disposable fixture authority.
3. `app_acls`: create only new Tracebolt app directories/files with their
   explicit ACLs. Existing resources are never adopted or repaired.
4. `loopback_transport`: create temporary memory-only fixture authority and two
   local listeners using the explicitly selected transport; send real selected-profile
   telemetry only to that disposable peer. TLS uses normal TLS1.3 and client
   certificates. HTTP-test uses the production signed-request verifier and provides
   no confidentiality or server authentication.
5. `cleanup`: delete only the newly owned test services and app files
   after receipt, object ID, content hash and manifest checks. Unexpected or
   incomplete resources are retained with a failed cleanup result.

`inventory_metadata` must be true for Windows inventory and false for basic.
It approves the bounded process/service/software names, hostname/interface
addresses and CPU/RAM/system-volume observations inside the disposable peer.
`http_plaintext` must additionally be true only for HTTP-test. It explicitly
acknowledges plaintext invitation/enrollment/inventory data, forgeable peer
responses and the fact that signatures do not encrypt traffic. A TLS selection
rejects this extra acknowledgement rather than treating it as downgrade consent.

The action-time request must name the exact commit, workflow and disposable
runner, the above objects/identity/permissions/telemetry, and bounded cleanup.
It must disclose the prerequisite below and that a failed run can retain test
resources until runner destruction. An earlier request to implement Windows
support is not approval to dispatch this gate. Never reuse an approval for a new
source commit. There are no user computer targets or external manager credentials
in this workflow. The user's existing HTTP-test manager is not contacted or
silently treated as TLS. Proving this HTTP loopback selection would establish
only its selected transport path, not acceptance against that manager. There is
no dispatch command in this guide.

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
mutating driver calls, including an exact selection match against the driver.
The selection is also bound to the bootstrap, trust display, claim and final report. Main work is bounded to ten minutes; failure cleanup has
its own two-minute cancellation window using the same still-valid scope. The
wrapper's process deadline includes that cleanup interval. Cancellation does not
grant permission to adopt incomplete state or erase an ownership fence.

## Read-only provisioning prerequisites and native proof

Existing ancestors must pass trusted owner/non-replaceable writer, supported
ACL-shape and canonical local-path checks. An explicit LocalService-named read
ACE on each volume/Program Files/ProgramData ancestor is not required: enabled
groups, inherited grants and applicable ordered denies are evaluated by Windows
when the actual SCM process opens them. Actual runtime opens remain
authoritative. Executable traversal now also requests directory listing to make
its no-delete-sharing pins effective; protected-state listing remains unchanged.

The final executable retains its sufficient LocalService read/execute DACL
policy, and private state retains its exact service-SID protection. New app-owned
creation ACLs remain unchanged. See the [trust/access
contract](windows-runtime-read-preflight.md) for the distinction.

The ordinary read-only prerequisite job on exact source
`5bd1340f431b79e64d83d0049c1da8dcd370c27b` observed `blocked`, `ancestor-policy`,
`prerequisite-blocked` under the previous explicit-ACE rule. It proved neither
LocalService denial nor an unsupported Windows OS. A later static policy pass
also cannot prove runtime access. The separately approved native gate must
observe real image startup, limited token, runtime state opens and reporting.

No branch adds an ACE to a drive root, Program Files, ProgramData, Users or any
other existing directory. Do not change OS-managed ACLs merely to pass a test.
Other prerequisites are elevated administration, supported physical local NTFS,
persistent ACLs, no reparse points or case-sensitive directory semantics, and
absence of both fixed services and both app parents. Preflight pins existing
ancestor handles and never adopts or empties existing resources. If runtime
opens fail under the real SCM token, native acceptance fails; the controller
cannot promote policy-only support into a runtime pass.

## What a successful native subset would prove

The controller emits exactly fourteen finite outcome checks:

1. Read-only prerequisites passed.
2. App-only create-new provisioning matched source-bound artifacts.
3. Ordinary service install and protected state preparation completed.
4. One pending claim was committed under the selected profile/transport and
   explicitly checked public trust. HTTP does not claim server authentication.
5. The actual main service process token was LocalService with its enabled,
   owner-capable service SID, no enabled Administrators group and only
   `SeChangeNotifyPrivilege`. The SCM PID is rechecked after querying it.
6. A real pending service ran for at least five seconds, then stopped with zero
   ordinary and service-specific exit codes while preserving its original claim
   and approval deadline. Failed stopped services cannot count as orderly Stop.
7. On restart, explicit matching fixture approval activated that same identity
   and the ordinary sender delivered a profile-valid frame over the selected
   real loopback transport.
8. `profile_report` proves that the peer accepted the exact selected contract.
   For inventory, the real service collector/sender must supply healthy or partial
   CPU/RAM/disk and all five scoped inventory sections. Denied or unavailable
   sections remain in the finite report and fail this usable-inventory check;
   they are never promoted to empty or complete coverage. Partial/truncated
   observations remain explicitly partial. Basic cannot satisfy inventory proof.
9. A separate real LocalService process with another service SID was denied
   read opens of the initialized main private key and sender state with Win32
   `ERROR_ACCESS_DENIED`; absence, sharing violations and sentinels cannot pass.
10. A peer outage produced a real unavailable request without receipt progress;
    Stop retained the sender's durable pending generation.
11. Restart during that outage retained exactly the same pending bytes and
    sequence without a new claim or reset.
12. Recovery accepted same-identity progress; Stop left no pending generation.
13. Ordinary uninstall removed the SCM registration while retaining the verified
    private state unchanged.
14. Receipt/ID/hash-bound cleanup deleted only the newly owned resources through
    retained handles; unknown children or changed bindings cause retained failure.

A success is named `passed_native_subset`. The v2 report records the exact
`selection`, bounded inventory frame count and eight finite quality labels,
`loopbackPeerExercised`, and `nativeInventorySenderExercised`. Its terminal
current-state fields require the services stopped/uninstalled, no pending
sender generation and no retained cleanup resources. No row, hostname, address,
process name or metric value is exported. A partial quality does not establish
whole-machine completeness. A pass cannot be promoted to full deployment acceptance.

## Fixture boundaries and outstanding gates

The native peer in `internal/windowsacceptance/fixture` uses real enrollment
proofs, state transitions, issuance and the production `lanstore`/`windowsmanaged`
frame decoders. HTTP uses the production `signedhttp` verifier with the exact
Windows path, issued certificate and current activated identity. Strict sequence,
generation and capture-time progression follows exact-duplicate handling. It holds its
issuer and invitation only in process memory and listens only on IPv4 loopback,
under the exact selected TLS1.3 or explicitly acknowledged HTTP-test transport.
The ordinary Windows service uses its actual protected identity, real
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
The report always keeps `productionManagerExercised`, `productionIngressExercised`,
`sharedDashboardExercised`, `hiddenConsoleExercised`,
`osShutdownExercised` and `osRebootExercised` false. Source cross-builds are not
native proof. Persistent Event Log diagnostics remain separate from finite SCM
and console codes.

## Safe evidence and failure handling

Only a strictly validated bounded JSON report with exact source, finite stages,
finite reasons, selected profile/transport, bounded counts/quality labels, booleans
and the fourteen outcome names is retained. The wrapper
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

### Scoped ProgramData path binding

The [path-binding correction](windows-path-binding.md) permits only specific
ProgramData add-file/EA/attribute rights alongside real directory pins and
component-relative no-reparse create-only provisioning. Destructive grants,
untrusted owners, final binary checks and private-state protections remain
unchanged. Source/injected fixtures and a read-only policy pass leave the native
race, real token, service, cleanup, manager, console and reboot gates outstanding.
