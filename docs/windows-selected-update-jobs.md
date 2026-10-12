# Selected cached Windows update jobs: foreground source candidate

This source increment connects a separate manager job domain to enrollment-owned
storage, TLS relay ingress, named-operator request/review/approval/status and the
compact EN/DE Updates view. The composed source now connects the dedicated
[WUA adapter](windows-cached-update-adapter.md) through an explicitly administrator-
launched foreground executor and authenticated update-only local IPC. It opens only
already-provisioned exact protected state; a native provisioning workflow is not
supplied. No host grant, process/SCM ACL change, update installation, reboot, native
Windows acceptance or release is established by this source work.

## Authority and activation

`windows-selected-cached-update-install-v1` is a fresh, explicitly acknowledged,
default-off local scope. Its immutable binding includes manager, device, original
identity anchor, executor ID, distinct executor-public-key pin, grant ID and
manager permit key. Neither existing observation consent/receipts, Read admin,
Linux package permissions nor selected Windows service control authorizes it.
The observer remains restricted LocalService; installation is never a broker
opcode or an expansion of observation privileges.

`SetupWindowsUpdateJobsCreateOnly` is an explicit source provisioning seam. It
creates only the separate manager tables and reciprocal immutable credential
marker using supplied public keys/consent. It never creates a key or host grant,
and refuses an existing domain rather than adopting, resetting or repairing it.
There is no shipped setup command for the elevated executor. Incomplete or
missing used records/markers/tables fail closed.

The optional protected LAN setting `windowsUpdateJobsConfigFile` is absent by
default. When explicitly configured it requires TLS, Windows inventory enrollment
and named operator authentication. `windowsupdatemanager.Load` only opens existing
provisioned state, rechecks exact protected config/key material, validates the
full manager origin/profile/issuer/collection binding, and rejects key reuse with
enrollment, issuer, TLS, service or package action domains. The separate protected
configuration is:

```json
{
  "version": "tracebolt.windows-selected-update-manager-config.v1",
  "enabled": true,
  "binding": {
    "managerId": "<existing manager ID>",
    "deviceId": "<existing Windows device ID>",
    "incarnationDigest": "<original identity anchor digest>",
    "executorId": "<fresh executor ID>",
    "executorKeyId": "<separate executor public-key digest>",
    "grantId": "<fresh local consent grant ID>",
    "keyId": "<separate manager permit-key digest>"
  },
  "privateKeyFile": "/absolute/protected/windows-update-command.key"
}
```

These placeholders are not runnable setup instructions or permission to provision.
The operator must explicitly have `windows_update_install`; no existing account
receives it automatically. Approval reuses current named-session, Origin, CSRF and
short mutation-lease guards. Dispatch rechecks that the original approving actor
still has this capability after a manager restart.

## Bounded request, review, approval and result

1. The operator selects one exact nonzero lowercase WUA GUID and explicit
   nonnegative 31-bit revision from the current captured Updates rows. Selection
   is intent only: an inventory row cannot prove install readiness.
2. The manager durably creates one finite, exact manager-signed readiness challenge.
   The challenge carries a separate monotonic signed readiness sequence. The
   observer can poll metadata and claim that challenge once. A lost claim is
   not redelivered. No native/network work runs under the operator session lease.
3. A report must be signed by the separately pinned executor key and bound to the
   exact challenge digest, selection, original binding, capture and deadline.
   Observer TLS possession alone cannot invent readiness or a result.
4. A ready report produces an immutable preview. The operator must explicitly
   reopen/review it and check the initially unchecked acknowledgement. The preview
   expires within 60 seconds of its original readiness capture and never outlives
   the challenge, consent or approving current leaf. Refresh never renews it.
5. Approval saves one purpose-separated Ed25519 install permit and original start
   deadline. Exact approval replay returns saved state without a new signature,
   sequence or expiry. Only one live unsigned preview is admitted.
6. Installation delivery is consumed before bytes are returned. A separate endpoint
   ledger consumes the exact signed sequence before native preparation, and saves
   `Attempted` before the single native adapter call. Crash, timeout, uncertain
   persistence or a lost claim never triggers another installation attempt.
7. Signed per-update results preserve the permit digest, WUA result code/HRESULT,
   attempted truth and reported reboot requirement. The dedicated executor signs at the actual completion time and saves the
   exact signed report atomically with the result. Identical signed result retry
   is idempotent; a conflicting result never overwrites the saved one. A timeout,
   partial WUA result or failed result write remains uncertain or intervention-required.

There is one replaceable unsigned readiness slot. Rejected readiness checks and
expired unsigned previews do not consume permanent operation capacity. The first
source contract retains at most **32 approved jobs per admitted endpoint identity and its fixed local update
grant for that scope’s lifetime**, not a manager-wide shared allowance;
all their permits, claims and results remain, including expired/uncertain jobs.
There is no pruning, reset or backup-rollback recovery. Capacity exhaustion is
explicit in the API/UI. A failed or uncertain attempted update blocks later jobs
pending separately reviewed intervention; it is never silently retried.

Operator endpoints are `GET /api/devices/{id}/windows-update-jobs`, and POST
`.../request`, `.../preview`, `.../approve`. Source TLS relay endpoints are POST
`/v1/windows-update-jobs/{poll,readiness-claim,install-claim,report}`. They use strict
bounded canonical framing. Polls and operator views contain no execution envelopes,
keys or source error prose. Runtime ingress admits only the bound endpoint's
currently activated TLS leaf, plus pinned executor signatures for reports.

## Readiness and dedicated executor contract

The initial selection is exactly one already-downloaded software update. Every
fact has an explicit known/unknown representation; missing data fails readiness.
The contract rejects installed/hidden/nonsoftware updates, any bundle (including
an unreadable bundle count), unaccepted EULAs, prompts, source media, network
requirements, busy installation and a reboot required before installation.
Reboot behavior must be known; a later restart may still be required.

The separate source-only `PrepareExact`/`Inspect`/`InstallOnce` adapter pins the exact
WUA object after fresh exact cached resolution for each execution and rechecks
the same facts immediately before dispatch. `IsInstalled` is a search-time
snapshot, not a fresh applicability scan when reread from that object
([Microsoft IsInstalled contract](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-get_isinstalled)). It must retain
cached-only search with `Online=false` and `CanAutomaticallyUpgradeService=false`
and mandatory readback, no source registration, no self-upgrade, no forced install,
no source prompts, no Tracebolt-requested forced application closure and no
automatic restart. WUA installation can still interrupt applications; installer
flags do not establish a general no-disruption guarantee
([IUpdateInstaller3 scope](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdateinstaller3)). It
must never silently substitute another revision, bundled update or selection.
The supplied `InactiveExecutor` always returns unavailable and never calls WUA.

Microsoft documents [IUpdateInstaller as Administrator-only](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa387103(v=vs.85)).
Its [Install method](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdateinstaller-install)
is synchronous and requires checking installer busy state. The selected update's
[IUpdate properties](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdate)
provide identity, cached-content, EULA, bundle and source-media facts;
[IInstallationBehavior](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iinstallationbehavior)
provides interaction, network and reboot behavior. These APIs establish the design
requirements, not native acceptance of this source contract.

## Executor readiness, status and exact evidence outbox

`OpenExecutor` requires an explicitly supplied dedicated Ed25519 private key and
verifies both its seed/public correspondence and the exact stored executor pin.
It opens only the already-protected `executor.json`, `started.json` and
`receipt.json`; it never initializes, adopts or repairs them. Key custody
and create-only provisioning remain separate native gates. The composed foreground
runtime below opens this state and supplies the dedicated local relay transport.

`Executor.Readiness` verifies the manager signature, immutable binding, exact
selection, original issue/deadline, current local leaf, local revocation and
consent. It durably consumes the signed readiness sequence before any adapter
access, then calls only `PrepareExact`, `Inspect` and `Close`. The source must
return an exact fresh bounded capture; failures never manufacture a fresh
capture. Known ineligible and unknown facts can be signed honestly, and the
manager blocks them. A final local authority/time fence and durable report write
precede release of signed bytes. Every durability wait is followed by a fresh
non-writing clock check; an expiry discovered there retains its rejection floor
before returning. Capture must be at or after the immediate pre-source check,
not merely the earlier claim. The install path likewise reacquires current local
authority after consuming the permit and before native preparation. Installation
is never called by readiness.

Issue/deadline timestamps alone were not strictly increasing: blocked checks can
be replaced in the same second. The manager now retains a separate 64-bit
readiness sequence, with no wraparound, and the enrollment transaction rejects
rollback or sequence reuse for a replaced challenge. The executor keeps only a
monotonic consumed sequence and one latest readiness slot. Older or out-of-order
challenges cannot reread the source, including after restart. This does not spend
the separate 32-approved-install lifetime allowance, and rejected readiness
checks do not build an unbounded ledger. This is a fresh development schema;
older/missing fields are not silently adopted and there is no migration/reset
path for used state.

`Executor.Status` provides exact job/selection/reference digests, original
claim/deadline/completion times, attempted truth, remaining installation
capacity, intervention status and whether each report is missing, available or
expired. It supplies no execution envelope, signature, key or source error text.
It is operation-read-only: only the durable observation clock floor may advance.
It neither scans WUA nor changes a job outcome. A consumed job with no completed
result remains intervention-required; absence is never evidence that an attempt
did not run or that Windows rolled it back.

`Executor.Outbox` requires the report kind, job ID and exact challenge/permit
digest. It returns a copy of only the already-persisted signed bytes under current
local authority. Readiness is retained in the one latest slot; every installation
report stays with its immutable attempt. Result issue time is the actual original
completion time and expiry is at most 300 seconds later, even when completion
itself is after the original dispatch deadline. The start deadline is never
extended. After report expiry, status still shows the original evidence but the
outbox returns expiry; it cannot renew the signature or completion time. There is
no acknowledgement-driven deletion, signing-on-read, reinstall or recapture.

A crash before the consumed write cannot reach the source. A crash after it
cannot repeat that challenge. A missing completion/report after an installation
crash remains unknown; if the atomic result/report write completed but its reply
was lost, the exact saved bytes can be relayed while still valid. A result without
its required signed report is an integrity failure, not a recovery opportunity.
The manager may recognize a byte-identical report it already accepted even after
expiry; that idempotence does not authorize a new or refreshed report. A missing
manager claim reply likewise cannot be reconstructed by endpoint status.

## Renewal, revocation and uncertainty

Manager state commits inside the same enrollment SQLite transaction as current-leaf
admission and retirement. Original identity/consent/capture/permit bytes stay fixed
across same-key renewal. Final before-commit checks repeat current-leaf expiry,
revocation, scope, deadline and clock checks, plus live configuration and the
original approving operator’s current capability. Operator routes supply a trusted
live clock and recheck the same active session at that fence; bounded request-body
reads happen before the short session mutation lease is reacquired. Successful reads and rejected/expired
requests retain monotonic observation/rejection floors so clock rollback cannot
revive old authority. No envelope is returned when its transaction fails.

After a valid permit is delivered, manager revocation cannot retroactively cancel
it or a WUA operation. The endpoint can check protected local consent/current local
credential state immediately before dispatch, but a disconnected executor cannot
promise instantaneous knowledge of manager revocation. Deadline expiry, canceling
or killing a helper likewise does not prove Windows stopped installation or rolled
it back. That uncertainty remains durable and blocks a replacement attempt.

## Remaining native and release gates

- Separately approved protected executor state/key/public-pin provisioning and
  explicit local installation/process-query consent
- Native acceptance of the separate cached exact-readiness/installation adapter,
  including owned worker/cancellation behavior and per-update result truth
- Native acceptance of the integrated observer relay and administrator-launched
  foreground command; source wiring does not start either on a Windows host
- Separately authorized native acceptance, including renewal/retirement races,
  protected state/ACL checks, lost claim/result, timeout and pending reboot cases
- Actual deployment, binary release and publisher authentication

Source tests and cross-builds are not full Windows patch management, compliance,
CVE coverage, complete cache coverage or a promise that an update is safe for a
particular machine. Existing cached inspection and read-only receipts remain
unchanged. See [Windows update runtime](windows-update-runtime.md),
[service action boundaries](windows-service-actions.md) and
[automatic certificate renewal](automatic-certificate-renewal.md).

## Composed source bridge

The typed observer loop, dedicated cached-only adapter, signed durable executor
state, local current-authority adapter and fixed authenticated IPC are now wired
in source. The following section describes their exact boundaries and the
remaining separately approved native provisioning/acceptance gates.

## Foreground dedicated executor and authenticated local transport (source candidate)

The current source composes the signed executor ledger, cached-only WUA adapter,
fresh observer relay, and a separately administrator-launched foreground command.
This is a usable source entry path once its exact protected state is separately
provisioned. It is not a released installer, a service installation, or native
Windows acceptance. Source fixtures and Windows cross-builds grant no host rights.

The dedicated binary is `tracebolt-windows-update-executor.exe`, fixed under the
machine KnownFolder Program Files `Tracebolt` directory. Start it explicitly as
an administrator with `--run-foreground`. There is no alternate configuration or
IPC-supplied path, SCM entry point, account creator, key generator, state reset,
repair, or adoption command. Existing observation/service-control permissions
cannot activate it. The observation client imports only the public update IPC
client and cannot read the executor signing key or call the installer adapter.

The separate `Tracebolt\windows-update-executor` ProgramData root must already
be a valid `windowsstate` SYSTEM/Administrators-only store with the exact schema
returned by `windowsupdateipc.StoreOptions()`. Its immutable `config.json`
contains only public configuration: exact install consent/binding, independent
manager/executor public pins, the expected executable path/hash, the completed
observation-service ownership receipt, and explicit process-query acknowledgement.
`executor-key.json` has version `tracebolt.windows-update-executor-key.v1` and the
already-provisioned dedicated Ed25519 private key. `started.json` and `receipt.json`
are the original exact consent bytes. `executor.json` is the validated used ledger.
Missing, replaced, incomplete, foreign, or uncertain state fails closed; opening
this command never creates it. The private key and used ledger are never included
in the public configuration digest, IPC, output, logs, or source artifacts.

Fresh observer relay consent includes `executorPeer`: the exact public binding,
executor public key, executable path/hash and canonical public configuration
SHA-256. Old or missing pin shapes do not activate the transport. Public peer proof
uses a purpose-separated Ed25519 signature over a new 32-byte nonce, exact binding,
held server PID and process creation time, and both public digests. The client
independently holds the server process, compares its actual image path and creation
time, and rechecks liveness and named-pipe PID before and after traffic. It does
not pretend a foreground process has SCM executor identity, open a foreign token,
or read the private executable/key. The server pins and hashes its protected own
executable and rechecks exact configuration/current authority before signing.

A foreground elevated process normally needs a deliberately allowed peer query.
The optional `--allow-observer-process-query` flag is accepted only together with
`observerProcessQueryAcknowledged: true` in the fresh protected public config.
The verified existing observation service SID/receipt is the only recipient.
The source path preserves and validates the current process DACL and adds only
PROCESS_QUERY_LIMITED_INFORMATION plus SYNCHRONIZE (0x00101000) for that SID.
It changes no token, thread, default DACL, account, SCM, firewall, or network rights.
The permission lives only for this foreground process lifetime. Without both
acknowledgements, an absent exact process-query ACE fails closed. Actually invoking
this permission change is a separately approved native security action; this
source work does not invoke it.

The update-only fixed pipe is `\\.\pipe\Tracebolt.Windows.SelectedUpdate.v1`.
It uses a retained first instance, local-only byte frames, explicit client access
that excludes FILE_CREATE_PIPE_INSTANCE, IDENTIFICATION-level client QoS, bounded
frames/timeouts, and drained overlapped cancellation. Before any action, the server
verifies the exact current observation SCM process and isolated last-read pipe
identification token. The identification thread performs no storage, network,
action, or COM operation. Failed token reversion strands that thread and stops the
server. No service-control, generic-command, key, reset, or report-refresh opcode
exists. Every client call obtains a fresh server proof; connected writes are never
retried.

Submission now calls `Accept`, which durably consumes the original permit before
acknowledgement without opening WUA. A private one-use in-memory capability passes
to one independent bounded operation owner via `RunAccepted`; it cannot be
serialized, reconstructed after a restart, or used by a different executor. The
single native install is never owned by the short pipe connection. A disconnect
or lost acknowledgement permits only Status/Outbox reconciliation, never another
submit. Readiness is blocked by unresolved installation state. Short preparation
can return immediate busy; the potentially 30-minute install runs outside the
ledger mutex so status and exact outbox remain accessible. Restarted unfinished,
failed, or uncertain attempts require intervention and block new installation.

The final adapter-owner dispatch fence reacquires the current installed activated
TLS identity, exact fresh local relay/config/consent and current leaf. It checks
the original signed start deadline, fresh durable clock floor and shorter current
leaf/consent bounds after potentially blocking work, then samples time again. This
is a start gate, never a new installation-duration deadline. Local authority uses
fresh protected reads rather than holding a global credential lock during the
installation; it cannot guarantee instantaneous remote revocation. Native work
still retains all cached-only, exact-revision, no-download, no-EULA, no-app-close,
no-reboot and at-most-once safeguards from the reviewed adapter.

Required release gates remain: separately approved create-only native provisioning
of exact protected state/keys/public pins, both supported Windows architectures,
restricted-observer mutual proof and negative identity/ACL cases, actual bounded
foreground lifecycle, controlled exact cached-update acceptance, disconnect/crash
reconciliation, and operator-visible original result delivery. No native command,
installation, process-ACL change, key grant, or WUA action was run for this source.
