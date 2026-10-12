# Selected cached Windows update jobs: inactive native source candidate

This source increment connects a separate manager job domain to enrollment-owned
storage, TLS relay ingress, named-operator request/review/approval/status and the
compact EN/DE Updates view. It does **not** supply a usable native Windows update
installer. No host grant, service/ACL change, download, EULA acceptance, update
installation, reboot, native Windows execution or release is established.

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
   The observer can poll metadata and claim that challenge once. A lost claim is
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
   attempted truth and reported reboot requirement. Identical signed result retry
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

The future native `PrepareExact`/`Inspect`/`InstallOnce` adapter must pin the exact
WUA object after fresh exact cached resolution for each execution and recheck
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

## Still inactive / remaining gates

- Separate elevated executor identity, protected command/executor key custody,
  fixed relay IPC and create-only local provisioning/consent UI
- Native cached exact-readiness and WUA installation implementation, with owned
  worker/cancellation behavior and native per-update result truth
- End-to-end observer relay runtime loop; this increment supplies manager ingress
  and source contracts but does not start a polling helper on a Windows host
- Separately authorized native acceptance, including renewal/retirement races,
  protected state/ACL checks, lost claim/result, timeout and pending reboot cases
- Actual deployment, binary release and publisher authentication

Source tests and cross-builds are not full Windows patch management, compliance,
CVE coverage, complete cache coverage or a promise that an update is safe for a
particular machine. Existing cached inspection and read-only receipts remain
unchanged. See [Windows update runtime](windows-update-runtime.md),
[service action boundaries](windows-service-actions.md) and
[automatic certificate renewal](automatic-certificate-renewal.md).

## Next source bridge

1. Add the observer's fixed typed relay loop beside the existing Windows action
   client transport. It may move opaque manager permits and executor-signed
   readiness/results through the dedicated update routes only. Add durable
   readiness-challenge consumption, read-only executor status and an exact-byte
   signed-result outbox; expired signatures must not be renewed to retry results. It must neither
   interpret an update command as a service-broker opcode nor hold the executor's
   private signing key or gain elevated observation rights.
2. Implement the dedicated executor's native WUA adapter behind `PrepareExact`,
   `Inspect` and `InstallOnce`: one cached software update, exact GUID/revision,
   retained native object, all readiness facts rechecked, and durable attempted
   state before one call. The preview deadline bounds starting the attempt, not
   the duration of a WUA operation; the native adapter needs a separate bounded
   operation-duration and uncertainty contract. Keep downloads, EULA acceptance, source changes and
   restarts outside this contract; report per-update outcomes without automatic
   retry after lost delivery, timeout or uncertainty.
3. Integrate fixed local IPC and separately reviewed protected provisioning only
   after their host authority is approved. Exercise native acceptance before
   describing the source foundation as operational patching. Manager-only source
   wiring and cross-builds do not activate these host components.
