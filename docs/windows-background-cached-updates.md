# Fresh background cached Windows Update service

Source candidate only. No native setup, credentials, ACL/SCM change, Windows
Update execution, reboot or release is established by these fixtures/builds.
The native acceptance gate below remains separately approved and pending.

This fresh manual-only profile extends the existing reusable-MSI paired setup.
After one explicit endpoint setup and activation, named central approvals reach a
separate background WUA service through the unchanged restricted observer relay.
Each job still selects one exact cached GUID/revision, checks current readiness,
requires its own initially unchecked approval, and saves its independent signed
outcome. Setup does not authorize any installation.

## Authority and risk

The dedicated own-process LocalSystem account has high machine privileges and
machine-network access. Update/native/custom code is not sandboxed. The initial
boundary is Windows x64 on a non-domain-controller. The observer remains its
existing restricted LocalService identity. Its service-object rights are only
query/config/status/read-control; its rights on this executor process are only
query-limited/synchronize. It receives no service start/control, token, key,
executor-state or shared-fence rights.

Fresh WUA consent v4, registration v2, service configuration v1, service receipt,
key domain, observer relay v3 and shared plan/roster/activation v3 are create-only.
They cannot adopt foreground v1, scheduling v2, coordinated v3, prepared-MSI or
existing reusable foreground state. The existing foreground entry still rejects
service tokens and requires its original elevated interactive nonzero session.
Scheduling is excluded. A later combined scheduling profile needs separate consent.

The service reads protected public agent configuration, original certificate,
renewal manifest, activated ready marker and exact relay consent. It never calls
the enrollment private-key loader or builds an HTTP client. Double-read current
leaf/generation checks surround blocking runtime checks; a final clock sample
follows storage/lock waits. Renewal preserves original identity and fixed grant
expiry. A disconnected endpoint cannot learn a later manager revocation until
its authenticated relay or local authority changes; no online-revocation claim
is made by a local snapshot.

Fixed resources:

- Service: `TraceboltWindowsCachedUpdate`
- Image: `Program Files\Tracebolt\tracebolt-windows-update-service.exe`
- Executor state: `ProgramData\Tracebolt\windows-update-service`
- Relay: `ProgramData\Tracebolt\windows-agent-background-update-job-relay`
- Pipe: `\\.\pipe\Tracebolt.Windows.CachedUpdateService.v1`
- Shared owner: existing `ProgramData\Tracebolt\windows-mutation-fence`

Protected held image handles, exact own-process SCM account/PID, held process
creation time and fresh signed nonce bind the service peer. The pipe accepts
only the proven observer, using identification-only token acquisition with
verified immediate reversion. No native or state operation runs impersonated.

## Fresh setup and activation

Prepare the separate WUA offer and reusable-MSI v3 offer with their existing
manager setup tools. Keep the original absolute expiry and original protected
inputs. Review exact source-built x64 MSI-service and new update-service artifacts.
Under the existing stopped-observer lifecycle lease, use the paired command with
all its existing named inputs plus `--background-updates`:

```
tracebolt-windows-service.exe --coordinated-mutations-provision --background-updates --msi-manager-offer C:\Reviewed\msi-offer.json --msi-service-file C:\Reviewed\tracebolt-windows-managed-msi-service.exe --msi-artifact-manifest C:\Reviewed\msi.manifest.json --update-manager-offer C:\Reviewed\wua-offer.json --update-executor-file C:\Reviewed\tracebolt-windows-update-service.exe --update-artifact-manifest C:\Reviewed\wua-service.manifest.json
```

Apply repeats the exact inputs and reviewed digest, requiring all unchecked
acknowledgements: `--apply --approve <digest>`,
`--acknowledge-coordinated-mutations`, `--acknowledge-managed-delivery`,
`--acknowledge-reusable-managed-jobs`, `--acknowledge-selected-updates`,
`--acknowledge-background-updates`, `--acknowledge-localsystem-risk`,
`--acknowledge-observer-relay`, `--acknowledge-observer-process-query`.

The shared durable intent precedes both keys. Exact local config, image custody,
used ledger, disabled SCM service and relay must complete before the immutable
paired activation record. Both services remain disabled and the observer stays
stopped. Partial setup is fenced; never retry, reset, repair or adopt it.

Finalize MSI registration first, then the matching WUA registration. WUA finalize
returns a purpose-separated manager-signed background registration receipt only
after both durable registrations and exact protected MSI/WUA manager completion
receipts and configuration proofs. A database marker alone is insufficient. Save
this public receipt for endpoint activation. Preserve the original input and both staged LAN configs. Compose the
separate activation LAN config as described in
[coordinated setup](windows-coordinated-mutations.md), retaining both exact domain
references. Start the manager/observer only with their separately approved host
steps. Explicitly activate the MSI service with its configuration digest and the same
public WUA registration and manager receipt:

```
tracebolt-windows-service.exe --managed-msi-activate --apply --approve-config sha256:<MSI config digest> --background-registration C:\Reviewed\wua-registration.json --manager-activation C:\Reviewed\wua-manager-activation.json --acknowledge-start-localsystem-service
```

Only this fresh background pairing requires those two public inputs. Its MSI
activation record independently verifies their exact WUA roster participant; the
MSI service never reads WUA private state. Both manager registrations therefore
precede activation of either service.
Activate WUA using its returned `wuaConfigDigest` and exact manager receipt:

```
tracebolt-windows-service.exe --background-updates-activate --apply --approve-config sha256:<exact public config digest> --manager-activation C:\Reviewed\wua-manager-activation.json --acknowledge-start-localsystem-service
```

Activation durably records intent before changing the disabled service. An
uncertain response never invites another start/reconfiguration attempt. Confirm
SCM and fresh signed executor evidence separately; submitted activation or saved
configuration is not proof of running. Observer-only uninstall and every legacy
mutation setup reject the new service/state/relay namespace rather than orphaning
or silently coexisting with it. This slice has no automatic removal/repair flow.

## Jobs, shutdown and durable uncertainty

The existing cached-only readiness/install kernel is reused unchanged: downloaded,
accepted-EULA, noninteractive, nonbundled exact GUID/revision only; no download,
EULA acceptance, reboot, repair, arbitrary commands or retry. Domain consumption
precedes shared reservation; domain Attempted and shared dispatch intent precede
native work. The separate final authority hook runs at the actual COM syscall
edge after blocking preparation and durability waits.

The original grant has 32 WUA jobs for its fixed lifetime. One-time setup never
means unlimited or perpetual authority. Scheduling reservations in separately
consented older profiles are not refunded by cancellation/expiry; this manual-only
profile cannot create them. Reusable MSI and WUA continue to share one durable
owner. Signed outcomes/history remain independently attributable to each domain.

Stopping closes admission and cancels bounded callers. A caller timeout is not
native completion. The service remains STOP_PENDING and advances SCM checkpoints
while it waits for the actual COM owner thread, every reference release and
apartment cleanup. There is no process timeout that reports a clean drain or
releases the shared owner. Forced process death, SCM disappearance or reboot
cannot clear durable uncertainty. Late native completion never overwrites the
saved uncertain result. Only existing exact saved settled completion evidence
can release the shared owner; there is no automatic unlock or native replay.

The Updates UI shows a compact background/manual-only profile. A fresh signed
active shared-status capture is labelled recent evidence; configuration alone or
expired evidence means unknown. Neither label asserts that the service is
currently running. Critical unknown/freshness, outcomes and shared ownership stay
visible; extra explanation remains collapsed.

## Required native acceptance (pending)

With separate explicit approval on a disposable Windows x64 non-DC:

1. Verify exact source hashes/artifact manifests; stage fresh paired authority,
   validate both disabled services and exact config/image/receipt/relay/roster.
2. Show omitted acknowledgements, old grants, wrong account/image/PID/creation
   time/nonce and a sibling LocalService process are denied. Verify observer
   cannot start/control services or read executor keys/state/shared ownership.
3. Finalize both registrations; prove missing/wrong manager activation receipt
   cannot start WUA. Explicit activation should survive normal service restart
   without a repeated foreground elevation. Do not test on a user workstation.
4. Use one specifically reviewed cached downloaded accepted-EULA update. Record
   readiness, separate named one-time approval, exact native result and restart
   outbox/history. Reject alternate revisions, bundles, terms/download needs,
   expired/replaced leaves and local revocation after blocking waits.
5. Compete inert/admitted MSI and WUA starts: only the shared owner reaches native
   work. Stop during blocked native work/cleanup: retain STOP_PENDING and the
   durable owner. Forced termination/reboot must retain uncertainty and prevent
   replay or replacement. Do not unlock by deleting state or elapsed time.

These are acceptance source requirements, not an executed native pass or host
permission. Existing hosted fixtures are synthetic and do not establish SCM,
NTFS, token, COM or Windows Update acceptance.

A separate fresh [scheduled background profile](windows-scheduled-background-updates.md)
adds explicitly approved bounded UTC windows. This manual-only v4 profile and its
original consent/receipt bytes remain unchanged; it cannot adopt scheduling.
