# Fresh coordinated MSI and cached Windows Update setup

This is a source candidate. Fixtures and cross-builds do not authorize endpoint
setup, keys, ACLs, SCM changes, a package/update installation, native acceptance
or release. No native action has been performed by these checks.

The fresh profile pairs central managed MSI delivery/install with the existing
explicitly administrator-launched cached WUA executor. Their independent keys,
grants, IPC, ledgers and original identity remain separate. The observer remains
LocalService. Prepared-MSI v1 and service-control brokers remain incompatible.
Existing standalone state is not adopted or migrated.
The separate [fresh reusable MSI v3 profile](windows-reusable-managed-msi.md)
adds explicit reviewed retirement and another independently approved MSI job under
the same original grant. The v1 paired profile described below is unchanged.

## One reviewed fresh setup

Prepare both separate manager offers against the same currently activated TLS
endpoint and original incarnation, with distinct manager signing keys. Review the
matching MSI-service and update-executor artifact manifests. Stop the owned
observer, then use the matching source-built Windows service CLI to review:

```
tracebolt-windows-service.exe --coordinated-mutations-provision --msi-manager-offer C:\Reviewed\msi-offer.json --msi-service-file C:\Reviewed\tracebolt-windows-managed-msi-service.exe --msi-artifact-manifest C:\Reviewed\msi-service.manifest.json --update-manager-offer C:\Reviewed\update-offer.json --update-executor-file C:\Reviewed\tracebolt-windows-update-executor.exe --update-artifact-manifest C:\Reviewed\update-executor.manifest.json
```

Apply repeats all those inputs and requires the exact reviewed digest plus every
initially absent acknowledgement:

```
--apply --approve sha256:<exact combined plan> --acknowledge-coordinated-mutations --acknowledge-managed-delivery --acknowledge-one-managed-install --acknowledge-selected-updates --acknowledge-localsystem-risk --acknowledge-observer-relay --acknowledge-observer-process-query
```

The combined approval discloses distinct delivery/install/update permissions,
LocalSystem/custom-action risk, foreground WUA/process-query requirements and
shared blocking/recovery. One stopped-observer receipt lease covers both offers,
images and identities. A fixed create-only shared intent precedes key generation;
an immutable participant roster binds each independent grant and signing-key pin.
New MSI grant v2 and WUA consent v3 bind the plan and exact reciprocal peer binding.
Only the fresh paired config/receipt/ledger versions can join the shared fence.
Standalone v1 JSON bytes and guards remain unchanged.

Both local participants must have exact durable config, receipt, image and relay
proofs before shared activation. Partial setup remains disabled/fenced and must
not be retried or reset. The deployment service is still staged disabled; WUA is
never installed as a service or silently started. Finalize the MSI manager
registration first, then the matching WUA registration. Each finalize must retain
its own original prepare LAN-config path and bytes; passing the MSI staged LAN
config to WUA finalize is unsupported and rejected. Preserve the original inputs
and both generated staged LAN files.

After both finalize operations complete, explicitly create and review a separate
protected activation LAN config: copy all fields from the WUA staged LAN output,
then add the exact `windowsManagedMSIConfigFile` reference from the MSI staged LAN
output. Verify both source outputs use the same original manager, state directory,
TLS, operator and listener settings and differ only in their separate optional
domain references. The activation file must retain both exact manager-config
paths. Do not overwrite an original input, staged output, domain config, key or
receipt; no grant or authority is created by composing these two references.
Starting the manager still independently validates both original domain bindings,
keys, receipts and enrolled records. This manual source activation step requires
its own host authorization. The output contains both public
registrations; save each named registration object using the already approved
public-file handoff. Start the observer explicitly, activate the MSI service with
its exact public configuration digest, and launch WUA only through its existing
foreground command with its separate process-query acknowledgement. These remain
separately approved real-world operations. Scheduled WUA is not added to this
first coordinated profile.

## Exclusive native admission

The fixed `ProgramData\Tracebolt\windows-mutation-fence` store uses the existing
InstallerOnly protection: SYSTEM and elevated Administrators only. No observer
SID receives access. Short fail-fast transactions retain one domain/job/sequence/
permit owner. The original identity, random fence identity, immutable roster,
clock/revision floors and 32-WUA-plus-one-MSI lifetime history are never reset.

Domain claim is durable before shared reservation, which precedes native
preparation. Domain Attempted and shared dispatch_intent are durable before any
native call. Preliminary checks are reusable; the precise MSI/COM syscall edge
requires the separate one-use final native hook. That hook checks the exact owner,
closes the shared transaction and then checks current domain authority and expiry.
No lock or storage wait follows that final authority check. Opening persisted
state cannot reconstruct a runnable capability. A blocked permit is consumed
without a native attempt; there is no silent queue or uncertain retry.

Domain result, original signed report and a private exact completion receipt are
saved together before release. The receipt requires native return, successful
owner cleanup and successful final admission. Exact saved evidence can finish a
lost release after reopening without repeating native work or changing the
original result. Service/process death, missing process locks, elapsed time or
reboot cannot release an unresolved owner. Failed pre-native starts initially
remain fenced conservatively. No remote unlock/reset tool is provided.

## Eligible MSI only

Coordinated review adds an unchecked assertion tied to the exact package metadata,
package hash, terms-review digest and native-acceptance evidence: all deployment
and rollback work is synchronous and none detaches after native return. A bounded
read-only CustomAction table check independently rejects every Type with the
0x80 asynchronous flag, including async/wait and async/no-wait. It runs under exact
protected package custody during coordinated inspection and installation.
Synchronous flags cannot prove arbitrary custom-action code harmless or prevent
it detaching work; package-specific review/native acceptance remains required.
There is no sandbox or universal safety/offline claim.

Known, settled native results keep their original meaning. MSI 1618 is busy and
consumed; 1641, timeout, uncertain registration/cleanup or write failure stays
fenced. Verified 3010 retains restart-required truth. Another mutator still needs
fresh reboot-clear readiness: WUA's existing installer checks, or coordinated
MSI's fixed-key reboot indicators. No reboot is requested automatically.

## Saved status

Software and Updates retain the original result and show one compact independently
signed shared-status snapshot: owner domain/job, release state and recovery note.
Snapshot refresh never changes an install result or extends authority. Old
snapshots are labeled saved state. Only exact terminal receipt recovery can
finish a lost release; other uncertainty requires separately reviewed local
intervention. A status observation is not installation permission.

## Required native gate

In a separately approved disposable Windows x64 environment, verify both exact
fresh setup artifacts, observer denial to the shared InstallerOnly store, paired
foreground/background lifecycle, simultaneous admissions, SCM/process death
while native work survives, final-expiry/revocation after waits, synchronous and
async MSI rejection, cleanup/result-write interruption and saved-release recovery.
Keep prepared/standalone v1 and service-broker exclusion checks. No automated test
here runs a native installer or treats compilation as host acceptance.

Coordinated manager approval requires a signed active-idle observation less than 60 seconds old. Missing, stale, busy or unknown status blocks approval without consuming it. This is a consumption safeguard only; the durable endpoint fence remains the final native admission authority.

The separate fresh [background manual cached-update profile](windows-background-cached-updates.md) removes repeated foreground launch only after new explicit paired setup and activation. It does not adopt this foreground profile or enable scheduling.

The separate [fresh reusable cached-update profile](windows-reusable-cached-update-jobs.md)
uses an explicit new v4 shared roster and successful-result-bound WUA retirement.
It preserves independent reusable MSI retirement, original fixed grants and exact
idle-owner checks. Earlier coordinated profiles cannot acquire this authority.
