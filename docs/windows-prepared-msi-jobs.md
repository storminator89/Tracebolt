# Install prepared MSI: bounded source candidate

This increment wires one administrator-reviewed, locally staged **x64 machine
MSI** into the existing Software view. It is not central software distribution,
a download catalog, an EXE runner or general Windows package management. Source
fixtures and cross-builds do not establish native Windows acceptance, choose an
installer, grant access or authorize an installation.

## Exact scope and review

A fresh `windows-prepared-msi-install-v1` consent pins one complete package:
SHA-256 and byte size, ProductCode, PackageCode, three-part ProductVersion,
`amd64` architecture, display name, terms-review digest and human review reference.
The consent also records the package-specific native-acceptance evidence digest
and explicit package-review acknowledgement. It grants **one lifetime approved
attempt**, under a separate software manager key, executor key, grant, permission,
protected ledger and IPC domain. Existing read, WUA update, Linux package and
Windows service-control grants never promote.

A hash proves byte identity, not that an MSI is benign or offline. MSI custom
actions can run arbitrary code, contact the network, change services, close
applications or otherwise disrupt the machine. The administrator must review the
specific publisher/package, terms, custom actions, required privileges and
possible effects, then complete separately authorized native acceptance for
that exact package before making a real grant. The review evidence is an explicit
administrator attestation, not a static-analysis or publisher-trust certificate.
No package is selected or native acceptance claimed by these source tests.

## Protected local custody

Setup is create-only. Its read-only plan checks the exact byte hash, size and
compound-file signature against the administrator-supplied manifest. Native MSI
metadata is deliberately not claimed from that initial byte check. Apply first
records durable intent, then creates only the absent fixed
`ProgramData\Tracebolt\windows-software-package\prepared.msi` under pinned
SYSTEM/Administrators-only custody. No existing or partial artifact is adopted,
overwritten, reset or silently repaired.

The receipt binds the original file and directory NTFS identities as well as
all package metadata. Every execution opens that exact receipt, rechecks protected
ancestors/ACLs, rejects reparse points, alternate streams, hardlinks, replaced
objects, changed bytes and unsupported volumes, and keeps file/ancestors pinned
without write/delete sharing. The MSI-facing path is resolved from the pinned
handle using the local volume GUID, not a mutable drive-letter mapping. The
source candidate requires native acceptance of this pinned-path integration.

Metadata uses `MsiOpenDatabaseW` in read-only mode plus fixed bounded database
queries and summary properties. It never uses `Win32_Product`, opens an installer
session for inspection or performs consistency repair. The narrow candidate
requires exact ProductCode/PackageCode/version/name, `ALLUSERS=1`, x64 summary
platform, an original compressed source with embedded cabinets, no uncompressed
file override and no Upgrade-table operation. It rejects caller transforms,
patches, repair, removal and per-user installation. These structural checks do
not prove the behavior of custom actions or replace package-specific review.

## Request, review, approval and one attempt

1. Software shows the already prepared package, device and current state. There
   is no upload, path, URL, command line or arbitrary MSI-property input.
2. Request readiness creates a short-lived exact manager-signed challenge.
   Its independent monotonic sequence is consumed durably before any source read.
   The ordinary observer relays metadata only. Only the separately pinned
   executor can sign readiness and outcomes.
3. Readiness verifies protected package identity, absence of that ProductCode in
   machine registration, package review/native-acceptance acknowledgement and a
   current explicit maintenance window. Unknown or changed facts fail closed.
4. Review reopens the same immutable preview. An initially unchecked approval
   confirms that exact package/device and its package risks. Hashes and review
   evidence remain expandable. The original preview expires within 60 seconds,
   bounded by source capture, current leaf, consent and maintenance window.
5. Approval writes one signed permit. Exact approval replay returns the original
   bytes without re-signing or renewing time. Both manager delivery and endpoint
   admission consume once before acknowledging.
6. The endpoint durably writes `Attempted` before the fixed native call. The
   running capability exists only in that process; it cannot be reconstructed
   from disk. Crash, lost response, cancellation, persistence uncertainty or a
   restart never retries installation.
7. Original signed result bytes can be relayed idempotently while valid. Missing
   evidence stays missing, not fresh success; result lookup never reinstalls or
   signs a newer completion time.

Manager commits remain in the same enrollment transaction as current TLS-leaf,
original identity, revocation and durable time-floor checks. Operator approval
and dispatch also recheck the named actor's current software permission. Renewed
credentials never extend the package grant, preview or permit. A disconnected
executor cannot promise immediate knowledge of a later manager revocation.

## Foreground maintenance gate and native call

The dedicated software executor requires an explicit local interactive elevated
launch and a fresh acknowledgement of an exclusive maintenance window. Its
start gate lasts at most 10 minutes; each signed preview remains at most 60 seconds
and is clamped to that original window. It is an administrator assertion that
other deployment work has been paused, **not a mutex shared with WUA or SCM**.
Do not run other Tracebolt update/service jobs or external installers during it.
The observer's account and service privileges are unchanged; any limited
process-query allowance remains separately acknowledged for this foreground
process only.

The native adapter owns all custody handles on one thread and calls
`MsiInstallProductW` at most once. There is no shell or `msiexec` process invocation.
The fixed policy is `ACTION=INSTALL`, `ALLUSERS=1`, empty `MSIINSTALLPERUSER`,
`REBOOT=ReallySuppress`, `REBOOTPROMPT=S`, `MSIRESTARTMANAGERCONTROL=Disable` and
`MSIDISABLERMRESTART=1`, with `INSTALLUILEVEL_NONE` set and read back. These flags
suppress ordinary installer UI/reboot and Restart Manager closure; they are not
a sandbox around package code. An administrator-reviewed package can still be
disruptive. No application is forcibly closed or reboot explicitly requested by
Tracebolt.

The adapter repeats current identity/time and package checks before dispatch.
The `_MSIExecute` mutex presence is only a conservative readiness observation,
not a reservation; a competing installer can still race and return 1618.
Cancellation or the bounded caller wait does not establish that Windows stopped
work or rolled back. Custody stays owned until the synchronous native call ends,
even if the caller has already retained an uncertain result.

## Exact outcomes

- **0:** success only if the exact ProductCode is installed in machine context
  and its PackageCode and version match. Missing/mismatched/unreadable post-state
  remains uncertain.
- **3010:** restart required, with independent registration-verification truth.
  No automatic reboot or new attempt follows.
- **1641:** unexpected restart initiation. Never ordinary success.
- **1618:** installer busy. The one attempt is still consumed; no automatic retry.
- Other returned numeric codes are retained as failure.
- Before a native return or after an abandoned call, `returnCodeKnown=false`
  distinguishes an unknown native result from actual code 0.

Machine registration uses only exact `MsiGetProductInfoExW` queries in
`MSIINSTALLCONTEXT_MACHINE` with no user SID, for State, PackageCode and
VersionString. Matching registration verifies the reported installation
identity, not application health or all custom-action side effects.

## Fresh setup commands (source only)

These are matching-source development commands for a separately authorized host,
not instructions to execute from source tests. First explicitly grant the named
operator `windows_software_install` in the protected operator configuration;
existing operators never receive it automatically.

On the manager, `windows-software-manager-setup prepare --lan-config <protected
TLS config> --enrollment-config <protected enrollment config> --device-id <exact
activated device> --expires-at <absolute Unix expiry>` produces a read-only plan.
Applying that exact plan additionally requires `--apply --approve-plan
sha256:<reviewed plan> --ack-prepared-msi-install`. The create-only phase emits
only a public manager offer; it does not change the active LAN configuration.

On the Windows endpoint, stop the exact owned observer and review:

```
tracebolt-windows-service.exe --prepared-msi-provision --manager-offer C:\Reviewed\offer.json --executor-file C:\Reviewed\tracebolt-windows-software-executor.exe --artifact-manifest C:\Reviewed\executor.manifest.json --package-file C:\Reviewed\package.msi --package-review C:\Reviewed\package-review.json
```

The canonical public review file has `package` containing every Selection field
and `nativeAcceptanceDigest` containing the reviewed package-specific acceptance
record's SHA-256 digest. It contains no credentials, path or MSI properties.
Apply repeats the same inputs and adds all of:

```
--apply --approve sha256:<exact-plan-digest> --acknowledge-prepared-msi --acknowledge-observer-relay --acknowledge-observer-process-query --acknowledge-package-risk-and-terms --acknowledge-package-native-acceptance
```

Fresh setup records intent before key generation, executor image creation,
package staging, executor state or observer relay creation. It never starts the
observer or executor. Failures leave an explicit permanent fence and retained
partial objects; there is no repair/reset/adoption path. Successful output is the
public registration. `--prepared-msi-export` can re-export only the same completed
registration without recreating authority.

Back on the manager, `windows-software-manager-setup finalize` uses the same
protected config/device inputs plus `--registration-file <public registration>`.
Review and apply are separate, with the same exact-plan and explicit scope flags.
Finalization creates separate software tables/immutable credential markers and
stages a new LAN configuration containing `windowsSoftwareJobsConfigFile`.
Starting the manager with it remains an explicit activation step. Both setup and
startup reject software-key reuse with enrollment, TLS, service, Linux package
and WUA manager/executor purposes. No existing domain is promoted.

After separately approved observer startup, explicitly launch:

```
tracebolt-windows-software-executor.exe --run-foreground --allow-observer-process-query --acknowledge-exclusive-maintenance
```

The executor's ten-minute start gate is tied to this launch and never extended by
polling. It opens only completed protected setup and package receipts. Leaving
the foreground process closes admission; killing it does not prove that a native
MSI operation stopped. Without a separately reviewed retirement workflow, any
existing or partial software authority blocks observer uninstall.

## Required native acceptance

Before release or use: exercise create-only ACL custody, reparse/hardlink/stream
and replacement refusals, metadata/media bounds, the volume-GUID MSI path, the
separate relay/process identity, explicit fresh local and named-operator grants,
expiry/revocation/renewal races, exactly-once dispatch, lost claims/results,
0/3010/1641/1618 and mismatched-registration outcomes on a disposable approved
Windows x64 machine. No real installation, key generation, grant, host ACL or
network change is performed by source tests. No rollback, removal, upgrade,
repair, scheduling or distribution workflow is supplied.

Microsoft API references: [MsiInstallProductW](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msiinstallproductw),
[MsiSetInternalUI](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msisetinternalui),
[MsiGetProductInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msigetproductinfoexw),
[compressed sources](https://learn.microsoft.com/en-us/windows/win32/msi/compressed-and-uncompressed-sources),
[64-bit packages](https://learn.microsoft.com/en-us/windows/win32/msi/64-bit-windows-installer-packages).
