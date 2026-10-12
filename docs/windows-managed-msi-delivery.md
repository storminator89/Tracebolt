# Central managed MSI: bounded source candidate

One uploaded x64 machine MSI can be delivered to one specifically set-up endpoint
and imported in the background. Installation is a separate reviewed one-attempt
operation. This is source code, fixtures and unsigned cross-build evidence;
no package, endpoint, native acceptance or deployment is selected or approved by
this document. See [manager setup](windows-managed-msi-manager.md) and the
[required native gate](windows-managed-msi-native-acceptance.md).

This first slice excludes co-enabled Tracebolt WUA, prepared-MSI and service-control
mutators on that endpoint. Observation remains available. Reciprocal create-only
setup guards and final runtime checks enforce that limitation. It is partial
management, not full software/update coexistence. A separate [fresh coordinated source profile](windows-coordinated-mutations.md)
now pairs managed MSI and foreground cached WUA under a durable shared Windows
mutation fence. The Linux fence is not reused. External
administrators and other installation tools remain outside these guards.

## Authority and package review

The fresh `tracebolt.windows-managed-msi.v1` domain has independent manager and
executor keys, two distinct local delivery/install grant IDs, an explicitly
opted-in observer relay, its own pipe, private state, and operator permissions.
No prepared-v1, read, WUA or service-control grant is promoted. Prepared-v1's
foreground token policy and stopped-observer package staging remain unchanged.

One-time setup authorizes the central operator to select one exact package later.
The delivery permit fixes complete Selection (SHA-256, size, ProductCode,
PackageCode, version, amd64, name, terms-review digest, review reference), native
acceptance evidence digest, original endpoint incarnation, executor/grants,
current leaf, transfer ID and absolute expiry. No request can carry paths, URLs,
filenames, executable commands, transforms or arbitrary MSI properties.

Uploading or delivering does not accept terms or authorize installation. The
administrator still reviews the exact package, publisher/custom actions, terms,
privileges and package-specific native acceptance evidence. Digests identify
bytes/evidence, not package safety, publisher trust or offline behavior.

## Background service and custody

`TraceboltWindowsDeployment` is a new own-process LocalSystem service. LocalSystem
has extensive local authority and can authenticate remotely as the computer.
An unrestricted elevated primary token, no thread impersonation and x64 are
required; domain controllers are excluded from the initial candidate. Neither
the service nor MSI custom actions are sandboxed. MSI code may use the network,
change services, start asynchronous programs and disrupt applications.

The observer remains LocalService and relays only fixed signed messages over the
separate `Tracebolt.Windows.ManagedMSI.v1` pipe. Both peers verify process identity;
the observer checks SCM/image and a fresh executor signature, and the service
checks the exact observer SCM process and identification-only pipe token. The
service owns its signing key and package/install state. Its current-authority
reader uses public certificate/renewal/config/relay records only; it never loads
an enrollment private key or creates a manager HTTP client.

Managed custody lives in the new fixed protected
`ProgramData\Tracebolt\windows-managed-msi-package\managed.msi` namespace. It
never adopts prepared.msi. Handle-relative NTFS checks pin ancestors, directory
and file identity, reject reparse/hardlink/stream/replacement cases, and preserve
SYSTEM/Administrators-only custody while the observer runs.

Both upload and delivery use 32 KiB raw chunks, at most 4096 for a 128 MiB artifact,
inside 64 KiB canonical frames. Manager partial plus completed bytes share one
bounded private artifact slot; SQLite contains metadata, never MSI blobs.
The endpoint records transfer intent before creation and original object IDs
before progress. Each pending chunk is persisted before bytes; file sync and
checkpoint persistence precede acknowledgement. Restart can resume only the same
recorded chunk bytes into the same object. Unexplained partial lengths, replaced
objects, missing identity or uncertain writes fence the transfer. A completed
acknowledged prefix is fully rehashed on reopening; the live handle maintains
incremental hashing between chunks. Only complete hash plus read-only native MSI
metadata verification creates a protected import receipt.

A delivery permit expires within 24 hours and never outlives its original grant
or current certificate. Each storage wait is followed by fresh authority checks.
A TLS renewal changing that exact leaf fences an in-flight transfer; this first
slice does not reissue it or extend its expiry. Reports retain original bytes and
capture times. Disconnected endpoints cannot know a later manager revocation
immediately. No proxy, redirect, compression, Range request or arbitrary artifact
route is supported.

## Review, one install, durable result

After protected import, the operator explicitly acknowledges package review,
terms and an exclusive bounded maintenance window of at most ten minutes.
Fresh signed readiness covers the exact delivered package, machine registration,
installer-busy observation, native acceptance and that original window. A separate
initially unchecked approval binds the exact readiness report. Its start permit
lasts at most 60 seconds, clamped to the original readiness/grant/current leaf.
Service uptime and maintenance badges grant no installation authority.

The endpoint writes admission and then `Attempted` durably before the fixed
`MsiInstallProductW` call. Restart never reconstructs the in-process execution
capability. Missing response, stop, crash, cancellation or uncertainty never
retries installation. Custody remains held on the native owner thread until the
synchronous call finishes; cleanup failure yields uncertainty.

Fixed properties retain ACTION=INSTALL, ALLUSERS=1, empty MSIINSTALLPERUSER,
REBOOT=ReallySuppress, REBOOTPROMPT=S, disabled Restart Manager closure/restart,
and verified no-UI mode. There is no shell or msiexec process. `_MSIExecute`
presence is a conservative observation, not a reservation against racing tools.

The exact return-code vocabulary is preserved:
- 0: succeeded only with matching machine ProductCode/PackageCode/version
- 3010: restart_required, with independent registration-verification truth
- 1641: unexpected_restart, never ordinary success
- 1618: busy; the one attempt remains consumed
- Other known codes: failed
- Unknown result, failed custody cleanup or unmatched code-0 registration: uncertain

A service stop or native return does not prove rollback, cancellation, absence of
asynchronous custom actions or application health. No automatic reboot, removal,
repair, replacement package, second attempt or generic deployment queue exists.

## Matching-source endpoint setup (separate approval required)

The manager's protected prepare step emits the fresh public offer. Stop the exact
owned observer, review the source artifacts and offer, then run the read-only plan:

```
tracebolt-windows-service.exe --managed-msi-provision --manager-offer C:\Reviewed\offer.json --service-file C:\Reviewed\tracebolt-windows-managed-msi-service.exe --artifact-manifest C:\Reviewed\tracebolt-windows-managed-msi-service.manifest.json
```

Applying the exact plan additionally requires all initially absent flags:

```
--apply --approve sha256:<exact plan> --acknowledge-managed-delivery --acknowledge-one-managed-install --acknowledge-localsystem-risk --acknowledge-observer-relay --acknowledge-observer-process-query
```

Setup records permanent intent before creating a key, image, disabled SCM service
or relay. Existing/partial objects are never adopted, reset or overwritten. It
outputs a public manager registration, leaves the observer stopped and stages the
deployment service disabled. No MSI input is required at local setup. The public configuration digest is
printed on stderr. `--managed-msi-export` re-exports only the same completed
registration and digest, without creating or repairing authority.

After separately approved manager finalization and explicit observer startup,
review the public configuration digest and activate the deployment service once:

```
tracebolt-windows-service.exe --managed-msi-activate --apply --acknowledge-start-localsystem-service --approve-config sha256:<exact public configuration>
```

Activation intent is durable before the automatic-start change and SCM start.
Unconfirmed activation is not safe to repeat. Setup and activation create persistent
privileged access and require separate real-world approval; the source tests run
neither. Existing managed authority also blocks ordinary observer uninstall.
There is no retirement/reset workflow in this slice.
