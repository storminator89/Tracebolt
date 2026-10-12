# Windows: current functionality and limits

The current development source targets a fresh x64 Read admin installation.
It is ahead of the published Windows preview. The exact source identified below
passed a bounded hosted packaged-Setup subset; complete provider coverage and
real manager interoperability remain unproved. Current priorities combine
remaining Admin data with useful fleet monitoring and management workflows.

[Guides](README.md) · [Fresh Read admin setup](windows-read-admin-setup.md) · [Next priorities](windows-admin-roadmap.md)

## Current development source

Fresh Setup offers **Read admin** with twenty-one explicitly disclosed read scopes,
grouped into concise sections. Consent starts unchecked, including the personal
session labels, identifying serial metadata and selected historical-message risks. The manager and endpoint must
implement the same profile. Selecting it does not prove access under the
installed service identity.

| Area | Available source functionality | Important limit |
| --- | --- | --- |
| Fleet and resources | Reported hostname/IP search, CPU/RAM/volume observations, resource history | Original age and partial/unavailable sources remain visible; capacity is not disk health |
| CPU and memory context | [CPU models and source-labeled processor counts, installed SMBIOS RAM, OS-usable/available RAM, commit current/limit/remaining and aggregate pagefile capacity/use](windows-resource-context.md) | Independent sources; no pagefile names/paths, paging-I/O/thrashing/health verdict or change to CPU utilization sampling |
| Inventory | [Complete caller-visible process snapshots](windows-full-processes-contract.md), separate process CPU/working-set RAM sample, complete caller-visible Win32 services, HKLM 32/64 machine software generations | CPU/RAM remains a separately consented 128-row sample; no drivers, ACL-invisible services, per-user/Store or portable-app completeness |
| Software history | [Observed HKLM registration and metadata changes](windows-software-history.md) between complete comparable generations | Separate explicit seven-day history grant; whole-comparison quota gaps are visible. No actual install times or upgrade inference |
| Network | Numeric TCP/UDP endpoints, adapter link/DNS/gateway context, [caller-visible routes and raw interface octet/error/discard counters](windows-network-context.md) | Separate source snapshots without index joins; counters may reset, are not rates or guaranteed since-boot totals. No traffic capture, probes or DNS lookup |
| Updates | Build labels, bounded retained update history, checked reboot indicators | History is not current patch compliance; no online update scan or Windows CVE assessment |
| Security | Independent Defender/Firewall plus [Security Center antivirus registration/status and TPM presence/version](windows-security-coverage.md) | Client-only Security Center; no protection, TPM readiness or effective-policy verdict. BitLocker and Secure Boot remain open |
| Users / Sessions | Caller-visible WTS sessions and local domain/workgroup join context | No complete account discovery, session actions or remote desktop |
| Storage | Drive letters mapped to volume GUIDs, provider-reported physical-disk status/media/bus and separately consented [aggregate PerfDisk throughput, operations, latency and queue context](windows-storage-io.md) | Independent snapshots; no guessed topology, per-disk completeness, SMART or health verdict. Missing counters and idle latency remain unavailable |
| Hardware / power | Manufacturer/model, separately labeled chassis/BIOS serial, firmware and system battery/power | No validated unique hardware identity, RAM-module inventory or battery-health claim |
| Logs | Recent Application/System headers and [bounded older-event search plus selected messages](windows-event-history-runtime.md) | Fresh explicit history grant; one channel, UTC window, 100-header cap and original 15-minute expiry. No complete retained-log claim |

[Read admin scope contract](windows-read-admin-setup.md) links these fields to
their fixed local providers, exact grants and privacy notices. Disabled or denied
providers remain unknown/unavailable; Setup does not install providers or widen
service privileges to obtain data. Existing grant bytes keep their exact scope.

Current storage-I/O transport reserves a bounded 26 KiB base preview within the
unchanged frame ceiling. Complete inventory and derived history use their separate
bounded transport/store. See [frame bounds](windows-storage-io.md#worker-transport-and-privacy).

## Separate optional features

- [Selected event messages](windows-event-content-runtime.md): request exact
  reported headers under a separate local grant. Message text expires in the
  originating operator session's private cache; it is not retained-history or AI export.
- [Cached Windows Update inspection](windows-update-runtime.md): an independently
  granted offline cache read. Freshness stays unknown; no scan, download,
  installation or reboot is performed.
- [Selected cached update jobs](windows-selected-update-setup.md): separate fresh
  manager/Windows setup, exact revision approval and a dedicated foreground executor.
  One fixed device binding; no download, license acceptance or automatic reboot.
  Native setup and installation acceptance remain pending.
- [Background cached updates with approved UTC windows](windows-scheduled-background-updates.md):
  separate fresh combined consent, dedicated activated service and reusable-MSI
  shared fence. Exact readiness, named install/schedule authority, original
  fixed expiry and 32 lifetime approvals remain. Native acceptance is pending.
- [Disk](windows-capacity-health.md), [CPU/RAM](windows-resource-health.md) and
  [selected-service checks](windows-service-health.md): independent default-off
  manager policies over already accepted observations. Missing data stays unknown.
- [Fleet groups](fleet-groups-health.md): manual device organization and reviewed
  one-time disk/CPU/RAM settings. New members do not inherit settings automatically.
- [Windows incident inbox](windows-incident-inbox.md) and [bounded planned
  maintenance](windows-maintenance.md): retained incident acknowledgement and
  explicit device/domain windows with original end times. Maintenance marks
  operator planning with suppression of separately approved
  [Windows notifications](windows-notifications.md). Incidents and evidence continue;
  recipient setup and exact Windows source approval remain separate and default-off.
- [Selected service control](windows-service-actions.md): exact reviewed targets,
  explicit approvals and saved action receipts. Separate [fresh broker setup](windows-action-provisioning.md)
  creates a disabled restricted broker after exact local approval; Read admin
  does not grant service actions. Native activation and acceptance are pending.

![Cached Windows Update inspection with explicit coverage and freshness limits](screenshots/2026-10-10-windows-parity/windows-cached-updates.png)

*Actual source-preview capture using invented data. [Capture details](screenshots/2026-10-10-windows-parity/README.md).
This does not show native Windows collection or the published preview's features.*

## Published preview

The unsigned x64
[v0.1.0-windows-preview.1](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.1)
contains the older **five-scope** setup: base inventory, Application/System event
headers, volume metadata, process metrics and numeric network endpoints.
It does not contain the current twenty-one-scope Read admin profile or later
complete inventory, context, message-content and cached-update additions.

Its accepted native subset covers fresh hosted **Windows Server 2025 x64** with a
loopback fixture manager: installation, approval/reporting, cancellation and
owned-service removal. This result does not transfer to later source or prove
Windows 10/11, real Linux-manager/shared-browser interoperability or reboot.
Exact artifact/source evidence is in the [historical installation guide](windows-prerelease-historical/windows-prerelease-install.md#selected-native-evidence).

## Current hosted Setup acceptance

Source `62435ef7e605df0b102e030bf1d68cb255829a90`, tree
`b66e8a8eaa8cfdb0a5b7108254c930ae244b6763`, passed the three TLS-only Server 2025 x64
packaged-Setup cases and aggregator in first-attempt
[native run 38303755541](https://github.com/storminator89/Tracebolt/actions/runs/38303755541).
The cases exercised install/service removal, hidden-input cancellation and
pending-transport interruption. The install case verified receipt12/twenty-grant
bindings and two accepted ordinary frames; removal left the owned service absent
while retaining files, keys and state. The six tested package files remain exact.
Source-input comparison found seven byte-identical files and 2,619 files differing
only by LF-to-CRLF checkout conversion; this is not cross-OS rebuild equivalence.

This evidence is an **unsigned current21 packaged GUI subset**. Windows 11, a real
Linux manager/shared dashboard, complete providers, event-history requests,
renewal cutover, native restart, reboot, human invitation/UAC, ARM64 and optional
MSI/WUA/service actions or selected-user software remain unproved. See the
[current gate contract](../tests/windows_native_acceptance/CURRENT_SETUP.md).
The accepted-tree publisher pin does not release a download: successful exact-source
full Validate, a separately reviewed later publisher revision, live original
artifacts and explicit publication approval are still required. Follow the
[promotion contract](windows-prerelease-publication.md); the published preview
above stays unchanged until promotion actually completes.

## Before installing or releasing

Current-source Windows 11/provider/service-identity acceptance, real manager
interoperability and reboot/sleep behavior remain open. Signing, ARM64 runtime
and deliberate complete removal are separate work. See the
[desktop acceptance checklist](windows11-acceptance-matrix.md).
There are no existing user installations to migrate; upgrades and reconsent are
preserved development interfaces, not current delivery gates.

Use reviewed matching artifacts on an explicitly approved target. Keep HTTPS
and OS protections intact. An unsigned build may be blocked by policy.
Cancellation can retain identity and partial state; service removal retains
files and does not revoke manager trust. Follow the
[retained-state/removal guide](windows-setup-preview.md#cancellation-retained-state-and-service-removal)
instead of deleting state to retry setup. Builds, CI and screenshots do not
by themselves authorize host changes or establish native acceptance.

### Optional selected-account software source

[Selected-account HKCU/MSIX capture](windows-selected-user-software.md) adds a
separate default-off receive scope and one-shot normal-user foreground helper,
with private account/source filtering in Software. It is not included in the
21-scope Setup consent, installed by Setup, shipped in the historical preview or
accepted by the current-profile native harness. Separate unsigned helper build
artifacts and exact source instructions are documented; native acceptance and
runtime provisioning remain separately gated.

## Central managed MSI source candidate

The fresh [upload-once fleet worklist](windows-fleet-managed-msi.md) extends central
custody to at most 25 explicitly configured endpoints. Delivery, exact review and
one installation attempt remain separate per-device approvals. Native acceptance
and real host setup remain pending.


[Central delivery](windows-managed-msi-delivery.md) now has a separate bounded
source path: chunked manager upload, background protected import, fresh review,
one separately approved install, and durable per-device outcome. This does not
change the released profile or imply native acceptance. The dedicated LocalSystem
service is explicit opt-in and excludes other Tracebolt mutators on that endpoint;
observation remains available. [Manual native acceptance remains pending](windows-managed-msi-native-acceptance.md).
