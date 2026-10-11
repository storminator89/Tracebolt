# Windows daily-administration roadmap

Updated 11 October 2026. This is the prioritized product plan, not a list of
released capabilities. Deliver working collector → manager → dashboard slices;
use focused functional/security regressions and required CI rather than delaying
features for marginal test polish. A confirmed authorization or data-integrity
defect still blocks the affected feature.

## Current starting point

- **Published:** unsigned x64 Windows preview.1, source `14719116`, with five
  explicitly approved observation scopes. Its accepted native subset is fresh
  Windows Server 2025 x64 with a fixture manager.
- **Merged, not released:** tree `5086354` on main `04fd9413` adds separately
  consented selected event messages and offline WUA cache inspection, Windows
  resource/selected-service policies, and local receipt-bound own-agent restart.
  Source/hosted CI is not installed-feature or Windows 11 acceptance.
- **Implemented in source, draft review:** complete caller-visible Win32 service and separately
  consented HKLM 32/64 machine software registration generations, bounded transport,
  server-side search and paging. Exact-source hosted CI and native acceptance
  remain separate gates. The existing service-health chooser still uses its bounded preview;
  complete browsing does not silently expand alarm authority.
- **Implemented in source, draft [PR #39](https://github.com/storminator89/Tracebolt/pull/39):**
  fleet search/display using already-reported Windows hostname and interface IPs.
  Existing Linux identity scope and stable device routing IDs remain separate;
  exact-source hosted CI is pending.

The published preview still transmits at most 128 process, service and software
rows per section, potentially fewer under the byte budget. Browsing a page of
that sample is not complete inventory. Software currently means HKLM uninstall
registrations; offline update candidates are not a patch-compliance verdict.

## Prioritized delivery

| Order | Increment and useful admin outcome | Status and boundary |
| --- | --- | --- |
| 1 | **Dependable inventories:** finish all caller-visible Win32 services; then complete machine-wide software registrations and processes with generation-bound search/paging. Find an item beyond the old 128-row sample and distinguish absent from unreadable/incomplete. | Services and machine software registrations are implemented as separate default-off source scopes; complete processes remain planned. Machine software covers caller-visible HKLM 32/64 uninstall registrations, with optional-field quality and duplicate registrations preserved. Per-user/MSIX/Store coverage needs an explicit user-context design; LocalService HKCU is not the logged-on user. Arbitrary portable EXEs cannot be promised discoverable without a separately approved filesystem scope. |
| 2 | **Recognizable fleet:** search and display Windows reported hostname/IPv4/IPv6, original age and partial coverage. Later add cross-device inventory queries. | Implemented in source, draft PR #39; hosted CI and native evidence remain separate. Uses existing consented metadata without additional collection, IP-based routing, DNS lookup or provider export. Missing/stale identity stays visible. |
| 3 | **Patch and security posture:** Windows edition/release/build revision, installed-update history, applicable update freshness and global pending-reboot reasons; Defender/AV status, firewall profiles, BitLocker state, Secure Boot and TPM state. | Planned read-only increments. Show unavailable/unsupported/error explicitly; no “secure” or “fully patched” verdict from absent data. Cached WUA remains offline unless a separately disclosed future online scope is approved. Never collect recovery keys, credentials or key material; no update installation, reboot, firewall/AV changes or remediation implied. |
| 4 | **Network diagnosis:** DNS configuration, default gateways/routes, adapter link state/speed and traffic/error counters alongside existing numeric socket observations. | Planned. Bounded interface-scoped reads, sample intervals and counter resets made explicit. No packet payload capture, credential collection, automatic probes or stable process ownership inferred from a PID snapshot. |
| 5 | **Storage/performance diagnosis:** familiar drive letters and volume mapping, I/O latency/queues/throughput, physical disk/SMART health where supported, and memory commit/pagefile pressure. | Planned incremental fields and UI. Capacity is not disk health; working set is not private/committed allocation. Report inaccessible, virtual/RAID and unsupported measurements honestly; no driver installation or elevation to obtain a value. |
| 6 | **Help-desk context:** active/disconnected console and RDP sessions, domain/join state, hardware make/model/serial, CPU/RAM configuration, BIOS/firmware and laptop battery state. | Planned. User/session names and serial numbers need clearly disclosed purpose, access and retention. Keep collection least-privileged and optional; no user-profile crawling, session control, passwords, tokens or private documents. |
| 7 | **Changes and historical troubleshooting:** software install/remove/version-change history, useful inventory diffs, bounded event time-range/older-event retrieval and source-wide search with continuation. | Planned. Compare complete compatible generations; missing/partial capture must not invent an uninstall. Preserve capture/receipt times and distinguish log rollover/clears/lost continuation. Additional channels and retained message content require explicit scope/retention. Current message search covers only already fetched selected messages. |
| 8 | **Operational follow-through:** link evidence to purposeful incident acknowledgement/maintenance/delivery, and later separately approved exact Windows service/update actions. | Planned after reliable read-only evidence. Existing alarms and provider approvals do not grant new data sharing or privileged actions. Local Tracebolt restart is not remote control of arbitrary services. |

## Common delivery rules

Every increment includes its actual data source and caller-visible coverage,
source failures, bounded work/transport/storage, original capture/receipt age,
and a usable English/German screen. Keep one coherent generation across pages;
do not hide truncation or treat unknown as healthy. A manager update must not
promote existing endpoint consent into broader collection. Named-operator access,
session expiry and revocation must apply to the new view; metadata does not
automatically enter AI, exports or notifications.

For each slice, demonstrate the production path with synthetic fixtures and
focused regressions, then ordinary exact-source CI. Mark native acceptance
separately and state which OS/architecture and installed identities were tested.
Do not let an extra manual native grant block unrelated source development.

## Windows 11 and lifecycle gate

Windows 11 x64 is an intended desktop target consistent with the current production
API/manifests; it has no native acceptance result yet. The
[explicit Windows 11 matrix](windows11-acceptance-matrix.md) covers installation,
human UAC, service identity, real enrollment/manager/browser, data sources,
update cache, events, full services, own-agent restart and retained-state removal.
The existing Server 2025 controllers have exact target locks and must not be
relabeled as desktop evidence. `windows-latest` is not Windows 11 proof.

Reboot/sleep recovery, same-identity upgrade/repair, signing, ARM64 runtime and
deliberate complete uninstall remain separate lifecycle work. No date or full
parity claim is made by this roadmap. See [current Windows status](windows-status.md),
[the historical Linux/Windows comparison](windows-linux-parity.md), and
[complete service scope](windows-full-services-contract.md), and
[machine software scope](windows-full-software-contract.md).
