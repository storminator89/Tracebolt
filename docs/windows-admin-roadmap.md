# Windows priorities

The immediate goal is useful daily administration: finish the current inventory
and fleet workflows, then expand job results, monitoring and controlled
software/update management. Close remaining Admin data gaps alongside that work.
Unsigned [Windows preview.2](windows-status.md#published-preview) is available
for fresh x64 Read admin setup, with narrow hosted acceptance. Current source
features and their separate release limits are described in
[Windows status](windows-status.md).

There are no existing user installations. Migration, binary upgrade and
reconsent are not delivery gates for this fresh-install target. Integrated
remote desktop is deferred.

## Already in the source

- [Complete caller-visible process snapshots](windows-full-processes-contract.md),
  Win32 services and HKLM 32/64 machine software
  generations, with bounded search/paging
- Fleet hostname/IP search, attention-first filtering, resource observations and
  independent optional disk/CPU/RAM/selected-service checks
- [Manual fleet groups and reviewed one-time Windows disk/CPU/RAM settings](fleet-groups-health.md)
- [Selected-account HKCU and Store software capture](windows-selected-user-software.md),
  with separate consent and an explicit normal-user foreground helper
- Adapter link/DNS/gateway, build/update history/reboot, Defender/Firewall,
  session/join, hardware/firmware/power and drive-letter/provider-disk context
- [Observed machine-software change history](windows-software-history.md), with a separate explicit scope, original before/after observation times, bounded private paging and visible comparison gaps
- [Aggregate storage I/O](windows-storage-io.md): local PerfDisk (_Total) throughput, operations, read/write latency and average/current queue context with the actual sample window
- [CPU and memory context](windows-resource-context.md): model/source-labeled processor counts, installed SMBIOS versus OS-usable RAM, commit current/limit/remaining and aggregate pagefile capacity/use
- [Caller-visible routing metadata and raw interface counters](windows-network-context.md), with exact uint64 values and independent private paging
- [Security Center antivirus registration/status and TPM presence/version](windows-security-coverage.md), with explicit client/server and provider-access limits
- Event headers, separately approved selected messages and offline cached updates
- [Bounded older Windows event search and deliberately selected historical messages](windows-event-history-runtime.md), with an independent default-off grant and same-session receipt-bound followup
- Concise fresh Read admin setup with explicit unchecked consent; service control
  remains separately optional
- [Selected cached Windows update jobs](windows-selected-update-jobs.md), with
  independently configured device bindings, exact per-device reviews and named
  approvals, saved outcomes and [fresh background UTC scheduling](windows-scheduled-background-updates.md)
- [Reusable cached-update jobs](windows-reusable-cached-update-jobs.md) in a fresh
  paired MSI/WUA profile: explicit retirement of a successfully settled result
  permits a later independently reviewed job; failed or uncertain outcomes stay blocked
- [Windows incident acknowledgement](windows-incident-inbox.md),
  [planned maintenance](windows-maintenance.md) and separately approved
  [notifications](windows-notifications.md)
- [Managed MSI fleet delivery](windows-fleet-managed-msi.md),
  [saved exact worklists](windows-saved-msi-worklists.md) with staged approvals and
  per-device results, and [bounded scheduled installation](windows-scheduled-managed-msi.md)
- [Fresh multi-package MSI catalogue and guided package review](windows-multi-package-msi-catalogue.md):
  up to four retained packages within one shared 128 MiB budget; package identity,
  terms, native and publisher evidence still need explicit review
- [Selected-service action receipts and explicit fresh broker setup](windows-action-provisioning.md),
  with separate authority; native activation and action acceptance remain pending

These workflows require matching source and their own explicit setup/consent.
Optional MSI, WUA and service-action native acceptance remains pending. Source
implementation does not establish release or native provider-access coverage. The
[individual scope guides](windows-read-admin-setup.md) define the coverage and
exclusions; do not treat a complete registration list as every installed app.

## Ongoing group monitoring

[Ongoing group monitoring](fleet-group-monitoring.md) adds explicitly reviewed
disk/CPU/RAM assignments for exact existing Windows members. Only opted-in
assignments follow future definition changes. New or re-added members need fresh
opt-in; a per-device policy Save detaches that metric. This is implemented in
source and is not part of published Windows preview.2.

## Missing Admin data

Drive-letter mapping and physical-disk provider status are implemented in source.
The remaining data areas below can progress independently.

1. **Storage and performance.** [Aggregate PerfDisk I/O](windows-storage-io.md) is implemented independently of [drive/volume and provider context](windows-storage-context.md). Per-disk attribution and real paging-I/O measurements remain open. Commit capacity and aggregate pagefile use are implemented, but do not prove paging pressure or thrashing. Add physical disk/SMART
   information only where safely supported. Capacity is not disk health; no
   driver installation or elevation to fill a missing field.
2. **Broader process metrics and software.** Complete basic process snapshots now
   have generation-pinned search/paging. CPU/RAM remains a separately consented
   128-row sample; extending it needs creation-identity-safe measurement and its
   own explicit scope. Selected-account HKCU/Store capture is implemented;
   it does not enumerate all user profiles or discover arbitrary portable apps.
3. **Security and patch detail.** BitLocker state, Secure Boot and TPM readiness where legitimately accessible,
   and trustworthy update freshness/applicability/CVE evidence. Never read
   recovery keys or infer “secure” or “fully patched” from absent data.
4. **Hardware and measurement detail.** Broader RAM-module and processor topology detail beyond the current source-labeled CPU counts and installed/usable RAM totals, with honest virtual/unsupported/provider limits. Routes and raw traffic/error/discard
   counters are implemented in a separate scope; rates would need their own
   identity-safe measurement design. No automatic probes, packet content or
   privilege expansion.
5. **Changes and history.** Observed machine-software registration/version changes
   from complete comparable generations are implemented in a separate scope.
   Bounded older-event search and selected-message followup are implemented in
   a separate scope. Broader inventory diffs, retained-event continuation and
   retention remain open. Partial captures must not invent an uninstall or
   erase log gaps. Broader content/retention requires explicit scope.

## Native acceptance and release

Preview.2 passed three TLS-loopback Server 2025 x64 packaged-GUI cases:
install/service removal, hidden-input cancellation and pending-transport
interruption. Service removal retains files, keys and state. Use its
[attached installation guide](https://github.com/storminator89/Tracebolt/releases/download/v0.1.0-windows-preview.2/windows-prerelease-install.md)
for the exact artifacts and matching manager/frontend source.

Next, validate the matching Setup, service, real Linux manager and shared
dashboard on fresh Windows targets. The
[Windows 11 checklist](windows11-acceptance-matrix.md) covers human UAC, hidden
invitation/identity approval, service-token reads and actual manager/browser data.
Windows 11, complete providers and optional actions are not covered by the hosted
Server subset. Reboot/sleep, signing, ARM64 and complete removal remain separate
gates. Keep source CI, browser fixtures and native results distinct; fresh Read
admin consent does not authorize optional execution scopes.

## Next management workflows

Selected-service action receipts, shared disk/CPU/RAM settings, incident
acknowledgement, planned maintenance, notifications and managed MSI fleet
workflows are implemented in source. Selected cached update jobs support up to
25 independently configured device bindings. A temporary fleet worklist can
hold one common UTC window, while each device retains its exact revision,
fresh review, separate unchecked approval and independently saved outcome.
Current fresh background profiles and legacy foreground profiles keep their
separate consent and activation requirements.

For reusable WUA, finish native validation of fresh paired setup, successful-result
retirement and later independently approved jobs. Unresolved or failed outcomes
still block replacement; retirement never refreshes grant expiry or retries a job.
Validate ongoing group monitoring and the guided MSI/fleet workflows on exact
native artifacts before release.

Broader update policies and automatic responses still need their own bounded
design, reviewed authority, explicit approval, least-privilege execution and
durable one-use records. Groups and monitoring do not grant endpoint permissions.
Local Tracebolt restart is not arbitrary remote control. Remote desktop remains
deferred.

## Rules for every feature

Keep screens compact, readable and bilingual, with useful screenshots rather
than repeated status prose. Show source, original age, bounds and failure states.
Unknown is not healthy. New collection is default-off and explicitly disclosed;
manager updates do not expand local grants. Preserve session expiry/revocation
and keep operator-only metadata out of AI, exports and notifications unless
separately approved. Use focused regressions and required CI; a real authorization
or data-integrity defect blocks the affected feature.
