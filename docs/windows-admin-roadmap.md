# Windows priorities

The immediate goal is useful, dependable Admin data in the shared dashboard.
Finish these source features first, then validate fresh native installation and
publish compatible artifacts. Current development and the older downloadable
preview are described in [Windows status](windows-status.md).

There are no existing user installations. Migration, binary upgrade and
reconsent are not delivery gates for this fresh-install target. Integrated
remote desktop is deferred.

## Already in the source

- [Complete caller-visible process snapshots](windows-full-processes-contract.md),
  Win32 services and HKLM 32/64 machine software
  generations, with bounded search/paging
- Fleet hostname/IP search, resource observations and independent optional
  disk/CPU/RAM/selected-service checks
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

Implementation is not a release or native provider-access result. The
[individual scope guides](windows-read-admin-setup.md) define the coverage and
exclusions; do not treat a complete registration list as every installed app.

## Missing Admin data

Drive-letter mapping and physical-disk provider status are implemented in source.
The remaining data areas below can progress independently.

1. **Storage and performance.** [Aggregate PerfDisk I/O](windows-storage-io.md) is implemented independently of [drive/volume and provider context](windows-storage-context.md). Per-disk attribution and real paging-I/O measurements remain open. Commit capacity and aggregate pagefile use are implemented, but do not prove paging pressure or thrashing. Add physical disk/SMART
   information only where safely supported. Capacity is not disk health; no
   driver installation or elevation to fill a missing field.
2. **Broader process metrics and software.** Complete basic process snapshots now
   have generation-pinned search/paging. CPU/RAM remains a separately consented
   128-row sample; extending it needs creation-identity-safe measurement and its
   own explicit scope. Broader software coverage needs a user-context design;
   per-user/Store and portable apps are not covered by machine HKLM registrations.
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

After missing Admin data is complete, validate the exact matching Setup, service,
manager and dashboard on fresh Windows targets. The
[Windows 11 checklist](windows11-acceptance-matrix.md) covers real installation,
human UAC, hidden invitation/identity approval, service-token reads and actual
manager/browser data. A hosted Server 2025 result is not Windows 11 evidence.

Keep source CI, browser fixtures and native results distinct. Reboot/sleep,
signing, ARM64 and complete removal need explicit evidence. Do not reuse the
published five-scope approval as consent for the current Read admin profile.

## Later management work

Connect trustworthy evidence to incident acknowledgement, maintenance and
notifications. Broader exact-target service/update actions require separately
reviewed authority, explicit approval, least-privilege execution and durable
one-use records. Local Tracebolt restart is not arbitrary remote control.
Remote desktop, general file management and unattended remediation remain out
of the current scope.

## Rules for every feature

Keep screens compact, readable and bilingual, with useful screenshots rather
than repeated status prose. Show source, original age, bounds and failure states.
Unknown is not healthy. New collection is default-off and explicitly disclosed;
manager updates do not expand local grants. Preserve session expiry/revocation
and keep operator-only metadata out of AI, exports and notifications unless
separately approved. Use focused regressions and required CI; a real authorization
or data-integrity defect blocks the affected feature.
