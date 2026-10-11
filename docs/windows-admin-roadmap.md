# Windows priorities

The immediate goal is useful, dependable Admin data in the shared dashboard.
Finish these source features first, then validate fresh native installation and
publish compatible artifacts. Current development and the older downloadable
preview are described in [Windows status](windows-status.md).

There are no existing user installations. Migration, binary upgrade and
reconsent are not delivery gates for this fresh-install target. Integrated
remote desktop is deferred.

## Already in the source

- Complete caller-visible Win32 services and HKLM 32/64 machine software
  generations, with bounded search/paging
- Fleet hostname/IP search, resource observations and independent optional
  disk/CPU/RAM/selected-service checks
- Adapter link/DNS/gateway, build/update history/reboot, Defender/Firewall,
  session/join, hardware/firmware/power and drive-letter/provider-disk context
- [Security Center antivirus registration/status and TPM presence/version](windows-security-coverage.md), with explicit client/server and provider-access limits
- Event headers, separately approved selected messages and offline cached updates
- Concise fresh Read admin setup with explicit unchecked consent; service control
  remains separately optional

Implementation is not a release or native provider-access result. The
[individual scope guides](windows-read-admin-setup.md) define the coverage and
exclusions; do not treat a complete registration list as every installed app.

## Missing Admin data

Drive-letter mapping and physical-disk provider status are implemented in source.
The remaining data areas below can progress independently.

1. **Storage and performance.** Extend [drive/volume and provider context](windows-storage-context.md) with I/O latency,
   queue/throughput and memory commit/pagefile pressure. Add physical disk/SMART
   information only where safely supported. Capacity is not disk health; no
   driver installation or elevation to fill a missing field.
2. **Complete process inventory.** Use one coherent generation with search/paging,
   visible collection limits and unambiguous missing/denied results. Broader
   software coverage needs its own user-context design; per-user/Store and
   portable apps are not covered by machine HKLM registrations.
3. **Security and patch detail.** BitLocker state, Secure Boot and TPM readiness where legitimately accessible,
   and trustworthy update freshness/applicability/CVE evidence. Never read
   recovery keys or infer “secure” or “fully patched” from absent data.
4. **Network and hardware detail.** Routes, traffic/error counters and CPU/RAM
   configuration, with honest virtual/unsupported/provider limits. No automatic
   probes, packet content or privilege expansion.
5. **Changes and history.** Software version/install/remove changes from comparable
   complete generations; useful inventory diffs; bounded older-event retrieval,
   continuation and search. Partial captures must not invent an uninstall or
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
