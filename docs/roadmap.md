# Linux priorities

The Linux source already provides a self-hosted manager, guided enrollment,
nonroot background reporting and a fresh read-admin setup. The published endpoint
command selects **v0.1.0-rc.3**. See [installation](installation.md) for supported
hosts and [Windows priorities](windows-admin-roadmap.md) for the current Windows
Admin-data work.

## Available source functionality

- Reported hostname/interface identity, contact and 24-hour CPU/RAM/disk history
- Complete visible process/mount and dpkg package generations, services and sockets
- Explicitly approved exact-service journal capture and retained browsing
- Cached APT candidates and bounded Debian/Ubuntu CVE warnings
- Contact/disk/selected-service Health, rule-based investigations and optional
  manager-side HTTP/HTTPS/DNS/TCP checks
- Default-off webhook delivery and separately approved Health/service-log AI
- Separate controlled-service and selected-APT execution source workflows;
  their host grants and native acceptance are not supplied by read-admin setup

The [guides](README.md) describe actual setup and scope. A complete dpkg inventory
does not include Snap, Flatpak or manually installed software. Cached candidates
are not an installation guarantee; CVE matches are not exploitability verdicts.
A manager update does not replace an endpoint binary or grant new collection.

The [CVE-to-cached-Updates review flow](linux-cve-warnings.md#review-an-exact-binary-in-cached-updates)
is implemented in source. It carries an exact binary name/version/architecture
into cached Updates for manual review, without selecting or installing anything.
A cached candidate does not prove that the CVE is resolved. This flow is not part
of published Linux rc.3.

## Remaining work

1. **Dependable installation and lifecycle.** Confirm fresh supported-host
   behavior, interruption/recovery, reboot and backup/restore on exact artifacts.
   Linux ARM64/Pi installation remains gated by its [native acceptance](linux-arm64-support.md).
   Do not infer fleet readiness from one host or a cross-build.
2. **Certificate renewal.** Complete automatic-renewal review and release/host
   acceptance while preserving identity, history, local grant bindings, counters
   and revocation across certificate generations. Expiry/revocation handling is
   not yet a shipped automatic renewal service.
3. **Controlled actions.** Validate the separately authorized
   [service workflow](guided-service-action-setup.md) and
   [selected APT updates](selected-package-updates-native.md) on disposable native
   targets before release. Preserve exact plans, durable consumption, shared
   mutation fences and explicit partial/unknown outcomes. No automatic reboot,
   replay or blanket package installation.
4. **Useful incident history.** Inventory changes, maintenance/acknowledgement and
   alarm/recovery context should retain original times and missing-data gaps.
   Broader kernel/system/authentication or application logs need new bounded
   source scopes, not a generic file reader.
5. **Real-target monitoring.** Verify approved application checks and webhook
   delivery with their actual destinations. Provider acceptance is not human
   receipt. Add database/backup adapters only for a concrete need; a successful
   backup job does not prove restore works.

## Keep the daily workflow simple

Use one reviewed local setup step followed by dashboard identity approval.
Preserve selected device/service, search and capture window through ordinary
refreshes. Keep missing permissions, empty captures, empty search results,
expired snapshots and temporary failures visibly distinct. Source/time details
should be available without filling the main screen with implementation history.

Remote shell, integrated remote desktop, customer multi-tenancy and unattended
remediation are outside this plan. Native acceptance and production hardening
remain separate from implemented source and published prereleases.
