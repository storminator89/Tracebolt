# Guides

Start with the task you want to complete. The [project overview](../README.md)
describes current development functionality. The published endpoint prereleases
have their own installation guides and narrower feature sets.

## Choose the matching package and evidence first

Use the linked status or candidate guide to select the exact manager/frontend
and endpoint source, profile, artifacts and acceptance record together. A current
source feature is not automatically in a published package; a published package
or successful fixture run is not full native acceptance. Do not combine Go Read
admin and Rust Basic installation instructions or infer authority from a smaller
collector. The Rust candidate still uses the broader `windows-inventory-v1`
manager identity; it is not a distinct basic-only authorization domain. See its
[scope and delivery contract](../rust/windows-agent/README.md#scope-and-delivery).

Release versions and source pins belong in those guides and their manifests,
not a second independently maintained download recommendation in this index.
Historical packages remain linked separately below.

## Setup

- [Local dashboard demo](../README.md#try-the-dashboard-locally)
- [Linux/Docker manager installation](installation.md)
- [Connect a Linux device](dashboard-verified-download.md) and [review its read-admin scope](read-admin-onboarding.md)
- [Windows Go Read admin: published package, matching source and bounded native evidence](windows-status.md)
- [Windows fresh-install audit, priorities and shorter preparation](windows-installation-audit.md)
- [Windows Read admin scope and setup](windows-read-admin-setup.md)
- [Rust Windows Basic integrated test candidate](integrated-test-candidate.md): separate manager/package pairing and remaining native gates
- [macOS unsigned service-test package](macos-prerelease.md) and [basic/inventory source limits](macos-status.md): architecture and profile selection; native installation and reboot acceptance remain pending
- [Troubleshoot missing data or incomplete setup](troubleshooting.md)

## Everyday use

- **Devices:** search reported hostnames/IPs, open a device, and check original
  observation time and source coverage. [Fleet identity](fleet-endpoint-identity.md),
  [Windows identity](windows-fleet-identity.md), [resource history](resource-history.md).
- **Inventory:** browse/search the collected generation. Linux has separate
  [process/mount](complete-overview-extension.md) and package data; Windows has
  [process snapshots](windows-full-processes-contract.md),
  [services](windows-full-services-contract.md) and
  [machine software](windows-full-software-contract.md). A bounded sample is not
  a complete inventory. Optional [selected-account software](windows-selected-user-software.md)
  adds explicitly captured HKCU and Store registrations. Separately acknowledged [software change history](windows-software-history.md)
  retains observed registration/metadata differences with original times and visible gaps.
- **Logs:** choose an exact [Linux service and time window](journal-content-mvp.md)
  or approved [retained service history](retained-journal-browsing.md). Windows
  offers [event-header browsing](windows-logs-sample-browser.md) and separately
  approved [selected messages](windows-event-content-runtime.md).
- **Storage:** [drive-letter mappings and physical-disk provider context](windows-storage-context.md), plus separately consented [aggregate PerfDisk I/O](windows-storage-io.md), with independent source coverage and no inferred disk-health verdict.
- **Updates and security:** inspect [cached APT candidates](complete-cached-updates-extension.md)
  and [Linux CVE coverage](linux-cve-warnings.md), or Windows
  [build/history/reboot context](windows-patch-context.md),
  [cached updates](windows-update-runtime.md) and [Defender/Firewall posture](windows-security-posture.md).
  The [Linux CVE-to-Updates source workflow](linux-cve-warnings.md#review-an-exact-binary-in-cached-updates)
  carries an exact binary into cached Updates for manual review. It is not part
  of published Linux rc.3.
- **Health:** [Linux checks](health-dashboard.md); Windows
  [disk](windows-capacity-health.md), [CPU/RAM](windows-resource-health.md) and
  [selected-service](windows-service-health.md) policies. Use [fleet groups](fleet-groups-health.md)
  to organize devices and review one-time Windows disk/CPU/RAM settings. The
  separate [ongoing group-monitoring source feature](fleet-group-monitoring.md) adds
  reviewed opt-ins for exact existing members and metrics. Check the
  [exact release boundary](windows-status.md) before using it with a published
  package. Group membership alone never enables a policy.
- **Optional settings:** [application checks](application-checks.md),
  [DNS/TCP checks](application-network-checks.md), [webhook alarms](alarm-delivery.md),
  [Health AI](proactive-ai-diagnostics.md) and [service-log AI](proactive-service-log-ai.md).

Opening a view does not grant collection, service control or external data
sharing. A fresh report is not an overall health verdict. Unavailable, partial
and stale results retain their original meaning.

## Operations and technical references

- [Trust and TLS](lan-trust.md), [named operators](named-operator-auth.md) and [security boundaries](lan-security-review.md)
- [Backup, restore and removal](installation.md#10-stop-back-up-restore-update-uninstall)
- [Windows retained state and service removal](windows-setup-preview.md#cancellation-retained-state-and-service-removal)
- [Support bundle and review before sharing](support-bundle.md)
- Separate controlled-action scope: [Linux services](guided-service-action-setup.md),
  [Windows services](windows-service-actions.md), [selected APT updates](selected-package-updates-native.md),
  [selected Windows update setup](windows-selected-update-setup.md),
  [fresh reusable cached-update jobs](windows-reusable-cached-update-jobs.md) and
  [guided MSI catalogue review](windows-multi-package-msi-catalogue.md#guided-package-review).
  These source workflows require separate consent and native acceptance;
  the Go preview's packaged-Setup subset does not validate optional actions.
- Existing development interfaces: [Linux read-admin update](read-admin-upgrade.md)
  and [inventory opt-in](guided-inventory-setup.md)
- [Frontend development](../web/README.md), [LAN runtime](lan-runtime.md),
  [client tests](../tests/lanclient/README.md), [Windows packaging](windows-setup-release.md)
- [Product scope](product-plan.md), [Windows priorities](windows-admin-roadmap.md), [Linux priorities](roadmap.md)

Scope contracts, release manifests and acceptance records remain alongside the
implementation they describe. Prior milestone/test narratives are kept in the
[archive](archive/README.md); they are not current setup instructions.

## Historical Windows packages

These are retained provenance, not the current setup recommendation. Use each
historical package's own source pin, manifest and narrower scope; do not pair it
with an arbitrary current manager. Current Go Windows release selection remains
in [Windows status](windows-status.md); Rust Basic is a separate candidate above.

- [Windows preview.2](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2) and its [attached installation guide](https://github.com/storminator89/Tracebolt/releases/download/v0.1.0-windows-preview.2/windows-prerelease-install.md)
- [Windows preview.1 historical installation guide](windows-prerelease-historical/windows-prerelease-install.md)
