# Releases and development

The [project overview](README.md) describes current source functionality.
The [Windows status](docs/windows-status.md) and platform roadmaps describe
remaining work. Source changes are not automatically included in published assets.

## Current development

Saved MSI worklists can review one shared UTC installation window for multiple
exact devices and one selected catalogue package. Fresh per-device scheduled
authority remains required; sequential approvals retain independent outcomes and
stop on uncertainty. No installation permit follows from merely saving a schedule.
See [scheduled MSI](docs/windows-scheduled-managed-msi.md#saved-fleet-scheduling-for-one-selected-package).

Fresh manager-only [multi-package MSI catalogue](docs/windows-multi-package-msi-catalogue.md):
four retained payloads within one 128 MiB reservation budget, exact custody/device
selection, scoped retirement and bounded per-entry worklists. Existing endpoint
grants and signed wire formats remain unchanged; source verification only.

Windows development adds complete service/machine-software browsing, richer
network/update/security/session/hardware/storage context and fresh fifteen-scope Read
admin setup. Selected event messages, cached update inspection, health policies
and service control retain their separate scope and acceptance requirements.
These additions are not in the older Windows preview. Missing Admin data comes
before current-source native acceptance and the next release.

## Published endpoint prereleases

- [Linux v0.1.0-rc.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-rc.3):
  verified Linux amd64 read-admin download selected by the dashboard.
  [Setup, scope and platform limits](docs/read-admin-onboarding.md).
- [Windows v0.1.0-windows-preview.1](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.1):
  unsigned x64 five-scope read-only preview, with a limited hosted Server 2025
  acceptance result. [Installation and exact artifact evidence](docs/windows-prerelease-install.md).

Manager deployment is separate from endpoint releases. The existing tags and
published assets are unchanged.

## History

The full [development/test log](docs/archive/development-log.md),
[archived planning snapshots](docs/archive/README.md), Git history and
[release records](https://github.com/storminator89/Tracebolt/releases) preserve
prior milestones. They are reference material, not current setup instructions.
