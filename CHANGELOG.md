# Releases and development

The [project overview](README.md) describes current source functionality.
The [Windows status](docs/windows-status.md) and platform roadmaps describe
remaining work. Source changes are not automatically included in published assets.

## Current development

Complete Linux process/mount views retain their search during explicit refresh,
restart at the first page of the newly checked generation and keep original
observation ages. A bilingual clear-and-refresh action permits recovery when
the retained search cannot be edited because the view is unavailable. Invalid
searches remain local. The independent enrollment test helper now extracts the
same production helper under both LF and Windows CRLF checkouts. Scheduled MSI
UI tests wait for the asynchronous mocked response before asserting its result.

The [fleet-group inventory filter](docs/fleet-groups-health.md#inventory-filter-states)
now distinguishes membership checks, unavailable membership and a missing selected
group from confirmed empty/search results. English/German recovery controls keep
the selection visible and let operators clear only the group filter. Unknown
membership shows an unknown count and admits no rows or CSV export. This is a
dashboard source change; published endpoint packages are unchanged.

Fresh [manual-download/scheduled-install coexistence](docs/windows-selected-update-downloads.md#fresh-manual-download-and-scheduled-install-coexistence)
uses separately acknowledged WUA/MSI installation scheduling under the existing
shared fence. Download remains manual; successful retirement precedes fresh WUA
installation review. Original manual-only profiles remain unchanged. Source
verification does not establish native Windows acceptance or release.

Read-only [fleet machine-software lookup](docs/windows-fleet-software-lookup.md)
finds reported application names/versions in existing complete HKLM generations,
with per-device source/age/coverage and identity-bound detail. No new collection,
selected-user inventory or installation authority is introduced.

Saved MSI worklists can review one shared UTC installation window for multiple
exact devices and one selected catalogue package. Fresh per-device scheduled
authority remains required; sequential approvals retain independent outcomes and
stop on uncertainty. No installation permit follows from merely saving a schedule.
See [scheduled MSI](docs/windows-scheduled-managed-msi.md#saved-fleet-scheduling-for-one-selected-package).

Fresh manager-only [multi-package MSI catalogue](docs/windows-multi-package-msi-catalogue.md):
four retained payloads within one 128 MiB reservation budget, exact custody/device
selection, scoped retirement and bounded per-entry worklists. Existing endpoint
grants and signed wire formats remain unchanged; source verification only.

Fresh Windows Read admin has twenty-one explicitly disclosed scopes. The next
[preview.3 candidate](docs/windows-prerelease-install.md) targets current source
with a matching manager/frontend build. Its bounded native Setup gate passed;
publication requires successful exact-source full Validate and publisher
review/CI. Optional features keep separate setup, consent
and acceptance requirements. Source changes are not a published release.

## Published endpoint prereleases

- [Linux v0.1.0-rc.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-rc.3):
  verified Linux amd64 read-admin download selected by the dashboard.
  [Setup, scope and platform limits](docs/read-admin-onboarding.md).
- [Windows v0.1.0-windows-preview.2](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2):
  unsigned x64 fresh 21-scope Read admin preview; three-case hosted Server 2025
  packaged-Setup subset. [Attached installation guide](https://github.com/storminator89/Tracebolt/releases/download/v0.1.0-windows-preview.2/windows-prerelease-install.md).
- [Windows v0.1.0-windows-preview.1](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.1):
  unsigned x64 five-scope read-only preview, with a limited hosted Server 2025
  acceptance result. [Historical installation and exact artifact evidence](docs/windows-prerelease-historical/windows-prerelease-install.md).

Manager deployment is separate from endpoint releases. The existing tags and
published assets are unchanged.

## History

The full [development/test log](docs/archive/development-log.md),
[archived planning snapshots](docs/archive/README.md), Git history and
[release records](https://github.com/storminator89/Tracebolt/releases) preserve
prior milestones. They are reference material, not current setup instructions.
