# Windows preview.3 prerelease

Unsigned [preview.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.3)
was published on 13 October 2026. Its endpoint and matching Linux manager/frontend
source is exactly `992b8d8c9d9693a97bd63301a3c147e1b2681357`, not current main.
Use the release's [attached installation guide](https://github.com/storminator89/Tracebolt/releases/download/v0.1.0-windows-preview.3/windows-prerelease-install.md)
and manifests. The [Windows status guide](windows-status.md) records current
source functionality separately from these published bytes.
The three-case native Setup gate and aggregation passed in
[run 38369063888](https://github.com/storminator89/Tracebolt/actions/runs/38369063888),
and the same exact source passed
[full Validate 38369024941](https://github.com/storminator89/Tracebolt/actions/runs/38369024941)
before publication. Those results do not accept newer source commits.
[Preview.2](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2)
and its attached instructions remain unchanged.

## What this prerelease includes

- Fresh **Read admin** Setup with 21 disclosed read scopes and unchecked consent,
  including personal/identifying metadata and sensitive historical event messages.
- Matching exact-release-source manager/frontend functionality: inventory browsing,
  fleet machine-software lookup, incident/service review and separately configured
  monitoring, notifications and maintenance workflows.
- TLS bootstrap, independent identity comparison, hidden invitation input and
  a compatibility check before installation writes.
- Disabled LocalService staging; activation and exact grant verification before
  automatic startup and Start. Cooperative cancellation retains uncertain state.
- Separately acknowledged same-key renewal enrollment and initial credentials.
  This gate does not test renewal cutover or native restart/reboot.
- Receipt-owned service removal with final SCM absence checks. Files, keys,
  identity, grants, counters and manager trust remain afterward.

Read admin does not activate optional MSI delivery/installation, WUA inspection,
selected update downloads/installation, service control, sampled-event messages
or selected-account software. Those require their own setup, approval and native
acceptance. Manager UI availability does not grant endpoint or external-delivery
authority, and no AI-export permission follows from read consent.

## Published release evidence and limits

The exact source passed first-attempt `windows-current-setup-acceptance.yml`:
three fresh hosted Server 2025 x64 cases
(install/service removal, hidden-input cancellation and pending-transport
interruption), plus aggregation. Exact-source full Validate also passed. This is a TLS
loopback-fixture packaged-GUI
subset. It does not prove Windows 11, real Linux-manager/dashboard use, complete
providers, event-history requests, renewal cutover, restart/reboot, human
invitation/UAC, ARM64, signing, VM disposal or optional-feature acceptance.
Software-history and event-history observations remain `not_run`; denied,
unsupported and unknown source outcomes never imply completeness.

Publication used the unchanged six-file tested package and canonical aggregate,
with the release's attached changelog, installation guide and `release-manifest.json`. Executable
filenames and embedded version remain `v0.0.0-setup-candidate`; no rebuild,
renaming, reversioning or signing is permitted. The manifest binds the separate
release tag, exact source/tree/run, publisher revision and original artifact
IDs/digests. Build-time `nativeExecution: false` remains unchanged.

The publication contract required all original reports and the tested input
package to remain available during publication. Their three-day retention could
not be replaced by the seven-day aggregate, a new upload or a rebuild. Expired
workflow artifacts do not make a fresh publication or overwrite permissible.
The public release carries its bound evidence and manifests; existing assets
are not replaced. See the [publication contract](windows-prerelease-publication.md).

## Before testing

Follow the attached installation guide on a separately approved fresh target,
including the exact-source Linux manager build and protected TLS/operator/guided
enrollment prerequisites. Setup and service are unsigned: do not bypass OS or
administrator policy blocks. This is not full Windows/Linux native parity, an
automatic updater or a full data uninstaller.
