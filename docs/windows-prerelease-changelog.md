# Windows preview.3 release candidate

**Release preparation.** Preview.3 targets the exact current source pinned in
`windows-prerelease-install.md`, with a matching Linux manager/frontend build.
The three-case native Setup gate and aggregation passed in
[run 38369063888](https://github.com/storminator89/Tracebolt/actions/runs/38369063888),
and the later publisher candidate pins that accepted tree. Exact-source
[full Validate 38369024941](https://github.com/storminator89/Tracebolt/actions/runs/38369024941)
must succeed before publication; the linked run’s live conclusion is
authoritative. Publisher review/CI and explicit publication approval are also
required. Verify release availability separately.
[Preview.2](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2)
and its attached instructions remain unchanged.

## What this candidate includes

- Fresh **Read admin** Setup with 21 disclosed read scopes and unchecked consent,
  including personal/identifying metadata and sensitive historical event messages.
- Matching current-source manager/frontend functionality: inventory browsing,
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

## Required release evidence

The exact source passed first-attempt `windows-current-setup-acceptance.yml`:
three fresh hosted Server 2025 x64 cases
(install/service removal, hidden-input cancellation and pending-transport
interruption), plus aggregation. Full Validate remains required. This is a TLS
loopback-fixture packaged-GUI
subset. It does not prove Windows 11, real Linux-manager/dashboard use, complete
providers, event-history requests, renewal cutover, restart/reboot, human
invitation/UAC, ARM64, signing, VM disposal or optional-feature acceptance.
Software-history and event-history observations remain `not_run`; denied,
unsupported and unknown source outcomes never imply completeness.

Publication uses the unchanged six-file tested package and canonical aggregate,
with this guide, the installation guide and `release-manifest.json`. Executable
filenames and embedded version remain `v0.0.0-setup-candidate`; no rebuild,
renaming, reversioning or signing is permitted. The manifest binds the separate
release tag, exact source/tree/run, publisher revision and original artifact
IDs/digests. Build-time `nativeExecution: false` remains unchanged.

All original reports and the tested input package must remain available; their
three-day retention cannot be replaced by the seven-day aggregate, a new upload
or a rebuild. Missing proof, expired artifacts or a changed source/publisher
lease stop publication. There is no overwrite, adoption or automatic write retry.
See the [publication contract](windows-prerelease-publication.md).

## Before testing

Follow the attached installation guide on a separately approved fresh target,
including the exact-source Linux manager build and protected TLS/operator/guided
enrollment prerequisites. Setup and service are unsigned: do not bypass OS or
administrator policy blocks. This is not full Windows/Linux native parity, an
automatic updater or a full data uninstaller.
