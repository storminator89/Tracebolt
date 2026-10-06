# Linux pilot roadmap

This is the ordered plan for making the Linux pilot easier to install and useful
for everyday device inspection. An item being planned or implemented does not
mean it has passed its release or host checks.

## Immediate delivery and approved follow-ups

The current priority is delivering the three reported Debian fixes (process
names, cached APT configuration and device-header refresh) through a verified
update of the existing full read-admin installation. The update must preserve
identity, history, consent and private counters while coordinating both helpers.
Publishing source or rebuilding the manager alone does not update the endpoint.
Other feature work must not delay that maintenance path and its acceptance.

The following requests have the individual source status below. Source work does
not activate a feature or change consent on an installed host:

- **Automatic certificate renewal with UI revocation.** Renew before expiry while
  keeping the same device identity and history. Existing revocation must block
  ingestion and renewal across every certificate generation. Preserve local
  helper/consent bindings and counters; show failures and an explicit recovery
  path if a device misses expiry. Do not silently grant perpetual credentials.
- **Recognizable device rows — implemented in source.** The main table shows the
  reported hostname and interface-scoped IP addresses, including multiple-address,
  stale and missing states. Stable IDs still bind navigation and remain visible
  as technical details. One bounded operator read reuses existing approved identity
  observations; it creates no collection grant. Hosted desktop/mobile acceptance
  of this new table remains pending. See [the display contract](fleet-endpoint-identity.md).
- **Usable alarm setup in Settings — implemented in source, off by default.**
  Administrators can review and save one generic public HTTPS webhook, explicitly
  approve the disclosed payload, enable or disable delivery, and deliberately
  enqueue a synthetic test. Named users need the existing configured administrator
  to grant the new manage_alarms capability; source publication grants nobody that
  capability. The complete URL is write-only and protected at rest. No provider was
  configured or contacted during source validation; new hosted UI acceptance remains
  pending. Provider acceptance does not confirm human receipt. See [alarm delivery](alarm-delivery.md).
- **Rule-based investigations for real LAN devices — implemented in source.**
  Investigations and Overview now project the existing durable Health incidents:
  contact loss, root-filesystem capacity and explicitly selected services. Open,
  recovered and monitoring-stopped history remain distinct, with original incident
  timestamps and separately aged current checks. Device Health, details and exact
  service-log links support read-only triage. This is not a new diagnosis engine,
  raw-evidence archive, AI root-cause analysis or separate case workflow. Native
  deployment and hosted browser acceptance remain pending. See
  [Health investigations](linux-health-checks.md#fleet-investigations).
- **Service-log selection and capture time — implemented in source.** Exact
  observed unit names and reported-alias hints reduce guesswork; an alias target
  is never inferred. Last 15 min explicitly prepares a new draft window while
  retained rows keep their original capture window and age. Empty capture and
  empty search remain distinct. Exact service/time review, unchecked content
  approval and local scope boundaries are preserved. New hosted layout/interaction
  acceptance and native Debian service evidence remain separate pending gates.

## Current MVP priorities

1. Make the on-demand Logs flow readable, searchable and actually testable from
   request through the separately granted local helper to the result view.
2. Make the everyday overview complete for supported visible processes, mounted
   filesystems and dpkg software. UI paging is welcome; silent successful capture
   truncation and contradictory sample/full totals are not.
3. Simplify the installer command the user copies. Keep provenance, environment,
   identity/state, permission and consent checks inside the supported flow, while
   reducing manual staging/build/hash steps. This follows Logs and complete
   inventory; it must not delay them or relax those checks.

Complete cached-APT rows and limited distribution-version CVE warnings are now
wired in source; their remaining limits are listed below. Compatible installed
binaries, explicit local grants and native acceptance remain separate from source
publication. Minor visual polish does not block these practical milestones.

## Available and observed

- The repository contains the Docker/native manager, guided Linux enrollment,
  an explicitly installed systemd agent, and the fresh `managed-operations-v3`
  collection profile. Use the [fresh-start guide](http-complete-first-start.md).
- Supported dpkg generations, service inventory and local socket/connection
  observations have bounded, paged views. Coverage, source failures, permission
  gaps and collection ages remain visible. A complete dpkg generation does not
  cover every software ecosystem.
- The [1dadb7b baseline](https://github.com/storminator89/Tracebolt/actions/runs/37204747228)
  passed all 13 CI jobs, including positive native Ubuntu observations and 92
  required browser checks. Three previously documented enrollment browser cases
  remain skipped.
- A manually operated Debian pilot has reported the installed service active and
  enabled, with fresh metrics and package/service/socket inventory. This is one
  pilot observation, not fleet, unattended-install or general reboot assurance.
  Reboot recovery must be observed separately.
- Capability descriptions now distinguish selected collection scope from actual
  successful reads. The source-archive commands preserve private permissions and
  refuse to overwrite an existing archive.

The [full-width device-page checkpoint](https://github.com/storminator89/Tracebolt/actions/runs/37210508045) also passed all 13 CI jobs and the same 92 required browser checks, with focused desktop/mobile page and consent-dialog review.

## Delivery order

1. **Clear device page and shorter enrollment flow — delivered in `a9a9d4e`.** Give device
   details enough room, simplify the invitation dialog, and keep capability and
   unavailable-state descriptions accurate. Preserve explicit consent, hidden
   secret entry and deliberate device approval.
2. **Opt-in hostname and interface addresses — published.** The default-off
   extension works with an existing activated v3 identity after explicit local
   consent. Native opt-in/report/restart/disable and 98 required browser checks
   passed; see [the fully green binary-source checkpoint](https://github.com/storminator89/Tracebolt/actions/runs/37219826603).
   Local addresses show their source and original age and do not establish
   external reachability. No network scan is implied.
3. **Verified release-download installer — rc.2 verified and activated.**
   The [dashboard command](dashboard-verified-download.md) pins bootstrap
   publication `08c7f0e` for rc.2, built from source `a6368b0`. Its release and
   all twelve public asset/provenance checks passed; hashes and immutable source
   references bind the bytes, rather than a claim that GitHub locked the release.
   The complete profile uses one combined local read-admin approval, hidden
   invitation entry and dashboard identity approval. Updating the manager does
   not upgrade the endpoint. A supported update of the installed full profile is
   the immediate delivery work above; no identity reset or reinstall is implied.
4. **Useful on-demand service logs — published and observed on one granted pilot.**
   The [d3628dc checkpoint](https://github.com/storminator89/Tracebolt/actions/runs/37228371588)
   passed all 13 CI jobs and 104 required browser checks, including six journal
   scenarios. The source connects exact service/time/severity requests, a separate
   least-privileged helper, original-expiry results, paged display and literal
   text search over the captured snapshot. Critical authority/retention checks
   and source review precede rollout. A manually approved, dedicated helper has
   returned real service-log content to the dashboard on one Debian pilot. That
   establishes the first capture path, not fleet or uninterrupted-retention
   assurance. Published corrections for a subsequent temporary-read cache-loss bug and
   silent paused-view bug pass expanded browser lifecycle checks. Full combined
   regression and target-host confirmation remain separate. See the
   [log boundary](journal-content-mvp.md) and [setup plan](linux-journal-helper.md).
   Minor visual polish does not block a usable, correctly bounded MVP.
5. **Complete everyday inventory overview — wired in published pilot source.**
   [Complete process/mount capture and paging](complete-overview-extension.md)
   preserve independent generations and original ages. Inventory now defaults to
   Packages; [current source presentation](inventory-security-workspace.md) keeps
   each reader and its coverage distinct. Earlier container, browser and retry
   hardening results are [historical checkpoints](../CHANGELOG.md); exact-commit
   aggregate checks and native acceptance must still be assessed separately.
   - Software totals and overview links use the completed dpkg generation,
     avoiding a contradictory bounded-preview count beside complete inventory.
   - Supported visible process rows use a generation-bound paged view; the
     existing bounded sample remains a separate diagnostic source.
     Command lines, environment and unrelated account data remain excluded.
   - Complete supported visible mount metadata has paged display, with measured
     local filesystems first and virtual mounts separately. The older 32-row
     preview cannot establish complete coverage.
   - Label the agent-visible mount/process namespace, including systemd sandbox
     mounts. A tmpfs is not a physical disk, and the service's `/home` view may
     differ from the host's real mount. Capacity that is not applicable differs
     from denied, failed or unimplemented measurement. Preserve resource ceilings
     as explicit failed/partial states, never successful complete prefixes.
   - Keep unsupported Snap, Flatpak and manual-software coverage visible. A
     complete dpkg dataset is not a universal installed-software inventory.
6. **Cached APT candidates and distribution CVE warnings — wired with limits.**
   [Complete cached candidates](complete-cached-updates-extension.md) require
   separate local opt-in, read existing APT metadata at a six-hour cadence and
   preserve original age, unknown comparisons and unsupported sources. No APT
   refresh or installation occurs. [CVE warnings](linux-cve-warnings.md) compare
   complete dpkg generations with an explicit Debian 13 feed sync or limited
   manual Ubuntu 24.04 OSV import. They do not prove installed-artifact origin,
   exploitability or installable fixes. Missing/stale data is not zero findings.

7. **Explicit service try-restart — default-off source candidate.** The narrow
   [service-action workflow](service-action-workflow.md) connects named-operator
   preview/approval, durable first-claim-only delivery and a separately granted
   root helper. UI completion remains agent-reported and distinct from service
   health; ambiguous outcomes block another action. The [create-only setup
   guide](guided-service-action-setup.md) provides fresh manager/endpoint adapters;
   named operators, protected command trust, a reviewed unit, local grants and
   native disposable-host acceptance remain required. No manager upgrade creates
   keys or enables privileged execution. The separate [package-plan
   core](selected-package-plan-core.md) remains pure and inert with no runtime callers.

## Requested usability and diagnostic follow-ups

These remain visible without widening the current complete-inventory slice:

- The source now offers a searchable observed-service selector and explicit UTC
  reference-window presets, preserving manual entry and stable drafts. Hosted
  checks remain commit-specific; target-host setup is separate. An observed name
  does not prove permission in the endpoint's separately managed local allowlist.
- Keep temporary read contention recoverable without discarding a live accepted
  snapshot. Expiry, session loss and revoked device authority still suppress
  content; no failed or lost request is automatically recollected.
- Separate fresh contact from overall health, which is not yet assessed. Keep
  navigation stable without caching private log content across sessions/devices.
- Show metric sample times, measurement windows, formulas and absolute memory
  units so guest values can be understood beside hypervisor measurements.
- Improve process ownership attribution only through a separately disclosed,
  narrowly granted read boundary; permission-denied attribution is not an empty
  ownership list or an external-reachability claim.
- Keep one target-host administration step followed by dashboard approval, with
  no manual bootstrap-file transfer. Each new runtime feature needs compatible
  verified binaries; a manager-only update cannot upgrade an endpoint implicitly.

Windows/macOS LAN installation, automatic remediation and production fleet
assurance remain outside this Linux delivery sequence. Certificate renewal is
now an explicitly requested Linux follow-up above, with release and host
acceptance still outstanding. Published
checkpoints and their validation limits are recorded in the [changelog](../CHANGELOG.md).
