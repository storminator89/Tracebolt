# Linux pilot roadmap

This is the ordered plan for making the Linux pilot easier to install and useful
for everyday device inspection. An item being planned or implemented does not
mean it has passed its release or host checks.

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
3. **Verified release-download installer — official pilot.2 verified and pinned.**
   The [attested build and fresh-version publication workflow](linux-release-distribution.md)
   and source-pinned dashboard command are implemented. Official assets passed
   independent public-byte and provenance checks. An observed owned upgrade
   committed successfully but its wrapper then reported a cleanup error; that
   narrow wrapper correction is tracked separately. Do not interpret a wrapper
   failure as permission to reinstall or reset an already committed identity.
   Existing pilot.2 binaries do not include the later journal feature.
4. **Useful on-demand service logs — current integration priority.** The current
   source candidate connects exact service/time/severity requests, a separate
   least-privileged helper, original-expiry results, paged display and literal
   text search over the captured snapshot. Critical authority/retention checks
   and source review precede rollout. A concrete local helper/content permission
   grant and actual host acceptance remain separate. See the
   [log boundary](journal-content-mvp.md) and [setup plan](linux-journal-helper.md).
   Minor visual polish does not block a usable, correctly bounded MVP.
5. **Complete everyday inventory overview — next functional slice.**
   - Use the completed dpkg generation for software totals and overview links,
     avoiding a contradictory bounded-preview count beside complete inventory.
   - Capture all supported visible process rows into a generation-bound paged
     view rather than presenting the existing sample as a complete overview.
     Command lines, environment and unrelated account data remain excluded.
   - Capture complete supported visible mounted-filesystem metadata with paged
     display. Put measured local filesystems first and virtual mounts separately;
     do not present the current 32-row preview as complete. Add the regression
     where 32 virtual mounts precede the measured root filesystem so the useful
     volume cannot disappear behind truncation.
   - Label the agent-visible mount/process namespace, including systemd sandbox
     mounts. A tmpfs is not a physical disk, and the service's `/home` view may
     differ from the host's real mount. Capacity that is not applicable differs
     from denied, failed or unimplemented measurement. Preserve resource ceilings
     as explicit failed/partial states, never successful complete prefixes.
   - Keep unsupported Snap, Flatpak and manual-software coverage visible. A
     complete dpkg dataset is not a universal installed-software inventory.
6. **Offered updates and full-generation CVE coverage — after logs/inventory.**
   Bind completed supported package generations to identified upstream advisory
   sources and exact release/source-package provenance. Add an actual read-only
   cached offered-update adapter separately from advisory fixed-version matching.
   Unknown coverage must not become zero missing updates or zero vulnerabilities.
   Current offline review candidates remain candidate evidence.

## Requested usability and diagnostic follow-ups

These remain visible without growing the active log slice:

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

Windows/macOS LAN installation, automatic remediation, credential renewal and
production fleet assurance are outside this Linux delivery sequence. Published
checkpoints and their validation limits are recorded in the [changelog](../CHANGELOG.md).
