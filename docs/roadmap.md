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
2. **Opt-in hostname and interface addresses — in progress.** Add a clear collection
   choice for hostname and local interface IPv4/IPv6 addresses. Show source and
   visibility limits. Local addresses do not prove external reachability; this
   does not add network scanning.
3. **Verified release-download installer — source prepared; official build pending.**
   The [manual attested build and fresh-version publication workflow](linux-release-distribution.md)
   and disabled dashboard command are implemented and source-reviewed. Provide official Linux
   release artifacts and a short installation command that verifies the selected
   release before execution. Publication, verification and a fresh-host install
   must pass before this replaces the current source-build instructions. Existing
   local state and approval boundaries remain protected.
4. **Narrow log and process attribution — planned.** Add only explicitly chosen
   read access needed for useful diagnostics, with bounded data and clear gaps.
   Do not grant blanket root collection or quietly broaden existing consent.
5. **Offered updates and full-generation CVE coverage — planned.** Bind supported
   package generations to current, identified upstream sources and explicit
   matching/coverage rules. Keep unknown results honest until those sources and
   mappings are verified. Existing offline review candidates are not confirmed
   vulnerabilities or offered-update counts.

Windows/macOS LAN installation, automatic remediation, credential renewal and
production fleet assurance are outside this Linux delivery sequence. Published
checkpoints and their validation limits are recorded in the [changelog](../CHANGELOG.md).
