# Windows inventory in the shared dashboard

This source candidate connects the Windows collector, ordinary service sender,
Linux manager and existing device dashboard. It requires a fresh, explicitly
acknowledged `windows-inventory-v1` identity. It does not upgrade a basic Windows
identity or reuse a Linux `managed-operations-v3` identity.

Source and synthetic integration tests are available. Installed Windows service,
real Windows-to-manager/browser, hidden invitation console, shutdown/reboot and
released Windows installer acceptance remain pending. The separate
[manual native gate](windows-native-service-acceptance.md) is still required;
its selected profile and transport must match this fresh Windows inventory
identity. The source gate now supports this richer profile but has not run. The historical ProgramData policy block now has a reviewed path-pinning
correction. Its ordinary read-only result on the final composed source must be
observed before a native installation attempt. Do not change OS-root or
ProgramData ACLs to make a prerequisite check pass.

## Same manager, explicit Windows scope

The existing guided enrollment manager may opt in with
`"windowsInventoryEnabled": true` in its protected LAN configuration. The default
is false. The primary enrollment configuration keeps its current collection
profile; setting that primary profile to `windows-inventory-v1` is rejected.
The Windows domain uses a separate protected `enrollment-windows.db` alongside
the original database, with the same manager instance, approved issuer and
configured origin. Its 25 retained enrollment-record limit is independent.
Disabling the option hides the Windows domain; it does not erase its ledger or
silently convert its identities. Existing database fragments without the
original mode marker cannot be adopted as fresh state.

The shared Devices page adds an Operating system selector. Windows invitation
creation requires explicit consent to process/service/software metadata,
hostname/interface addresses and system metrics. Existing identity comparison
and manual manager approval remain mandatory. The Windows public bootstrap
carries the exact Windows profile. No released Windows download command is
advertised by this candidate.

Production HTTPS remains the default. A manager deliberately configured for the
existing `http-test` profile can accept this new Windows profile on the same
agent listener and show it in the same dashboard. The Windows invitation dialog
requires a second, initially unchecked plaintext-metadata acknowledgement. The
local Windows command separately requires `--insecure-http-test` and prints the
full warning before enrollment/state operations. Signed requests bind the exact
Windows path, identity, sequence and body; signatures prevent forgery/replay but
do not encrypt host names, addresses, inventory, invitation material or other
HTTP traffic. There is no automatic HTTPS-to-HTTP fallback. Basic Windows
service enrollment stays TLS-only.

## Local candidate flow

After the separate native prerequisites, exact executable provenance and
persistent-service/credential changes have been reviewed and approved, the
existing source service command selects this fresh scope with
`--install --apply --windows-inventory --bootstrap-file ABSOLUTE_PROTECTED_PUBLIC_BOOTSTRAP`.
A deliberately approved HTTP test additionally supplies `--insecure-http-test`.
`--basic-readonly` and `--windows-inventory` cannot be combined. Resume uses
`--enroll --apply --windows-inventory` with the same HTTP acknowledgement when
applicable. The retained bootstrap, identity and sender ledger must agree; these
commands do not reset or broaden an existing identity.

The invitation secret remains a hidden local-console input, never an argument,
environment variable or log. The installed LocalService process uses the
retained exact profile, then waits for the ordinary public-key/comparison
approval. No manager request grants extra host rights or runs arbitrary shell
commands. Service installation/uninstallation follows the existing reviewed
lifecycle policy; uninstall retains identity state.

## Collected data and bounds

One native read-only report supplies both chart metrics and the inventory:

- CPU interval usage for one processor group, physical RAM and system-volume
  usage, each with its own timestamp and quality. This base profile is not all-volume or
  multi-group CPU coverage. Separately consented visible-volume source is described
  in [Windows volume inventory](windows-volume-inventory.md).
- Caller-visible process IDs, parent IDs, executable names and thread counts;
  no command lines, owners or executable paths. Separately consented process
  CPU/working-set memory is described in [process metrics](windows-process-metrics.md).
- SCM-enumerated service names, display names, state and process IDs; no service
  start/stop or configuration authority.
- Machine uninstall-registry names, versions and publishers from 32/64-bit
  views; no `Win32_Product`, MSI repair, per-user registry sweep or claim that
  all installed applications are visible.
- Hostname and interface index/name/address/prefix observations. No remote
  connection list, packet capture, connection owners or network targets.

Native enumeration is bounded to 2,048 processes/services/software rows and 512
addresses. Transport allows at most 128 rows per process/service/software
section, 64 interface addresses and one hostname; the entire snapshot is at most
48 KiB and telemetry frame at most 72 KiB. Deterministic trimming may omit more
rows to meet the byte cap. Every section retains its source, visibility scope,
observed count, exact/lower-bound count flag, quality, completeness and truncation.
An exact scoped count does not establish whole-machine visibility. Denied and
unavailable observations are never successful empty inventories.

## Transport, storage and UI

The Windows client configuration and frame have their own schema versions and
sender-binding domain. Fixed enrollment routes are under
`/v2/windows/enrollment/`; signed telemetry uses `/v1/windows/agent/telemetry`.
Unknown fields, duplicate keys, oversized rows/frames, wrong platform/profile,
noncanonical timestamps and unconsented members are rejected. New sequences
must also advance capture time and generation. Exact accepted retries preserve
the original body, signature, collection time and receipt time across sender and
manager restarts; another profile cannot adopt their state.

The manager persists the validated frame and replay floors atomically using the
existing durable store. The same transaction supplies actual CPU/RAM/system-disk
points to the existing 24-hour resource history. Shared device listing merges
the two enrollment domains while rejecting duplicate device IDs. Windows-only
inventory is available through the authenticated, same-origin, read-only
`/api/devices/{id}/windows-inventory` route. Invitation operations use
`/api/windows/enrollment` and the existing session/CSRF authority. The public
telemetry listener is not an operator inventory API.

The existing Windows device Overview shows the shared resource charts. Its
Inventory tab contains Processes, Services, Software, Hostname and Interfaces,
with EN/DE labels, visible-row filtering and keyboard tabs. Original capture and
manager receipt timestamps remain visible. Observations become stale after two
minutes and inventory rows disappear from the operator view after 24 hours;
this display bound does not delete the retained telemetry frame. Expired or
revoked identities hide inventory. Denied/partial/unavailable latest reports
replace prior successful rows. Clock regression, frozen-response refreshes,
request timeout, lost session and navigation discard private rows.

Linux APT/journal/CVE/action panels and Linux collection routes are not used by
this Windows view. Separately consented bounded event headers now have a source path to the shared Health tab; see [Windows event health](windows-event-health.md). Windows event content, complete event-derived alarms, Windows Update,
CVE matching, remote actions and Windows AI evidence scope remain separate
[parity work](windows-dashboard-parity.md).

## Evidence and remaining acceptance

The deterministic Go path covers an injected Windows report through the actual
adapter, enrolled identity, signed sender, production ingress, durable manager,
shared devices/history and authenticated operator view. It covers restart and
response loss, exact retry, original receipts, profile/path mismatch, replay,
expiry, denied/latest replacement and revoked visibility. Those inputs are
synthetic and create no Windows host grant.

React tests cover the strict contract, consent, stale/denied/partial display,
clock freshness and session/navigation interruption. The existing hosted LAN
browser runner includes one additive Windows case using real fixture login and
intercepted invented data at EN/DE desktop/mobile sizes. That case is UI-only;
its screenshots cannot establish native service or real manager collection.
Local Chromium execution was blocked by this environment; hosted browser
results must be observed on the final composed source before claiming that
stage passed.
