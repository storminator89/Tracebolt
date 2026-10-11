# Tracebolt

**Inventory, logs and diagnostics in one self-hosted dashboard.**

See what your machines report, investigate changes and keep the original evidence
in view. Tracebolt combines a Go manager, native agents and an English/German
dashboard with light and dark themes.

[Get started](#get-started) · [Help and guides](docs/README.md) · [Windows status](docs/windows-status.md) · [Windows admin roadmap](docs/windows-admin-roadmap.md) · [Linux roadmap](docs/roadmap.md)

![Tracebolt device overview with CPU, memory and disk history](docs/screenshots/2026-10-09-main-ui/resource-history-dark.png)

*Actual dashboard capture with invented test data. [Screenshots and exact-source provenance](docs/screenshots/2026-10-09-main-ui/README.md).*

## What you can see

- **Linux inventory:** visible processes, mounts, installed dpkg packages, services
  and connections, with search, paging and explicit coverage limits.
- **Resource history:** 24-hour CPU, RAM and root-filesystem charts, with original
  sample times and gaps instead of invented values.
- **Linux service logs:** choose an exact service and time window, review the
  request, then search the captured journal snapshot.
- **Package evidence:** cached APT candidates and Debian/Ubuntu CVE warnings,
  with source and coverage limits. A finding is not an exploitability verdict.
- **Windows read-only preview:** machine and adapter inventory, processes,
  services, software registrations, volume capacity, per-process CPU/working-set
  RAM, numeric TCP/UDP endpoints and Application/System event headers.
- **Optional checks and alerts:** application checks, webhook alarms and AI
  suggestions from explicitly approved Health incidents or service-log evidence.

Each feature depends on its platform and approved scope. Unavailable, partial and
stale observations stay visible. Windows event headers contain no message bodies.
The published preview has no Windows Update/CVE assessment. The current source
adds separately consented [cached Windows Update inspection](docs/windows-update-runtime.md)
and [selected event messages](docs/windows-event-content-runtime.md); both still
need installed-service/native acceptance. A separate default-off
[system-volume capacity policy](docs/windows-capacity-health.md) uses only the
existing quota-aware metric. Independent default-off [CPU and physical-RAM policies](docs/windows-resource-health.md)
use their existing basic samples. Separate default-off [service checks](docs/windows-service-health.md)
let administrators select reported services that should be running; missing rows
remain unknown. Overall Windows health remains unassessed and
native acceptance remains pending. AI provider/data approval is separate, and suggestions
remain unconfirmed.

![Tracebolt Linux log workspace with service selection and time-window controls](docs/screenshots/2026-10-09-main-ui/log-workspace.png)

Windows hardware/power context is a new source-only, default-off increment with
source-labeled serial metadata and fresh thirteen-scope Read admin consent.
See [scope and remaining native gates](docs/windows-hardware-context.md).

## Get started

### Connect real Linux devices

1. Follow the [installation runbook](docs/installation.md) to prepare the separate
   authenticated LAN manager, protected configuration and approved network access.
2. Use [Add device and the verified Linux download](docs/dashboard-verified-download.md).
   Run the dashboard's command in the endpoint's local terminal, review the
   [combined read-admin scope](docs/read-admin-onboarding.md), enter the invitation
   at its hidden prompt and approve the matching device fingerprint in the dashboard.
3. Keep the terminal open until setup finishes, then check the first accepted
   report, source coverage and timestamps. Existing completed read-admin installs
   use the [same-identity upgrade guide](docs/read-admin-upgrade.md).

The published Linux endpoint release is
[v0.1.0-rc.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-rc.3).
Its public assets are verified; the recorded Ubuntu TLS upgrade gate used a
source-built replacement. See the [release evidence and remaining host checks](docs/read-admin-onboarding.md).
Manager deployment is separate from the endpoint release.

### Try the local dashboard

From a reviewed source checkout, with Go **1.27.1**, Node.js **24**, npm and `make`
installed, run these commands from the repository root:

```sh
make web
make build
./bin/manager
```

Open **http://127.0.0.1:8787**. The demo includes seven synthetic devices **and a
limited read-only sample of the machine running it**. It binds only to loopback,
creates local state at `.local/state.db` and stops with Ctrl+C. It does not enroll
remote devices or install a service. Use `lan-manager` via the runbook for real
LAN operation. [Demo troubleshooting](docs/troubleshooting.md#local-demo).

### Published Windows preview

The unsigned x64 [v0.1.0-windows-preview.1 prerelease](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.1)
remains unchanged at source [`14719116`](https://github.com/storminator89/Tracebolt/commit/14719116bdb663d13e4bcaef434a4374a6265fe6),
with fresh installation and five explicitly approved read scopes.
Read the [prerelease installation guide](docs/windows-prerelease-install.md) and
[Windows status and limitations](docs/windows-status.md) before installing.
The accepted hosted Windows Server 2025 subset does not prove Windows 10/11,
reboot, upgrade or ARM64 support. Do not use the Linux installation command on Windows.

Read the [dated Windows parity review status](docs/windows-parity-review-status.md)
for subsequent source progress, CI evidence and remaining priorities. The
[Linux/Windows parity matrix](docs/windows-linux-parity.md) preserves a historical
baseline; its table is not a current runtime-coverage claim.

### Current Windows development source

Merged source at [`829ed26`](https://github.com/storminator89/Tracebolt/commit/829ed26b3f222276f77cd43b40f45d47f07a3b3f)
includes these later read-only capabilities; none is in the published preview:

- [Complete caller-visible Win32 services](docs/windows-full-services-contract.md)
  and [HKLM 32/64 machine software registrations](docs/windows-full-software-contract.md),
  with generation-bound search/paging beyond the old preview ceilings. Drivers,
  ACL-invisible services, per-user/Store and portable software are excluded.
  Selected-service health policies retain their separately bounded authority.
- [Fleet hostname/IP search](docs/windows-fleet-identity.md) over already-reported
  metadata, plus [adapter link state/speed and DNS/gateway context](docs/windows-adapter-context.md)
  and [build labels, retained update history and reboot indicators](docs/windows-patch-context.md)
  ([merged PR #42](https://github.com/storminator89/Tracebolt/pull/42)). Retained
  history does not establish current patch compliance.
- [Defender status and local Firewall profile configuration](docs/windows-security-posture.md)
  in Security ([merged PR #43](https://github.com/storminator89/Tracebolt/pull/43)).
  These do not establish overall protection or effective firewall policy;
  third-party antivirus, BitLocker, Secure Boot and TPM are not covered.
- [Caller-visible Users / Sessions and local domain/workgroup join context](docs/windows-session-context.md)
  ([merged PR #44](https://github.com/storminator89/Tracebolt/pull/44)). This is not
  complete account discovery or account management.

New host-read scopes are default-off and require explicit local consent. Cached
[Windows Update inspection](docs/windows-update-runtime.md), [selected event messages](docs/windows-event-content-runtime.md)
and opt-in [disk/CPU/RAM](https://github.com/storminator89/Tracebolt/pull/31) and
[selected-service health policies](https://github.com/storminator89/Tracebolt/pull/32)
are also unreleased source features. Exact-source CI and fixtures do not establish
native acceptance.

The newer source [fresh Windows Read admin setup](docs/windows-read-admin-setup.md)
presents twelve read scopes prominently, with a concise review and optional full
scope details. Actual consent boxes start unchecked, including explicit approval
of personal user/domain/session metadata; the prominent profile grants no consent.
Provider access still needs verification under the installed service identity.
Event-message content, cached Update inspection and service control remain separate.
The [service-action source](docs/windows-service-actions.md) introduced in
[PR #45](https://github.com/storminator89/Tracebolt/pull/45) remains separate; native
setup, ACL changes and any target service action remain separately gated.

Current development prioritizes fresh installation and dependable read-only data.
A future updater is separate work, not a prerequisite for these source increments;
there is no migration rollout to plan. The [Windows admin roadmap](docs/windows-admin-roadmap.md)
tracks remaining complete process inventory, broader security/network/storage and
hardware context, and software-change history. The
[Windows 11 x64 acceptance matrix](docs/windows11-acceptance-matrix.md) records the
still-open desktop and lifecycle checks. No new release or native Windows 11
acceptance is claimed.

| Cached Windows Updates, unreleased source preview | Mobile device overview, German |
| --- | --- |
| [<img src="docs/screenshots/2026-10-10-windows-parity/windows-cached-updates.png" width="660" alt="Tracebolt cached Windows Updates with invented update rows and explicit unknown cache freshness">](docs/screenshots/2026-10-10-windows-parity/windows-cached-updates.png) | [<img src="docs/screenshots/2026-10-10-windows-parity/windows-mobile-de.png" width="220" alt="German mobile Windows device overview with invented inventory data">](docs/screenshots/2026-10-10-windows-parity/windows-mobile-de.png) |

*Actual 10 October source-preview captures with invented Windows data.
[Inventory screenshot and exact-source provenance](docs/screenshots/2026-10-10-windows-parity/README.md). Native Windows acceptance remains separate.*

![Tracebolt selected Windows event messages with invented text, original expiry and partial availability](docs/screenshots/2026-10-10-windows-parity/windows-selected-messages.png)

*Selected Windows event messages, unreleased source preview with invented data.
Original expiry and per-record availability stay visible.
[Exact source and fixture boundaries](docs/screenshots/2026-10-10-windows-parity/README.md#selected-windows-event-messages).*

![Tracebolt Windows CPU health policy with an invented open incident, explicit threshold and original observation times](docs/screenshots/2026-10-10-windows-parity/windows-health-policy.png)

*Windows CPU health policy, an unreleased source candidate in
[PR #31](https://github.com/storminator89/Tracebolt/pull/31), shown with invented data.
This separate implementation is not part of the published Windows preview.
[Exact source and fixture boundaries](docs/screenshots/2026-10-10-windows-parity/README.md#windows-health-policy).*

## Platform support

| Component | Current boundary |
| --- | --- |
| Manager | Linux, native or Docker; exact-revision CI records architecture and runtime coverage |
| Published Linux read-admin | amd64; Ubuntu 24.04 or Debian 13, systemd, cgroup v2, kernel 6.5+; actual host acceptance still required |
| Linux arm64 / Raspberry Pi | Source/read-only testing; public installation remains closed pending privileged native acceptance |
| Windows | Published unsigned x64 read-only prerelease; bounded hosted Windows Server 2025 subset accepted, with Windows 10/11, full lifecycle, reboot/upgrade and ARM64 runtime gates still open |
| macOS | Limited standalone read-only collector; no supported LAN installation path |

The main agent is unprivileged. Linux journal and socket-owner helpers need
explicit local approval; the socket helper has broad process-memory authority.
Review the [exact scope](docs/read-admin-onboarding.md#exactly-what-the-one-approval-covers).
HTTPS is the default. [Isolated HTTP testing](docs/http-complete-first-start.md)
exposes credentials and content to the network. There is no arbitrary remote
shell or automatic package updater. Selected APT installation is a
[source candidate](docs/selected-package-updates-native.md); the published
installer does not enable it.

## Help and development

[All guides](docs/README.md) · [Troubleshooting](docs/troubleshooting.md) · [Web development](web/README.md) · [Security boundaries](docs/lan-security-review.md) · [Repository workflow](AGENTS.md) · [Changelog](CHANGELOG.md)

Run `make test`, `make build` and the [web checks](web/README.md#checks). Consult
[exact-revision CI](https://github.com/storminator89/Tracebolt/actions) for browser,
container and native coverage; a cross-build or screenshot is not host acceptance.

**Development pilot.** Production hardening and fleet-scale validation remain
open.

## License

Tracebolt is licensed under the [Apache License 2.0](LICENSE)
(SPDX: `Apache-2.0`). Third-party dependencies retain their own licenses and
notices, including the [Edwards25519 dependency notice](docs/dependencies/edwards25519.md).
