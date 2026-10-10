# Tracebolt

**Inventory, logs and diagnostics in one self-hosted dashboard.**

See what your machines report, investigate changes and keep the original evidence
in view. Tracebolt combines a Go manager, native agents and an English/German
dashboard with light and dark themes.

[Get started](#get-started) · [Help and guides](docs/README.md) · [Windows status](docs/windows-status.md) · [Roadmap](docs/roadmap.md)

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
stale observations stay visible. Windows event headers contain no message bodies;
Windows Update/CVE assessment is not implemented. AI provider/data approval is
separate, and suggestions remain unconfirmed.

![Tracebolt Linux log workspace with service selection and time-window controls](docs/screenshots/2026-10-09-main-ui/log-workspace.png)

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

### Windows preview

**There is no published Windows Setup download yet.** The unsigned source-built
wizard implements fresh installation and five explicitly approved read scopes.
Some native x64 phases have passed, but complete installed-service acceptance is
still blocked. Start with [Windows status and limitations](docs/windows-status.md)
before the [Setup preview guide](docs/windows-setup-preview.md). Do not use the
Linux installation command on Windows.

## Platform support

| Component | Current boundary |
| --- | --- |
| Manager | Linux, native or Docker; exact-revision CI records architecture and runtime coverage |
| Published Linux read-admin | amd64; Ubuntu 24.04 or Debian 13, systemd, cgroup v2, kernel 6.5+; actual host acceptance still required |
| Linux arm64 / Raspberry Pi | Source/read-only testing; public installation remains closed pending privileged native acceptance |
| Windows | Implemented bounded read-only inventory and unsigned Setup preview; no published installer, full lifecycle acceptance, reboot/upgrade proof or ARM64 runtime acceptance |
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
open. No project license has been selected; public source availability does not
grant an open-source license. Dependencies retain their
[own notices](docs/dependencies/edwards25519.md).
