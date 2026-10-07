# Tracebolt

**Inventory, logs and diagnostics in one self-hosted dashboard.**

Understand your Linux machines, investigate changes and keep the original evidence in view. Tracebolt combines a Go manager, native agents and an English/German dashboard with light and dark themes.

[Get started](docs/installation.md) · [Linux read-admin setup](docs/read-admin-onboarding.md) · [Roadmap](docs/roadmap.md)

![Tracebolt device overview with CPU, memory and disk history](docs/screenshots/2026-10-07-concise-ui/resource-history-dark.png)

*Actual UI capture with invented test data. [Screenshots and provenance](docs/screenshots/2026-10-07-concise-ui/README.md).*

## What you can see

- **Devices and activity:** reported hostnames, scoped IP addresses, contact history and selected Health checks.
- **Complete inventory:** processes, mounts, packages, services and connections, with search, paging and visible first-page refresh.
- **Resource history:** 24-hour CPU, RAM and root-filesystem charts, with original sample times and gaps.
- **Service logs:** choose an exact service and time window, then search the captured journal snapshot.
- **Package evidence:** cached APT candidates and Debian/Ubuntu CVE warnings, with source and coverage limits.
- **Optional integrations:** application checks, webhook alarms and proactive AI suggestions from explicitly approved Health incidents.

Unavailable, partial and stale observations stay visible. Package findings do not establish exploitability or trigger package installation. AI suggestions remain unconfirmed, and provider/data approval is separate.

![Tracebolt log workspace with service selection and time-window controls](docs/screenshots/2026-10-07-concise-ui/log-workspace.png)

## Get started

For real devices, follow the [installation runbook](docs/installation.md), then the [combined Linux read-admin setup](docs/read-admin-onboarding.md). The dashboard supplies a verified command; run it in the endpoint's local terminal, review its scope and approve the matching device. Existing completed installations use the [same-identity upgrade](docs/read-admin-upgrade.md).

The current Linux release is [v0.1.0-rc.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-rc.3). Its public assets and Ubuntu TLS install/upgrade paths are verified. Use deliberately selected test systems; user-host functionality and OS reboot remain separate checks.

For a quick local demo, install Go **1.27.1**, Node.js **24**, npm and `make`, then run:

```sh
make web
make build
./bin/manager
```

Open **http://127.0.0.1:8787**. This loopback demo contains synthetic devices; do not expose it to a network. Real devices use the separate authenticated `lan-manager` runtime.

## Platform support

| Component | Current scope |
| --- | --- |
| Manager | Linux, including native amd64/arm64 Docker validation |
| Full Linux read-admin | amd64; Ubuntu 24.04 or Debian 13, systemd, cgroup v2, kernel 6.5+ |
| Linux arm64 / Raspberry Pi | Native read-only tests and source preparation; public installation remains closed pending privileged acceptance |
| Windows | Native read-only inventory tested on amd64; inventory, shared-dashboard and LocalService candidates await installed-service acceptance |
| macOS | Limited standalone read-only collector |

The main agent is unprivileged. Journal and socket-owner helpers need explicit local approval; the socket helper has broad process-memory authority. Review the [exact scope](docs/read-admin-onboarding.md#exactly-what-the-one-approval-covers). HTTPS is the default; [isolated HTTP testing](docs/http-complete-first-start.md) exposes credentials and content to the network. There is no arbitrary remote shell or automatic package updater.

## Documentation and development

[Installation](docs/installation.md) · [Logs](docs/journal-content-mvp.md) · [Checks](docs/application-checks.md) · [Alarms](docs/alarm-delivery.md) · [Proactive AI](docs/proactive-ai-diagnostics.md) · [Windows inventory](docs/windows-inventory-dashboard.md) · [Security boundaries](docs/lan-security-review.md) · [Contributing workflow](AGENTS.md)

Run `make test`, `make build` and the [web checks](web/README.md); see [exact-revision CI](https://github.com/storminator89/Tracebolt/actions) for browser, container and native coverage. [Roadmap](docs/roadmap.md) and [changelog](CHANGELOG.md) hold the development detail.

**Development pilot.** Production hardening and fleet-scale validation remain open. No project license has been selected; public source availability does not grant an open-source license. Dependencies retain their [own notices](docs/dependencies/edwards25519.md).
