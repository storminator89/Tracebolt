# Tracebolt

Self-hosted Linux inventory and diagnostics, with evidence you can inspect.

Tracebolt combines a Go manager, a React/TypeScript dashboard and native Linux agents. It brings device inventory, service logs, package/CVE information and selected health checks into one interface, with collection time, coverage and unavailable data kept visible.

**Status: development pilot.** Use it on deliberately selected test systems. Production hardening, fleet-scale operation and full OS-reboot acceptance are still open.

## What it does

- **Inventory:** supported dpkg packages, system services, visible processes and mounted filesystems, with paged complete generations and explicit collection limits.
- **Network:** observed sockets/connections, hostname and interface addresses; optional helper-backed TCP/UDP process ownership with source and permission limits.
- **Packages and CVEs:** cached APT candidates and Debian/Ubuntu distribution-version warnings. These are evidence for investigation, not confirmed exploitability or guaranteed installable updates. Tracebolt does not refresh APT metadata or install packages.
- **Logs:** on-demand, service-scoped journal snapshots with time/severity selection, paging and literal search, through a separately granted helper.
- **Health & history:** contact, root-filesystem usage and selected-service checks, with incidents, acknowledgements and bounded maintenance windows.
- **Dashboard:** English/German, light/dark themes, searchable inventory, device details, evidence views and investigations.
- **Optional integrations:** configured application checks, webhook alarms, AI-assisted investigation and allowlisted service try-restart. Each has separate configuration/permission requirements and acceptance limits; the read-admin profile does not enable service actions.

Actual visibility depends on the approved collection profile, helper grants, platform and agent namespace. Missing or stale data never means a healthy device or an empty inventory.

## Platforms and current release

| Component | Current scope |
| --- | --- |
| Manager | Native Linux or Docker; authenticated LAN dashboard and agent ingress |
| Full Linux read-admin agent | Fresh Ubuntu 24.04 or Debian 13, **amd64**, systemd as PID 1, cgroup v2 and kernel 6.5+ |
| Linux arm64 | Published cross-built artifacts; runtime installation remains disabled |
| Windows/macOS | Limited standalone read-only collectors; no supported LAN agent or installed-service parity |

The fresh read-admin workflow has passed [disposable Ubuntu TLS native acceptance](https://github.com/storminator89/Tracebolt/actions/runs/37508637893), including socket ownership, journal content, service restart, revocation and cleanup. This does not establish Debian HTTP or actual OS-reboot acceptance.

**Current release:** [v0.1.0-rc.2](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-rc.2) is published and [all 12 public assets and provenance are verified](https://github.com/storminator89/Tracebolt/actions/runs/37513100878). The dashboard selects its combined read-admin command for the complete Linux profile. See the [verified-download guide](docs/dashboard-verified-download.md) for the exact source pins and acceptance limits.

## Get started

### Fresh Linux installation

1. Start with the **[installation runbook](docs/installation.md)**. Prepare a fresh Linux manager using the [Docker/native setup](docs/docker.md) and protected configuration. HTTPS is the default.
2. Follow the **[one-command read-admin guide](docs/read-admin-onboarding.md)** for the combined fresh-agent workflow and its current activation status. The administrator reviews the collection/helper scope, runs the verified command in a local root terminal, enters the invitation at the hidden prompt, and compares/approves the device in the dashboard.
3. Keep the terminal open until completion. Confirm fresh reports and each section's actual coverage in the dashboard; a running service alone does not establish complete collection.

The endpoint needs Python 3.11+, curl, the system CA bundle and the native tools listed in the [release prerequisites](docs/linux-release-distribution.md). The installer checks prerequisites but does not install dependencies. Start with a fresh supported host; the combined setup does not migrate an existing installation.

For a deliberately isolated disposable test, use the [HTTP manager guide](docs/http-complete-first-start.md). **HTTP exposes passwords, invitations, sessions, telemetry and requested log content, and permits server impersonation.** Use disposable credentials and explicitly accept that risk.

### Local development demo

Requirements: Go **1.27.1**, Node.js **24** with npm, and `make`. No separate database server is needed.

```sh
make web
make build
./bin/manager
```

Open **http://127.0.0.1:8787**. This loopback-only developer manager uses synthetic demo devices and local SQLite state in `.local/state.db`. Do not expose, tunnel or reverse-proxy it onto a network. Real devices use the separate `lan-manager` runtime.

## Security essentials

- The main agent runs as an unprivileged service. Journal content and socket ownership use separate explicitly approved helpers. The socket helper has broad `CAP_SYS_PTRACE` process-memory authority; metadata-only collection is a code policy, not an OS confidentiality boundary. Review the [read-admin disclosure](docs/read-admin-onboarding.md#exactly-what-the-one-approval-covers).
- Review collection destinations and scope before enrollment. Keep invitation secrets in the hidden local prompt and protect credentials, private keys, databases and exported logs. Logs may contain secrets or personal information.
- There is no arbitrary remote shell, network scan or automatic package/agent updater. Controlled service actions require their own named-operator approval and local allowlist/helper setup.
- Production use still requires a deployment/security review and operational audit, backup and retention controls. See the [LAN security review](docs/lan-security-review.md) and [installation boundaries](docs/installation.md).

## Documentation

- **Installation:** [runbook](docs/installation.md), [read-admin setup](docs/read-admin-onboarding.md), [verified downloads](docs/dashboard-verified-download.md), [release verification](docs/linux-release-distribution.md), [agent service](docs/linux-agent-service.md)
- **Inventory:** [processes and mounts](docs/complete-overview-extension.md), [hostname/interfaces](docs/endpoint-identity-extension.md), [socket-owner provenance](docs/socket-owner-source-provenance.md), [cached updates](docs/complete-cached-updates-extension.md), [CVE warnings](docs/linux-cve-warnings.md)
- **Operations:** [journal logs](docs/journal-content-mvp.md), [health & history](docs/linux-health-checks.md), [controlled service actions](docs/service-action-workflow.md), [service-action setup](docs/guided-service-action-setup.md)
- **Optional integrations:** [HTTP/HTTPS checks](docs/application-checks.md), [DNS/TCP checks](docs/application-network-checks.md), [webhook alarms](docs/alarm-delivery.md), [AI investigation](docs/ai-diagnostics.md)
- **Reference:** [LAN runtime](docs/lan-runtime.md), [native collection](docs/native-collection.md), [support bundles](docs/support-bundle.md), [API contract](docs/api-contract.json), [repository guide](AGENTS.md)
- **Development:** [web app](web/README.md), [browser acceptance](tests/e2e-review/README.md), [synthetic screenshot gallery](docs/screenshots/2026-10-04-linux-inventory/README.md), [roadmap](docs/roadmap.md), [changelog](CHANGELOG.md)

## Validate changes

```sh
go vet ./...
make test
make build
make crosscheck
bash tests/security/run.sh
(cd web && npm ci && npm run typecheck && npm test && npm run build)
```

Race-detector tests need a C toolchain; boundary regressions use Python 3 and curl. `make crosscheck` only cross-builds Windows amd64 and macOS arm64 collectors. Read the [exact revision's CI results](https://github.com/storminator89/Tracebolt/actions) and the linked acceptance guides: source, browser, container and native-service checks establish different things, and none substitutes for an actual OS reboot.

## License

No project license has been selected. Public source availability is not an open-source license grant. Dependencies retain their own licenses; see the [curve dependency notice](docs/dependencies/edwards25519.md) for distribution requirements.
