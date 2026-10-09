# Help and guides

Start with the task you want to complete. Tracebolt is a self-hosted development
pilot; feature implementation, a published artifact and native host acceptance
are separate milestones. Detailed design documents may describe unreleased
source candidates. Follow each guide's status and platform limits.

## Start here

| I want to… | Read this |
| --- | --- |
| Try the dashboard locally | [Local demo](../README.md#try-the-local-dashboard) |
| Run the manager on Linux or Docker | [Installation runbook](installation.md) and [Docker packaging](docker.md) |
| Connect a fresh supported Linux machine | [Verified dashboard download](dashboard-verified-download.md), then [read-admin scope and onboarding](read-admin-onboarding.md) |
| Update a completed Linux read-admin installation | [Same-identity, same-scope update](read-admin-upgrade.md) |
| Add inventory to an existing activated Linux agent | [One-time inventory setup](guided-inventory-setup.md) |
| Understand Windows availability | [Windows status](windows-status.md), then [unsigned Setup preview](windows-setup-preview.md) |
| Evaluate a Raspberry Pi or Linux ARM64 endpoint | [ARM64 support and native acceptance gates](linux-arm64-support.md) |
| Diagnose a failed or incomplete setup | [Troubleshooting](troubleshooting.md) |

Linux `v0.1.0-rc.3` is the published endpoint release. Windows Setup is unsigned
and unreleased. The local demo is separate from authenticated LAN operation;
copying a demo command does not deploy a manager or connect real endpoints.

## Use the dashboard

- **Devices and inventory:** [hostname/interface identity](endpoint-identity-ui.md),
  [complete process/mount overview](complete-overview-extension.md),
  [Windows inventory](windows-inventory-dashboard.md),
  [Windows volume capacity](windows-volume-inventory.md),
  [process CPU/RAM](windows-process-metrics.md) and
  [numeric network endpoints](windows-network-endpoints.md).
- **Performance and Health:** [24-hour resource history](resource-history.md),
  [Linux Health](health-dashboard.md),
  [Windows system-volume observations](windows-health-observations.md) and
  [Windows event-header Health](windows-event-health.md).
- **Logs:** [Linux exact-service captures](journal-content-mvp.md),
  [retained journal browsing](retained-journal-browsing.md) and
  [Windows accepted event-header samples](windows-logs-sample-browser.md).
  Windows Logs does not fetch message bodies or older event history.
- **Packages and findings:** [complete cached APT candidates](complete-cached-updates-extension.md)
  and [Debian/Ubuntu CVE coverage](linux-cve-warnings.md).
  Cached candidates are not an installation guarantee or Windows Update support.
- **Checks and notifications:** [application checks](application-checks.md),
  [DNS/TCP checks](application-network-checks.md) and [alarm delivery](alarm-delivery.md).
  Provider acceptance does not prove that a person received an alert.
- **Optional AI:** [Health-based suggestions](proactive-ai-diagnostics.md),
  [separately approved service-log AI](proactive-service-log-ai.md) and
  [optional settings persistence](ai-settings-persistence.md).

Opening a view does not grant an endpoint new permissions. A selected profile
is not proof of received data. Keep original observation times, partial results
and unavailable sources in view; [troubleshooting](troubleshooting.md) explains
common empty, stale and pending states.

## Operate safely

- [Preflight and approval checklist](installation.md#2-preflight-and-approval-checklist)
- [TLS, identities and trust](lan-trust.md)
- [Backup, update, rollback and removal](installation.md#10-stop-back-up-restore-update-uninstall)
- [Linux read-admin upgrade](read-admin-upgrade.md)
- [Windows cancellation and retained state](windows-setup-preview.md#cancellation-retained-state-and-service-removal)
- [Local support bundle and review before sharing](support-bundle.md)
- [Security review and boundaries](lan-security-review.md)

Service actions and native APT installation have their own local authorization
and acceptance gates. They are not enabled by ordinary read-only onboarding:
[service-action setup](guided-service-action-setup.md) ·
[selected package updates](selected-package-updates-native.md).

## Develop and review

[Repository instructions](../AGENTS.md) · [Frontend workflow](../web/README.md) ·
[LAN runtime](lan-runtime.md) · [LAN client tests](../tests/lanclient/README.md) ·
[Windows packaging](windows-setup-release.md) · [UI acceptance history](ui-acceptance.md) ·
[Current screenshot gallery](screenshots/2026-10-09-main-ui/README.md) ·
[Roadmap](roadmap.md) · [Changelog](../CHANGELOG.md)

Screenshots show actual rendered UI with invented fixtures. Their linked
source/run records establish what was captured; they do not establish native
collection, endpoint installation or production readiness.
