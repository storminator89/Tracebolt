# Troubleshooting

Use the exact source/release and the relevant platform guide. Preserve existing
identity, configuration and state while diagnosing a failure. Do not delete a
database, reset counters, weaken TLS or widen permissions to make setup pass.

[Help index](README.md) · [Installation runbook](installation.md) · [Windows status](windows-status.md)

## Local demo

**The page is missing or empty.** Run `make web` from the repository root before
starting `./bin/manager` there. The manager serves `web/dist` alongside its API at
`http://127.0.0.1:8787`. `npm run preview` serves frontend assets only; it is not
the supported API-integrated application.

**Port 8787 is in use.** Stop your previous demo with Ctrl+C or choose a free
loopback port explicitly, for example `./bin/manager --port 8789`, then open that
same port. Do not stop an unrelated process or expose the demo to the LAN.

**I see invented devices or a local machine.** This is expected: `cmd/manager`
seeds seven synthetic devices and takes a limited read-only local sample. Its
SQLite state defaults to `.local/state.db`. Real endpoints use the separate
`lan-manager` with authenticated configuration and enrollment. No demo device is
proof that an agent is installed or reporting.

See [frontend development](../web/README.md#run) for the build/watch workflow.

## Linux setup or reporting is incomplete

**There is no usable installation command.** Start with the
[verified dashboard download](dashboard-verified-download.md). A fresh complete
profile needs its compatible manager, verified release pin, supported endpoint
and approved protected setup. Do not compose flags from older releases or replace
a missing pin with a moving-branch download.

**Setup is waiting for approval.** Keep the local terminal open. Independently
compare the public fingerprint/comparison value shown there with the pending
device in the dashboard, then approve only the intended identity. Enter the
invitation only at the hidden local prompt, never in chat, a shell argument,
an environment variable or a file.

**The service exists, but no data appears.** Service startup, identity activation
and accepted telemetry are different steps. Check the setup phase result, the
selected device, first accepted report and original source times. Verify the
configured manager/agent origins, clock and network reachability against the
[runbook diagnostics](installation.md#9-diagnose-without-weakening-security).
The LAN manager does not invent fallback telemetry or sample the endpoint itself.

**An existing installation blocks a fresh install.** Preserve the original
receipt and state. A completed compatible read-admin installation uses the
[explicit same-identity upgrade](read-admin-upgrade.md). Partial installation,
missing receipts or an unknown identity are not permission to reset or reinstall.

## Windows Setup or download is unavailable

**Where is Setup.exe?** There is no published Windows download yet. The
[unsigned source preview](windows-setup-preview.md) is for separately reviewed,
explicitly authorized disposable-host acceptance. A workflow artifact is not a
released or signed installer. See [the current status](windows-status.md).

**Manager compatibility failed.** Setup needs a fresh public bootstrap export
from a Windows-enabled manager/frontend built from the same reviewed source as
Setup. The old Linux endpoint release is not that manager. Review the
[compatible-manager procedure](windows-setup-preview.md#compatible-manager-requirement);
do not bypass a trust error or switch to HTTP after a TLS failure.

**Windows blocks the unsigned executable.** Keep the protection intact. Do not
disable SmartScreen, Smart App Control or organizational policy to force the
preview to run. A hash check does not establish a trusted publisher.

**Setup was cancelled or failed after staging.** Retain files, protected receipts,
identity and grants. A final startup error can leave the service's startup state
indeterminate. There is no general repair/reset or fresh-install resume flow.
Use the [retained-state guidance](windows-setup-preview.md#cancellation-retained-state-and-service-removal)
and report the finite diagnostic code rather than deleting state and retrying.

**Uninstall is pending or completed, but files remain.** The preview removes only
the exact owned service and must observe actual SCM absence to confirm that step.
Open handles can delay deletion. Even successful service removal retains binaries,
bootstrap, identity, counters and grants; manager trust is not revoked. It is not
full application removal, and retained state still blocks fresh installation.

## A view is empty, partial, stale or unavailable

- Check the selected platform, local scope, original capture time and source
  status. A manager-selected profile describes intended collection, not a
  successful native read.
- Partial means the visible data has a coverage limit; it is not a complete
  all-machine inventory. Denied/unsupported sources are not healthy zero values.
- Refresh reads available manager data. It cannot renew an old capture, grant a
  missing scope or establish that a service actually collected content.
- History starts with accepted observations; old samples are not backfilled.
  Resource charts preserve gaps. See [resource history](resource-history.md).
- Search and paging apply to the displayed source/generation. An empty filtered
  result does not prove that no matching object exists anywhere on the endpoint.

## Logs or updates do not match my expectation

**Linux service logs:** the helper and exact-service scope must already be set up.
Selecting a service or time does not collect content. Review the request and its
content acknowledgement before capture; retain the original service/window and
partial-source details. See [journal capture](journal-content-mvp.md).

**Windows Logs:** this is a bounded accepted Application/System **header sample**.
Filters and pages browse that sample; Refresh checks accepted telemetry. Message
bodies, XML/EventData, Security logs and older-event retrieval are not supported.
See [Windows log boundaries](windows-logs-sample-browser.md).

**Package updates:** Linux cached APT candidates do not refresh repositories or
install software, and CVE findings have vendor/source limits. Native selected
APT installation remains a [separate source candidate](selected-package-updates-native.md).
Windows Update/CVE is not implemented.

## What to include in a support report

Record the exact source commit or release, OS/architecture, whether this is the
local demo or LAN manager, the last completed phase, finite diagnostic code and
which checks passed, failed or were never run. State whether protected state was
retained. For CI, include the exact run/attempt link rather than an unrelated
green badge.

Review screenshots and the optional [local support bundle](support-bundle.md)
before sharing. Do not attach raw telemetry, event messages, private state,
credentials, invitation secrets, keys, cookies or unreviewed logs to a public
issue. Never change host permissions just to fill a diagnostic gap.
