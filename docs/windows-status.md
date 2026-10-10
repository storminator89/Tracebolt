# Windows status and limitations

**Status checked: 9 October 2026. No Windows Setup release is published.**

Windows has a native bounded read-only collector, a shared-dashboard path and an
unsigned source-built fresh-host Setup wizard. These are implemented features
under review, not a generally supported installation or full lifecycle pass.
The published Linux `v0.1.0-rc.3` release is not a Windows installer.

[Help index](README.md) · [Setup preview](windows-setup-preview.md) · [Packaging and release gates](windows-setup-release.md)

## Implemented read scope

The fresh Setup coordinator requests one explicit local approval for these five
scopes. Hidden invitation entry and separate manager fingerprint/comparison
approval remain required.

| Scope | What is exposed |
| --- | --- |
| Base inventory | Bounded caller-visible machine/system metrics, hostname/adapters, processes, services and software registrations |
| Application/System event headers | Provider, event ID, level, timestamp, channel and record ID; no message content |
| Volume metadata | Caller-visible volumes and capacity, with unavailable/partial states |
| Process metrics | Per-process CPU and working-set RAM; CPU starts unknown until a usable second sample |
| Network endpoints | Numeric TCP/UDP addresses/ports and API-snapshot owning PID; no traffic payloads or DNS lookup |

These scopes do not establish whole-machine coverage or Linux feature parity.
Configured service-startup metadata is a separate default-off source capability;
it is not included in the five-scope Setup choice. Windows event-message content,
Windows Update/CVE, remote service actions and external-AI export are not granted
by this setup.

![Windows inventory with synthetic adapter and interface rows](screenshots/2026-10-09-main-ui/windows-inventory.png)

*Actual shared-dashboard capture with invented fixtures. [Exact-source provenance](screenshots/2026-10-09-main-ui/README.md).
This image is not native collection or installation evidence.*

## Latest recorded packaged-Setup gate

[Run 37987458242, attempt 1](https://github.com/storminator89/Tracebolt/actions/runs/37987458242/attempts/1)
used source `9e6203b6c17cbc7e4e6f9e35ac86ff4fb664dd20` on disposable hosted x64
Windows machines:

- **Passed:** cancellation during hidden invitation input and while manager
  approval/transport was pending.
- **Partial TLS lifecycle:** registration, approval, automatic-start configuration
  and two accepted five-scope telemetry frames passed. Reopen and uninstall-Cancel
  checks passed, but the final uninstall stage failed before delete-pending and
  service-absence proof. Returning from the action is not confirmed removal.
- **Failed HTTP-test case:** failure was reported at preflight cancellation,
  before positive GUI checks. The exact failed substep was not established; the
  report marked native actions attempted, so absence of host effects is not proven.
- **No accepted package:** aggregate acceptance was skipped. Required VM disposal
  was not verified by these results.

These results are limited to that exact artifact/source/run. They do not certify
interactive human UAC/SmartScreen behavior, a user's manager and desktop,
shutdown/reboot persistence, upgrade, full application removal or ARM64 runtime.
Cross-builds, successful fixtures and CI artifact availability cannot fill those
gaps. Later results must name their own exact source and run.

## Before trying the preview

Use an explicitly approved disposable Windows target, the reviewed exact Setup
and service hashes, and a compatible manager built from the same reviewed source.
Follow the [preview prerequisites and consent steps](windows-setup-preview.md).
Keep HTTPS as the default and keep OS protection intact; unsigned builds may be
blocked by policy. Do not reinterpret a successful build as permission to install.

Cancellation after staging can retain protected identity and partial grants.
There is no general repair/reset, automatic upgrade or fresh-install resume.
**Uninstall service** retains application files and identity/state, and does not
revoke manager trust. Read [retained-state and removal behavior](windows-setup-preview.md#cancellation-retained-state-and-service-removal)
before acting; never delete state to force another installation.
