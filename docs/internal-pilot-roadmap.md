# Internal pilot roadmap

Status: delivery order and remaining acceptance work for one internal-customer
pilot. Source implementation is identified below; it does not establish deployment
or native/live acceptance. No dates or production-readiness promise are attached
to these phases.

## Goal and current starting point

Make Tracebolt useful for one operator team: see a problem, receive an external
alarm, inspect trustworthy evidence, perform an approved narrow action and
verify the result. Multi-customer tenancy, enterprise IAM and fleet rollout
automation are deferred.

Existing repository capabilities include enrolled Linux observations, inventory
and service views, cached APT candidates, limited distribution-version CVE
matching, and separately opted-in on-demand service journal reads. These are
read/assessment capabilities. Their source tests do not establish installation
or acceptance on this pilot's machines.

The UI/log-source amendment still needs target-host acceptance. Source now wires
default-off [webhook alarms](alarm-delivery.md), [service try-restart](service-action-workflow.md)
and [manager-side application observations](application-checks.md), including
[DNS/TCP](application-network-checks.md). Their setup and live/native gates remain
separate. Package execution, DB/backup adapters, broader log sources and change
history remain future work; the [package-plan core](selected-package-plan-core.md)
is pure and inert, with no runtime callers.

## Small prerequisites, applied where needed

- Use named operator identities with separate read/change permissions before
  enabling real remote changes. Derive audit identity from authenticated state.
  Do not silently turn the existing shared login into an unrestricted operator.
- Test backup and restore of manager state and configuration in a disposable
  environment. Preserve endpoint identity, consumed-action floors and pending
  delivery records; a restored old backup must not replay actions or duplicate
  old alerts. Fail closed until action-state reconciliation when authority is
  uncertain. Protect credentials separately from ordinary exported diagnostics.
- Production uses HTTPS. The requested isolated HTTP testcase remains supported
  with an explicit profile and visible warning. A real disposable-machine action
  test needs one local opt-in for its narrow scope, not new certificate setup or
  repeated local approval for every job. HTTP exposes sessions and content; a
  stolen operator session can authorize actions within that test scope.
- Keep test profiles, permits and state separate from production. Host helper,
  key or privilege installation and external message delivery require their
  own explicit setup/authorization; a passing source test grants none of them.

## Phase 1: finish the UI and log-source amendment

Finish the current operator flow before adding another dashboard surface.
Make service inventory, an allowed journal query and actually available log
content visibly distinct. Explain disabled, denied, unsupported, empty, partial,
expired and temporarily unavailable results without a misleading healthy state.

Retain the selected device/service, source provenance and original observation
time. Bound query windows and result sizes. Show an actionable next step only
when the corresponding endpoint capability and local consent actually exist.

The normal administration model is one explicit local diagnostic grant at setup
or migration, followed by central queries: select the device, service, time and
severity in Logs; the agent captures that requested window. Routine queries and
new services inside that approved scope must not require another terminal command.
The first broader profile is **all supported system services, including future
services**. Each request still selects one exact canonical service; this profile
does not continuously upload logs or allow arbitrary journal filters or paths.

The source candidate introduces an explicitly acknowledged v3 policy for this
profile. Existing v1/v2 three-service grants keep their original meaning. Its
guided one-command migration checks the installed agent and manager, shows the
bound destination and content/HTTP risks, and requires one confirmation of the
exact plan before using the existing atomic amendment lifecycle. It does not
upgrade binaries or install a missing helper. Fresh-install integration of this
same one-time profile follows after migration acceptance. The UI distinguishes
observed services from the last freshly reported permission scope.

Acceptance:

- Exercise the real manager/agent path for the supported source and UI flow
- Cover navigation, refresh, duplicate clicks, stale results, lost connectivity,
  missing local log permission, expired queries and service-selection changes
- Verify that an unavailable/partial source cannot become a successful empty log
- Record source checks and actual pilot-machine acceptance separately
- Accept the one-command migration on a disposable already configured endpoint;
  verify a newly installed service can subsequently be queried centrally without
  another grant, and old pending requests cannot cross the policy generation
- Integrate the same explicit profile into fresh setup without making binary
  upgrades, missing helpers or old narrow consent implicit permission

## Phase 2: external alarms that can be trusted

The [current source slice](alarm-delivery.md) wires a default-off public HTTPS
generic webhook, persistent health-transition outbox, bounded retries and
authenticated read-only API status with a compact Settings summary. Details explain
retained counts and provider acceptance; individual events are not reconciled.
There is no test-send or Slack/Teams/SMTP adapter. Destination/data approval, protected setup and one live
alarm/recovery acceptance pair remain outstanding. The following is the fuller
pilot target, including still-missing per-rule maintenance and test-send behavior.

Deliver to one explicitly configured destination first. Keep the first payload
small: incident ID, device label, rule/severity, observation time, concise reason,
current state and a relevant manager link. Do not include raw logs or secrets.

Build a persistent outbox with an incident/transition idempotency key, bounded
retry/backoff and delivery status. Distinguish queued, provider-accepted, failed
and uncertain outcomes; acceptance is not proof that a human received a message.
Use provider idempotency where available and do not promise exactly-once external
delivery when the provider cannot establish it.

Include from the start:

- Deduplication and modest hysteresis so repeated samples or flapping do not
  send the same alarm continually
- One recovery transition with coherent opening/recovery order; avoid sending a
  stale opening alarm after the incident has already recovered
- Explicit per-device/rule maintenance windows with start/end and automatic
  expiry; suppressed events remain visible in history and do not flood recipients
  when the window ends
- A test-send flow and a clear delivery-health indication, independent of the
  monitored machine's health

Acceptance: fake-provider tests cover outage, timeout after acceptance, manager
restart, duplicate sample, recovery, flapping and maintenance expiry. Then send
one authorized real test alarm/recovery pair to the confirmed destination and
verify what the provider and recipient actually observed.

## Phase 3: controlled actions with a real result

Follow the reviewed controlled-action architecture. Keep the ordinary agent
unprivileged and the existing journal helper read-only. Typed operations,
explicit per-job approval, protected local opt-in, durable consumption and
actor/time/result audit are the minimum, not a general remote-shell platform.

### 3a. Restart one running, allowlisted service

The [manager/agent/helper/UI workflow](service-action-workflow.md) is wired in
source, with a separate [create-only manager/endpoint setup guide](guided-service-action-setup.md).
It stays off until named operator authority, protected keys/state, one reviewed
unit and independent local grants are present. Source/fixture evidence does not
establish the native acceptance below.

Start with one harmless, locally reviewed test service. Preview the exact target
and interruption, approve it, run the fixed operation and report observed state.
Use try-restart semantics so an inactive service is not silently started. Check
the reviewed effective unit and relevant restart/stop relationships; do not
claim that a service-name allowlist bounds all transitive effects.

Acceptance: demonstrate a real permitted restart and an inactive/no-op result,
then denial for unauthorized actor, wrong target, changed policy, replay and
production use of an HTTP-test permit. Double clicks, disconnects and restarts
must never manufacture another execution. Report ambiguity honestly.

### 3b. Approved APT package updates

The existing [selected-package plan core](selected-package-plan-core.md) only
validates inert manifests and hook descriptions. It has no runtime callers and
does not refresh metadata, invoke APT or install packages.

Add an explicit metadata-refresh/planning step and an exact approved package
manifest, including authenticated archive hashes and source identity. Begin
with selected installed packages; new dependencies, removals, downgrades, held
changes and release upgrades stay out of scope.

Revalidate the actual package transaction before dpkg. A simulation followed by
blind installation is insufficient. The proposed APT package guard is a fence
for explicit package changes, not isolation from trusted hooks, maintainer
scripts or triggers. Test the exact supported APT versions and clean-state
checks before enabling execution.

Use a durable runner outside browser/agent/helper lifetimes. Handle APT locks,
partial failure and original start expiry. Never delete locks or kill dpkg on a
UI timeout. Verify final versions and consistency, refresh inventory and report
reboot evidence separately. No automatic reboot, replay, repair or rollback.

Acceptance: disposable Debian/Ubuntu tests cover competing APT activity, changed
plan/archive, insufficient disk, failed script, configuration conflict, network
loss, duplicate dispatch, process/machine interruption and reboot-needed output.
A test double or successful compile does not pass this execution gate.

## Phase 4: application health and broader diagnostic evidence

### 4a. HTTP, TLS, DNS and TCP checks

The default-off [HTTP/HTTPS and verified TLS leaf-expiry slice](application-checks.md)
and [DNS/TCP extension](application-network-checks.md) are wired with protected
target configuration and compact read-only Overview status. All checks run from
the manager; reachable resources do not establish endpoint or full application
health. HTTP reports 2xx/non-2xx, DNS checks returned addresses against an explicit
allowlist, and TCP reports one bounded connection attempt. Unknown/stale states
and destination restrictions remain explicit.

Configurable expected HTTP status, content matching, latency results, history
and alert integration are not implemented. These remain future work alongside
maintenance/recovery integration with the existing alarm machinery. Database
and backup adapters also remain future work.

Acceptance: source/fixture checks do not establish real-target/native success.
Verify healthy, failed, slow, invalid-certificate, unexpected-answer, disconnected
and stale cases on separately approved targets, preserving address restrictions,
redirect blocking and credential-free requests.

### 4b. Database and backup adapters

Add only the database and backup product actually used by this pilot. Use
read-only bounded checks and separately configured least-privilege credentials.
No automatic database maintenance or repair. Backup success, backup age and a
tested restore are different facts; a successful job alone is not recoverability.

Acceptance: verify one real supported adapter end to end, including permission
denial and stale data. Demonstrate a disposable restore before claiming recovery
coverage. Add further adapters only for a concrete pilot need.

## Next diagnostic slice: broader logs and time/change history

Build the first version alongside phases 2–3 from the accepted existing sources;
later application adapters can add their observations. The slice is a bounded
incident timeline linking original
observation time, receive time, alarm/recovery, maintenance and approved action
results. Add service-state and package-version changes from comparable inventory
generations. Preserve missing-data gaps and clock uncertainty; correlation does
not prove that an observed change caused an incident.

After the all-service profile is accepted, add separately typed kernel and
system/authentication sources to the diagnostic profile when needed. This is a
profile boundary expansion requiring a new one-time local approval, not a local
approval for each subsequent query. Kernel, whole-system and system-wide
authentication collection are not implemented by the all-service profile.
File/application/database logs need source-specific allowlists,
local consent, size/time bounds and sensitive-content handling. Do not add a
generic file reader or continuously ship every log by default.

Acceptance: reconstruct one deliberately caused test incident from its timeline
and bounded logs, including recovery and action outcome. Cover restart persistence,
out-of-order arrivals, gaps, retention and revoked source access. Retain only the
diagnostic history the pilot needs; this is not a full observability platform.

## Pilot exit evidence and deferred work

The pilot should establish that an operator can receive one real alarm, inspect
the correct source, perform a genuinely authorized narrow action and verify its
result. Record remaining blockers, supported platforms/adapters and restore
evidence. Do not turn source/fixture results into a production readiness claim.

Deferred: customer isolation/billing, enterprise SSO/IAM, broad fleet orchestration,
unattended remediation, arbitrary scripts, release upgrades and universal log or
database support. These are separate decisions after the single-customer pilot.

## Related boundaries

- [Current on-demand journal design](journal-content-mvp.md)
- [Linux journal helper](linux-journal-helper.md)
- [Linux CVE limits](linux-cve-warnings.md)
- [Existing LAN agent security boundaries](lan-agent-security-review.md)
- [Controlled-action architecture](controlled-linux-actions.md): companion draft;
  a design reference is not an installed feature
