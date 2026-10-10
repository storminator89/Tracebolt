# Windows system-volume capacity checks

This source candidate adds a separate, default-off manager policy to the Windows
Health tab. It evaluates only the existing accepted Windows basic `disk` metric.
It neither installs nor changes a collector, enrollment, local consent receipt,
service, credential, event scope, update scope, AI provider or notification route.
Published Windows preview bytes do not include this newer manager feature.

## What the percentage means

The existing Windows collector derives the system-directory drive root, requires
fixed media, and uses matching caller-total and caller-available values from
`GetDiskFreeSpaceExW`. Its percentage is
`100 * (callerTotal - callerAvailable) / callerTotal`, including caller quotas.
The policy compares that existing percentage directly; it does not recalculate
physical-volume free space or use Linux root-filesystem assumptions. It does not
assess every volume, physical-disk condition, disk activity or overall health.
The separate neutral system-volume reading remains available with its source.

A new schema, manager upgrade, successful GET or accepted report cannot enable a
policy. Under collapsed settings, a shared administrator deliberately enables the
check, chooses a whole-number threshold from 50 through 99 percent, and saves.
The initial proposed threshold is 90 percent and the policy starts disabled.
Named read/maintenance accounts may inspect existing policy/history but cannot
change this administrative setting. No new named capability is introduced.

## Evidence and transitions

- A usable observation requires a healthy-quality percentage, finite value from
  zero through 100, original capture and accepted receipt no more than 120 seconds
  old, and current matching guided Windows certificate authority. The receipt and
  capture are separate. An unrelated truncated service/process inventory section
  does not change the independently quality-labelled basic disk metric; missing,
  partial, denied or stale disk values are unknown.
- A value at or above the configured threshold starts pending confirmation.
  Opening requires distinct advancing original captures spanning at least 60
  seconds and at least 60 seconds of continuous manager evaluation. Repeated GETs
  or evaluations of the same sequence cannot open an incident or advance its
  last confirmed high sample.
- An open episode recovers only with distinct advancing low captures spanning
  at least 60 seconds, also continuously evaluated for at least 60 seconds, at
  or below five percentage points below the configured threshold. For a 90%
  policy, recovery requires 85% or below. The hysteresis band keeps the incident
  open. Recovery always requires a sequence newer than the last high observation.
- Missing/partial/denied/future/stale evidence, authority loss, manager restart,
  an evaluation gap over 90 seconds, or an unavailable evaluator removes current
  confidence and resets waiting periods. Unknown never closes an incident.
  Clock rollback fails closed. Durable accepted-sequence, receipt and capture
  floors survive unknown, restart, disabling and policy changes, so older
  evidence cannot become a fresh success after an interruption.
- An evaluation more than 120 seconds old or an accepted tuple newer than the
  evaluator's tuple makes the current view unknown. Browser aging can only remove
  confidence; it cannot open or resolve an incident.
- Disabling or changing a policy closes its open episode as `policy-changed`,
  explicitly not recovered, retaining its original policy revision and threshold.
  Re-enabling starts fresh confirmation. Saving an identical current policy is a
  no-op. Stale optimistic revisions are rejected rather than replayed.

The private table holds at most 25 device records and 100 incidents per device.
Closed incidents are pruned after 30 days during an authorized evaluation/policy
change; open incidents are retained. Disabled records are not periodically
rewritten, so their closed history may remain until another policy change.
Canonical bounded decoding fails closed on corruption. Failed writes do not
replace the retained policy/history. The monitor uses one source transaction per
pass, separate from Linux Health, investigations, proactive AI and alarm delivery.
The production Windows scheduler evaluates contact first and capacity second on
the existing 30-second cadence, avoiding contention for the bounded shared reader.
With no enabled disk, CPU or RAM policies, that evaluator does not read enrollment at all.

## Operator boundary and browser behavior

GET `/api/devices/{id}/windows-capacity` is read-only. It requires a current
operator session and matching Windows identity/certificate authority, with a
second check before release. History is never transferred to a replacement
identity. Missing or revoked devices do not expose a live policy/history view.

POST `/api/devices/{id}/windows-capacity/policy` accepts exactly:
`enabled`, `thresholdPercent`, and `expectedRevision`. It requires the current
shared administrator, same-origin JSON, CSRF, live mutation authority, and an
unchanged device binding. Its response does not itself run an evaluation.
Both routes reject ambiguous paths/query parameters. The closed v1 view is
bounded to 128 KiB and omits certificate hashes, invitation IDs, process epochs
and transition/floor metadata.

The selected real Windows Health tab alone reads this endpoint. It preserves
original capture, receipt and evaluation times separately. EN/DE settings explain
quota-aware scope, confirmation and hysteresis before saving. Uncertain writes
are not automatically retried; the UI reads back state and preserves uncertainty
if that reconciliation fails. Device/session/navigation changes, metadata failure,
blur, hidden pages, expiry or access loss clear private visible data and cancel
requests. Bounded isolated timing watermarks prevent repeated/remounted reads
from renewing old observations. Unsaved selections never apply a policy.

## Verification boundaries

Portable tests cover default-off policy, exact threshold/hysteresis edges,
source-spanning confirmation and recovery, repeated samples, unknown/rollback
floors, restart/gaps, disable/re-enable, canonical corruption, optimistic writes,
read-only GETs, source-only enrollment reads, role/CSRF/session/authority changes,
25-device monitor admission, and storage failures. An invented accepted Windows
frame crosses the real enrollment store, independent monitor, operator store and
authenticated API. Go-generated view fixtures bind the TypeScript parser.

Component and synthetic browser fixtures are source verification, not proof of
native Windows reads, quota behavior, installed-service lifecycle, real
Windows-to-Linux interoperability or production deployment. Hosted visual/browser
acceptance and any native work remain separate gates. Selected Windows service
rules, event-derived diagnostics, acknowledgment/maintenance, notification and
AI scopes remain future parity work with their own explicit policies.

## Subsequent source increment

Independent default-off [CPU and physical-RAM policies](windows-resource-health.md)
reuse this percentage evidence engine with separately tagged policies/history and
source-specific floors. The disk v1 contract and opt-in remain unchanged. The
same coordinated monitor reads all enabled percentages in one source transaction;
when disk, CPU and RAM are all disabled it reads no enrollment source.
