# Complete-generation Windows service checks

This manager-only source candidate adds an explicit **Complete service checks /
Vollständige Dienstprüfungen** workflow for one Windows device or exact selected
members of a manual group. It reuses the separately acknowledged
`windows_full_services` source; it never enables collection or extends endpoint
privileges. Native acceptance, release and deployment remain separately pending.

## Deliberate source and bounded choice

The chooser uses the existing authenticated, body-only complete-service query:
server-side search and at most 100 rows per page, pinned to one complete generation,
local grant/revision and operator session. It can find services beyond the old
128-row telemetry preview. An administrator explicitly selects at most eight
exact original names and the should-be-running expectation. Labels remain display
names; exact names remain identity. The complete source's original native name
limits (256 UTF-16 code units / 1,024 UTF-8 bytes) are retained. Missing state fields
remain unknown; a captured identity with an unavailable state can be selected.

Health reads stream-verify the bounded complete generation (at most 8,192 rows /
8 MiB), then retain only the requested zero-to-eight exact service rows. Group
lists read no complete generations; a selected member loads its own source lazily.
The monitor adds selected rows to the existing coordinated source transaction,
without a new competing loop. All-disabled policies perform no source reads.

The policy records its explicit complete-source kind and local grant/revision.
New selections, re-enablement and a new local grant require the exact reviewed
current generation and manifest digest. The enrollment-to-operator lease freezes
original enrollment, active leaf, grant and complete generation through commit;
post-SQL-wait/final clocks and live sessions are checked. Positive evaluator
commits use the same source lease, including a fresh post-wait evaluation time and
final capture/receipt/credential expiry checks. Revoked or replacement identities
can only clear confidence; one permanently unavailable policy does not block the
remaining coordinated checks. Removal or disabling
retained names does not need a fresh generation, but still needs live identity
and operator authority. A read or group membership never grants monitoring.

## Evidence and timing

Each observation records complete-source provenance: original capture start/end,
final receipt, grant/revision, independent capture sequence, generation ID and
manifest digest. The telemetry frame counter and receipt are never substituted.
A new generation does not reset the manager epoch or pending timer. Repeated reads
of one cached generation never become new evidence.

Complete-source capture and final receipt must each be at most **five minutes**
old. The original 24-hour inventory retention is not a health freshness promise.
The endpoint's capture minimum is one minute, but its default foreground loop
waits 30 seconds after serialized optional stages, each with its own cooperative
budget; full service bursts have 20 seconds / 64 operations. Context-source
fairness rotates within telemetry collection, while full services runs afterward
on its independent capture domain. Thus 120-second preview freshness would cause
routine gaps on slower healthy cycles. Five minutes is an explicit ceiling,
not a delivery guarantee; delayed multi-burst transfers can remain unknown.
No collector cadence, frame, wire, consent or receipt has changed.

The manager still evaluates every 30 seconds. A manager evaluation gap over
90 seconds, restart or source error interrupts continuity; current evaluation
must be at most 120 seconds old. To open an incident, distinct advancing captured
generations must span 120 seconds, and the manager must continuously evaluate
stopped/paused evidence for 120 seconds. Recovery similarly needs newer running
captures spanning 60 seconds plus continuous manager evaluation. Two-to-three
minute source cadence works without pretending cached data is new.

Only a complete, current, healthy generation of the selected grant is eligible.
Newer partial/pending or failed attempts, missing/corrupt data, revoked/disabled
scope, stale/future timestamps and unavailable selected states are unknown.
Missing rows never prove stopped, removed or absent, including caller-visible
complete enumeration. Unknown never resolves an open incident. Grant changes
never silently transfer policy authority. Durable sequence/capture/receipt floors
and exact generation identity survive restart, missing sources and policy changes.

## Versioned manager contract

- GET `/api/devices/{id}/windows-services/complete` returns
  `tracebolt.windows-service-view.v2`.
- POST `/api/devices/{id}/windows-services/complete/policy` accepts exactly
  `enabled`, `services`, `expectedRevision`, `source`. Source is the exact reviewed
  provenance, or null for allowed removal/disable without fresh data.
- GET `/api/fleet/groups/{groupId}/service-checks-complete` returns
  `tracebolt.fleet-group-service-checks.v2`.
- GET/POST the same route plus `/{key}` returns
  `tracebolt.fleet-group-service-choice.v2`; writes additionally require exact
  `groupRevision`, `consent:true` and current original membership.

The v2 inventory projection contains selected evidence only, not a chooser prefix.
Its source rowCount describes the entire captured generation; zero selected rows
is not a complete empty generation. The separate existing complete-service query
remains the chooser. V2 observations and inventory have explicit source objects;
policy source is absent before first deliberate configuration.

The same device ledger/table and eight-check limit are shared by strict tagged
v1/v2 states. A used v1 state is not automatically converted; legacy requests
cannot mutate or read a v2 policy as v1. There are no existing user installations,
so there is no migration or re-consent project. Existing v1 state bytes, preview
semantics and old endpoint contracts remain supported separately.

History is bounded to at most 100 incidents, 30-day closed retention and 256 KiB
per device. Complete provenance may reach the byte limit sooner; only oldest
closed episodes can be pruned. Open episodes and source floors are never discarded.
The new complete-source history is shown in its v2 Health panel. Legacy v1 fleet
incident acknowledgement, notification delivery and service-action review are
not promoted; v2 episodes do not enter those old contracts. A separately explicit
v2 fleet incident/notification bridge remains follow-on work. No AI, automatic
restart, external notification or remediation is authorized by this policy.

## Verification boundary

Invented Go tests exercise 2,051-row complete inventory beyond the preview,
independent frame/generation counters, original receipt/capture, missing/partial/
failed/disabled/revoked sources, exact grant/generation and active-leaf admission,
source-age expiry after waits, restart and durable-state loss, strict legacy
isolation, confirmation/recovery at three-minute captures and bounded history.
Recorder-only handler tests use no listener/socket/native endpoint. Shared
Go-generated JSON is consumed by EN/DE component tests and hosted synthetic
changed-view capture source. Rendered browser and native Windows acceptance are
separate pending gates; source checks establish neither deployment nor release.
