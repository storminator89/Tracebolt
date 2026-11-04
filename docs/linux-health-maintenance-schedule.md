# One-time Linux Health maintenance

This source feature adds a complete fixed-time planning workflow to the existing
Linux Health settings. It is manager-side suppression, not a host scheduler. It
is not included in the published Linux rc.3 package and has not had browser,
native-host or release acceptance.

## Plan, inspect, cancel or end

1. Open a Linux device's Health settings and the one-time maintenance controls.
   Reading saved status is deliberate. No endpoint capture or action is requested.
2. An existing shared Linux Health administrator chooses an exact **UTC** start
   and a 15-minute, one-hour or four-hour duration. The start must be at least
   60 seconds and at most seven days after manager admission.
3. Review both fixed UTC bounds and explicitly confirm the suppression. Closing
   a review does not save it. The manager revalidates the window and revision at
   commit, so a stale review can be rejected rather than moved forward.
4. Before the start, cancel the exact saved window. While active, end that exact
   window early. Both operations require a fresh view, review and confirmation.
   Expiry is the original saved end, even after a manager restart.

Only one pending or active schedule is allowed per device. An active legacy
immediate window blocks creating a future schedule. Conversely, a pending or
active schedule blocks all immediate maintenance commands, including generic
"stop". Use the exact schedule controls instead. Terminal schedules do not block
later immediate maintenance. Existing named read access can inspect metadata;
a named maintenance capability does not acquire Linux Health write authority.

## What suppression means

The existing Linux rules are preserved: an active window prevents new Health
incident openings. Existing incidents remain visible and can genuinely recover.
Planning a future window does not reset today's pending confirmation. Time before
or inside a used window cannot earn a new opening's post-window minimum duration.
Samples still have to be fresh, consecutive and advancing.

The same window predicate gates alarm admission. All definitively unsent queued
opening notices that cross a used window are consumed as suppressed, including
future cooldown/retry due times and the first claim after a missed window. They
are not backlogged until maintenance ends. Original payload transition times,
including nanoseconds at an early end, determine the boundary. A canceled window
that never started suppresses nothing. An early end suppresses only through its
actual saved end. In-flight sends cannot be recalled: provider-accepted, failed
or uncertain outcomes keep their real meaning. Genuine paired recovery delivery
still requires an accepted opening under the existing rules.

Existing separately approved Health AI and service-log AI also honor scheduled
maintenance at their maintenance gates. This feature changes no provider, content,
export, collection, consent or grant. It starts no command, package operation,
service action, reboot or remote session and creates no new access scope.

## Storage, time and uncertainty

The manager retains up to **64 lifetime windows per device**, including canceled
and completed records. The UI shows remaining slots. Capacity is not silently
recycled: retained bounds are needed to suppress a late requeued opening after a
newer plan. This is bounded maintenance state, not an audit/event feed.

Commands use immutable random IDs and exact revisions. Cancel/end also name the
original window. A replay of the immediately last identical command returns the
saved fixed bounds; changed or historical IDs cannot target a newer plan. The UI
never retries writes after a lost response. It reads saved metadata to reconcile
an exact request. If a verified later revision supersedes an uncertain attempt,
its original outcome stays unconfirmed, but a newly reviewed distinct command can
use the verified current revision. An absent match is not proof of failure.

Feature-aware reads/effect admissions durably retain a manager-time high-water
mark. Expiry is terminal and clock rollback cannot reactivate an observed spent
window. Trusted time is sampled again after serialized store admission so a
queued older monitor sample is not mistaken for wall-clock rollback. This is not
a cryptographic protection against restoring an older database/VM snapshot:
restoring prior state can restore its prior plan and requires operator review.

Legacy untouched Health records stay version 1 and retain their original JSON
shape. First use of scheduling makes that device's stored Health state version 2.
An older manager rejects that state instead of silently ignoring/dropping its
schedule. Preserve the matching manager/database and a tested backup when
updating; an arbitrary downgrade is not supported. The public Health v1 DTO is
unchanged. Schedule metadata uses its separate versioned contract.

## API and evidence

`GET /api/devices/{id}/health/maintenance-schedule` returns bounded saved metadata,
manager time, revision, management permission, remaining slots and the latest
window/request. Reads may durably observe expiry and consume queued openings.
`POST` accepts exactly six fields: `requestId`, canonical decimal string
`expectedRevision`, `action`, `windowId`, `startsAt`, `endsAt`. Only timestamps may
be null, and only cancel/end use null bounds. Schedule IDs equal request IDs.
Mutation requires the existing same-origin/CSRF and shared-admin fences. Current
Health source eligibility and session validity are rechecked; no new host grant
is inferred from a saved schedule. Storage/write-response failure can be uncertain.

Focused tests cover fixed bounds, CAS/replay/ID reuse, corruption and capacity,
legacy bytes/version marker, start/end/early-end truth, no duration credit,
restart/rollback, queued trusted-clock admission, all-due/retry suppression,
in-flight results/recovery, real TLS API permissions/framing/session expiry and
actual Health-panel wiring. Frontend tests cover explicit review, on-demand reads,
uncertain reconciliation, time/session/navigation cleanup and view-only behavior.
These fixtures do not establish native-host, webhook-provider or browser acceptance.
