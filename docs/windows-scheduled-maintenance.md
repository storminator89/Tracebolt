# One-time scheduled Windows maintenance

This manager-only source feature adds fixed future maintenance windows for
already-admitted Windows identities. It addresses the planning workflow covered
by Datto RMM's [Maintenance policies](https://rmm.datto.com/help/en/Content/3NEWUI/Policies/Policies.htm),
without claiming recurring-policy, host-action or product-wide feature parity.
It is not included in a published endpoint package or a deployed-manager claim.

## Plan, cancel or end a window

Open **Schedule Windows maintenance** beside the existing immediate-maintenance
controls. Choose the exact device; the form proposes a start one hour ahead, a
one-hour duration, all Windows notification domains and planned work. Quick
choices also offer four hours or 24 hours ahead. These are editable proposals,
not saved plans. The input is explicitly UTC, and review additionally shows local
time with its offset.

Review the exact identity, scope and immutable UTC start/end, then check the
initially empty approval and save. The manager requires a start at least one
minute and at most seven days ahead, and a duration of one minute through 24 hours.
The UI offers 15 minutes, one hour or four hours. A stale review is rejected,
never moved forward to a new time.

Before the saved start, cancel that exact window. While it is active, end that
exact window early. Each review uses an initially unchecked, action-specific
confirmation. The latest saved state, fixed UTC dates and any cancellation or
early-end time stay visible above the collapsed history, using the already loaded
response. The original start/end remain in history. Expiry means only that the planning window
ended, not recovery or health. The page reads on demand; it does not poll or
create a host job. Local browser time can withdraw confidence but cannot promote
an upcoming window into active status without a fresh manager read.

One pending or active window is allowed per device/scope. An all-domain window
blocks domain windows, and vice versa; different domain windows can coexist.
Pending/active schedules block immediate and group-immediate starts for the same
overlapping scope. An active immediate window blocks planning there. This first
slice does not offer multiple future bookings, recurrence or group scheduling.

The separate [finite weekly series](windows-maintenance-series.md) source option
requires its own exact review and an explicit operator-database version-3 opt-in.
It does not reinterpret or promote the one-time v1 records described here.
Pending/active series reservations also block overlapping one-time and immediate
maintenance, including gaps between the series occurrences.

## Suppression preserves Windows evidence

Only separately approved Windows notification delivery is muted. Contact,
system-volume capacity, CPU, physical RAM, selected-service and complete-service
checks, source observations, incidents and acknowledgement continue unchanged.
The service scope includes the existing complete-service notification bridge.
No Linux Health, AI, provider permission, collector, enrollment, host grant,
package job, reboot or service action is changed.

Creating a future plan does not mute today's notifications. Once the window has
started, all matching definitively unsent work whose original transition crosses
that used interval is consumed, including future-due retries and the first worker
claim after a wholly missed window. There is no end-of-maintenance backlog. A
cancelled plan suppresses nothing. An early end uses its actual original
nanosecond boundary; an event at that exact boundary is outside the window.

In-flight sends cannot be recalled. Their accepted, failed or uncertain outcomes
remain truthful, while maintenance blocks definite retries. Accepted opening
records and the existing recovery-pairing rules are not pruned or rewritten.
Source transition admission and the final dispatch boundary independently check
scheduled suppression. A final guard that crosses the start cannot dispatch
using the earlier sampled clock.

## Bounded retention and time

The existing private operator database stores at most 150 exact identity/domain
records with up to 16 retained windows each. The latest four remain visible.
Older terminal windows can be retired only after their effective end (or unused
cancellation) plus the existing 24-hour original-notification lifetime. Before
retirement, matching queued work is consumed and in-flight retries are fenced.
Original event queue expiry remains independently enforced. Retired window count
and revision floors remain durable, so reclamation never resets IDs or makes a
shortened ledger look unused. If all slots are still required, planning fails
visibly until safe reclamation is possible; there is no permanent lifetime cap.

Same-original-identity certificate renewal and manager restart preserve plans.
Replacement identities do not inherit them. Missing, revoked or expired devices
expose none of the old metadata. Exact revisions and window IDs prevent replay
or accidental cancellation of a later plan. Unknown write outcomes are followed
only by reads, never automatic write retries.

Schedule-aware reads, worker checks and newly admitted source transition times
retain a durable UTC high-water mark. Delayed source transitions preserve their
original time and cannot lower the floor. Clock rollback fails closed and cannot
cancel an already-observed active window as if it had never started. Restoring a
whole older database/VM snapshot can restore its older floor and plans; that
requires operator review rather than an automatic reset.

A create-only used marker detects missing schedule records. First explicit
schedule use advances the **operator database compatibility marker to version 2**,
so an older manager refuses the database instead of silently ignoring planned
suppression. Untouched stores remain version 1. Keep the matching manager and
backup together; arbitrary downgrade after schedule use is not supported. No
endpoint, enrollment, credential or legacy maintenance v1 bytes are migrated.

## API and verification

GET `/api/fleet/windows-maintenance-schedule` returns the separate closed
`tracebolt.windows-maintenance-schedule.v1` projection, no more than 150 targets
and 256 KiB, with original identity anchors kept private. Reads may normalize the
already-created schedule clock, retention and matching unsent notification work.

POST `/schedule` requires exactly `key`, `revision`, `startsAt`, `endsAt`, `intent`.
POST `/cancel` and `/end` require exactly `key`, `revision`, `windowId`.
Canonical UTC timestamps, shared-administrator access, Origin/CSRF, current
original-identity lease, session and final clock guards remain mandatory. Named
read accounts can inspect but cannot mutate. The existing immediate/group API
and strict v1 DTOs remain unchanged.

Focused invented fixtures cover future admission, cancel/end, expiry, exact
revision and identity, scope overlap, finite retention and safe reclamation,
missing used state, restart/rollback, delayed source events, source/claim/final
clock suppression, future-due queues and in-flight truth. Actual Go projection
fixtures feed strict TypeScript tests. EN/DE component tests cover the real
maintenance-page entry, suggested times, explicit review, action-specific unchecked
confirmation, visible saved status without additional requests, uncertain reads and focus/navigation cleanup. These are source tests, not native,
external-webhook, browser-automation, installed-service or release acceptance.
