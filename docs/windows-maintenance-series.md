# Finite weekly Windows maintenance series

This manager-only source candidate adds an explicitly reviewed series of two,
three or four fixed UTC maintenance windows for one original Windows identity
and one notification scope. It is not indefinite recurrence, a host scheduler,
an endpoint grant or a deployment. No released package, real database migration,
native Windows acceptance or external notification delivery is established.

## Exact review and consent

Open the series controls inside the existing on-demand scheduled-maintenance
panel. Select one device, one scope, a first UTC start, a duration and a count.
The first start must be at least one minute and at most seven days ahead.
Each occurrence starts exactly seven UTC days after the previous one, lasts
between one minute and 24 hours, and the final end is within 29 days of approval.

Review every start and end before approving. Local times include their offsets;
keeping the same UTC time across daylight-saving changes can change the local
time. The initially unchecked approval covers only this exact finite list,
original identity and scope. The complete list is saved atomically or none is.
An expired review is rejected, never silently moved to a later time.

Only matching, separately approved Windows notifications are suppressed.
Collection, checks, incidents and acknowledgements continue. Existing source
approvals, destinations, payloads and their authorization remain independent.
This feature enables no notification delivery, AI export, endpoint command,
package operation, reboot or service action. Shared administrators can make
changes; existing named accounts remain read-only here.

## Conservative overlap restriction

Any pending or active occurrence reserves its device/scope for the series.
While that reservation remains, another one-time, immediate, group-immediate or
series window in an overlapping scope is blocked, including in the gaps between
weekly occurrences. An all-domain reservation conflicts with each individual
domain, and vice versa. Independent nonoverlapping domains remain separate.

This conservative restriction is deliberate. The feature does not promise a
calendar in which every visually empty gap can be booked. The series never
follows later group membership or a replacement device identity.

## Per-occurrence controls and evidence

Every occurrence keeps its own immutable ID, series ID, original start/end and
creation time. Cancel an exact occurrence before it starts, or end an exact
active occurrence early, using a fresh action-specific review. Neither operation
moves later dates, rearms a cancelled occurrence, retries a save or creates a
catch-up window. Expired or ended means the suppression window ended, not that
the device recovered.

The manager snapshot determines current status. Elapsed browser time can make
that status require refresh, but cannot promote a future occurrence to active.
All live occurrences are shown, rather than only the legacy four-row history.
Original-identity renewal preserves saved series; replacement, revocation,
expiry or unavailable current authority never exposes or grants the old plan.

Interrupted writes are reconciled only through reads and their exact operation
receipt. A missing receipt is not proof that a write never committed and never
authorizes an automatic retry. Closing the view does not cancel a committed
series or stop an already admitted request.

The interface retains pending-operation metadata only in component memory for
the current session. Closing and reopening the controls retains it while that
component remains mounted; a full unmount or page reload does not. This is not
cross-reload receipt recovery. A new view must read current saved state, and the
server's revision and overlap checks remain authoritative.

## Operator database version 3

The first committed series atomically advances the operator database
compatibility marker to **version 3** with the full series and its receipt.
Opening an old database with the new manager does not by itself opt it in.
Existing immediate-maintenance and one-time schedule records keep their original
representations; no endpoint state or grant is migrated.

**Older managers that support at most database version 2 cannot open this database
after its first series is saved.** Cancelling every occurrence or later retiring
history does not make it safe to downgrade. Keep the compatible manager and its
complete state together. There is no supported shortcut using a lower version
marker, deleted series tables, reset used-state or reconstructed records.

Version-3 startup validates the series ledger and its durable used-state before
creating or repairing schema objects. Missing, malformed or inconsistent used
state fails closed. New occurrence IDs, revisions, receipts and retirement floors
are independent of the legacy serial-window history contract.

## Suppression, clock and retention

The single-window and series ledgers jointly govern overlap and notification
suppression. Existing source admission, worker claim and final dispatch checks
must all see the same authoritative state. A manager that misses a complete
window still consumes matching definitively unsent work. Cancellation before
start suppresses nothing; early end uses its actual boundary. In-flight delivery
cannot be recalled, and accepted or uncertain outcomes remain truthful. Ending
maintenance does not release an old notification backlog.

The combined single-window/series capacity stays bounded to 150 distinct
identity/domain targets and 16 retained scheduled occurrences per target.
Pending occurrences cannot be retired. Series retirement is deliberately more
conservative than legacy one-time retention: an occurrence remains until its
**original scheduled end plus the 24-hour notification lifetime**, even if it was
cancelled or ended early. Only an eligible oldest prefix can be retired, after
consuming affected queued work and fencing retries. The latest four occurrences
remain. Original series definitions, the retired boundary and time evidence allow
the remaining members to be checked without treating a missing future occurrence
as completed. Legacy one-time retirement is unchanged. Byte limits and durable
floors remain independent bounds; capacity exhaustion is visible and never resets
IDs or removes live reservations.

The manager retains durable UTC high-water marks. Clock rollback fails closed,
and delayed source transitions keep their original timestamps. A manager restart
does not change dates, renew approval or create another occurrence.

## Separate typed API

The new routes stay below `/api/fleet/windows-maintenance-schedule/series`:

- GET the base route for the closed `tracebolt.windows-maintenance-series.v1`
  view of current authorized targets, all retained series occurrences and combined
  schedule capacity. No view creates a series or notification permission.
- POST `/review` for an exact create proposal, or `/cancel/review` and
  `/end/review` for one exact occurrence and revision. The server returns a
  session-bound, expiring review token and operation ID.
- POST `/commit` with that review, operation ID and explicit acknowledgement.
  The original dates, identity, scope, action and revision cannot be substituted.
- GET `/receipts/{operationId}` for the exact saved operation outcome under
  current identity and operator authority. Receipts have a bounded 24-hour
  lifetime; unavailable evidence remains unresolved, never proof of non-commit.

The old one-time projection cannot describe a live series. It refuses an
incomplete view rather than silently reporting that no maintenance is planned;
an unmodified v1-only frontend receives that refusal for the entire schedule
view while any currently authorized series is pending or active. Use the matching
series-compatible frontend to retain unrelated one-time controls. Its separate
series controls remain reachable. The modern one-time panel uses
GET `/legacy` below the series route instead. Its separate closed envelope
contains the unchanged one-time projection and exact per-target series
reservations and combined capacity from one transaction. A series on one device
therefore does not remove another device's one-time controls; nonoverlapping
domains on the same device also remain usable. Exact legacy cancel/end operations
and their response shapes stay unchanged. A write response alone does not refresh
the combined view; the client reads it again before enabling further changes.
The existing one-time DTOs are not expanded to accept series data. No runtime
permission allowlist is changed.

## Recovery and verification limits

A whole database or VM rollback can restore older cancellations, receipts and
clock floors. This feature cannot detect an unannounced rollback from that same
restored state alone. It supplies no backup, automatic recovery or release from
[restore quarantine](restore-quarantine.md). Restoring remains a separately
reviewed operation with writers and outbound delivery stopped and current
authority reconciled. An older snapshot is not a safe downgrade shortcut.

Focused source tests and independent source review do not establish rendered
browser behavior, native endpoint acceptance, real webhook delivery, deployment
or release readiness. The separate Go source-vocabulary allowlist and existing
fleet-capture regression must not be bypassed or modified as part of this feature.

See [one-time scheduling](windows-scheduled-maintenance.md) for the unchanged
legacy contract and [notification authorization](windows-notifications.md) for
the separate sources, destinations and delivery lifecycle.
