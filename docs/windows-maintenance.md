# Bounded Windows planned maintenance

This manager-side source increment adds a compact **Windows maintenance** panel
beside the fleet incident inbox. It records current operator planning for an exact
admitted Windows identity and either all Windows checks or one domain: contact,
system-volume capacity, CPU, physical RAM, or selected-service checks.

These windows now suppress matching [explicitly enabled Windows notifications](windows-notifications.md).
Checks, source evidence, incidents and acknowledgement continue unchanged. Start
consumes queued matching work; an already in-flight request cannot be recalled, and
its accepted or uncertain result remains truthful. Early end or expiry never sends
a backlog. Linux Health, alarms and AI admission remain unchanged. Maintenance
never grants host actions, changes a source policy or reports recovery or health.
There is no recurrence, future-start calendar, automatic response or generic scheduler.

## Deliberate, bounded windows

A shared administrator selects the exact identity and scope, a required purpose
(`planned-work`, `investigation`, or `other`), and reviews an absolute end time.
Compact dates use the browser’s local timezone with an explicit UTC offset;
expandable exact details retain the original UTC instant, full device ID and
reviewed revision. Duplicate device names receive distinguishing ID suffixes;
all selections and writes still use the unchanged opaque identity/domain key.
The manager starts the window at its actual transaction time. The end must be at
least one minute and at most 24 hours later. An active whole-device window cannot
overlap a domain window; independent domain windows can coexist. A window cannot
be extended or edited: end it early, or let it expire, then explicitly review a
new one. Named operators can read but cannot start or end windows.

The active badge shows the current scope and original end. Its disappearance at
expiry means only that the planning window ended. Explicit early-end records
remain ended even after the originally scheduled end passes. Opening, reading,
refreshing and expiry do not write any table. The latest four windows are retained
for each device/scope, including early-end and naturally expired windows; this is
a bounded recent planning history, not a complete audit log.

The canonical metadata binds the original device ID, invitation and immutable
issued-certificate anchor. Same-identity leaf renewal and normal manager restart
preserve windows. A replacement identity receives a different opaque target key,
revision zero and no inherited history. Only an explicit start for that confirmed
replacement replaces that device/scope's old private metadata. Missing, revoked,
expired or replaced identities expose none of their old metadata. Unavailable
other identities are never pruned by unrelated changes.

The table has a hard capacity of 150 device/scope records, each with at most four
windows. At capacity a new record fails visibly rather than evicting other
history; existing records can still be ended or deliberately replaced. Six
targets are offered for each of at most 25 currently admitted devices, even when
no policy or retained incident exists. Reads never initialize source state.

## Time and private transaction boundary

Expiry uses the trusted manager UTC clock and the immutable original end. Times
before a target's stored start/change floor are rejected, including after manager
restart. Guards reject clock rollback within a request and a deadline crossed
while acquiring SQLite or immediately before commit/response. Browser elapsed
time can only withdraw an active badge or the private view. This is not a claim
to detect arbitrary machine-clock rollback across manager restarts; reliable
manager time remains an operational requirement.

GET `/api/fleet/windows-maintenance` accepts no query parameters. Its closed
`tracebolt.windows-maintenance.v1` response contains the server time, bounded
authority deadline and six opaque targets per admitted identity. Targets are
ordered by device ID and then domain (`all`, `contact`, `cpu`, `disk`, `memory`,
`service`). Each has its exact revision, latest change and newest-first windows.
The complete response is capped at 256 KiB. Original identity anchors stay private.

POST `/api/fleet/windows-maintenance/start` accepts exactly `key`, `revision`,
`endsAt`, and `intent`. The end must use canonical RFC3339Nano UTC spelling.
POST `/api/fleet/windows-maintenance/end` accepts exactly `key`, `revision`, and
`windowId`, and ends only that currently active latest window. Every successful
change increments the target revision. Start assigns that revision as the window
ID; early end retains the ID and original end time. Stale or repeated POSTs fail
instead of refreshing a deadline. Both responses return the current projection.
Uncertain writes are reconciled through a GET, never automatically retried.

Both mutations require the live shared-administrator session, same-origin JSON,
CSRF, exact revision, current original identity and bounded clock. The existing
enrollment `BEGIN IMMEDIATE` lease surrounds the operator metadata transaction,
so revocation, replacement and renewal cannot commit between admission and the
metadata commit. The transaction reloads revision/history after SQLite waits,
checks overlap and capacity, then checks the live session, locked credential and
final sampled deadline before commit. A final source/session/clock check guards
response release. This lease adds no enrollment state or host permission.

The panel is separate from the strict incident-inbox v1 wire. It does not attach
maintenance to an independently fetched incident using a mutable device ID. A
future per-incident annotation would need an explicit common original-identity
binding. Selection and review use opaque target keys and are cleared on refresh,
visibility/session/route changes and expired authority.

## Verification boundary

Focused store/API fixtures cover revision replay, immutable ends, early end,
scope overlap, latest-four retention, normal restart, replacement and renewal,
capacity without eviction, canonical corruption, read-only expiry, current
authority, SQL-wait/final guards, exact requests, named read-only access and
unchanged source/acknowledgement/Linux state. A Go-generated wire fixture is shared
with the TypeScript parser. Component fixtures cover explicit review, bounded
expiry, uncertain-write readback and interrupted private views.

These are source and synthetic checks. They do not establish deployed behavior,
native Windows reads, service installation, privileges, actions or an actual
browser render. Hosted synthetic browser acceptance remains a separate gate.
