# Watch sampled Windows events

Source-only manager feature. In a Windows device's **Logs** tab, open **Watch
sampled events**, select up to four exact observed event types, and explicitly
approve the local derived-retention notice. Nothing is enabled by opening the
panel, collecting headers, installing Read admin, or upgrading the manager.

This watches **samples**, not the complete Windows event log. Events can be
missed. No match means only that no matching event was observed. It never means
healthy, a successful backup, or recovery. The feature does not retrieve older
events, collect messages, subscribe to native event logs, or contact an endpoint.

## Separate manager consent and source

The existing `windows-application-system-event-headers-v1` local grant remains
unchanged. It supplies at most 16 Application and 16 System headers, through the
existing accepted report. The new, default-off manager policy separately stores
exact channel/provider/event-ID/level selections while enabled and derived local
match counts and original capture/receipt times. That choice does not grant new
collection, privileges, installation, notification delivery, AI or export.

Only shared administrator sessions can change policy or mark an observation
reviewed. Named read sessions can inspect permitted retained views. Every write
uses the existing Origin, CSRF and live-session gates, an expected operator
revision, an exact source token and a fresh explicit command ID. Uncertain writes
are reconciled with GET; the browser never replays them.

The manager uses existing accepted-contact and Windows inventory reads, matching
sequence and original receipt, then holds the existing exact accepted-frame
lease through its own transaction. The lease's historical function name includes
"notification"; this feature uses only its authority guard and adds no outbox,
recipient, external request or notification permission. No enrollment contract,
collector, transport shape or source allowlist changes.

Only the current periodic-header snapshot is admitted. Separate historical-header
and selected-message scopes expressly prohibit this reuse and are not inputs.
Security events, messages, XML, EventData and identities are excluded. Existing
raw-header freshness and 24-hour private-view expiry are unchanged.

## Matching and lifecycle

Enablement records the current sample as a baseline without creating an alert.
An exact match thereafter requires an advancing accepted sequence and capture,
a record ID above that channel's durable baseline, and an event timestamp strictly
after enablement and no later than the capture. Event timestamps are inspected
transiently, not retained in incident records. Endpoint clock uncertainty can
conservatively suppress matches. Missing rows, truncation and collection gaps do
not establish complete coverage or an accurate total event count.

At most one unreviewed incident is retained per selector. Its count is a lower
bound on matching sampled records. Repeated snapshots, GETs, retries, restart and
review do not count the same record again. Marking an incident reviewed is a
human workflow action, not confirmation that the underlying problem is fixed.
No absence-based recovery is implemented. A later distinct matching event can
open another incident.

A decreasing channel record maximum means continuity is uncertain, possibly
because the source log was cleared. Evaluation pauses until an explicit re-arm
under the same source grant establishes a new baseline. Replacing the original
identity or header grant never transfers settings or history. This first slice
fails closed rather than supporting grant migration or a ledger reset.

All derived incident records expire exactly seven days after their latest
matching accepted receipt, including unreviewed incidents. Expiration is not
recovery. Cleanup runs independently of current source availability. There are
at most 100 retained incidents per device and 25 device ledgers; capacity failure
stops admission instead of silently discarding evidence. Disable clears saved
selectors and deduplication floors, but does not prematurely erase unexpired
derived incident records. Original identity/grant bindings remain. Public views
hide private information when current source authority or the original grant is
absent or changed.

## Private browser behavior

The collapsed panel reads only when opened, with explicit refresh thereafter.
It never sends a collection request or stores private data in browser storage.
Source choices come from the current fresh periodic sample. Session/device
changes, close, blur, hidden pages, navigation, request failures and expiry clear
choices, consent and history; late responses cannot restore them. Views have at
most a 30-second lease, shortened by source freshness and authority expiry.
English/German controls expose exact selections without a query language.

## Verification boundary

Portable synthetic tests cover opt-in, baseline/no historical backfill,
uint64 record floors, deduplication, source/identity replacement, partial or stale
samples, clock changes, record regression, manual review, bounded hard retention,
canonical storage, final lease rollback, authenticated API writes and source
isolation. Node-only type/SSR tests and a frontend build are source evidence.
No real event logs, installed endpoint, external transmission, manual browser,
host modification or deployment is part of this slice. Native and interactive
browser acceptance remain unverified; no release is implied.
