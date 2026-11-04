# Resource history

The authenticated LAN device Overview includes compact CPU, memory and root
filesystem usage charts for the preceding 24 hours. Hover over a measurement or
focus a chart and use Left/Right/Home/End to inspect its exact timestamp and
percentage. Missing or unavailable observations are gaps, including gaps between
reports longer than two minutes. A measured zero is a real zero. Disk is used
root-filesystem capacity, not disk I/O or the total capacity of every mount.

History starts with newly accepted observations after the manager update. There
is no invented backfill, replay of the old latest sample, agent re-enrollment,
identity reset or expanded collection permission. Existing enrolled agents
already send these three basic percentage observations. History persists across
manager restarts. Manual-certificate-only enrollment currently reports history
as unavailable; no synthetic history is substituted.

## Bounded storage and read contract

- The existing private enrollment database gets only an optional history table
  and age index, atomically on its first newly accepted observation. Existing
  identity, credential, counters, lifecycle and inventory schemas stay intact.
- One authentic last accepted observation per UTC collection minute is retained.
  Its original sequence, collection/receipt times and three metric timestamps
  and qualities are preserved. Values are not averaged or interpolated. The
  timestamp/sequence comes from the already validated telemetry frame, not a
  browser refresh or a client-supplied device identity.
- Reads expose at most 1,441 minute samples inside the exact 24-hour window. The
  existing 30-second endpoint-clock tolerance is unchanged; observations ahead
  of manager time stay hidden until that time arrives. Storage allows one extra
  minute bucket for that existing tolerance, at most 1,442 rows per identity and
  1,024 bytes per row. Current report/replay state remains independent.
- New observations prune the selected device's retired buckets. The existing
  complete-profile manager maintenance loop also deletes at most 256 expired
  history rows per step. History reads prune one such bounded batch and always
  enforce the precise collection-time cutoff, even before physical cleanup.
  SQLite may reuse freed pages; this is logical retention, not secure erasure.
- GET /api/devices/{agent_id}/resource-history is an operator-only, no-store,
  read-only endpoint. Named readers may inspect it. Only the canonical optional
  afterSequence cursor is accepted; other query parameters and writes are rejected. Agent ingress, public bootstrap and the development API do not
  provide this history. No history is supplied to AI diagnostics.
- Revoked, terminated, expired or nonactivated identities never return history
  points. Auth is rechecked immediately before output; certificate expiry and
  retention are rechecked against trusted manager time after the store read and
  again after the single response encoding, before those verified bytes are sent.
- The API response is capped at 1.5 MiB. The browser validates identity, window,
  timestamp and sequence ordering, minute uniqueness, quality and finite bounds.
  A visible Overview makes one bounded read at a time, yielding to pending API
  reads and polling at 60-second intervals. Hidden/suspended views, navigation,
  logout and access loss clear the chart reader and ignore late replies.

## Verification

Go coverage exercises authentic timestamps/zero/unknown points, per-minute
selection, full-day storage bounds, additive schema compatibility, duplicate and
replay behavior across restart, revocation/expiry and bounded physical cleanup.
Operator tests cover authentication, same-origin, canonical routes, query/method
rejection, named readers and session expiry during a read.

React tests cover response validation, segmented lines, keyboard inspection,
empty/revoked states, language, bounded reads and concurrency, interrupted reads,
auth/device changes, clock failure, access denial and suspension. The existing
hosted LAN browser runner includes an explicitly synthetic chart case for
English/German, light/dark/mobile rendering, keyboard timestamps, gaps, empty
history, navigation and protected-session loss. These fixtures do not establish
installed-service or native host acceptance.

The history schema is additive, but older managers that do not recognize this
optional table can reject the database. Use the matching updated manager build;
do not reset device identity or remove private state to force a downgrade.

## Investigate and compare retained intervals

The device Overview now offers **1, 6, 12 or 24 hours** inside the same retained
snapshot. The initial 24-hour chart remains available. Shorter windows keep
original metric timestamps, reported unknown states and disconnected chart
segments; no interpolated values or additional observations are generated.
Keyboard inspection still identifies the exact original measurement.

**Compare with previous interval** opens the sample statistics for the immediately
preceding equal interval. Both intervals are anchored to the original manager snapshot,
not the browser clock. The boundary sample belongs only to the later interval.
The preceding 24-hour interval is outside retention, so that comparison is disabled
instead of inventing a baseline. Exact UTC interval bounds are shown alongside
the original UTC snapshot time. New accepted snapshots naturally advance both
periods; this is live investigation, not a pinned or exported report.

Each resource has independent usable-sample and minute-bucket coverage, minimum,
median, nearest-rank 95th percentile, maximum and the longest interval between
usable samples including its leading/trailing edges. The bucket denominator
includes any partial UTC minute intersected by the interval. It is not uptime or
continuous observation coverage. Samples are classified by their original metric
timestamp; retained-report counts separately use each report's collection time.
These can differ when a report carries an earlier original metric timestamp.

Only valid observations whose original quality was healthy participate. This
means valid **at capture**, not currently healthy. Measured zero remains zero;
stale, denied, unknown and absent measurements are never replaced with zero.
Repeated original metric timestamps count once. Conflicting valid values at one
timestamp are withheld from statistics and counted explicitly. This does not
rewrite retained observations or the existing chart's source data.

The median difference uses percentage points and appears only when both intervals
have usable samples. Statistics describe a sample distribution, not time-weighted
load, continuous high utilization, a trend forecast, root cause or improvement.
Sparse or missing previous evidence remains visibly incomplete. Root filesystem
allocation and Windows system-volume capacity retain their different meanings;
neither is storage I/O.

Window selection, comparison and disclosure are local presentation controls.
They perform no request, export, storage write, refresh, collection or action.
The existing one-at-a-time bounded authenticated reader, 24-hour retention,
delta protocol, certificate/session checks and suspension/clearing rules are
unchanged. Controls reset when device/session scope changes or the source clears.
Synthetic model/component tests cover boundary ownership, sparse/zero/unavailable
samples, duplicates/conflicts, original times, repeated controls, source loss,
keyboard inspection and EN/DE capacity labels. Browser/native acceptance and
deployment are not claimed.

## Session-local delta reads

The first read returns the complete verified v1 history. Subsequent visible
minute polls may supply `?afterSequence=N`, where N is the last accepted sequence
in that same device, operator session and protected-request epoch. The decimal
cursor is positive, canonical and at most 9223372036854775807. It is not an access
credential and bypasses no store validation, authorization or expiry check.

An available delta has schema `tracebolt.resource-history-delta.v1`, the exact
`baseSequence`, authoritative full `pointCount` and `lastSequence`, and every
retained point newer than N. A newer observation in the same UTC minute replaces
that minute; no additional averaging, downsampling or peak suppression occurs.
An unchanged response has an empty delta, current server time and the same
verified full count/watermark. Full bootstrap remains compatible, including a
full fallback if a supplied watermark is ahead of the server. Terminal states
return full empty v1 responses.

The browser prunes its verified baseline against the returned server window,
merges by minute, then validates the complete combined history, exact count and
last sequence. A wrong baseline, gap in the delta protocol, regressing clock,
invalid observation or access change clears the view. Nothing survives logout,
navigation, background suspension, or a different operator/device scope. A
resume or retry without a baseline bootstraps again. Protected responses remain
no-store; there is no shared HTTP cache or authorization cache.

The output still encodes only once and rechecks the complete source view after
encoding, including expired points that were not repeated in the delta. Delta
transport reduces repeated network/JSON work; it deliberately retains the full
server-side integrity read.
