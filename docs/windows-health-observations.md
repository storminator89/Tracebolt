# Windows Health observations

This source-only UI slice shows accepted contact and system-volume observations
in the Windows Health tab, before the existing event-header sample. It does not
add host collection, grants, API routes, persistent health state or provider
exports. Existing Windows inventory and device-metadata reads supply the view.

## Exact evidence and semantics

- **Agent contact** uses the manager's accepted `receivedAt` from the validated
  Windows inventory view. It is **recent** through two minutes and **stale**
  afterward. A repeated GET or duplicate telemetry retry is not new contact.
  A recent receipt can coexist with an old inventory capture. No ping, live
  reachability or offline determination is performed.
- **System volume** uses the existing Windows basic `disk` metric, its own
  original `collectedAt`, source, percentage unit and reported quality. The
  measurement is caller-visible, quota-aware system-volume allocation, not all
  volumes, physical-disk condition or disk activity. A value such as 99% remains
  a neutral reading; no Linux root-filesystem threshold is imported.
- **Events** retain their separate consent, sample quality, bounds, original
  event/capture times and expiry. Contact or a disk reading does not establish
  successful event collection or a complete health assessment.

The UI requires matching real Windows LAN identity, a usable Windows inventory
view, exactly one supported manager-owned `agent_identity` capability and
manager-owned current certificate metadata. A newer revoked device-metadata
response cannot borrow authority from an older inventory reply. Expiry is enforced against
advancing time. It withholds metrics on device-metadata failure or refresh and
clears contact/readings on inventory failure, interruption, access loss or
unreliable time. Missing, malformed, partial, denied, future or stale metrics do
not become current healthy readings. Numeric stale values are withheld while an
eligible original time/source may remain visible.

The existing inventory hook exposes elapsed time from **request start**, including
response delay. An isolated in-memory Windows-Health clock retains only timing
watermarks, keyed by device/session within the protected authority epoch, across
refresh, failure, blur and component remount. Unchanged or tiny advances in manager
time cannot renew observations. The map is bounded and fails closed on exhaustion;
it stores no telemetry or health decisions. Nanosecond-aware age comparisons are
used for source, receipt and certificate boundaries.

The summary is compact, English/German and responsive. Sources and assessment
limits start collapsed. **Inspect storage** opens the existing Storage tab; it
neither reads a new host source nor enables its optional scope. The Windows tab
is labelled **Health**, avoiding a promise of incident history.

## Durable Windows checks remain a separate contract

The Linux `HealthInputs` source remains Linux-only. It is also an authority
boundary for investigations and AI workflows and must not be generalized just
to populate this view. A future Windows evaluator needs its own reviewed
observation/authority contract, contact semantics, caller-capacity thresholds,
duration/hysteresis policy, durable incident lifecycle, service selection model
and independent export approval boundary. This UI supplies none of those grants
or guarantees and must not be described as full Linux Health parity.

## Verification boundary

Portable component fixtures cover exact receipt/source age, 120-second and
certificate boundaries, nanoseconds, missing/partial/denied/stale/future metrics,
identity/platform/profile authority, request-start delay, repeated GETs and
remounts, metadata refresh/failure, inventory failure/blur/session loss, clock
rollback, EN/DE labels and the read-only Storage navigation. Existing Windows
inventory/event and Linux Health suites remain regression checks.

Source tests and production builds do not establish visual browser acceptance,
native Windows installed-service behavior or a deployment. No browser launch,
host read, public release or real provider request is part of this slice.
