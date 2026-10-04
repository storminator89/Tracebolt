# Conditional advisory review API (unpublished)

This read-only view interprets a bounded selection of **reported source-package
versions** against the operator's unverified normalized Debian catalog. Every
returned item is a **review candidate**. This does not establish that a CVE
affects the installed artifact, that a newer package is offered, or that an
endpoint is secure. The existing coverage endpoint and its null affected-CVE /
offered-update counts remain unchanged. No result becomes a case or AI packet.

## Route and authority

`GET /api/devices/{id}/security/review`, without a query or body. It uses the
existing authenticated operator router and requires the selected
`managed-operations-v2` runtime to compute candidates. Known devices in other
profiles return `not_configured`; unknown devices return404. There is no device
request, catalog URL, trust flag or caller-supplied inventory on this route.

One manager-wide review slot is acquired before any package-store work. Busy
admission returns429 `review_busy` with `Retry-After: 2`; typed store admission
pressure returns429 `storage_busy`. A four-second cooperative context bounds
store waits and pure comparison work. There is no network, subprocess, package
manager or advisory-service call. The portable comparator uses the existing
assessment comparator interface; unsupported versions stay review/unknown and
are not reinterpreted as malformed collected inventory.

## Envelope

- `schemaVersion`: `tracebolt.advisory-review-view.v1`
- `deviceId`: exact requested server-assigned identity
- `serverNow`: manager UTC RFC3339 timestamp
- `maxAgeSeconds`:120
- `collectionStatus`: `not_configured`, `awaiting`, `fresh`, `stale`, `revoked`, or `unavailable`
- `receivedAt`: original manager receipt time or null
- `sequence`: original accepted sequence or null
- `review`: `offlinecatalog.ReviewResult` or null

Only a current fresh package observation gets a non-null review. A missing or
synthetic catalog yields an explicit unavailable core result with no live rows.
A fresh successful envelope always has a non-null result. All other collection
states have a null result. The core preserves catalog revision/ID/hash/import
time plus package generation/collection time and metadata limits. Its
`affectedCves` and `offeredUpdates` are always null. Full response size is capped
at65KiB; the core is capped at64KiB and128 rows,4096 inspected pairs,1024 comparisons.

The package read uses current durable identity/profile/receipt state. After
computation, the handler re-reads it and rejects changed sequence, receipt,
snapshot, expiry or revocation; it also rechecks catalog revision and operator
session. Changed inputs return409 `review_changed`, without a partial result.
This is a versioned read snapshot, not a cross-store write transaction; a later
change can occur after the final check. Clients must retain lineage and expire
freshness against the server clock rather than treating old results as current.

## Client behavior and limitations

Read lazily after explicit expansion. Abort and clear results on device/session
change, hidden/restored page, invalid time anchor, invalid response or409; a new
request is needed. Render catalog labels, package names and versions only as text.
Do not link imported content or derive remediation commands. A completed selected
scope inspection with no rows is not a zero-CVE result. Partial inventory, missing
covered sources, comparison errors and count/byte caps remain visible.

Exact release matching initially supports only reported Debian13/Trixie.
Ubuntu24.04 source observations are retained but this catalog has no matching
Ubuntu interpretation. Installed artifact origin remains unknown; catalog origin
is unverified and publication freshness unknown. These limitations also apply
when package collection and transport themselves succeeded.
