# Conditional advisory review candidate UI

This is a read-only, lazy disclosure inside the authenticated LAN device Security
coverage panel. The independent release/source-package panel is unchanged. This
UI does not configure collection, import a catalog, enroll a device, fetch feeds,
export to AI, create cases, install software, or offer remediation.

## Meaning and presentation

English uses “review candidate”; German uses “Prüfkandidat”. A review candidate
compares only reported source metadata to one operator-supplied offline catalog.
It never establishes an affected CVE, trusted artifact origin, installable update,
secure host, or host-wide coverage. Both authoritative counts remain null and are
shown as unknown. A completed review means only the selected-scope inspection
finished. Empty candidates are explicitly not evidence of zero affected CVEs or a
secure host. Synthetic catalogs explicitly produce no live review candidate rows.

The disclosure shows selected inventory row count, whether the declared inventory
scope is complete, partial/unavailable review status and fixed bounded-work reason
labels. It shows all three exact reported release fields, source mapping basis,
reported source package/version, declared advisory/status/fix/qualifications,
conditional comparison basis, the exact catalog revision/content hash/catalog ID,
and the exact observation generation/receipt sequence/timestamps. An incomplete
inventory flag is described as “not complete”, because this flag alone does not
establish a healthy partial inventory. Unverified catalog origin, unknown catalog
freshness and unknown installed artifact origin remain visible. The core's unknown
snapshot freshness is distinguished from the manager's checked collection window.

Every server token is ordinary React text. There are no external links, HTML
rendering sinks, downloads, export actions, or new catalog-import controls. Unknown
reason/basis vocabulary and unsolicited keys fail validation rather than appearing
as raw server errors.

## Contract and bounds

The only request is same-origin authenticated GET
`/api/devices/{id}/security/review`, with no query or body. The existing protected
request helper bounds the complete UTF-8 response at 65 KiB. The parsed exact DTO
uses `tracebolt.advisory-review-view.v1`; it accepts only the existing package-view
collection statuses, the requested device ID, canonical UTC RFC3339 times and an
exact 120-second collection window. Receipt and positive safe-integer sequence
must appear together. Only fresh envelopes contain a non-null review. All
nonfresh envelopes contain null. Not-configured and awaiting have no receipt.

The nested `tracebolt.offline-review.v1` shape mirrors
`internal/offlinecatalog/review.go`. The validator independently caps canonical
core bytes at 64 KiB, candidate rows at 128, pairs at 4,096 and comparisons at 1,024.
It requires null affected-CVE/offered-update fields and fixed unknown/unverified
assurance values. Catalog metadata reuses the existing offline-catalog validator.
Candidate package, architecture, Debian-version and safe-token grammars remain
bounded. Candidate sorting/identities, consistent reported source facts for each binary/architecture,
consistent declared rule facts for each source/advisory, basis/reason/status compatibility,
prerequisite reasons and impossible work counts are checked. Source versions are
never compared in JavaScript and suffixes are never removed. Exact-key validation
is an operator DTO check; raw agent ingestion remains the server's responsibility.

## Private lifecycle

Nothing is fetched before explicit expansion. Closing or unmounting aborts work
and destroys the local resource. Device or operator session changes remount a
closed disclosure. No review data is written to browser storage.

The request identity, abort signal and live/suspended/auth-lock state guard every
response. A read times out at 10 seconds. Receipt and collected ages preserve
sub-millisecond RFC3339 boundaries and use server time plus monotonic elapsed time,
conservatively anchored at request start. The review expires at the earlier of the
collection freshness boundary and a 60-second request-start lease. Expiry clears
the entire response; historical candidates are not retained. A wall/monotonic
clock discrepancy greater than 1.5 seconds or a backward/nonfinite monotonic clock
invalidates output and cannot grant freshness.

Page hiding, blur, visibility loss, hash/history navigation and authentication loss
abort work and clear displayed output. Focus/visible/BFCache restoration requires
a new read and cannot resurrect the old response; hidden or auth-locked resources
do not reload. The encompassing AuthBoundary also replaces the authenticated
session on BFCache restoration. A 401 locks the resource until a new session.
A 409 explicitly means the snapshot or catalog changed, clears previous output
and asks for a fresh read. A 429 gives a bounded busy notice without auto-retrying.
Refresh clears old candidates before making its read.

## Verification scope

The implementation has synthetic DTO, React/jsdom, actual protected-request helper
and DeviceDetail/AuthBoundary integration tests. Focused tests cover EN/DE labels,
null counts, synthetic suppression, exact nested keys, unsafe/overlong tokens,
source mapping, basis/reason consistency, duplicate/order rejection, exact 64 KiB
acceptance and one-byte overflow rejection, both freshness clocks, 65 KiB transport
rejection, invalid UTF-8, lazy access, refresh/409/429/401, held streams, late results,
device/session/tab changes, visibility/blur/history/BFCache invalidation, timeout,
clock discontinuity and lease expiry. Existing package and offline-security suites
are also regression checked. The independent security-review tests are recorded
separately in `review-ui-security.md`.

These are local synthetic checks, not browser screenshots, a hosted UI run, a LAN
deployment, or evidence from a real endpoint/catalog. No hosted/browser/real-device
claim is made. The exact tested source file allowlist and hashes are reported by
the implementing task to its coordinator; this shared checkout has no Git metadata.
