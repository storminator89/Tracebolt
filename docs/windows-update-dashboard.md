# Cached Windows Updates dashboard candidate

Source candidate, 10 October 2026. The shared Windows device page now has
Inventory → Updates, using the same private operator inventory read. This is a
cached-metadata display, not patch/CVE coverage, online detection, downloads or
installation support. Native Windows acceptance and hosted-browser acceptance
are separate gates; synthetic parser/DOM tests do not establish either.

A separate [selected-update job source](windows-selected-update-jobs.md) adds an
inactive-by-default capability/review surface alongside the read-only cache.
It requires independent authority and supplies no native installer.

See [cached inspection](windows-update-inspection.md) for the reviewed WUA source
and separate consent boundary. Existing Windows Setup, inventory and event
header grants do not authorize this collection.

## Read contract

The existing authenticated `GET /api/devices/{id}/windows-inventory` keeps
`tracebolt.windows-inventory-view.v1`. The frontend bounded reader now accepts
up to 160 KiB, including the newer optional context sections. Its
optional `updates` sibling contains the exact
`tracebolt.windows-update-inspection.v1` snapshot. Old responses without this
sibling remain accepted, including every combination of the other five optional
sections. The frontend does not call a Linux inventory, package, CVE or mutation
endpoint for Windows Updates.

Defensive parsing requires the exact field sets, separate scope/grant, exact base
generation and original capture instant. An update grant cannot alias a present
older extension's grant. It enforces 64 retained rows, 24 KiB of Go-compatible
HTML-escaped JSON, canonical nonzero lowercase GUIDs, nonnegative 31-bit revisions,
sorted unique identity/revision pairs, canonical sorted unique KB identifiers,
eight KB values per row, 256 UTF-8 title bytes and the fixed severity/reason sets.
Control, formatting, malformed Unicode and noncanonical title whitespace are
rejected. Plain markup-shaped titles remain inert React text, with no links.

Quality and count validation follows the source contract. An exact observed
count may exceed retained rows. Partial results retain exact or lower-bound count
semantics, including zero. Denied/unavailable results require a fixed reason and
no rows or successful count. Byte fitting does not turn omitted rows into a
complete result. An explicit null, extra field, wrong binding or malformed sibling
invalidates the response and clears the previous private display.

Capture age must be below 24 hours. The existing base/receipt ordering and
30-second clock-skew allowance are preserved: future captures within that bound
remain valid inventory envelopes, but only the Updates rows are withheld until
the capture time is reached. This visibility wait starts at response acceptance,
so request latency cannot reveal future rows early. A nonfinite or untrusted
acceptance-anchor elapsed value also withholds update rows, even if the earlier
request-start anchor remains within its clock tolerance. The earlier request-start
anchor still controls conservative expiry. The panel identifies the clock skew.
More than 30 seconds of skew is rejected. Neither manager receipts, refreshes nor
retries renew the original capture time.

## Display and privacy

The English and German views explain:

- Source is `wua-cache`; cache freshness is always unknown.
- A recent inspection can inspect an old cache. It is not a current patch
  assessment. Empty cached results never establish a fully patched device.
- The cached search covers caller-visible non-hidden, not-installed software
  updates. It excludes installed, hidden and driver updates.
- Observed counts are before row validation/retention; truncated, partial,
  access-denied and unavailable outcomes remain distinct.
- A vendor severity label is not a CVE match or exploitability assessment.
  Downloaded means WUA reported content already cached, not that this UI requested
  a download or observed installation.
- Titles or KB metadata may be shortened. The retained rows are not necessarily
  the highest-severity updates in the native result.
- Refresh reads the latest accepted manager report only. No host scan, cache
  refresh, EULA acceptance, download, installation, reboot, service change or AI
  export is available in this panel.

Search and sorting operate only over the already accepted bounded rows. Pages
contain at most 25 rows; result counts distinguish matching/retained rows from
the source collection count. Unspecified severity sorts last in either direction.
Stable GUID/revision tie-breaking never mutates the source array. All mobile cells
have localized labels and use the existing stacked inventory-table layout.

The panel shares the established authenticated inventory resource, request byte
limit, timeout, monotonic/server-time replay checks, two-minute stale state and
24-hour privacy envelope. Refresh hides rows while checking. Device/session
replacement, auth/protected-epoch loss, disabled scope, request error, hidden page,
blur, pagehide, route change and unmount discard visible private rows. Late or
aborted responses cannot restore them. Filters survive only a same-generation
in-flight reread; absence, errors, expiry, changed identity/grant/capture and
leaving the Updates tab reset them. There is no browser storage or independent
cross-generation update cache.

## Verification

Focused checks:

```sh
cd web
npm run typecheck
npm test -- src/windows-updates-types.test.ts src/windows-updates.test.tsx
npm run build
cd ..
node --test tests/e2e-review/windows-updates-fixtures.test.mjs
```

Seven generated Go source-contract vectors also pass through the TypeScript
validator. Regenerate with the repository-pinned Go toolchain using
`go run web/scripts/windows-updates-fixtures.go` and atomically replace
`web/src/windows-updates-go-fixture.json` with its output. The generator calls only
`windowsupdates.Encode` on invented metadata.

Tests cover old-view and all optional-sibling combinations, grant/capture binding,
malformed schemas and metadata, canonical bounds, quality/count variants,
nanosecond/30-second/24-hour boundaries, literal HTML, EN/DE data labels, keyboard
navigation, bounded search/sort/paging, filter reset, manager-only refresh,
Windows/Linux route separation, stale/expired data, interrupted refresh/session,
late response, timeout, clock regression/replay, visibility and error clearing.

`tests/e2e-review/windows-updates-browser.mjs` supplies an invented fixture and
assertion helper wired into the existing authenticated Windows inventory browser
case, after Logs and before the legacy fixture. The same EN/DE × desktop/mobile
loop, GET-only route, fixed original capture, 26 case count, session timeout and
virtual clock budget are preserved. Its source fixtures run through the existing
Windows inventory fixture gate. These source checks are not a hosted-browser
result; actual harness execution and pixel review must be reported separately.

No native WUA inspection, real endpoint collection, persistent host grant,
installed-service change or external AI request is performed by these checks.


## Explicit cached fleet triage

The collapsed Windows update worklist can freeze at most 50 Windows devices,
then explicitly **Read cached updates**. One GET-only batch reads the existing
private inventory endpoint, four devices at a time, with the same 160 KiB reader
and full inventory validator. Each request is limited to ten seconds and the
whole batch to one minute. It neither triggers a host scan nor requests readiness.
Only each device's update rows and original grant, generation and capture evidence
remain in temporary memory; unrelated inventory sections are discarded.

The compact EN/DE list groups only exact GUID/revision pairs. Title, KB and vendor
severity remain metadata; equal titles or KBs never merge different revisions.
Each group shows reporting and downloaded counts. Device-specific metadata and
source evidence remain collapsed. Partial/truncated, stale and unavailable reports
are counted separately; a stale report can also be partial. An empty result never
proves compliance, and downloaded content does not establish install readiness.
Search operates on retained rows, with ten exact pairs per page.

Choosing a pair narrows only the frozen local device list. Opening a reporting
device performs its own fresh inventory read and fixes that same GUID/revision in
the existing job session. Missing or changed exact rows cannot substitute a new
revision, including during session/CSRF checks. Every device still requires its
own readiness click and initially unchecked approval. Shared UTC windows, original
signed readiness, grant/leaf deadlines, exact saved receipts and GET-only uncertain
write reconciliation remain unchanged. Changing the local filter grants nothing
and cannot replace an unresolved job or reuse another device's approval.

Read results clear on cancellation, close, blur, hidden-page/navigation, session
loss or unmount, and after five minutes at most. Original two-minute stale and
24-hour source limits remain conservative; rereading cannot renew a capture or a
slow/replayed manager clock. Future captures wait from response acceptance. Late
or aborted reads cannot restore private rows. There is no browser persistence,
background fleet polling, bulk approval, backend or consent change.

Source checks cover exact-pair grouping, bounded/canceled reads, separate evidence
states and two independent approvals. The existing canonical fleet scheduling
capture manifest adds one triage scene in EN/DE at desktop/mobile sizes. Inert
fixture tests and a UI build are not hosted-browser/pixel or native acceptance.
