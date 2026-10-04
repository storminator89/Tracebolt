# Complete process and mount browser acceptance

This additive target uses the built React app and real operator HTTP-test
handler on loopback. Processes, mount paths and dpkg records are entirely
invented. The fixture creates ordinary disposable activated v3 identities, then
uses typed generation build, begin, append and finalize operations. It does not
read processes, mounts or packages from the host, invoke a collector, grant local
consent, install anything or test native ingress.

## Run

After building `web/dist` with the pinned frontend dependencies:

```sh
TRACEBOLT_SOURCE_SHA=<exact-github-sha> node tests/e2e-review/complete-overview-browser.mjs
```

Use `--api-smoke` for source preparation without launching a browser. That mode
checks real auth/CSRF, generated metadata, paging/search, independent section
retention, package counts and production frontend DTO decoders. Its result is
not browser acceptance.

The runner builds only `tests/e2e-review/overviewfixture`, using Go from PATH or
`GO_BIN`. Playwright uses installed Chromium unless `CHROMIUM_PATH` selects a
supported browser. `OVERVIEW_REVIEW_PORT` defaults to 19898 and binds loopback.
No TLS warning bypass is used. Actual browser execution belongs to hosted CI.

## Required six cases

1. Primary Processes uses complete generations: 205 rows across 100/100/5 pages,
   observed zero values, explicit denied/exited/unavailable field outcomes,
   cumulative CPU time, literal case-insensitive search and unchanged binding,
   capture time, retention and cursor deadline.
2. Mounts uses 125 rows across 100/25 pages. Per-page capacity groups distinguish
   measured zero, denied local, memory, remote-skipped and virtual N/A values.
   German mobile keeps document bounds and keyboard-scrollable table overflow.
3. Failed process attempts retain the old process generation while a new mount
   generation is current, and vice versa. Each retains its original age and
   expiry; mixed captures remain explicit.
4. Successful zero enumeration differs from missing data. An expired cursor
   clears old rows until an explicit refresh. Original mount retention expires
   while a later process generation remains available.
5. Injected hidden visibility clears rows until fresh real metadata arrives.
   Device navigation cancels or discards a held old page. Actual Sign out clears
   private content before the real logout response; the original cookie fails
   protected reads and reload remains signed out.
6. Software totals come from the complete dpkg metadata ledger: 205 rows,
   200 installed and 5 incomplete. Metadata display issues no package page read.
   Open Packages selects the full view; the secondary bounded preview retains
   explicit sample limitations and cannot supply the complete total.

The service clock is fixture-controlled and forward-only through private stdin.
Operator time remains real with the supported one-hour fixture session. Clock
advancement demonstrates original expiry rules, not actual elapsed wall time,
OS lifecycle, native capture or browser BFCache acceptance.

## Existing gate preservation

The d362 journal, LAN and endpoint runner fixes are retained exactly. The 104
existing required case identities, three named enrollment skips and five review
lifecycle cycles remain. The v3 runner adapts Inventory's default Processes tab
and explicitly selects the legacy preview where that is the subject. The
conditional runner similarly selects Bounded preview; its old package-observation
counters match the exact `/api/devices/{id}/packages` endpoint so that separate
complete-software metadata reads are not mistaken for old source-package reads.
Its v3 lazy-source check permits the intentional software metadata read while
continuing to forbid package-page and system reads until selection. Quarantine
bodies, lifecycle-cycle bodies and other assertions remain intact.

## Bounded evidence

Require six uniquely named PASS cases, no failures, `summary.setupFailure=false`,
`runtimeErrorCount=0`, and exact `sourceSha` equal to the tested GitHub commit.
Only these target artifacts under `artifacts/review/` may be uploaded:

- `complete-overview-browser-results.json`
- `complete-overview-browser-manifest.json`
- `synthetic-complete-overview-processes-en.png`
- `synthetic-complete-overview-mounts-de.png`

The two images contain only invented rows, use viewport framing and include
source identity, original image hashes, locale and fixture disclosure in the
manifest. Pixel acceptance is separate from script preparation.

Reports retain only fixed test names/phases, duration, source and scoped
provenance. Raw exceptions, responses, process/mount data, cookies, passwords and
private state paths are withheld. Partial completed results are preserved and
failures exit nonzero. Report and manifest must have all these flags false:
`secretsExported`, `realTelemetryExported`, `hostInventoryRead`,
`collectorExecuted`, `permissionChanges`, `installerExecuted`, `userVmAccessed`.
The local `complete-overview-api-smoke.json`, temporary fixture state, binaries,
control output and logs are excluded from upload.
