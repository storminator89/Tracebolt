# Independent UI acceptance

Prerequisites: build the React app with `cd web && npm ci && npm run build`, install Go on `PATH` (or set `GO_BIN` to its executable), and install the project-pinned Playwright Chromium (`cd web && npx playwright install chromium`). Alternatively set `CHROMIUM_PATH` to a compatible local Chromium or headless-shell executable.

Run from the repository root:

```sh
node tests/e2e-review/run.mjs
```

The runner:

- Compiles the current Go manager into a unique temporary directory.
- Starts it on loopback port 19879 (`REVIEW_PORT` overrides it) with a unique SQLite database.
- Runs the project-pinned Chromium headless shell (or the explicitly selected executable) through the project's Playwright dependency.
- Uses real HTTP and SQLite for normal workflows and explicit interception only for failure, loading, and interrupted-response tests.
- Writes reproducible screenshots and JSON results to `artifacts/review`.
- Terminates the manager and removes the disposable database even if a test fails.
- Never uses the default `.local/state.db`, connects enrolled customer devices, shares telemetry externally, publishes, or executes suggested runbooks.

Only screenshots prefixed `synthetic-` are eligible for a public gallery after independent pixel review: they show Windows demo inventory, a demo device, or a demo case. The other review screenshots can include real sandbox metrics and must remain local.

Desktop viewport: 1440×1000. Mobile emulation: 390×844. This is responsive Chromium testing, not real mobile-device, Windows, or macOS native-agent validation.

The notes mutation test intentionally stores a harmless markup-shaped text payload in the disposable database to verify that it is rendered literally rather than interpreted as HTML. No external URL is involved.

Results are focused product and regression checks, not an independent security certification or an exhaustive accessibility audit.

## Optional AI integration checks

For a source checkpoint containing the AI API and UI, run:

```sh
TRACEBOLT_REVIEW_AI=1 node tests/e2e-review/run.mjs
```

This adds eight scenarios against a deterministic in-process loopback fixture provider. It performs no real model inference and never sends sandbox telemetry. The fixture key is an obvious synthetic test string, not a credential. Reports record whether these checks were enabled; AI screenshots include `ai-fixture` in the filename and show the fixture model label. They must never be presented as evidence of real-model accuracy.

## Managed-preview transport UI

Run `node tests/e2e-review/managed-preview.mjs` in a separate job after building the frontend and installing the pinned Playwright browser. It builds the real manager and one-shot Linux dev-agent, observes awaiting→accepted→stale with actual two-minute expiry, compares rendered values and provenance with the actual manager, and verifies seven demos remain separate.

Only `artifacts/review/managed-preview-result.json` is suitable for upload. It contains bounded pass/fail metadata, no metric values, receipts, logs, database or screenshots. The runner deliberately captures no screenshots. This is a loopback development preview, not production enrollment or sender authentication.

## English, German and bounded viewport shell

The coherent LAN/i18n source runs 32 baseline/shell scenarios, or 40 with the eight AI scenarios enabled. Existing regression paths explicitly select German. Primary synthetic inventory, device and case gallery scenes start with a clean English default. Six additional checks cover English→German state continuity, long case/settings content, independent main scrolling, reachable navigation at 1024×420, keyboard use at a 720×500 CSS viewport (200% equivalent space), and mobile overlay dismissal. The reduced CSS viewport is not a claim of native browser/OS zoom certification.

All new screenshots are `fullPage:false`, exactly the configured viewport. The manifest records language, selected content section and `main-content.scrollTop`. Detailed AI captures scroll the actual content pane; they do not extend the document beyond the sidebar. Do not reuse old full-document gallery images as evidence of this shell.

## Authenticated HTTP-test browser acceptance

Run after the normal and managed targets:

```sh
node tests/e2e-review/lan-browser.mjs
```

The LAN runner contains 25 scenarios against the real `NewLANOperatorHandler` with explicit `InsecureHTTPTest:true`, bound only to 127.0.0.1 (port 19886, overridable with `LAN_REVIEW_PORT`). The test fixture uses a known synthetic password, an in-memory ephemeral CA and the safe awaiting-agent contract from `docs/lan-api-examples.json`. It starts fresh disposable state for each scenario and tests real login, cookie/CSRF boundaries, logout and actual short expiry. Malformed bootstrap, protected 401 and interrupted logout are explicitly injected fault paths. Nothing calls a real model or enrolls a device.

Upload only `lan-browser-results.json`, `lan-browser-manifest.json` and `synthetic-http-test-*.png` from `artifacts/review`. These contain bounded outcomes and labelled synthetic UI fixtures, no raw cookies, passwords, private keys or real telemetry. Login screenshots are captured before password entry. The target does not run the production LAN CLI or validate real trusted TLS browser deployment. It never uses `ignoreHTTPSErrors`, certificate-error launch flags, a certificate-warning bypass, a public listener or a tunnel.

The application-status case in `application-checks-browser.mjs` runs through this
same runner, real fixture login and same-origin UI. Only the application status
responses are explicitly intercepted with invented DTOs. Its four rows separate
HTTP 204 with an expiring verified leaf, HTTP 503 with a leaf expiring beyond
30 days, retained HTTP 204 whose previously verified leaf has since expired, and
failed TLS verification with unknown expiry. The expired row was observed before
its leaf expired; it never represents a successful new handshake with an expired
certificate. The actual DTO validator and freshness projection also check these
fixtures in the existing independent source/DOM suite.

The case opens Observation scope, verifies its qualification, the original sample
time/age, and only one read control with no target/configuration inputs. Repeated
reads cannot renew that sample: 21 seconds of browser-clock advancement ages its
65-second-old observations past the four-row 85-second bound. A 503 clears all
rows, recovery retains the old age, and a 401 removes private content and stops
application reads. Request accounting permits only the real fixture login POST;
all application traffic must be body-free GETs to the status route. No application
write, run or configuration request is allowed. The case keeps the runner's
existing session lifetime, assertion timeouts, launch options and cleanup.

Desktop and mobile captures use the `synthetic-http-test-application-checks-`
prefix, viewport-only screenshots and the existing source-SHA manifest fields.
Their `fixtureDisclosure` explicitly identifies invented application-status
responses and excludes actual management-server target probes, a new TLS
handshake and native acceptance. These are UI fault-injection previews; they
require an actual successful hosted-browser run and pixel review before use as
visual evidence. Source/DOM checks alone do not generate or validate screenshots.

The same application-status case also checks actual row geometry at 390×844 and
1440×1000: every result, certificate value and original observation age must be
visible inside its viewport and the table must have no horizontal overflow. It
checks the mobile labels and explicit row/column header associations, plus
aligned desktop columns. Exact value assertions target the value span so hidden
mobile labels cannot contaminate desktop text comparisons.

Additional phases use invented v1 HTTPS/plaintext HTTP and v2 DNS/TCP/HTTPS DTOs,
validated by the production validator in the source suite and the real browser
UI. They have the same original 65-second sample age and a declared 75-second
interval, with the production row-count freshness bounds. DNS/TCP rows have no
HTTP or certificate fields; their certificate cell explicitly says that the
certificate is not part of this check on mobile. The observation disclosure
qualifies system name resolution and connect-and-close TCP without application
health or TLS claims. Each phase rechecks unchanged age on reload, stale
projection, 503 clearing/recovery and 401 removal/stopped reads. That application extension preserves its twelve case names/count, session
lifetime, assertion timeouts and launch options. The alarm-status case described
below adds one required case, bringing this runner to thirteen. No real application target or probe is introduced.

Additional desktop/mobile screenshot names include `v1-http-https` or
`v2-dns-tcp-https` under the existing synthetic prefix; a second v2 mobile capture
shows the HTTPS row below the DNS/TCP rows. Capture metadata labels these as
invented retained DTOs with no actual target probe or TLS handshake. These new
captures are produced only by the upcoming hosted browser run, not source tests.


## Read-only alarm status in Settings

`alarm-status-browser.mjs` adds exactly one required case through the existing
`lan-browser.mjs` runner. It is one of the current 25 LAN cases. Previous case names,
assertions, fixture session lifetimes, timeouts and browser launch options are
unchanged. The existing hosted browser step and artifact upload already include
this runner and its new `synthetic-http-test-alarm-status-*.png` captures; no
alternate launcher or browser route is introduced.

Real fixture authentication and all other handlers remain intact. Only the exact
existing `GET /api/alerts/status` is intercepted with invented aggregates,
validated against `web/src/alarm-status-types.ts` using the pinned Node 24 runtime.
It checks quiet Off, retained On and disabled historical counts, Pending as queued
plus in flight, separate Failed/Uncertain/Dropped meanings, and the qualification
that provider acceptance does not establish human receipt. The API supplies no
event or server timestamps: Loaded is explicitly the browser's clock. Failed,
malformed and timed-out refreshes keep the original Loaded value and retained
counts marked Previous snapshot with Unknown current state.

The case covers explicit refresh, duplicate clicks, no polling/retries, a held
late response after a newer refresh, navigation, visibility/page suspension,
real session revalidation, protected 401 clearing and fresh-login isolation.
Browser time is advanced within the existing session lifetime; authentication
routes, server clocks and session duration are not stubbed or extended. Request
accounting allows the fixture login POST only, requires all alarm requests to be
body-free status GETs, and forbids external requests and mutations.

English and German 390×844 layout checks measure panel and element clipping,
verify labelled Details with keyboard activation, and use the existing genuine
viewport capture helper. Desktop captures use 1440×1000. The disabled German
case includes the maximum safe dropped counter. Captures and their existing
source-SHA manifest are evidence only after a successful hosted run and pixel
review. Local source, syntax and DOM checks do not execute a browser or produce
screenshots. Nothing probes a target, sends a webhook or test alarm, changes
configuration, or establishes production/native delivery acceptance.


## Bounded CVE continuation

`cve-continuation-browser.mjs` supplies one of the current 25 required LAN
cases. Existing case bodies, fixture TTLs, assertion deadlines,
launch options and hosted workflow are unchanged. The case reads the exact
Go-generated `web/src/linux-cve-go-fixture-continuation.json` projection, validates
every DTO with the production validator and adapts the surrounding synthetic
device list/detail identity to the Go fixture's device ID. Real fixture login and
authentication endpoints remain intact. A request guard aborts unexpected
mutations and all external requests before forwarding them.

The case holds the second protected GET after 2,000 of 2,017 checks, verifies
retained warning cards and progress, then completes with exactly 2,017 warnings
and 100 bounded cards with an omission notice. Completion stops automatic reads;
an explicit refresh uses the unchanged cached projection with zero comparisons.
A fresh panel scope displays a blocked saved prefix and resumes on deliberate
refresh. Duplicate progress, changed assessment/generation/feed bindings and
stale inventory each stop the chain and clear old totals. Held responses released
after navigation or a protected metadata 401 cannot restore the old view; a
fresh login gets a new explicit panel read.

Two viewport-only captures use the existing source-SHA manifest:
`synthetic-http-test-cve-continuation-pending-desktop-en.png` (1440×1000) and
`synthetic-http-test-cve-continuation-complete-mobile-en.png` (390×844). Their
fixture disclosure identifies invented data, exact cumulative totals and capped
details. Geometry checks cover large counts, primary warning cards, versions and
expanded source/coverage text without horizontal overflow. Captures become
evidence only after the publisher's successful hosted run and pixel review.

Local source acceptance is `node --check tests/e2e-review/cve-continuation-browser.mjs`
and `node --test tests/e2e-review/cve-continuation-fixtures.test.mjs`. These pure
checks do not launch a browser/server or produce screenshots. No real inventory,
vendor fetch, feed import, command, host operation, held Setup/socket work or
native deployment acceptance is included.

## Bounded complete CVE detail pages

`cve-detail-pages-browser.mjs` adds one disjoint required case after the original
continuation case, within the current 25-case LAN runner. Earlier case bodies
and guards remain unchanged, as do their fixture TTLs, assertion deadlines,
launch options and hosted workflow. Pure fixture checks bind the current total.

The new case uses `linux-cve-go-fixture-details.json` and both production detail
DTO validators. It starts with a real fixture login and a completed 145-warning /
435-version summary. No detail POST occurs before explicit browsing; the first
cursor is zero even though the preview contains 100 rows. A short page sequence
covers Next, Previous and First. Eleven maximum-field pages reach checks 100–109,
which were absent from the cached preview, and Previous also reaches the omitted
middle checks 96–99. The selected version's eight binary pages render and compare
all 146 exact names/architectures, including those beyond 128, with the other
installed version excluded. Global counts stay unchanged. A held response after
the empty 0→4000 scan proves that the preview stays visible without a fabricated
empty final result; the 4000→4001 result completes without repeating the cursor.

Only the two exact same-origin read-query POST paths are allowed after explicit
UI actions, with exact binding, cursor, limit and body-key checks, a 64-query cap,
and the original real CSRF/session preflight. Other mutations and external
requests are aborted. Auth responses are forwarded unchanged. Synthetic evidence
timestamps are shifted together once per scope to the real fixture clock; page
server time follows the real preflight while inventory/feed evidence timestamps
stay fixed. All other Go-projected DTO fields, bindings and counts remain intact.
A changed page revision and an expired retained generation clear details. Held
pages cannot reappear after navigation or protected metadata access loss; fresh
login and explicit browsing start from zero without replay. This shared-login
browser case does not establish named-role server authorization.

The existing source-SHA manifest records two new viewport-only captures:
`synthetic-http-test-cve-detail-pages-desktop-en.png` (1440×1000) and
`synthetic-http-test-cve-detail-pages-mobile-de.png` (390×844). The German view
checks the actual Erste/Vorherige/Nächste controls. Both views check navigation,
256-character source names, 512-character versions and horizontal overflow.
Captures are evidence only after successful hosted execution and pixel review.

Local checks are `node --check tests/e2e-review/cve-detail-pages-browser.mjs`,
`node --check tests/e2e-review/lan-browser.mjs` and
`node --test tests/e2e-review/cve-detail-pages-fixtures.test.mjs tests/e2e-review/cve-continuation-fixtures.test.mjs`.
They use Node 24's built-in TypeScript stripping to load the production validator
with its sole extensionless import resolved to the existing TS source. These
syntax and pure fixture/guard checks never start a browser/server, create sockets
or produce screenshots. Hosted acceptance and pixel review remain publisher
owned. No real inventory, vendor fetch, feed import, command, host action or
native deployment acceptance is included.

## Selected package update workspace

`package-updates-browser.mjs` adds one case to the existing LAN runner, for
25 cases total. Earlier cases, fixture session lifetimes, assertion deadlines,
launch options and cleanup remain unchanged. The explicit Node fixture list in
`.github/workflows/validate.yml` includes its pure guard/DTO contract test.

The case starts with the default unavailable/not-configured result. Its later
selection, exact package/version/source review and unknown outcome use disclosed
simulation projections from `web/src/package-update-go-fixtures.json`, checked by
the production TypeScript validator. The candidate inventory row is derived from
those invented package identities and versions. A single timestamp offset,
request binding and HTTP-test transport adaptation are presentation-only; the
adapted projection is not a newly signed or Go-validated native plan. Cached
inventory is never shown as native preparation evidence. Any fixture-only authentication display proxy is
explicitly synthetic; it does not establish a real named-account permission or
native package authority.

Real fixture login and protected CSRF reads retain their existing boundary. All
package requests used for the presentation are intercepted and validated in
memory. Unexpected writes and external requests are blocked. No preparation,
installation, repository refresh, helper, service, key or local grant is invoked.
Original package consent and approval-expiry rules are not relaxed.

The case uses the existing source-bound screenshot manifest for English/German
and desktop/mobile viewport captures. Each capture discloses invented evidence
and simulation. Syntax, pure fixture and targeted UI tests do not produce these
screenshots: the hosted browser run and pixel review are still required before
visual acceptance. No local Chromium launch or alternative browser route is part
of this amendment.
