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

This adds thirteen scenarios against the real `NewLANOperatorHandler` with explicit `InsecureHTTPTest:true`, bound only to 127.0.0.1 (port 19886, overridable with `LAN_REVIEW_PORT`). The test fixture uses a known synthetic password, an in-memory ephemeral CA and the safe awaiting-agent contract from `docs/lan-api-examples.json`. It starts fresh disposable state for each scenario and tests real login, cookie/CSRF boundaries, logout and actual short expiry. Malformed bootstrap, protected 401 and interrupted logout are explicitly injected fault paths. Nothing calls a real model or enrolls a device.

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
`lan-browser.mjs` runner, for thirteen total LAN cases. All previous case names,
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
