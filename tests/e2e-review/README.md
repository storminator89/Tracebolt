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

### Keyboard access in the responsive shell

The existing concise synthetic gallery cases also check keyboard focus outlines
on the OS, status and sort selects, plus the localized Save view/Saved accessible
name while the mobile caption is hidden. They reuse the built-in synthetic-only
overview projection and existing viewport screenshot/source-SHA manifest.

The mobile cases check that a closed drawer cannot take focus, trap forward and
reverse Tab when open, and cover Escape, explicit close, backdrop, navigation and
Help dismissal. Resizing across 760/761 CSS pixels must clear the mobile overlay,
keep desktop navigation usable and retain the shell DOM. These are responsive
browser checks, not real zoom or assistive-technology certification.

The focused real-App jsdom suite is `web/src/mobile-navigation.test.tsx`.
It checks drawer semantics, focus ownership and return, device-route Escape,
breakpoint changes, retained children and localized button names without API
mutations. jsdom does not implement native inert Tab traversal or rendered CSS
outlines; the hosted gallery checks those. Source/type/syntax checks produce no
screenshots. Hosted execution and independent pixel review remain required
before claiming visual acceptance. No auth, consent, evidence or action scope
changes are part of these navigation checks.

## Authenticated HTTP-test browser acceptance

Run after the normal and managed targets:

```sh
node tests/e2e-review/lan-browser.mjs
```

The LAN runner contains 25 scenarios against the real `NewLANOperatorHandler` with explicit `InsecureHTTPTest:true`, bound only to 127.0.0.1 (port 19886, overridable with `LAN_REVIEW_PORT`). The test fixture uses a known synthetic password, an in-memory ephemeral CA and the safe awaiting-agent contract from `docs/lan-api-examples.json`. It starts fresh disposable state for each scenario and tests real login, cookie/CSRF boundaries, logout and actual short expiry. Malformed bootstrap, protected 401 and interrupted logout are explicitly injected fault paths. Nothing calls a real model or enrolls a device.

The existing authenticated awaiting-agent case also exercises Overview, Devices
and Investigations through the actual sidebar, rapid repeated route changes and
browser Back/Forward. `workspace-navigation-browser.mjs` checks document and
shell/sidebar/topbar/main DOM identity, including transient removals and a return
to global initial loading, while preserving the device filter. It permits no
document request, repeated overview read or session bootstrap during these
transitions. Only request/body-presence counters and DOM lifecycle booleans are
inspected; this probe captures no response data, headers, storage or screenshots.
It uses the existing browser, fixture, 25 case names and session/assertion deadlines.
Its pure metadata/observer contracts run through the existing investigations
fixture test entry point; those checks do not establish a hosted browser pass.

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
continuation case, within the current 26-case LAN runner. Earlier case bodies
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
26 cases total. Earlier cases, fixture session lifetimes, assertion deadlines,
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

The additive retained-journal browsing case uses production DTO guards and real
loopback login/CSRF with invented content. It covers direct scoped service reads,
source-wide literal search with empty nonexhausted pages, exact cursor continuation,
content replacement, expiry, no export and desktop/mobile layout. It never reads a
host journal or grants access. Native systemd acceptance remains separate.

## Windows Health evidence layers

The existing Windows inventory case also admits the production synthetic adapter
fixture into Network with its independent grant and exact base capture/generation.
Its compact table checks native-state labels, separate TX/RX values, unknown versus
unavailable speeds, initially collapsed DNS/gateway details, one expanded row and
panel-bounded desktop/mobile layout. Endpoint assertions remain scoped to their
own section through empty, denied, partial, stale and expired phases.

Four `synthetic-windows-adapter-context-{1440,390}-{en,de}.png` viewport captures
are required by the same runner before PASS, with source SHA, case, locale,
viewport and fixture-disclosure metadata. The existing Node inventory fixture gate
checks capture/grant admission and omission/metadata negative controls. No case,
session lifetime, clock advance, route permission or native read is added. These
inert checks do not create screenshots; a hosted run and independent pixel review
remain required for visual acceptance.

The Health source-presence case was removed: it passed when the helper returned
without doing anything and failed on a harmless local helper rename. The existing
executable clock, route, validator and selector tests retain their separate
behavioral coverage, alongside the completion checks below.
Literal API spellings were brittle hints, not execution or permission proof.
The actual route/request guards and finite diagnostics remain unchanged.

Before the live LAN runner marks the Windows case as passed, it now requires
all eight existing Health screenshot records: positive and missing-authority
states in English/German at desktop/mobile sizes. Each record must match the
current source, case, locale, viewport and viewport-only safety metadata. The
runner records these outputs only after the actual screenshot call succeeds;
an early return that skips the Health helper therefore cannot produce a passing
Windows case. No new screenshot, browser action or deadline is added.

Pure omission, duplicate and metadata negative controls check that completion
contract without a browser. Completion metadata alone does not prove pixel
content, native collection or host acceptance. The helper's strict DOM assertions,
the hosted run and independent pixel review remain the visual evidence.

## Fleet identity browser coverage

`node tests/e2e-review/fleet-identity-browser.mjs` retains five Linux real-store
cases and adds one Windows UI interoperability case. Windows uses exported
production-handler vectors at an authenticated GET transport seam, with invented
Windows overview rows; it does not establish live Windows store or native-host
acceptance. Synthetic device bindings and advancing response time are adapted,
while original capture, receipt and expiry times remain unchanged. Real operator
login, CSRF logout, unauthorized responses and existing request deadlines remain
in effect.

The Windows case checks compact hostname/IPv4 display, disclosed IPv6/interface
scope, local hostname/dual-stack search, OS filtering, unavailable hostname with
partial addresses, suspension clearing, exported expiry and real session loss.
Four viewport screenshots cover English/German at 1440×1000 and 390×844. The
existing fleet report/manifest pins source SHA, disclosure and PNG SHA-256; CI
requires all six cases and all four Windows images. Browser execution and pixel
inspection must occur on ordinary hosted browser CI before claiming acceptance.
`node --test tests/e2e-review/windows-fleet-fixtures.test.mjs` checks the seam and
wiring without a browser, network listener or native collection.

### Windows patch context in Updates

The same synthetic Windows inventory browser case includes a separately granted
`patchContext` sibling beside cached Updates. It uses the production validator and
UI with invented edition/release/build, independent reboot-source states and
bounded retained WUA history. History is neither current installed inventory nor
patch coverage. The helper performs no native read, grant or update action.

Completion requires eight viewport captures: compact
`synthetic-windows-patch-context-{1440,390}-{en,de}.png` and expanded
`synthetic-windows-patch-history-{1440,390}-{en,de}.png`. Source SHA, test, locale,
viewport and fixture disclosure must agree with the runner manifest. These are
real browser pixels of synthetic data, never native Windows acceptance.

`windows-patch-context-fixtures.test.mjs` is imported by the existing Windows
fixture gate and checks binding, absent/empty/partial/failure/expiry states and
screenshot-completion requirements without launching a browser.

### Windows previous session capture

The existing `sessions` stage keeps its eight English/German summary and source
detail captures at 1440×1000 and 390×844. The additive `sessions-retained` stage
uses the same intercepted inventory response and existing refresh button. It
shows a current unavailable/budget result alongside an independently dated,
one-hour-older useful session/join snapshot under the exact same grant and a
different generation. Only invented personal labels appear. Server-time advances
never change either capture time; the older snapshot expires independently.

The previous capture must start collapsed, expand with its original date and
an explicit warning that it does not establish current state, and collapse
again after tab navigation. The current unavailable result remains on the page.
Eight additional viewport-only captures are required before the same Windows
case can pass: `synthetic-windows-sessions-current-failure-{1440,390}-{en,de}.png`
and `synthetic-windows-sessions-retained-details-{1440,390}-{en,de}.png`.
Normal scrolling centers each compact region away from the app/test banner.
The first capture requires the current date and unavailable result in its
viewport while the previous capture is collapsed. The second requires the
older date and caution after expansion. The exact budget failure and both
original dates are asserted; both complete sections need not fit simultaneously.
The existing `sessions-completion` check now requires
all sixteen session records with exact source SHA, case, locale, dimensions,
viewport-only/public-safe flags and fixture disclosure. Inert omission,
duplicate and metadata controls reject the former eight- and twelve-record results.

Run `node --test tests/e2e-review/windows-session-context-fixtures.test.mjs
tests/e2e-review/windows-health-fixtures.test.mjs` for the focused inert checks.
These checks do not produce screenshots. Hosted browser execution and independent
pixel review remain unverified until performed; no new browser harness, endpoint,
clock advance, native read, installation, grant, account or permission change is
part of this source-only scenario.


## Shared Windows Update fleet window

The existing `windows-service-actions-runner.mjs` also requires three cached-triage/common-window
scenes from `windows-update-schedule-browser.mjs`, each in English/German at
1440×1000 and 390×844. The first reads existing cached inventory explicitly,
keeps matching KB/title metadata in two distinct GUID/revision pairs, then
filters the frozen list to reporting devices without readiness or approval.
Opening one device rereads inventory and keeps that exact pair fixed. The second
shows the frozen exact UTC window in an initially unchecked per-device
prospective review. After explicitly showing all frozen devices, the third shows a scheduled
first device and a separately saved revoked/blocked second device. Opening the
second device is deliberate and GET-only; selecting the window and approving
the first device cannot advance it. Reopening the first device reads its exact
saved job, with no replay.

The twelve `synthetic-windows-fleet-update-schedule-*.png` captures use the same
viewport-only screenshot helper and exact source-SHA manifest. They are required
in addition to all existing foreground/background scheduling and service-action
checks, under the unchanged 120-second runner budget. Existing CI artifact paths
already include them; there is no new workflow or browser-launch route. The
shared scene manifest drives the runner allowlist and exact evidence checker;
the behavioral checker additionally requires GET-only triage, exact pair
selection, fresh selected-device inventory and unchanged per-device approval. All new
scene requests are intercepted. The single synthetic scheduling POST changes
only the in-memory fixture; no real API mutation, grant, native installation or
release is established. Inert source checks do not produce screenshots or prove
browser layout; successful hosted captures still require pixel review.

## Completed reusable Windows update review

The existing Windows service-actions runner also captures one compact completed-job
review in English and German at 1440×1000 and 390×844 (four images). It uses the
compiled UI with entirely intercepted synthetic metadata and checks unchecked
exact acknowledgement, duplicate-click suppression, one retirement POST, GET-only
reload, original success/restart evidence and no automatic next job.

`windows-update-retirement-browser.mjs` owns the scene/viewport contract and the
`--check-evidence <source-sha>` validator used by both PR checks and full Validate.
The validator requires the four source-bound image files and all reconciliation
assertions. Source-only fixture tests do not establish a hosted-browser pass,
durable manager behavior, endpoint owner release or native WUA acceptance.


## Complete-generation service checks v2

The existing hosted Windows service-actions runner also invokes
`web/scripts/capture-windows-complete-service-health.mjs` on its installed browser.
Its canonical scene manifest supplies the single-device beyond-preview selection
and exact group review in EN/DE at 1440×1100 and 390×844. The eight existing
`complete-service-*.png` filenames and component interactions are preserved.
These are real compiled components and hooks with invented intercepted data,
not whole-App mounting, native Windows acceptance, policy writes or deployment.

Both focused PR checks and full Validate require the canonical scene/source digest,
exact ordered image matrix, file hashes and viewport dimensions, zero unexpected
or external requests, and successful existing runner cleanup and failure gates.
The source SHA must match hosted HEAD; compiled source bytes must match tracked
blobs in that commit. All previous action/update scenes and the 120-second budget
remain. The artifact upload includes the separate complete-service manifest and
images. The inert `--check` and Node contract tests generate no browser evidence;
successful hosted captures still require independent pixel review.

## Paused presentation clocks and cold detail routes

The service-action display, package-update display, and Investigations' Health
reloads retain their paused fixture clocks. After a cold document loads React
under that clock, its resolved Suspense retry can wait for a 300 ms commit timer.
`paused-detail-route.mjs` first observes the loading fallback or the real ready
locator, advances once by exactly 300 ms only when the fallback is visible, then
requires the original ready state. It does not resume the clock, drain timers,
retry simulated time, rewrite fixture timestamps, or extend assertion deadlines.

This adds at most 300 ms to each service/package case and 2,100 ms across the
seven Health reloads. The existing three 32 ms disclosure ticks remain, giving
at most 2,196 ms total controlled Health progress. Source tests use production
React, the actual route boundary and pinned Playwright clock in inert jsdom,
including command replay across all seven documents and unchanged deadline
rejection. These are a reproduced scheduling mechanism and a bounded harness
correction; only the normal hosted LAN run can establish browser acceptance.
The three cases' diagnostics expose reviewed finite stage codes only.

The same test-only readiness gate covers the paused Windows managed-MSI and
mutation-coexistence direct documents/reloads, Storage IO's initial detail and
warm list/detail mounts, and the service-actions runner's service, history,
update, download, retirement, standalone/background schedule and prepared-MSI
detail recipes. The eager fleet-schedule list and standalone complete-service
health capture are excluded. No fixture, consent, request, privacy guard or
acceptance assertion is changed. Each genuine cold detail document consumes at
most 300 ms. Managed-MSI, coexistence, service, update, download, retirement,
prepared MSI and each schedule profile therefore add at most 600 ms per isolated
context; history adds at most 300 ms. Contexts do not share clock budgets.

Storage IO advances only 300 ms for its first cold detail. Its four same-document
list/detail mounts are warm and consume zero, leaving 200 ms before the existing
retained sample's original initial+500 ms deadline. Its unchanged 1,000 ms expiry
step crosses that deadline (1,300 ms total controlled progress). Capture and
retained timestamps are unchanged. The previous immediate away/back mount could
bypass the initial fallback, so no prior Storage IO browser failure is claimed.

Run `node --test tests/e2e-review/paused-windows-routes.test.mjs` for the inert
full-App reproduction and actual driver-prefix regression. It bundles production
App/auth/details/React, holds only the emitted lazy import until the real route
fallback commits, and injects the actual pinned Playwright clock before React
loads into each fresh jsdom document. It checks the 299/300 ms boundary, both
locales, real direct/reload readiness prefixes, zero-progress warm mounts and
the unchanged Storage IO expiry transition. It does not run the drivers' later
interactions, produce screenshots or establish hosted browser acceptance.
The selected Windows failure diagnostics expose only finite source-defined
case/stage coordinates; service-action diagnostics retain their exact
source/invocation/locale/viewport binding and shared stage contract.

Storage IO's retained age assertion derives the exact displayed seconds from the
original retained sample end and the paused clock. Initial readiness accepts only
zero or 300 ms; each warm mount and retained-age checkpoint must remain at that
same time. This keeps the exact EN/DE assertion valid across the second boundary
(3,608 to 3,609 seconds) without permitting extra advancement. The original
sample timestamp, 24-hour retention deadline, initial+500 ms near-expiry sample
and subsequent 1,000 ms expiry check remain unchanged. A finite `retained-age`
diagnostic isolates this assertion without exposing sample or runtime values.

### S03/S04 focus and error color evidence

The existing shell/conditional/v3 runners also exercise the narrow shared
contrast corrections. See [the scope, arithmetic, and capture recipe](../../docs/focus-contrast.md).
The `synthetic-focus-contrast-*` images use real controls in existing invented
fixtures, EN/DE, 1440×1000/390×844 and both themes. Their existing screenshot
manifest entries include computed `contrast` measurements alongside revision
and fixture provenance. The helper never launches a browser on import or grants
any endpoint authority. Source arithmetic is not pixel/browser acceptance; review
the exact hosted images before closing the visual gate.

Package table/mapping captures additionally enter through real preceding
controls with forward Tab, reject bounded top/side clipping and LAN-header
occlusion, and record geometry/hit-test evidence. Only tall table bottoms may
remain cropped. See the linked correction notes for the exact exposure contract
and remaining marker/pixel review; no local browser result is implied.
