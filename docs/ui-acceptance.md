# Tracebolt UI acceptance

## Current review-read recovery checkpoint

Exact source **`2641448162d2d9d53fc17db6c4cb8865fcebc7cb`** passed the required browser targets in [CI run 37198507471](https://github.com/storminator89/Tracebolt/actions/runs/37198507471). Independent readback verified exact source identities, all 18 unique conditional case results, the five lifecycle attempts, report totals and runtime-error counts. This acceptance covers the described browser flows and original synthetic pixels; it does not declare every CI job, native/service behavior or every panel-recovery path complete.

| Target | Result |
| --- | --- |
| General UI, language, shell and controlled AI | 40 PASS |
| Actual Linux managed preview | 6 PASS |
| Operator HTTP-test UI | 10 PASS |
| Guided enrollment reduced gate | 10 PASS, 3 named SKIPPED; full enrollment acceptance remains false |
| Operational/package/catalog/conditional review | 18 PASS, including five consecutive persisted-page cycles |
| Browser runtime errors | 0 across all five targets |

### Confirmed failure and bounded recovery

The unchanged ed18 code later failed one persisted-page case on eff256b. Diagnostic source `85fd06b5db7258c70ace532ccd8d6c69a06f7556` established the actual failure: page restoration started auth, coverage and review reads together; auth and coverage returned 200, while review returned **429 / storage_busy**. The old rows were removed correctly and the private view became visible/non-inert. The missing final row resulted from review-read contention, not a privacy or visibility failure. The store's single-reader admission bound remains unchanged.

The corrected review resource repeats only its read-only GET once, after two seconds, for the exact 429 storage_busy code. It announces recovery in English/German, keeps rows cleared, and retains the original AbortController, protected-request epoch, monotonic/wall anchor and total ten-second deadline. Invalidation cancels the delay; a second busy response remains visible. It does not retry mutations, generic 429 errors, authorization failures or arbitrary network errors. Independent QA reran 46 targeted API/retry regressions successfully. The exact 64KiB boundary fixture was also made cheaper to construct; its 65,536-byte acceptance, 65,537-byte rejection and timeout were preserved, and the ten focused boundary tests passed independently.

On the accepted hosted source, lifecycle cycles **1 and 2** recorded actual review **429 storage_busy → 200** sequences. Cycles **3–5** returned review 200 directly. Every cycle ended with exactly one candidate row, no review alert, and a visible/non-inert private view. All original row-removal and fresh-read assertions remained; no case was skipped or weakened. The browser test injects page lifecycle events and does not certify real OS suspension or BFCache implementation behavior.

**Remaining coverage-panel recovery gap:** the same bounded trace records coverage HTTP 429 in cycles 3 and 5, without a subsequent coverage 200. The current coverage resource maps that failure to its load-error/manual-refresh state. The passing lifecycle assertions concern the review panel; they do not establish automatic recovery of every surrounding panel. No stale data or healthy-state fallback is introduced. Broader coverage recovery remains a separate usability issue.

### Pixel readback and evidence scope

All five fresh original conditional PNGs were individually hash-verified and inspected at original resolution (1440×1000 desktop, 390×844 mobile; fullPage:false). Navigation/drawer framing remains intact; fixture, unknown and unverified labels are legible, and no secret is visible. The catalog settings API-key field is empty. The English mobile table and candidate views are deliberately scrolled detail views. The German mobile detail still omits its heading above the viewport, so it remains test evidence rather than a new primary gallery image. This update does not replace the previously published ed18 gallery or its source attribution.

These captures contain entirely invented observations and catalogs on the loopback HTTP-test profile. The managed-operations-v2 fixture binding intentionally contains the unchanged operational-v1 component. A catalog declaring synthetic:false is still an invented, unverified interchange fixture, not a real vendor source or authoritative CVE finding. Direct store admission is not native collection or telemetry-transport acceptance.

Artifact ID: `11302236740`. Retrieved archive SHA-256: `1c11e90435301208214d2ee1ee042640a935d39c4a655468b80f4c5ff4025c2c`. Exact image hashes:

| Original PNG | SHA-256 |
| --- | --- |
| `synthetic-conditional-inventory-desktop-en.png` | `231c2146d6f2620f5e18e8112498a3793044764f35f039016de35d5f64a9fb79` |
| `synthetic-conditional-candidate-desktop-en.png` | `3a6706eb3132d69c8c0639d643a84494019be0f4829d11ef5d748ca7c4aab3b7` |
| `synthetic-conditional-catalog-desktop-en.png` | `531b03c983c70cc4c0c12aaba3b64d91886e2128cc66be2d3bf16e44f1eafc0a` |
| `synthetic-conditional-packages-mobile-en.png` | `b0c4128a85e652f131454ba3784534645c65dc0fb316e32dc33243aedae1cd01` |
| `synthetic-conditional-review-mobile-de.png` | `973ba0d08bd55756ad588a225d44bebd46ef1c7f105ccb71cb0ea6b7def57cf0` |

Repeat the conditional gate after building the UI and installing pinned Playwright Chromium:

```sh
TRACEBOLT_SOURCE_SHA=<exact-source-sha> TRACEBOLT_REVIEW_LIFECYCLE_REPEATS=5 node tests/e2e-review/conditional-browser.mjs
```

The baseline archive provenance remains separately labelled applicationBaselineArchiveSha256. Exact tested identity comes from TRACEBOLT_SOURCE_SHA/github.sha. Existing enrollment quarantines and all fixture/export limitations below remain applicable.

## Historical ed18 operational inventory checkpoint

Exact source **`ed18d9ab0dd88a14ea86eaec1548facd807ecc22`** passed the required browser targets in [CI run 37193131587](https://github.com/storminator89/Tracebolt/actions/runs/37193131587). Independent readback checked the source identity, unique case names, summaries and runtime-error counts in all five reports. This section records browser and pixel acceptance; other CI jobs and native/service acceptance have their own evidence.

| Target | Exact result | Scope |
| --- | --- | --- |
| General UI, language, shell and controlled AI | 40 PASS | Built React and real development API, with a disclosed test AI provider |
| Managed preview | 6 PASS | Separate Linux development sender, actual expiry; bounded report without telemetry screenshots |
| Operator HTTP-test UI | 10 PASS | Real loopback operator handler and explicit HTTP-test profile |
| Guided enrollment reduced gate | 10 PASS, 3 SKIPPED | The three named quarantines remain open; `fullEnrollmentAcceptance:false` |
| Operational/package/catalog/conditional review | 18 PASS | Real handlers and store, entirely invented observations and catalog files |
| Browser runtime errors | 0 across all five targets | No setup failures reported |

The 18 new cases cover explicit collection consent, lazy device-bound reads, partial/unknown/retained data, exact binary/source-version distinctions, conditional source-bound comparison, stale/revoked/retention boundaries, catalog import/clear and revision conflicts, uncertain committed responses without replay, wrong-device or inconsistent response rejection, protected 401 handling, injected page lifecycle changes, keyboard table scrolling, and English/German mobile viewport bounds. Direct synthetic store admission does not verify native collection or telemetry transport. Age transitions use an injected service clock while the auth clock stays real. Injected lifecycle events do not certify real BFCache or OS suspension.

The application baseline archive is separately identified as `applicationBaselineArchiveSha256` (`b3acbd80ba33e173f6425256c75ed1f372c9ea7ff2c9e516e5e937aaf5937d9b`). The exact composed and tested source is the commit above; the archive hash is not presented as that final tree.

### Catalog-browser correction and confirmation

The prior c943 run recorded 16/18 passing cases. Both catalog recovery scenarios looked for the replacement button after a refresh recreated its import disclosure closed. Source review and two isolated component checks established the closed/hidden/disabled state. The harness now opens that disclosure through its summary, then requires a visible disabled replacement action and empty file input. Real 409, lost committed-response, single-write, catalog-state and storage assertions remain. Application source was unchanged. The new exact-source hosted run passes all 18 cases; the original three enrollment quarantines were not changed.

### Fresh pixel selection

All five new original PNGs were inspected at their actual resolution after individual SHA-256/source checks: desktop 1440×1000 and mobile 390×844, all `fullPage:false`. Fixed navigation and drawer framing remain intact. Unknown states, source/version facts, unverified catalog provenance and the HTTP-test warning are legible. No secret is visible; the settings API-key input is empty.

Four images are selected for publication with exact hashes and required captions in [the gallery selection](screenshots/2026-10-04-linux-inventory/gallery-selection.json): operational inventory desktop, conditional-candidate desktop detail, offline-catalog desktop, and English mobile package-table detail. The German mobile image remains valid test evidence, but its candidate heading and first row label are above the scrolled viewport, so it is excluded from this first gallery selection. No image was edited.

Every caption must identify entirely invented QA data and the loopback HTTP-test profile. Catalog fixtures may declare `synthetic:false` solely to exercise the unverified interchange path; they are not real vendor advisories. Candidate rows do not establish an affected-CVE total, available update or verified installed-artifact finding. Mobile/detail captures show a bounded scrolled viewport rather than a full table or complete review summary.

Artifact ID: `11300151573`. Retrieved archive SHA-256: `ffdd1773e0067e4a5e920c8f8fa13da4bb18664c1ee037069f824029312f7838`. Browser checks do not imply trusted-TLS browser deployment, native Windows/macOS service acceptance, real customer-fleet operation or security certification.

The new target can be repeated after building `web/dist` and installing pinned Playwright Chromium:

```sh
TRACEBOLT_SOURCE_SHA=<exact-source-sha> node tests/e2e-review/conditional-browser.mjs
```

See `tests/e2e-review/CONDITIONAL.md` for fixture boundaries and the artifact allowlist, and `tests/e2e-review/ENROLLMENT.md` for the retained enrollment quarantines and restoration command.

## Historical scroll-shell checkpoint

The following records the earlier b4a6f40 checkpoint; its claims and image selection apply to that exact historical source.

## Accepted source and evidence

Source **`b4a6f40ce9193f9ee91290eb2c50eb07ab8819a9`** passed the complete browser acceptance checkpoint. [Exact CI run](https://github.com/storminator89/Tracebolt/actions/runs/37142090350). The independent reviewer read the structured results and matched their source hashes with both screenshot manifests.

| Target | Result | Verification scope |
| --- | --- | --- |
| General UI, language, scroll shell and AI | 40/40 passed | Real built React app and Go API; eight AI checks use a controlled loopback provider |
| Managed-preview transport | 6/6 passed | Actual separate Linux manager and one-shot sender, including real two-minute expiry |
| Authenticated HTTP-test UI | 10/10 passed | Real operator HTTP-test handler on loopback, with synthetic awaiting-agent data |
| Browser runtime errors | 0 across all three targets | Uncaught page errors fail the corresponding target |
| Supplemental DOM regressions | 9/9 passed | Focused source/DOM checks, separately from browser and pixel evidence |

The reviewer inspected the twelve selected gallery captures at their actual pixels. No visual blocker remains in this selection. Every image is an unedited **1440×1000 desktop or 390×844 mobile viewport**, with its exact source hash, language and selected content section retained in the manifest. The primary inventory, device and investigation images show the English default. German screenshots demonstrate the alternate language and controlled AI workflow. Original evidence prose is preserved in its source language.

## Scroll-shell repair

The preceding `cc724cfc753a25e3ea5ab8752552dfac7fbdb683` run passed 36/40 general cases but failed four new geometry checks. Long-case content caused outer document overflow and moved the window 55–60px; its AI screenshots visibly lost the topbar. A hidden, absolutely positioned case-note label lacked a containing block within the main pane.

The accepted source adds `position:relative` to the scrollable main pane. All four strict checks now pass without relaxed thresholds: the outer document stays within the viewport, window scroll remains zero, long content scrolls within the main pane, and navigation remains reachable. Coverage includes long case/settings views, a 1024×420 short window, mobile overlay dismissal, and keyboard navigation at a 720×500 CSS viewport. The latter represents the available CSS space of a 1440×1000 display at 200%; it is not native OS/browser zoom certification.

Fresh scrolled-case and AI-result pixels confirm that the full topbar and sidebar remain intact. The earlier mobile AI provider wrapping and full-document capture problems are also absent from the selected fresh viewport images.

## Functional and security-relevant coverage

- Inventory search, OS/status/source filters, sorting, saved views, empty states, CSV formula neutralization, safe unknown/malformed routes, and explicit error/loading states with no fake fallback.
- Device → evidence → investigation navigation, browser history, dialog keyboard containment and dismissal, skip-link focus, repeated actions, delayed-response navigation, literal rendering of markup-shaped text, notes/status persistence, and manager restart.
- Clean English default and an explicit German switch preserving the active route, filter, theme and unsaved note draft. Language preference persists across reload.
- AI destination/evidence review and explicit one-request consent; no provider call on configuration save or dismissal; one request under repeated submission; bounded packet exclusions; immutable citations; invalid-output rejection; cancellation; empty key input/storage checks; and configuration loss after restart. **Testanbieter / keine reale Modellanalyse** identifies every AI fixture capture. These checks establish integration behavior, not real-model diagnostic quality.
- Actual HTTP-test login rejection/success, one submission under repeated clicks, HttpOnly/SameSite session behavior, real CSRF logout, actual short expiry, fail-closed bootstrap and protected 401 handling, no interrupted-write replay, unconfirmed logout across reload, cross-tab logout and persistent transport warnings. Password fields are empty in the selected sign-in capture.
- Actual Linux development transport awaiting → accepted → stale, displayed values matched against the real API, preserved collection/receipt provenance, no manager fallback after the sender exits, seven separate demo devices and unknown whole-device health. Its report exports no telemetry or screenshots.

Fault injection is explicit: unavailable or malformed responses, delayed responses, protected 401 and interrupted logout. These tests exercise selected recovery paths rather than every deployment failure.

## Publication selection

The twelve exact approved filenames and captions are recorded in the companion `screenshots/2026-10-03-lan-ui/manifest.json` selection, along with individual image SHA-256 hashes. Use only those unedited source captures for this gallery checkpoint.

The HTTP-test images use the safe synthetic awaiting-agent contract and a disposable known test password. They must be captioned as loopback HTTP-test fixtures, not an actual enrolled endpoint, production LAN rollout or trusted TLS browser session. AI images require the explicit test-provider/no-real-analysis caption. No raw database, manager log, cookie, private key, real sample screenshot or raw telemetry is suitable for publication.

## Reproduction and limits

Build `web/dist`, install the repository-pinned Playwright Chromium, and use Go on `PATH` or `GO_BIN`. Run from the repository root:

```sh
TRACEBOLT_SOURCE_SHA=<exact-source-sha> TRACEBOLT_REVIEW_AI=1 node tests/e2e-review/run.mjs
TRACEBOLT_SOURCE_SHA=<exact-source-sha> node tests/e2e-review/managed-preview.mjs
TRACEBOLT_SOURCE_SHA=<exact-source-sha> node tests/e2e-review/lan-browser.mjs
./web/node_modules/.bin/vitest run --config tests/e2e-review/vitest.config.mts
```

All targets use unique disposable state and loopback listeners. See `tests/e2e-review/README.md` for ports and artifact allowlists. Local browser launch was blocked by the workspace environment; the exact hosted CI above supplied actual Chromium evidence. No tunnel, public deployment, browser certificate-warning bypass or `ignoreHTTPSErrors` was used.

This review does not establish production enrollment, RBAC, real customer-fleet operations, real mobile hardware, native Windows/macOS installation or service lifecycle, or trusted-TLS browser deployment. Separate native, Docker and TLS/CLI checks must be reported with their own evidence. It is not formal security certification or an exhaustive accessibility audit. Later enrollment or sender changes require their own acceptance and are outside this immutable checkpoint.
