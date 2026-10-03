# Tracebolt UI acceptance

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
