# Tracebolt UI acceptance

## Scope

Independent acceptance review of the local Go API, SQLite state, and built React application. The review uses a unique disposable database, never the default application database. Raw captures are produced under `artifacts/review`; only inspected synthetic images are included in the [public gallery](screenshots/2026-10-03-ui-preview/README.md).

The automated review runs desktop Chromium at 1440×1000 and mobile Chromium emulation at 390×844, with light and dark themes. Its scenario source is `tests/e2e-review/run.mjs`; exact machine-readable outcomes are in `artifacts/review/results.json`.

## Verification levels

- **Real implementation:** inventory and case HTTP responses; search, filter and sorting behavior; device/case/evidence navigation; note and status writes through CSRF-protected API; durable SQLite behavior after reload and manager restart.
- **Explicit fault injection:** initial HTTP failure, interrupted refresh, delayed response, failed note mutation, and malformed route. These checks exercise the real UI against controlled failures; they do not prove recovery from every deployment or network failure.
- **Synthetic evidence:** the seven demo devices and diagnostic cases are fixtures. The markup-shaped note is harmless controlled text in the disposable database.
- **Limited local sample:** only the bundled Linux sandbox collector is available. Its data is not an enrolled remote endpoint and is not a native Windows/macOS acceptance result.
- **Visual acceptance gate:** inspect actual screenshot pixels after capture, including small-screen layouts, drawer content, readable hierarchy and both themes. All 12 synthetic screenshots from the first hosted run have been inspected. Screenshots alone cannot establish semantic accessibility.
- **Not verified by this review:** native Windows/macOS installation or collectors, real mobile devices, remote enrollment, production authentication/RBAC, customer telemetry, deployed hosting, unrestricted remote command execution, or formal security certification.

## Reproduction

Build the frontend, then run `node tests/e2e-review/run.mjs` from the repository root. See `tests/e2e-review/README.md` for prerequisites and isolation guarantees.

## Results

The first real-browser run passed all **25 scenarios with zero runtime errors** on source commit `594e88eee0e45060374a2c1049be711a96b58d37`. It used the built React app, a real loopback Go manager and a unique SQLite database on a standard Linux CI runner. [Exact CI run](https://github.com/storminator89/Tracebolt/actions/runs/37128509338).

The independent reviewer inspected all 12 actual synthetic screenshots across 1440px desktop, 390px mobile, light and dark layouts. Inventory, evidence drawers and case pages have coherent hierarchy, readable primary content, explicit provenance, and no observed clipping or horizontal overflow. Two screenshot-only refinements are queued: complete CSS transitions before capture, and capture a fixed device modal at viewport height rather than extending beyond the visible screen.

An additional small patch suppresses global help/search shortcuts while a dialog is active and uses opaque keyboard focus outlines. Its source/DOM regression passes locally; the expanded 26-scenario browser rerun and refreshed screenshot inspection remain pending for that later source commit. The 25-pass result above must not be attributed to the later patch.

Local browser execution was unavailable in the restricted workspace: system Chromium could not create its singleton socket, the dedicated cloud browser rejected loopback navigation, and an official headless-shell download returned an empty ZIP. The service remained loopback-only throughout; hosted CI provided the actual browser evidence without a tunnel or deployment.

A supplemental independent DOM/source suite is runnable with:

```sh
./web/node_modules/.bin/vitest run --config tests/e2e-review/vitest.config.mts
```

The supplemental suite now passes all 9 checks after repairs. The ninth interrupted-keyboard regression initially found that opening help from a device drawer and pressing Escape closed both layers. Global help/search shortcuts are now suppressed while a dialog is active; the independent rerun passes. It confirmed aggregate attention filtering, safe malformed-route parsing, CSV formula neutralization, UTF-8 note byte counting, skip-link focus without changing route, explicit first-load API failure without fake inventory, and literal rendering of markup-shaped names. The initial run reproduced a saved-view validation crash: a persisted filter with `query: null` threw when recalled. The implementation now validates saved filter/theme shapes; the independent regression rerun passed.

Source contrast arithmetic also identified low-contrast light-theme metadata text and undersized mobile hit areas. The owner has darkened text tokens above 4.5:1 against intended backgrounds and increased action targets to at least 40px; the first hosted browser run confirmed the targeted interactive hit areas are at least 40×40 CSS pixels. Focus outlines now use the opaque accent color.

The supplemental DOM tests are not a replacement for browser, layout, focus-trap, pixel, native OS, or end-to-end API verification. Browser/API and visual evidence are recorded separately above. Native Windows/macOS and real-device mobile acceptance are not claimed.

## Artifact provenance and publication

`TRACEBOLT_SOURCE_SHA` is recorded in both result JSON and the screenshot manifest. A browser runtime error fails the suite. Completed scenarios and screenshots survive later scenario failures, with a nonzero exit status.

Only `synthetic-*.png` images are intended for a public gallery. Those are captured before mutation tests and show Windows demo inventory, a demo device, or a demo case in desktop/mobile and light/dark layouts. The remaining review images can include real sandbox observations and must not be published. The database and manager logs are never public artifacts.
