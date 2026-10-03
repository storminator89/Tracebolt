# Tracebolt Web

German-first React/TypeScript admin UI for the local Tracebolt development prototype. Source labels distinguish synthetic demonstration devices from the actual sandbox collector; no API failure is replaced with fixtures.

## Run

From `web/`:

```sh
npm ci
npm run build
```

From the repository root, start the Go manager using the project README. It serves `web/dist` at the same loopback origin as the API (default `http://127.0.0.1:8787`).

For changes, run `npm run dev` in `web/` (build and watch), keep the manager running, and refresh the browser. There is deliberately no permissive Vite API proxy: strict same-origin and CSRF checks remain intact. `npm run preview` is only an asset preview, not the supported API-integrated application.

## Checks

```sh
npm run typecheck
npm test
npm run build
npm audit --omit=dev
npm audit
```

All fonts/icons are installed dependencies served locally; no CDN or remote font request. Dark/light theme and one saved inventory view persist in local browser storage. CSV export neutralizes formula-leading cells. Notes validate the backend's 2000 UTF-8 byte limit. Dynamic strings are rendered as React text, not HTML.

## Screenshots

`node scripts/capture-screenshots.mjs` captures actual rendered UI against the running manager with Playwright. Install the official browser with `npx playwright install --with-deps chromium` on a supported development or CI runner. Optional environment variables:

- `TRACEBOLT_BASE_URL` (default loopback port 8787)
- `TRACEBOLT_SCREENSHOTS` (output directory)
- `CHROMIUM_PATH` (an existing browser executable)

The capture script uses only synthetic-device inventory, case, and drawer views. The overview screenshot is deliberately cropped above the mixed-source table, excluding actual sandbox telemetry. It fails if synthetic inventory contains a real-source row, mobile pages overflow, or JavaScript errors occur.

On the initial cloud coding executor, Chromium could not create its required profile socket (`EPERM`); the cloud browser separately blocked loopback access. These are recorded verification gaps until a supported CI renderer produces real screenshots. No mockup screenshot should be presented as a verified UI capture.
