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

Only screenshots prefixed `synthetic-` are approved for a public gallery: they show Windows demo inventory, a demo device, or a demo case. The other review screenshots can include real sandbox metrics and must remain local.

Desktop viewport: 1440×1000. Mobile emulation: 390×844. This is responsive Chromium testing, not real mobile-device, Windows, or macOS native-agent validation.

The notes mutation test intentionally stores a harmless markup-shaped text payload in the disposable database to verify that it is rendered literally rather than interpreted as HTML. No external URL is involved.

Results are focused product and regression checks, not an independent security certification or an exhaustive accessibility audit.
