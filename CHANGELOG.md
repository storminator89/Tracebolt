# Changelog

Meaningful development checkpoints are recorded here. These are prototype milestones, not production releases.

## 2026-10-03 — Native runtime CI and keyboard refinements

### Added
- Read-only agent runtime smoke jobs on standard hosted Linux amd64, Windows amd64 and macOS arm64 runners.
- Native package tests and actual executable/schema/privacy validation with required-field availability checks. Only pass/fail summaries and availability counts are logged; raw runtime samples are not uploaded.
- An additional independent dialog-shortcut regression and corresponding Chromium scenario.

### Fixed
- Global help/search shortcuts no longer open background views while a device dialog is active.
- Keyboard focus outlines use an opaque accent color.
- Screenshot capture waits for animations to complete and frames fixed dialogs at the viewport height.

### Verification boundaries
- Native hosted execution outcomes are recorded per exact CI commit. A configured job does not itself prove a platform passed.
- Hosted CLI checks do not establish service installation, reboot persistence, ordinary-user permission parity, macOS TCC behavior, signing, or production readiness.
- The earlier gallery remains tied to its actual source commit; refreshed captures follow the new browser run.

## 2026-10-03 — Verified browser gallery

### Added
- Eight actual synthetic-data screenshots covering inventory, device evidence and investigations across desktop/mobile and light/dark themes.
- A gallery with immutable source-commit association, CI run, capture time, viewports, and image SHA-256 hashes.

### Verified
- Hosted Chromium completed 25 real-manager scenarios with zero failures and zero uncaught runtime errors for source `594e88eee0e45060374a2c1049be711a96b58d37`.
- Coverage includes API loading/failure/retry, filters and sorting, source quality, dialogs and history, literal note rendering, write deduplication, persistence across manager restart, delayed-save navigation, malformed routes, and responsive layouts.
- The same commit's Go, UI, Linux CLI bundle-schema and HTTP boundary jobs passed.

### Scope
- Screenshots contain synthetic devices and cases. No live sandbox telemetry, database, or raw server log is published.
- These browser results do not imply native Windows/macOS agent acceptance or production deployment approval.

## 2026-10-03 — Investigation UI and bounded native preview

### Added
- React/TypeScript investigation UI with light/dark themes, responsive layouts, inventory search/filter/sort, saved views, CSV export, device evidence, and durable case workflows.
- Loading, error, stale-data and missing-data states, keyboard navigation, dialogs, and route history handling.
- Limited read-only Windows and macOS collector adapters with injected-provider tests and explicit target-acceptance limits.
- A versioned, validated stdout-only support-bundle export capped at 64 KiB.
- Independent HTTP boundary and support-bundle regression tests.
- Standard Linux CI for Go, UI types/tests/build, same-origin browser acceptance, and synthetic-only screenshot artifacts.

### Safety and correctness
- Formula-like CSV values are neutralized, note text is rendered literally, malformed routes are handled, and obsolete asynchronous case responses are guarded.
- Unknown or denied collection results remain explicit; valid metric quality never becomes a whole-device health claim.
- Disposable test state, screenshots of live local readings, raw logs, and support bundles are excluded from source publication.

### Known limits
- This is a local prototype with no authenticated fleet enrollment, remote actions, or production deployment approval.
- Native Windows/macOS target execution remains unverified; provider tests and cross-builds are not runtime acceptance.
- Browser acceptance is recorded in CI for each exact commit. Gallery images are added only after a real render is inspected.

## 2026-10-03 — Local diagnostics backend

### Added
- A loopback-only Go manager and JSON API.
- SQLite persistence for synthetic case notes and status changes.
- Seven clearly labeled synthetic Windows, Linux, and macOS devices with diagnostic evidence.
- Deterministic service, storage, and network investigation scenarios and read-only runbooks.
- A bounded, single-sample Linux collector plus explicit unsupported adapters for other platforms.
- API/collector/rule/persistence test coverage, build instructions, and least-privilege Linux CI.
- Product scope, API contract, platform limitations, and release gates.

### Known limits
- The browser UI is a separate upcoming checkpoint; no UI screenshot is claimed for this backend milestone.
- No operator authentication, enrolled endpoints, remote commands, privileged actions, or connected AI.
- Linux sandbox readings have incomplete host attribution. Cross-builds do not establish native Windows or macOS support.
- Local data is unencrypted and must stay private. Network exposure is unsupported.
