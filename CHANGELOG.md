# Changelog

Meaningful development checkpoints are recorded here. These are prototype milestones, not production releases.

## 2026-10-03 — Isolated read-only assessment foundation

### Added
- Bounded fixed-path Debian package inventory parsing, an injectable/native Debian version comparator, digest-pinned normalized synthetic advisory matching, and in-memory last-good result retention.
- Separate inventory, offered-update and CVE result types with nullable counts, source/coverage/freshness evidence, origin qualification and explicit unknown states.
- Independent contract tests, adversarial parser fixtures, safety checks, cross-build checks and short fuzz smoke coverage.
- A reviewed multi-platform implementation plan and updated product requirements.

### Verification
- Focused assessment race/vet and independent security-contract tests passed on the isolated source overlay.
- Full Go tests, Windows amd64/macOS arm64 test cross-compilation, and two bounded three-second fuzz smoke runs passed. Cross-compiled assessment tests were not executed on those target systems.

### Known limits
- Live advisory import, verified package-origin adapters, offered-update adapters, and UI/API integration remain unimplemented.
- This does not yet show real missing updates or CVEs in Tracebolt. All advisory fixtures are explicitly synthetic, and no real inventory or customer data is published.
- No LAN/authentication, Docker or new language-interface implementation is included in this foundation checkpoint.

## 2026-10-03 — Robust timestamp-based transport checks

- Give the deliberately aged test observation a 15-second admission margin, then wait against its actual timestamp and the server's configured expiry. The same freshness, replay and stale-state assertions remain in place.
- Report safe failure stages, top-level test names and source-line identifiers without exposing raw telemetry or request bodies.
- Run browser acceptance independently after frontend validation; backend/security jobs still contribute to the overall workflow result.
- Application source and security guards are unchanged.

## 2026-10-03 — Stable current-address browser assertion

- Identify the runtime-address row by its stable Manager label while retaining the exact custom-port assertion.
- No application behavior changed. The preceding run passed all eight AI test-provider scenarios and all six real managed-preview checks; this updates the remaining Settings test locator before a complete rerun.

## 2026-10-03 — Provider form readiness and native test isolation

### Fixed
- Provider settings become editable only after the fetched configuration is applied, preventing early edits from being overwritten. Inputs remain disabled during save.
- Form-validation tests wait for actual configuration readiness and cover the first editable state.
- Native agent smoke jobs keep all collector, bundle and agent tests while selecting only independent support-bundle contracts from the shared security-test package. Linux-only managed transport and AI/API checks still run in the full Linux job.
- Native smoke failure diagnostics expose only fixed package and top-level test names, never raw runtime samples.

### Verified locally
- 57 UI tests, nine independent UI regressions, type checking and production build passed.
- Actual Linux native test/build/CLI schema, cap and privacy checks passed. Hosted Windows/macOS and new browser results remain commit-specific CI gates.

## 2026-10-03 — Consent-based AI preview and local agent delivery

### Added
- Optional OpenAI-compatible provider configuration held in process memory, with explicit evidence-and-destination review before each analysis request.
- Bounded, validated AI suggestions with evidence citations, unconfirmed-cause labeling, cancellation and clear provider-error states. Automated validation uses only a deterministic local test provider, not a real model.
- A separate one-shot development agent and opt-in loopback telemetry preview, with awaiting/fresh/stale states, replay rejection, receipt provenance and no manager-side fallback sampling.
- Additive AI and transport security reviews, contracts, independent API regressions, and separate AI/managed browser scenarios.

### Improved
- Concise operational headings and current-address runtime information.
- Unknown collection times and awaiting samples remain visibly unknown rather than appearing as valid measurements.

### Verified prior milestone
- Source `2bccc168c6ef770484b1641bcaeabfe1d10270df` passed actual hosted Linux amd64, Windows amd64 and macOS arm64 read-only agent/runtime checks, plus 26 Chromium scenarios with zero runtime errors.

### Scope
- Provider tests use synthetic evidence and an explicitly labeled test provider. They do not establish diagnostic quality of a real model.
- Managed preview remains loopback-only, without enrolled sender identity, LAN transport, remote actions, service installation or production approval. Native hosted CLI smoke does not establish service, reboot or ordinary-user permission acceptance.
- New UI/browser outcomes are recorded for this checkpoint's exact CI commit; earlier browser passes do not cover these new features.

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
