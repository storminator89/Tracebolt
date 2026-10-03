# Tracebolt

Evidence-first endpoint diagnostics, built for a self-hosted future.

Tracebolt is an early, local-only development prototype. It combines a React investigation interface, a Go manager, durable SQLite case notes and status, deterministic diagnostic rules, seven explicitly synthetic demo devices, and bounded read-only collectors. Windows and macOS adapters are implemented previews. Read-only CLI smoke has passed on standard hosted native runners; broader endpoint acceptance remains unverified.

**Do not expose this prototype to a network or use it to manage customer endpoints.** It has no operator authentication, enrolled endpoint identity, production audit trail, or remote execution capability.

## Screenshots

Real Chromium captures with synthetic demo data. [View the desktop/mobile, light/dark gallery and capture provenance](docs/screenshots/2026-10-03-ui-preview/README.md).

![Tracebolt investigation, light theme, synthetic demo case](docs/screenshots/2026-10-03-ui-preview/synthetic-case-desktop-light.png)

## Run locally

Requirements: Go 1.27.1 (the version in `go.mod`), Node.js 24 with npm, a C toolchain for race-detector tests, and `make`. Python 3 and curl are used by boundary regressions. No database server or container runtime is required.

```sh
make web
make build
./bin/manager
```

Open **http://127.0.0.1:8787**. The manager serves the built UI and API from the same origin and stores local state in `.local/state.db`. Do not use a separate frontend dev-server origin for mutations. For UI development, run `cd web && npm run dev` in another terminal to rebuild on changes, then reload the manager page.

The JSON API is also available:

```sh
curl http://127.0.0.1:8787/api/health
curl http://127.0.0.1:8787/api/overview
curl http://127.0.0.1:8787/api/capabilities
```

For a disposable session or a different port:

```sh
./bin/manager --port 8788 --db .local/experiment.db
```

Stop with Ctrl+C. The database persists notes and case status across restarts. It is not encrypted. Keep it private and use synthetic data only. Copy the closed database for a local backup; do not commit it.

The standalone collector emits a single bounded JSON observation to stdout and exits:

```sh
./bin/agent --once
```

It does not contact a server, enroll a device, execute commands, or install a service. A bounded, schema-versioned support bundle is also available:

```sh
./bin/agent --support-bundle > support-bundle.json
```

This writes local stdout only, capped at 64 KiB. Review the file before sharing it; no upload endpoint exists. See the [support bundle contract](docs/support-bundle.md).

## Investigation interface

- Light and dark themes, desktop and narrow-screen layouts
- Searchable inventory with OS, status and source filters, sorting, saved local views, and CSV export
- Device details with collection provenance, capability boundaries, and expandable evidence
- Case investigations with read-only next steps, durable notes, and status transitions
- Explicit loading, missing-data, stale-data, and error states
- Keyboard navigation, focus-contained device dialogs, and Back/Forward navigation

The interface uses the real local API. Browser acceptance and screenshots are produced by the same-origin Playwright workflow; inspect the exact commit's CI outcome rather than assuming every rendered state has passed.

## Optional previews

- [AI-assisted investigation](docs/ai-diagnostics.md): configure an OpenAI-compatible provider, inspect the bounded evidence packet and destination, then explicitly approve an analysis. Provider configuration and keys are memory-only. Suggestions remain unconfirmed and cannot execute actions. Validation so far uses a deterministic loopback test provider, not a real model.
- [Local agent transport preview](docs/local-transport-preview.md): start the manager with `--managed-preview`, then run the separate one-shot development sender. The manager starts with unknown/awaiting data and never substitutes its own sampler. This is loopback-only development transport, not authenticated enrollment or LAN support.

## Assessment foundation

An [isolated read-only inventory and synthetic CVE-assessment foundation](docs/assessment-foundation.md) is available for further development. Live advisory import, verified package-origin adapters, offered-update adapters, and UI/API integration remain unimplemented. **This does not yet show real missing updates or CVEs in Tracebolt.** The [implementation plan](docs/update-vulnerability-plan.md) records the remaining platform, provenance and release gates.

## What the data means

- Seven Windows, Linux, and macOS demo devices, their histories, cases, and evidence are synthetic fixtures.
- The additional live Linux sample reads only fixed local OS and kernel sources for CPU, memory, filesystem usage, OS label, and uptime. A sandbox may share a kernel or expose host-wide readings; attribution and container limits are unknown.
- `healthy` metric quality means the observation was collected successfully. It is not a security or endpoint-health verdict.
- Missing, denied, stale, and unsupported observations remain visible. No language model is connected by default. Diagnostic rules and optional AI suggestions do not claim proven root causes.
- Windows and macOS have limited implemented read-only adapters. Provider tests and cross-compilation check code contracts and buildability; installation, lifecycle, ordinary-user permission parity, signing, and distribution remain unvalidated. A bounded CLI smoke passed on hosted Windows amd64 and macOS arm64 at [2bccc168](https://github.com/storminator89/Tracebolt/actions/runs/37130214233). Windows CPU and macOS CPU/RAM utilization remain explicitly unknown. See [native collection and verification](docs/native-collection.md).

## Validate

```sh
go vet ./...
make test
make build
make crosscheck
bash tests/security/run.sh
(cd web && npm ci && npm run typecheck && npm test && npm run build)
```

`make crosscheck` builds the agent for Windows amd64 and macOS arm64. It does not run those binaries. GitHub Actions validates Go, UI types/tests/build, disposable HTTP boundary checks, and same-origin Chromium workflows on standard Linux runners. It does not deploy a website or install agents on real endpoints.

For browser acceptance locally, install Chromium with `cd web && npx playwright install chromium`, return to the repository root, then run `node tests/e2e-review/run.mjs`. This creates an isolated manager and database. See [browser acceptance](tests/e2e-review/README.md) for scope and screenshot privacy rules.

## Security boundary

The manager combines a fixed loopback listener, loopback peer check, exact Host and Origin checks, mutation CSRF tokens, no CORS, bounded request bodies, and canonical paths. These reduce common browser-to-local-service attacks, but they are not user authentication. Other processes or users able to reach the loopback service can access its local data. Never reverse-proxy, tunnel, or publish the manager.

Case notes are local text. Runbooks are read-only suggestions. There is no arbitrary shell, remote control, privileged remediation, network scan, patch installation, or automatic update path.

Before any network-exposed pilot: authenticated operators and endpoints, revocation, roles, protected audit records, signed agent distribution, retention controls, native OS acceptance tests, and an independent deployment review are required.

## Project map

- `cmd/manager`: loopback development manager
- `cmd/agent`: single-sample, read-only collector command
- `internal/api`: request boundaries and API handlers
- `internal/collector`: bounded local observations and platform adapters
- `internal/store`: SQLite persistence
- `internal/bundle`: bounded support-bundle export contract
- `web`: React/TypeScript interface
- `tests/security`: independent boundary and bundle regressions
- `tests/e2e-review`: same-origin browser acceptance and screenshot capture
- `internal/fixtures` and `internal/rules`: synthetic scenarios and deterministic findings
- [API contract](docs/api-contract.json)
- [Product scope and release gates](docs/product-plan.md)
- [Scoped security review and verification](docs/security-review.md)

## License

A project license has not been selected. Public source availability is not an open-source license grant. Dependencies retain their own licenses.
