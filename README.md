# Tracebolt

Evidence-first endpoint diagnostics, built for a self-hosted future.

Tracebolt is an early, local-only development prototype. The current backend milestone contains a Go manager, durable SQLite case notes and status, deterministic diagnostic rules, seven explicitly synthetic demo devices, and a limited read-only Linux sandbox collector. The browser interface is being developed separately and will land as a tested milestone.

**Do not expose this prototype to a network or use it to manage customer endpoints.** It has no operator authentication, enrolled endpoint identity, production audit trail, or remote execution capability.

## Run the backend

Requirements: Go 1.27.1 (the version in `go.mod`), a C toolchain for race-detector tests, and `make`. No database server or container runtime is required.

```sh
make build
./bin/manager
```

The manager binds only to `127.0.0.1:8787` and stores local state in `.local/state.db`. Until the UI milestone lands, use the JSON API:

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

It does not contact a server, enroll a device, execute commands, or install a service.

## What the data means

- Seven Windows, Linux, and macOS demo devices, their histories, cases, and evidence are synthetic fixtures.
- The additional live Linux sample reads only fixed local OS and kernel sources for CPU, memory, filesystem usage, OS label, and uptime. A sandbox may share a kernel or expose host-wide readings; attribution and container limits are unknown.
- `healthy` metric quality means the observation was collected successfully. It is not a security or endpoint-health verdict.
- Missing, denied, stale, and unsupported observations remain visible. No language model is connected, and diagnostic rules do not claim proven root causes.
- Windows and macOS have explicit unsupported collector adapters. Cross-compilation checks buildability only; native collection, installation, lifecycle, and permissions are not validated.

## Validate

```sh
go vet ./...
make test
make build
make crosscheck
```

`make crosscheck` builds the agent for Windows amd64 and macOS arm64. It does not run those binaries. GitHub Actions validates the Go code on a standard Linux runner; inspect each run for its actual outcome.

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
- `internal/fixtures` and `internal/rules`: synthetic scenarios and deterministic findings
- [API contract](docs/api-contract.json)
- [Product scope and release gates](docs/product-plan.md)

## License

A project license has not been selected. Public source availability is not an open-source license grant. Dependencies retain their own licenses.
