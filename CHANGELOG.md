# Changelog

Meaningful development checkpoints are recorded here. These are prototype milestones, not production releases.

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
