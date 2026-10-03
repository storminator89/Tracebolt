# Tracebolt development security review

Review date: 2026-10-03. Method: independent source review and focused regression execution against the current local-development implementation. This is not a production-security approval, certification, or complete penetration test.

This document records the initial manager/collector/UI checkpoint before optional AI configuration was integrated. The subsequent AI scope is reviewed separately in [ai-security-review.md](ai-security-review.md), and the Linux one-shot ingress in [transport-security-review.md](transport-security-review.md). Newer features are not implicitly covered by the baseline results below.

## Conclusion and scope

The reviewed localhost backend, collector/bundle contract, and frontend checks pass the tests described below. No unresolved blocker was found in those tested boundaries. The standard-runner real-browser gate passed 26/26 scenarios for source `2bccc168c6ef770484b1641bcaeabfe1d10270df`, with zero recorded runtime errors. Later changes require their own checks. Read-only CLI execution also passed on hosted Linux, Windows and Apple-silicon macOS runners for that source. Ordinary-user, installation and service-lifecycle acceptance remain unverified.

Reviewed source: `cmd/manager`, `cmd/agent`, `internal/api`, `internal/store`, `internal/collector`, `internal/bundle`, `internal/rules`, `internal/fixtures`, and the frontend's API, routing, rendering, export, and case-mutation paths. Third-party source was not exhaustively audited. Dependency advisory scans are listed separately.

## Implemented protections

### Local HTTP boundary

- The manager binds TCP4 `127.0.0.1` only. No host flag or environment setting broadens the listener.
- Every route first requires a loopback peer and exact `127.0.0.1:PORT` or `localhost:PORT` authority. Foreign, malformed, missing, and duplicate Host requests were rejected in independent tests.
- A supplied Origin must match the chosen authority exactly. Cross-site fetch metadata is rejected. There is no permissive CORS response.
- The only state-changing API operations are case notes and workflow status. They require POST, the exact same Origin, one current process-generated CSRF token, and `application/json`. Missing, foreign, null, duplicate, or invalid guard headers were rejected.
- Raw bodies are limited to 4096 bytes before JSON parsing. A note is limited to 2000 UTF-8 bytes. Parsing rejects duplicate keys, unknown fields, malformed Unicode/JSON, trailing JSON, wrong types, invalid statuses, and disallowed control characters. Chunked transfer bodies are not accepted.
- Paths are canonicalized by rejection, not by permissive reinterpretation. Hidden static components are denied, and resolved static files must remain inside the built UI root, including after symlink resolution.
- Responses set no-store, nosniff, same-origin resource policy, no-referrer, frame denial, a restrictive CSP, and disabled camera/microphone/geolocation policies. Read/header/write/idle timeouts are configured.

These guards do not authenticate an operator. Another process running locally can obtain the token and access the API. Do not expose, reverse-proxy, tunnel, or network-publish this development manager as if it had production authentication.

### Persistence and execution

- SQLite uses parameterized values, transactions, one configured database connection, WAL, and full synchronous writes. The database file is created/restricted to mode `0600`.
- The tested case-history limits are 100 notes and 500 timeline entries per case. Rejected writes did not partially update notes/status/timeline. Concurrent writes were retained without lost updates.
- No remote enrollment, arbitrary shell/job/remediation endpoint, model connection, or model credential store is implemented. Runbooks are guidance only.
- Case resolution is a workflow state, not an assertion that endpoint health changed.

### Read-only collectors and support bundle

- Linux reads fixed, size-bounded OS/proc sources and the root filesystem. It explicitly warns that kernel counters can have shared-host scope; cgroup limits and physical-host attribution are not established. Whole-device health remains unknown.
- Windows source uses fixed system APIs for numeric NT version/build, uptime, physical memory, and caller-visible system-volume capacity. The filesystem target derives from the native system-directory API, must be a drive-letter root, and must report fixed local media. Environment-provided paths and UNC targets are not used. System DLL loading uses the system-only loader.
- macOS source reads four fixed sysctl keys and `statfs("/")`. It discards mount-source, owner, and filesystem identifiers. Total memory capacity is not misrepresented as used-memory percentage. APFS/container accounting limitations remain explicit.
- Missing, denied, malformed, or unsupported observations stay unknown/denied/null. Windows/macOS CPU sampling and macOS memory-utilization sampling remain unsupported.
- `--support-bundle` writes one JSON object to stdout, capped at 65,536 bytes. There is no upload endpoint or additional collection step. The encoder enforces fixed role metadata, bounded fields/arrays, finite metric values, quality/value consistency, unique evidence IDs, and no IP, case history, trend, or healthy-device claim. Empty arrays stay arrays.
- Intended exclusions include hostname, serial, IP, account identifiers, process lists, environment dumps, logs, credentials, and personal file contents. Free-text observation fields are not a universal data-loss-prevention filter: only trusted collector output is accepted, and operators must review bundles before sharing. System characteristics and timestamps can still be informative.
- Cross-builds and injected-provider tests do not verify target-machine permissions, native API behavior, installation, signing, reboot lifecycle, or uninstall. Native output keeps target acceptance explicitly unverified.

### Frontend data handling

- Evidence, logs, names, and case notes are rendered as React text. The reviewed paths contain no raw HTML insertion or executable-template evaluation.
- A component test renders HTML/script-looking evidence literally and confirms no injected `img` or `script` DOM exists.
- CSV cells that could be spreadsheet formulas are neutralized before quote escaping.
- Malformed URL fragments and malformed saved-filter state are handled without crashing route/filter parsing.
- Case detail is keyed by case ID so an old asynchronous save response cannot replace the newly selected case component.
- Missing/stale/denied telemetry, synthetic fixtures, and local sandbox data are visibly distinguished. Failed API reads do not silently substitute demo fixtures. The note editor counts UTF-8 bytes to match backend limits.

## Independent verification

Executed against the reviewed source on Linux:

- `go test -race ./... -count=1`: passed, including the independent bundle tests under `tests/security` and provider-backed native composition/negative tests.
- `go vet ./...`: passed.
- Independently rebuilt manager and agent binaries: passed.
- `bash tests/security/run.sh`: all **13 test groups passed**, followed by SQLite integrity `ok` and file-mode `0600` checks.
- Actual Linux `--support-bundle` output: JSON Schema Draft 2020-12 plus date-time format validation passed; final sampled output was 6753 bytes, below 65,536. Fixed role labels, null IP, unknown whole-device health, and absent runtime hostname were also checked during review.
- Initial frontend `npm run typecheck`, `npm test`, and `npm run build`: passed; **30 frontend tests** across three files passed at that local checkpoint. The subsequent pinned-source CI UI test/build jobs also passed.
- Real-browser results were independently inspected from the standard-runner artifact: **26/26 Chromium scenarios passed, zero runtime errors**, for source `2bccc168c6ef770484b1641bcaeabfe1d10270df`. The tests used the real local manager and a disposable database. They cover literal attack-looking notes, same-origin writes, repeated clicks, status/note persistence across reload and manager restart, delayed-save navigation, failed-write preservation, malformed routes, unknown/stale states, desktop/mobile layouts, and modal keyboard behavior. [CI run](https://github.com/storminator89/Tracebolt/actions/runs/37130214233). This result includes the modal background-shortcut regression. It does not automatically cover the subsequent AI/settings or managed-transport work.

Native CLI follow-up: GitHub job status and the decoded job logs were independently checked for source `2bccc168c6ef770484b1641bcaeabfe1d10270df`. Native Go package tests and the actual read-only CLI schema/cap/privacy check passed on Linux/amd64, Windows/amd64 and macOS/arm64. Available/unavailable percentage-metric counts were respectively 3/0, 2/1 and 1/2, preserving unsupported readings rather than manufacturing them. These hosted-runner results do not establish ordinary-user permissions, service installation, signing, reboot or uninstall behavior. [Exact native/browser CI run](https://github.com/storminator89/Tracebolt/actions/runs/37130214233).

The 13 HTTP groups cover:

1. Normal read contract, no CORS/no-store, and disabled remote capabilities.
2. Exact Host authority across API/static reads and writes, including duplicate/missing values.
3. Origin/CSRF failures and unchanged state after rejection.
4. Unsupported methods and GET attempts on mutation paths.
5. Malformed JSON/Unicode, duplicate/extra keys, wrong types, non-finite values, blank/excessive text.
6. Raw and multibyte body caps and content types.
7. Status enum validation.
8. Traversal, hidden files, out-of-root symlink, encoded separators/NUL, injection-looking IDs, and guard-preserving path aliases.
9. Literal HTML/SQL-looking note roundtrip and preserved case table.
10. Legitimate status write and restoration.
11. Duplicate Origin/CSRF, conflicting Content-Length, and chunked transfer rejection.
12. Eight concurrent unique writes, with all notes and unique IDs retained.
13. The 100-note limit and atomic rejection of an additional note.

The wrapper creates deliberately placed hidden files and an escaping symlink, uses a fresh seeded database, verifies its own server using a unique marker, bounds readiness requests, and cleans up only its own process/state. Do not run the lower-level mutation harness against a database whose notes matter: it intentionally fills one case to its note limit.

## Review-driven corrections verified

- Hidden-file denial before SPA fallback.
- Initial Darwin platform/capability enum inconsistencies.
- Cross-port frontend proxy removal in favor of same-origin manager serving.
- Formula-safe CSV export, malformed-fragment handling, UTF-8 note counting, validated saved filters, and keyed case navigation.
- Native collector/bundle role metadata agreement, checked through provider-to-bundle integration tests.
- Bundle fixed-label/field-bound validation, healthy/null rejection, and schema-conforming empty arrays.

The case-navigation fix also passed the delayed-response real-browser regression on the pinned source above.

## Dependency evidence

- The npm lockfile uses lockfile version 3. All 216 resolved remote package entries use `registry.npmjs.org` and have integrity values.
- Captured npm production-only and all-dependency audit reports both contain **zero reported vulnerabilities** after the Vite/Vitest/esbuild updates. These reports were inspected independently; npm audit was run by the frontend owner.
- `go mod verify` passed according to the backend build evidence.
- The backend owner's official `govulncheck` v1.8.0 runs reported **no vulnerabilities found** in Linux, Windows-amd64, and Darwin-arm64 static target contexts on the review date. These are advisory/call-graph checks, not target-OS execution or a guarantee that every possible vulnerability is known.

## Unverified and later release gates

- Chromium interaction passed for the pinned source above. The test runner could exercise the manager on its own loopback without publishing the application. Local cloud-browser access remained blocked and was not bypassed. Other browser engines, every CSP edge, and changes after that source are not covered by that result.
- Independent syscall tracing was attempted but the sandbox prohibits ptrace. Zero network/child-process activity was not established by a successful runtime trace; no-network/no-shell statements above are source-backed.
- Hosted Windows/macOS read-only CLI execution passed as recorded above. Real ordinary-user permission denial, full filesystem semantics, signing/notarization, installation/lifecycle and uninstall still require target-machine acceptance. Full Linux host/systemd/service/log behavior is likewise outside the exercised sandbox scope.
- No adversarial local-user isolation, multi-user authorization, encrypted database, protected audit log, fleet identity/enrollment, rotation/revocation, transport authentication, or production availability guarantee is supplied.
- A network-exposed pilot needs a separate design and deployment review: authenticated operator sessions and roles, authenticated per-agent identity, TLS and enrollment controls, bounded/rate-limited ingestion, protected audit/retention/backups, signing/update controls, and threat-model-driven tests.

Keep the scope statement with this report. A passing localhost regression suite must not be reused as a claim of secure production RMM readiness.
