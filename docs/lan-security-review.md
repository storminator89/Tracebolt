# LAN foundation security review

Status: **targeted source, CLI, component, HTTP-test browser and hosted container checks passed. No deployment approval is implied.** Reviewed on 2026-10-03. The pinned accepted manager/UI source is `b4a6f40ce9193f9ee91290eb2c50eb07ab8819a9`, verified in [CI run 37142090350](https://github.com/storminator89/Tracebolt/actions/runs/37142090350). Real-browser evidence covers the explicit HTTP-test handler, not trusted-TLS browser setup or real enrollment. The later native sender is a separate milestone.

## Implemented boundaries reviewed so far

- Separate HTTPS operator and mutually authenticated agent handlers. Operator sessions cannot authorize agent ingress; agent certificates cannot access operator routes. The development handler is disabled once the application is wrapped for the LAN operator surface.
- Explicit canonical authority/origin, actual TLS 1.3 request state in the default TLS profile, bounded strict JSON, no cross-origin access, per-session CSRF, and no query/bearer authentication fallback.
- One operator password verifier using a preprovided bounded Argon2id hash. Passwords and sessions are not persisted. Session tokens are random, stored only by SHA-256, and delivered in a Secure, HttpOnly, SameSite=Strict, host-only cookie. Login rate, hashing concurrency, peer buckets and active session counts are bounded.
- Explicit private CA material; no system-root fallback or TLS-verification bypass. Manual approval binds the full leaf-certificate fingerprint to an opaque manager-assigned identity. Certificate names and payload IDs do not select device identity.
- Strict public-certificate parsing, client/server purpose separation, modern key/signature checks, TLS session tickets disabled, and live approval/time/chain checks on every request. Revocation takes effect on reused connections; already-admitted work has separately documented ordering semantics.
- Durable SQLite approvals, tombstones, latest observations and per-agent replay state. Approval identity cannot be reassigned or revived. Exact retries retain their original receipt timestamp; conflicting payloads or non-increasing sequence/observation times are rejected. No raw private keys, passwords or browser sessions are stored there.
- Linux state storage requires a private directory owned by the effective user, trusted ancestor ownership, and safe database/sidecar files. Existing insecure paths fail rather than having permissions silently changed. Approval SQL columns must agree with the decoded descriptor.
- Telemetry is a bounded, strictly shaped protocol frame around a validated read-only observation. All observation times are checked; stale measurements degrade without a self-collected fallback. Whole-device health remains unknown. A valid authenticated observation is not proof that the endpoint itself is uncompromised.

## Explicit insecure HTTP test profile

The separate default-off HTTP test profile requires explicit plaintext-risk acknowledgement and profile-labelled authentication/state material. It uses a distinct non-`__Host` cookie with HttpOnly/SameSite=Strict and intentionally without Secure. It does not reuse the TLS profile database or silently downgrade HTTPS.

Agent requests use a preapproved Ed25519 public certificate and a versioned length-prefixed signature transcript binding configured origin, method, fixed path, content type, leaf fingerprint, sequence, canonical timestamp and raw-body SHA-256. The verifier rejects TLS requests, browser/bearer/proxy headers, duplicate signature fields and noncanonical framing. It performs no standalone replay claim: the handler validates the frame, matches sequence/time, and atomically commits the observation and replay state.

**HTTP exposes telemetry, operator passwords and sessions to the network. Signatures do not encrypt data, authenticate the server/UI, or prevent operator session hijacking.** This is an explicitly insecure testing option using separate disposable material, not security equivalence to mTLS. No real deployment or credentials were used for this review.

## Independent checks

These tests use disposable databases, synthetic credentials and locally generated short-lived certificates. They do not create real operator/device credentials, modify global trust, expose a LAN listener or contact a real model provider.

- `tests/security/lantrust_boundary_test.go`: strict public-only approval, wrong roots/purpose, server SAN checking, required client certificate, certificate-to-server-ID mapping, revocation on the same TCP connection, and tombstones after registry reload.
- `tests/security/operatorauth_boundary_test.go`: pointer/value/JSON secret protection, expiry, real TLS cookie attributes and session/CSRF gates, disabled development handler, rejection of logout during body read, and cancellation of an active fake-provider HTTP request on logout with no analysis result returned.
- `tests/security/lan_ingress_boundary_test.go`: real mTLS surface separation, alternate path/header/body identity rejection, exact retry without age refresh, conflicting replay rejection, revocation, durable replay across store reopen, nonprivate directory and symlink-sidecar rejection, and inconsistent SQL/JSON identity failure.
- `tests/security/lanconfig_boundary_test.go`: redacted material JSON/value diagnostics, protected profile/key files, TLS SAN validation, profile-labelled authentication separation and symlink/insecure-key rejection.
- `tests/security/signed_http_boundary_test.go`: real loopback signed requests, body/header/path binding, atomic validation without consuming sequence on rejected frames, exact retry/no-refresh, revocation and refusal to become a TLS fallback.
- UI typecheck, all **97 component/unit tests** and production build passed independently on the checked source. Logout-intent persistence, cross-tab storage fallback, restored-page conceal/revalidation and browser/declared-transport mismatch cases are included. The pinned hosted frontend job also passed these 97 tests, nine additional independent UI regressions, typecheck and build.
- Independent `go test -race ./... -count=1`, `go vet ./...` and `go mod verify` passed on the integrated source, including separate real loopback TLS/HTTP runtime listeners. Container tests may be opt-in/skipped; this is not evidence of container execution.
- Independently reran `TestBuiltLANManagerCLI`: the actual built binary accepted its protected config/flags for both profiles, handled login/public approval/Linux observation/retry/revocation/logout, and exited cleanly after an owned-process interrupt. This was a loopback fixture, not a real LAN deployment.

## Findings and current disposition

1. **State-directory replacement boundary, corrected and independently retested.** Checking only a mode-0600 database did not prevent another local account from replacing entries in an insecure parent directory. The store now rejects insecure directories, owners, symlink/hardlink sidecars and mismatched approval descriptors.
2. **Logout during delayed body read, corrected in the checked source.** A request authenticated before its body finished could still perform a case mutation after logout. A deterministic independent regression originally returned HTTP 200 after revocation; the checked correction returns HTTP 401. A follow-on independent race test exposed a concurrent-logout hole: a second logout returned before admitted work drained. The corrected implementation retains the revoking gate until all admitted mutations finish, rejects further admission immediately, and makes concurrent logout callers wait on the same barrier. Independent race runs passed three times, including expiry, delayed-body rejection and active-provider HTTP cancellation.
3. **Cross-tab/reload logout visibility, corrected at source/component level.** A non-secret persisted logout-intent marker, receiving-tab storage fallback, cross-tab invalidation and restored-page conceal/revalidation now cover stale private DOM and request cancellation. The UI rejects a declared HTTPS session over an actual HTTP page before password entry. Independent component/build checks passed; the pinned HTTP-test browser gate additionally passed expiry, cross-tab logout, interrupted logout/reload, protected401 and no-replay flows. Trusted-TLS browser acceptance is separate.
4. **Key-bearing configuration JSON, corrected and independently retested.** An exported TLS certificate could serialize its private-key fields through generic JSON. Material now has value-safe JSON and diagnostic redaction; synthetic-key regressions pass.

## Pinned hosted acceptance

The reviewer independently inspected the exact-source JSON artifacts, completed GitHub job/step results and decoded container/frontend logs for the linked run.

- **40/40 general, AI, language and layout scenarios**, zero runtime errors. This includes the corrected long-content/sidebar/mobile/zoom containment checks; their assertions were not removed to obtain a pass.
- **10/10 real HTTP-test operator-handler browser scenarios**, zero runtime errors. These cover access-blocking bootstrap, password failure and draft clearing, unknown awaiting-agent data without a demo fleet, CSRF logout, actual short expiry, protected401, no replay after login, unconfirmed logout across reload, cross-tab logout and the persistent mobile plaintext warning. The handler runs on loopback with a synthetic awaiting-device contract and disposable known credentials. This is not a production-CLI, enrollment, native-sender or trusted-TLS browser test.
- **6/6 managed-preview browser checks**, including a separate Linux developer sender and actual two-minute expiry. That earlier developer transport is distinct from the authenticated LAN sender. No real telemetry screenshots or values were exported.
- The hosted Docker job **built and actually exercised both TLS/mTLS and explicit HTTP-test container profiles**. The opt-in image variable was set, so these lifecycle tests were not the ordinary skipped local-container check. Logs confirm durable approval/replay/revocation and a nonroot runtime. TLS clients used normal ephemeral CA verification. This is container/HTTP-client evidence, not browser certificate-trust acceptance or real deployment.
- Native Linux, Windows and macOS read-only collector/CLI jobs and the backend gate were also green. These jobs do not establish Windows/macOS LAN sender or service support.

All browser screenshots in this gate are declared synthetic contract/login/gallery data. No browser certificate-warning bypass or OS-global trust change was used.

## Dependency advisory evidence

A fresh authorized Linux source scan on 2026-10-03 used `golang.org/x/vuln/cmd/govulncheck@v1.8.0` and Go 1.27.1. The scanned source tree was unchanged during the run. Results were **zero reachable-symbol findings, zero imported-package findings, and one advisory in a required module**. A verbose rerun identified [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), which concerns the unmaintained `golang.org/x/crypto/openpgp` packages and has no known fixed version. The application uses Argon2; a separate dependency-list check confirmed that OpenPGP packages are not imported. This is not an observed reachable Tracebolt vulnerability, nor a claim that every module is advisory-free.

Earlier canceled scan attempts have no verified result and are not counted as evidence. The current scan is static Linux-source evidence only and does not establish native acceptance or absence of unknown vulnerabilities.

## Remaining gates and limits

- Preserve the verified mutation/revocation ordering and rerun its regressions against the final integrated profile source. The guard admits only current sessions; an already-admitted short mutation may finish, but logout does not return before it drains. Long provider I/O is cancelable and is not held under the mutation guard.
- The checked Linux CLI profile and protected-material paths pass fixture execution; deployment-specific bind addresses, certificate provisioning, container mounts, trust setup and actual devices still require their own acceptance.
- Trusted-TLS browser setup, other browser engines and future UI/source changes require their own acceptance; the completed browser gate above is explicitly HTTP-test/Chromium scoped.
- HTTP test approval currently accepts an otherwise valid Ed25519 leaf larger than the verifier's 4 KiB base64 certificate-header limit. Such a leaf cannot send telemetry and fails closed. Mirror this bound at approval in a follow-up; this is a nonblocking compatibility issue.
- The native one-shot sender is a separate reviewed source milestone and is not included in this pinned manager/browser checkpoint. No installed or continuously running agent is established by this report.
- LAN model destinations need their own explicit trusted-endpoint/CA/address policy review. The earlier public HTTPS and literal-loopback provider policy must not be relaxed wholesale.
- No actual LAN installation, certificate issuance workflow, OS-wide trust modification, service lifecycle, multi-operator authorization, fleet-scale availability, backup/restore, rotation or hostile-network acceptance has been established. Same-user/root compromise and deliberate external database modification are outside this process boundary.

This is a targeted development review with regression evidence, not a production-security certification or an exhaustive formal scan.
