# Guided-enrollment browser acceptance

Run after building `web/dist`, installing the pinned Playwright Chromium, and
putting Go on `PATH` (or setting `GO_BIN`):

```sh
TRACEBOLT_SOURCE_SHA="<exact tested commit>" node tests/e2e-review/enrollment-browser.mjs
```

This target retains 13 scenarios. The default required gate runs 10 and explicitly
reports the three temporary exclusions below as `SKIPPED`, never `PASS`. It
preserves the existing 40 general/AI,
6 managed-preview and 10 operator-auth scenarios. `ENROLLMENT_REVIEW_PORT`
overrides the loopback-only default port 19889. `CHROMIUM_PATH` is optional;
otherwise the project-pinned downloaded Chromium is used. No browser security
warning or certificate validation is bypassed.

The test fixture uses the real operator HTTP-test handler, durable enrollment
store/service, fresh disposable Ed25519 issuer, and native `enrollmentclient`
library performing ordinary native proof HTTP requests. The browser creates and
approves invitations. The private stdin pipe passes invitation bytes to the
fixture's native library without command arguments, environment variables,
URLs, logs or exported files. The fixture never installs a service or collects
telemetry; it is not the production CLI or a trusted-TLS browser deployment.
Both app and private native state live under a unique temporary directory and
are removed at completion. The root signing key is cleared after constructing
the disposable issuer; generated runtime key files remain private and temporary.

The complete retained suite covers capability gating, no write before creation consent, repeated
creation/approval, masking and explicit reveal/hide, public-only bootstrap
download, storage/URL exclusion, close/reload/route/session-loss clearing,
native fingerprint and comparison matching, re-confirmation after dialog close,
real approval/issuance/activation and revocation/rejection, no healthy claim
before observations, uncertain committed creation, real stale-revision conflict,
actual short invitation and pending expiry, malformed bootstrap rejection,
English/German and mobile layout. The browser clock skew and persisted page
lifecycle events are explicit injected tests. They do not establish actual
OS suspension or BFCache operation. Short expiry fixtures use the service's real
clock and supported test TTL settings, not a public time-control endpoint.

For a local API/native-library smoke without launching a browser:

```sh
node tests/e2e-review/enrollment-browser.mjs --api-smoke
```

That path checks real create, native claim, public comparison, approve, issue,
activate, unknown inventory, revoke, and native terminal response. Its separate
`enrollment-api-smoke.json` report explicitly states that no browser was run.

## Temporary browser quarantine

The exact hosted source `d4a4856e1f88bdc1d52419d73a9b96c65da2626f`
passed 10 of 13 enrollment scenarios with zero runtime errors. These three
scenarios are temporarily excluded from the required browser gate:

1. One creation request keeps its secret masked and ephemeral; bootstrap download contains only public configuration
2. Native claim comparison gates one approval, activation remains unknown without telemetry, and revocation stops the native identity
3. Pending native device can be rejected without granting an identity

Failures were recorded in the terminal-state phase; source review found assertions
could race the asynchronous response. The shared helper now waits for the actual HTTP 200 response, the exact
committed terminal state and its rendered status. The repair is retained, but its
hosted acceptance is still pending. Scenario bodies and strict assertions remain
in the file. The successful creation/export and complete approval/activation/
termination browser flows in those scenarios are therefore outside the default
acceptance claim while quarantined.

The other 10 enrollment scenarios, all existing 40+6+10 browser scenarios and all
backend/native security and lifecycle tests remain enabled. Runtime errors and
failures in enabled scenarios still fail the gate. JSON records every excluded
name and reason, a separate skipped count, and `fullEnrollmentAcceptance:false`.
A green reduced gate must be described as **10 passed, 3 skipped**, not 13 passed.

Restore execution of all retained cases with:

```sh
TRACEBOLT_REVIEW_QUARANTINED=1 TRACEBOLT_SOURCE_SHA="<exact tested commit>" node tests/e2e-review/enrollment-browser.mjs
```

Require a fresh exact-source 13/13 hosted run with zero runtime errors before
removing the quarantine or claiming complete enrollment browser acceptance.
The `--api-smoke` path is unaffected and retains native activation/revocation
checks. This quarantine changes browser gating only, not application behavior.

## Artifact allowlist

Upload only these new paths from `artifacts/review`:

- `enrollment-browser-results.json`
- `enrollment-browser-manifest.json`
- `synthetic-enrollment-http-test-create-desktop-en.png`
- `synthetic-enrollment-http-test-create-mobile-en.png`

Both PNGs are captured before invitation creation, contain the visible HTTP-test
warning, and use `fullPage:false`. The capture guard refuses secret, comparison
and fingerprint controls. Public gallery use still requires actual pixel review.
The manifest records exact source SHA, image SHA-256, viewport, locale and scope.
Reports preserve partial outcomes, a fixed failing-stage label, counts and exact
source SHA on failure, but never raw exception strings, requests, page dumps,
tokens, passwords, private keys, databases, native state or logs. Runtime errors
fail the target and are recorded as a count. Do not upload traces, videos,
downloads, HTML snapshots, process output or temporary state.

The harness does not provision real access or validate a complete enrollment
rollout. Actual CLI TLS/HTTP integration, cryptographic/durable-state review,
installer/service reboot behavior and real native endpoint operation are separate
verification levels.

## Creation response observation

The shared creation helper uses fixed first/second invocation labels for the
route/session-loss case and single elsewhere. It observes the application's
original bounded fetch reader for the exact loopback invitation POST. It never
clones a Response, creates another reader, fetches DevTools response bytes or
retries a mutation. The original Response, read values, bytes and errors remain
unchanged. A single exact request body is bound to the observed browser POST.

Success requires HTTP 201, one completed primary reader within the production
262144-byte bound, complete UTF-8/JSON, the v2 response schema and a string
invitation secret. Independently, the application must render a password input
whose value equals that response's secret; the equality assertion uses a boolean
so it cannot print the secret. EOF/valid JSON by itself is not acceptance: the
application's DTO, bootstrap, clock and access checks may still reject it.

The test-only observer is armed once per creation. It discards private bytes on
abort (including after EOF), duplicate requests, reader/cancellation/decoding
failure, navigation, hidden visibility, pagehide and authentication-required.
Taking a successful response is destructive, and helper finally always clears
remaining state. It never writes storage, screenshots or artifacts. Existing
route/session/lifecycle assertions and the three quarantine entries are unchanged.

Failure reports retain only fixed stages, bounded primary-reader state/counts,
and the existing finite transport snapshot before cleanup. No response body,
request body, unexpected schema value, error message or input value is reported.
Diagnostic errors cannot turn a failure into success. Genuine primary abort,
truncation, invalid JSON, invalid DTO/bootstrap and missing/mismatched UI still
fail; there is no fallback to a cached response or status-only pass.

This corrects the test's dependence on a secondary DevTools body retrieval. The
recorded body-data-missing/aborted transport failure did not establish why the
request was aborted or whether its primary consumer succeeded. Do not claim a
product root cause or historical primary success from this harness change.

The inert helper suite and enrollment-primary-body.test.tsx exercise finite
stages and real production decoder/UI behavior with synthetic streams. They do
not launch Chromium or establish hosted browser/native acceptance. The latter
suite is explicitly included in the existing independent UI regression target.
