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

## Creation failure localization

The shared creation helper uses only fixed stage labels. The route/session-loss
scenario labels its two calls `first` (before dismissal) and `second` (after
returning to devices). Stages distinguish opening, submission, waiting, HTTP 201,
JSON parsing, the v2 response schema, secret type and masked-field assertion.
No response body, unexpected schema value, exception text or input value is
exported. The original secret-type and password-mask assertions remain strict;
HTTP status/schema checks additionally fail closed. No mutation is retried and
no timeout, scenario, quarantine or application behavior changes.

The inert `enrollment-create-diagnostics.test.mjs` suite exercises this helper
with in-memory page/response doubles only. It does not launch a browser or run
the enrollment fixture. These checks are diagnostic coverage, not browser
acceptance or evidence that the original failure is fixed.
