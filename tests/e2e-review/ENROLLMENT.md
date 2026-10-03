# Guided-enrollment browser acceptance

Run after building `web/dist`, installing the pinned Playwright Chromium, and
putting Go on `PATH` (or setting `GO_BIN`):

```sh
TRACEBOLT_SOURCE_SHA="<exact tested commit>" node tests/e2e-review/enrollment-browser.mjs
```

This is a separate 13-scenario target. It preserves the existing 40 general/AI,
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

Coverage includes capability gating, no write before creation consent, repeated
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
