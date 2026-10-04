# Endpoint hostname/interface browser acceptance

This additive six-case target uses the composed endpoint extension on the page-based `a9a9d4e08233ed8b0e968e074da1fa7cf7916121` application baseline. The exact tested identity is supplied through `TRACEBOLT_SOURCE_SHA` by hosted CI. Existing 92 required cases, three explicit enrollment quarantines and five review lifecycle cycles remain unchanged.

## Scope and fixture

The Go fixture creates fresh disposable activated identities through the ordinary claim, approval, issuance and activation proof service. It admits invented endpoint snapshots through `systemwire.EncodeEndpoint` v2 and `Store.SaveSystemObservation`, with matching generation, timestamp, identity and certificate binding. Ordinary v1 system frames omit the extension and must retain the latest endpoint attempt's original age. A denied endpoint attempt replaces prior values; there is no implicit last-good endpoint fallback.

Only fixed invented hostname text and documentation-range IPv4/IPv6 addresses are used, including an IPv4-mapped IPv6 value. Interface names and flags are invented. Real operator authentication and the GET endpoint handler remain in use on explicit loopback HTTP-test. Private stdin commands can submit fixed modes, advance the service clock forward, or revoke a generated identity through the normal service. Auth uses real time. No HTTP fixture-control route exists.

Direct store admission is browser/API fixture evidence. It does not execute a host collector, write local consent files, opt a real endpoint in, prove authenticated native ingress, install a service or access a user VM. The HTTP-test warning is retained; no browser TLS warning is bypassed.

## Six required cases

1. Inert reported hostname, stable cryptographic device ID, independent per-interface IPv4/IPv6, unknown hardware and no primary-IP inference or address links.
2. Partial address coverage, denied hostname/family, successful empty family versus denied collection, complete empty interface list, German mobile and dark theme.
3. Ordinary v1 reports and manual refresh keep original sequence, generation, collection/receipt and expiry; the refresh clears old values until its real response returns.
4. Retention expires at the original deadline while still before the later ordinary report's hypothetical 24-hour deadline. Real identity revocation and never-collected states hide values without healthy-state fallback.
5. Injected hidden/visible lifecycle events clear values until a fresh real response. Device navigation during a held upstream-200 response must leave only the new device's values; browser cancellation or a discarded late fulfillment is valid cleanup.
6. Real JSON/CSRF logout invalidates the server session; the original cookie receives endpoint401, protected refresh clears the private UI, and reload remains signed out.

No arbitrary timeout increase, mutation replay, remote collection toggle, mocked endpoint values or production telemetry is added. Held real responses and injected visibility events are explicitly fixture controls, not actual OS suspension evidence.

## Commands

After building `web/dist` and installing the repository's pinned Playwright Chromium:

```sh
TRACEBOLT_SOURCE_SHA=<exact-github-sha> node tests/e2e-review/endpoint-identity-browser.mjs
```

For local real-handler verification without launching any browser:

```sh
node tests/e2e-review/endpoint-identity-browser.mjs --api-smoke
```

The runner uses `GO_BIN` or Go on PATH and defaults to Playwright's installed Chromium; optional `CHROMIUM_PATH` follows existing runners. Browser execution remains the hosted CI route.

## Report validator and artifacts

Require `endpoint-browser-results.json.sourceSha === github.sha`, six unique result names, all six `status: PASS`, summary passed6/failed0/setupFailurefalse, and runtimeErrorCount0. Require each fixed safety flag to be false: `secretsExported`, `realTelemetryExported`, `collectorExecuted`, `consentFilesWritten`, `installerExecuted`, `userVmAccessed`. A failure preserves only the fixed case/stage name, duration and bounded diagnostic sentence, and returns a nonzero exit code. No raw body, host inventory, password, cookie, private key or DB/log dump is included.

Allowed uploaded files:

- `artifacts/review/endpoint-browser-results.json`
- `artifacts/review/endpoint-browser-manifest.json`
- `artifacts/review/synthetic-endpoint-desktop-en.png`
- `artifacts/review/synthetic-endpoint-mobile-de.png`

The manifest pins the source SHA and original PNG hashes, viewport/locale and the invented-data/HTTP-test disclosure. Captures occur only on the data page, without invitation or comparison dialogs. The local `endpoint-api-smoke.json` is not in the upload allowlist. No gallery update is requested.

## Preparation evidence

The fixture builds and vets; the real-handler API smoke passes including typed complete/partial/denied/empty frames, original-age retention and expiry, revocation, not-collected state and actual JSON/CSRF logout with rejection of the original cookie. JavaScript syntax passes. The exact candidate's 101 endpoint decoder/component/API tests and production build pass independently. Backend seam review and focused read-only harness review found no remaining material blocker after correcting the JSON logout body and strengthening expiry/held-response preconditions. No local Chromium launch was attempted. Hosted execution and original pixel inspection remain pending for the final composed SHA.
