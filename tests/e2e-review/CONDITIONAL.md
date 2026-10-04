# Operational, package-source and conditional-review browser acceptance

This additive target uses the sealed conditional-review application baseline
archive SHA-256 `b3acbd80ba33e173f6425256c75ed1f372c9ea7ff2c9e516e5e937aaf5937d9b`.
Reports and manifests name this provenance field
`applicationBaselineArchiveSha256`. It identifies the application baseline, not
the final composed source tree. The exact tested commit is `sourceSha`, supplied
by `TRACEBOLT_SOURCE_SHA` from `github.sha`; that commit may also contain later
installer/helper changes. This QA overlay includes no later live APT work.

The existing 40 general/AI, 6 managed-preview and 10 auth scenarios remain
unchanged. Enrollment retains its 10 enabled cases and three explicit
quarantines; this target does not restore or claim complete enrollment browser
acceptance.

After building `web/dist`, with Go on `PATH` or `GO_BIN` and the project-pinned
Playwright Chromium installed, run from the repository root:

```sh
TRACEBOLT_SOURCE_SHA="<exact tested commit>" node tests/e2e-review/conditional-browser.mjs
```

The independent target has 18 scenarios. It starts a fresh loopback-only fixture
on port 19892 for each case (`CONDITIONAL_REVIEW_PORT` can override it).
`CHROMIUM_PATH` is optional; the default is the installed pinned browser. No
certificate-error flags, TLS-warning bypass, public listener or tunnel is used.

## Real handler and synthetic fixture boundary

`conditionalfixture` constructs the real operator HTTP-test handler, enrollment
service and durable store, offline catalog and conditional review routes. Three
ordinary ephemeral fixture identities are created through actual claim,
approval, issuance and activation proof validation; one is left awaiting its
first observation. Every observation is invented, with fixed-role bundle
metadata, an operational-v1 component and a package-source component under the
explicit `managed-operations-v2` binding. The fixture labels returned devices
`QA synthetic fixture …` for clear screenshots.

Frames are admitted directly to the real enrolled store with the generated
identity and certificate hash. This verifies store/API/UI integration, not the
network telemetry transport or native collection. The fixture never invokes a
collector, package manager, APT, model, external catalog, installer or service.
Current-state clock advancement and observation changes use only a private stdin
control pipe. There is no public test-control route. Age-boundary cases use this
injected service clock, not actual elapsed two-minute or 24-hour waits. The
operator session clock continues to use real time.

Invented catalog files deliberately exercise both `synthetic:true` and
`synthetic:false`. The latter is an interchange declaration needed to exercise the
unverified conditional-review path. It is still fabricated QA input, never real
Debian data, verified vendor authority or an installed-artifact finding.

## Coverage and interpretation

- Explicit operational/package-source enrollment consent and fresh acknowledgment
- Device-bound lazy reads, accessible tab navigation and disclosure dismissal
- Operational sample filters, section scope, unknown assessment and retained data
- Exact binary/source-version distinction, partial export and unknown new facts
- No live candidates from absent or declared-synthetic catalogs
- Actual source-version review with catalog revision/hash and observation lineage
- Missing source coverage, unsupported release and unavailable comparison
- Current stale/revoked/retention state suppressing conditional candidates
- Local file selection, actual catalog import/clear and stale-revision rejection
- Malformed imports, lost committed response and no automatic replay
- Rejection of wrong-device data and invented authoritative CVE counts
- Delayed responses across device/disclosure changes, protected 401 and lifecycle
- English/German mobile views, keyboard table scrolling and viewport bounds

Wrong-device/count data, 401/409 errors, held/lost responses and persisted-page
events are explicit fault injections. Normal reads, catalog parsing/CAS,
conditional comparison and store state are real. Injected page events do not
establish actual BFCache or operating-system suspension behavior. An empty review
never means zero CVEs, an available update or a secure endpoint.

Run the API/store integration smoke without launching a browser:

```sh
node tests/e2e-review/conditional-browser.mjs --api-smoke
```

This validates real authenticated APIs, source-version comparison, unknown and
partial state, retained operational observations, catalog revision and stale /
revoked / retention boundaries. Its report explicitly says no browser was run.

## Artifact allowlist

Only the following new artifacts under `artifacts/review` may be uploaded:

- `conditional-browser-results.json`
- `conditional-browser-manifest.json`
- `synthetic-conditional-inventory-desktop-en.png`
- `synthetic-conditional-candidate-desktop-en.png`
- `synthetic-conditional-catalog-desktop-en.png`
- `synthetic-conditional-packages-mobile-en.png`
- `synthetic-conditional-review-mobile-de.png`

Captures are original viewport-only PNGs (`fullPage:false`, 1440×1000 or 390×844).
Each manifest entry includes the exact tested `sourceSha`, the application
baseline `applicationBaselineArchiveSha256`, image SHA-256, viewport, locale and
the explicit invented-data/unverified-catalog/HTTP-test caption. No screenshot is publication-approved until its actual pixels have
been independently reviewed. No secret creation dialog is captured.

Reports preserve partial outcomes and bounded stage labels on failure. Runtime
errors fail the target and are exported only as a count. Do not upload private
state, databases, logs, request bodies, cookies, keys, invitation material,
downloads, browser traces, videos or HTML snapshots. The default auth fixture
password is a known disposable test constant; no real credential is used.

Passing this suite establishes only the explicitly described source/API/Chromium
flows. It is separate from native collectors, systemd lifecycle acceptance,
trusted-TLS browser deployment, real advisory accuracy and security certification.
