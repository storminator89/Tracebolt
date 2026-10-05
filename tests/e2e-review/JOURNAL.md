# Journal browser acceptance

This additive target exercises the built React app and the real authenticated
operator journal handler on an ephemeral loopback HTTP-test fixture. Every log
message is invented and marked synthetic. Existing 98 required browser cases,
three explicit enrollment skips, and five review lifecycle cycles are unchanged.

## Commands

Build `web/dist` using the pinned frontend dependencies, then run:

```sh
TRACEBOLT_SOURCE_SHA=<exact-github-sha> node tests/e2e-review/journal-browser.mjs
```

The runner uses `go` from PATH (or `GO_BIN`), builds only its disposable fixture,
and starts the fixture and Playwright in the same process environment. Playwright
uses its installed Chromium unless `CHROMIUM_PATH` explicitly selects a supported
installation. `JOURNAL_REVIEW_PORT` can override the default loopback port19896.
It never disables certificate verification. Browser execution belongs to the
existing hosted CI route; local Chromium is not an acceptance prerequisite.

For source/API preparation without launching a browser:

```sh
node tests/e2e-review/journal-browser.mjs --api-smoke
```

This validates actual login/CSRF, both content-acknowledgement requirements,
pending creation, typed result admission, literal search, paging, cancellation,
partial coverage, original expiry and logout. It also passes the actual handler
DTOs through the production frontend decoders. This does not pass the browser
target or establish any screenshot result.

## Seven required browser cases

1. Logs load only when the tab opens. The observed-service picker lazily reads
   the real protected service inventory, discloses that observation does not prove
   local allowlist permission, and only fills the manual field. Escape and selection
   close it and restore the appropriate focus; unsupported unit syntax is disabled.
   Time presets edit exact whole-second UTC windows ending at the displayed checked
   reference. Ordinary idle preserves that fixed reference and the draft. Explicit
   reference refresh performs a protected status read and preserves the draft until
   another preset is chosen. It requires one new authentication/status read pair,
   an actual HTTP200 status and a displayed reference at least as recent as the
   advanced fixture clock. The reference is read from the production-rendered UI,
   rather than retrieving the already-consumed response body again through CDP.
   Streamed-response React regressions independently require a complete valid body
   before exposing that reference; partial, malformed, invalid and interrupted
   bodies cannot enable the form. Selection/presets never acknowledge or capture logs.
   Separate content and HTTP acknowledgements gate one request; pending remains
   explicitly without captured content.
2. Complete and partial invented rows remain inert text. English desktop and
   German mobile retain truthful coverage and bounded viewport framing.
3. Case-insensitive literal search covers only the captured snapshot. Pagination
   follows100/100/5 rows from205, retaining identity, digest, original observation
   time and expiry. Regex-looking input is literal.
4. Cancel clears rows immediately. A deliberately lost response after the real
   cancellation commits triggers status reconciliation without mutation replay.
   Reload preserves the canceled state and consumed request floor.
5. Idle timer checks retain the selected draft service, UTC window and severity.
   A visible blur clears rows/search and shows an explicit paused state with the
   same disabled form controls. Explicit Refresh status rechecks the real operator
   session, holds the original status response behind the privacy assertions,
   and restores the same identity, digest and original observation/expiry without
   creating or canceling another capture. Acknowledgements and search reset.
   Injected hidden visibility still clears content until a fresh real read completes.
   A capture delivered120 seconds after creation still expires at the original
   fifteen-minute deadline. Fixture clock advancement is not elapsed wall time
   or actual browser BFCache acceptance.
6. Device navigation cancels or discards a held old-device result. Real operator
   logout rejects protected reads and removes private content through reload.
7. Source guidance distinguishes unsupported broader log scopes from observed
   services. Recognizable literal-search shortcuts never create/cancel a capture
   or grant access; English desktop and German mobile retain explicit permission
   uncertainty and the original content/HTTP acknowledgement boundary.

The fixture generates disposable activated v3 identities using ordinary proofs,
admits an invented typed system frame with three synthetic service rows, then consumes only the request created by
the operator through store Peek/Claim and JournalCache.Accept. Results round-trip
the typed journal wire format. Controls are bounded stdin messages, never an
HTTP test endpoint. The service clock can move forward; the operator clock stays
real with a60-minute fixture session. The production15-minute journal TTL is
unchanged. No source collection, native journal ingress, helper isolation, local
consent grant, permission change, service installation or user VM is exercised.

## Evidence and gate

CI must require exactly seven uniquely named PASS results, zero FAIL results,
`summary.setupFailure === false`, `runtimeErrorCount === 0`, and `sourceSha`
equal to the exact tested GitHub commit. None of the inherited three enrollment
skips is restored or counted as passed.

Only these files under `artifacts/review/` are allowlisted for this target:

- `journal-browser-results.json`
- `journal-browser-manifest.json`
- `synthetic-journal-desktop-en.png`
- `synthetic-journal-mobile-de.png`

Reports contain fixed scenario names, PASS/FAIL, bounded phase names, duration,
source identity and explicit scope. Errors never contain raw exceptions,
response bodies, generated device IDs, cookies, fixture state paths or messages.
Every browser case attaches the same bounded observer. Failures include the
latest 32 fixed route/method/status/lifecycle events, a capped query ordinal,
fixed query substep and allowlisted asserted-field name, plus DOM counts and
booleans. Second, third, previous and no-match pages have distinct phases.
The HTTP200, response JSON, identity/digest, original-time and rendered-row
assertions remain unchanged; diagnostics do not retry or suppress failed reads.
For explicit page actions, a test-only initialization script observes the original
fetch body reader at the exact loopback fixture query URL. It copies at most
65,536 bytes, only as the application consumes them, and exposes one immutable,
one-use JSON result after successful end-of-stream. It does not clone, prefetch,
retry, replace the Response, or retrieve the body through CDP. Incomplete,
cancelled, oversized, duplicate and malformed observations cannot supply a result.
The production decoder and accepted UI state are still required separately;
complete JSON with an invalid snapshot identity must fail the normal UI checks.
The independent UI regression target covers these streamed/disconnected paths.
Captured bodies stay in fixture memory only and never enter reports or artifacts.
On failure, already completed results and safe captures remain available and the
runner exits nonzero. The manifest contains each original image's SHA256,
viewport, locale, source identity and synthetic fixture disclosure. Captures are
viewport-only; no invitation, key, cookie, login field or real log is captured.

Both report and manifest require every following boolean to be false:
`secretsExported`, `realTelemetryExported`, `hostJournalRead`, `helperExecuted`,
`permissionChanges`, `collectorExecuted`, `installerExecuted`, `userVmAccessed`.

`journal-api-smoke.json` is local preparation evidence and is not in the upload
allowlist. Temporary databases, binaries, logs, cookie jars and control output
are never artifacts. A successful target proves only the stated synthetic
operator UI/cache/store flow, not an installed helper or real host journal read.
