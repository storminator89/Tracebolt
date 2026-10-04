# Offline catalog and coverage boundary review

Reviewed 2026-10-04 on Linux amd64, using Go 1.27.1 and Node 24.19.0.
This is an independent, source-bound review of the offline catalog/coverage
candidate. It is not a deployment approval, a dependency-vulnerability scan,
vendor-data validation, native update acceptance, or proof of real CVE detection.

## Result

No blocking security finding was identified in the reviewed boundary. The new
slice preserves the important separation between uploaded interchange metadata,
client-reported binary inventory, and unavailable assessment/update capabilities.

One strict-readback discrepancy was identified and corrected before the final
review: loaded catalog DTOs now reject `coveredSourceCount: 0`, matching the
importer requirement for nonempty `coveredSources`. Independent regression
coverage verifies the correction. No unresolved finding remains in this scope.

The clear-body error-code wording was clarified in the integration contract:
catalog-specific errors have fixed catalog codes, while shared framing/session/
typed-body errors retain existing fixed API codes such as `invalid_json` and
`body_too_large`. No raw parser errors are exposed by either path.

## Reviewed boundaries

- `internal/offlinecatalog` accepts only the bounded normalized format and exact
  Trixie release. The original fixed parser remains mandatory. Root/type/null,
  duplicate-key/identity, UTF-8, nested-array, string, depth, byte and record limits
  remain in force. XML/entity input is rejected as JSON rather than processed.
- Authority cannot be supplied by a document. Metadata permanently uses
  `originAssurance: unverified`, `freshness: unknown` and `publishedAt: null` for
  both synthetic and non-synthetic catalogs. A digest identifies bytes; declared
  provider/release and successful parsing do not authenticate a publisher.
- Catalog/Candidate retain no public rule accessor or matcher bridge. Pointer/
  value formatting and JSON serialization of these opaque types do not disclose
  imported names or rules. HTTP metadata and errors likewise omit raw content.
- Replacements are memory-only CAS operations. Failed parsing, canceled changes,
  invalid candidates and outdated revisions preserve previous metadata. Detached
  views cannot mutate stored state. A new Store has no previous catalog.
- Only the trusted managed-operations constructor enables imports. Development,
  manual and basic profiles do not gain an import path from request fields.
- Host, transport, session, Origin, CSRF, JSON content type, revision and body
  framing controls precede parsing. One import body/parser is admitted at a time;
  competing imports receive a bounded busy response before their body is read.
  The 2 MiB reader also enforces the actual body size.
- Import reads/parses precede the short operator mutation lease. A session is
  checked again after body consumption and under the lease before CAS commit.
  Logout during a held body can complete and prevents the late import. Clear
  invalidates a competing in-flight import through the revision check.
- Security coverage reads the existing device-bound operational view. There is
  no local manager-inventory substitution, source-package guess, OS-label release
  inference, version comparison or GET-triggered package/advisory operation.
- Only a complete exact binary enumeration produces `installedCount`. A valid
  complete zero binary observation remains distinct from missing inventory.
  Partial reported counts stay partial; retained records keep their original
  time/generation and become stale. Expired/revoked evidence never becomes fresh.
  Offered updates, affected CVEs and review candidates remain unknown/null,
  including after catalog upload and with an empty complete inventory.
- The browser helper counts UTF-8 bytes, bounds streamed responses, preserves
  raw JSON/BOM/duplicate keys and controls same-origin credentials and CSRF.
  Only the revision header is caller-selectable. Protected-epoch invalidation
  during the CSRF response body prevents the subsequent raw write.
- UI DTOs reject expanded shape, contradictory trust/freshness, cross-device
  responses, assessment zeros and totals invented from partial observations.
  Freshness ages from the server anchor plus monotonic elapsed time; stale data
  cannot become fresh. Displayed collection age is separate from inventory age.
- Configuration refresh invalidates the old form before fetching. Authentication
  loss, route/unmount/device/session changes, hidden documents, pagehide/BFCache,
  request deadlines and lease expiry cancel authority and clear selected bytes.
  Late reads/FileReader callbacks/write responses cannot reinstall old state.
  The catalog-only native-picker blur/focus exception neither refreshes nor
  extends its 60-second lease; actual lifecycle suspension still invalidates it.
- Main UI wiring lazily mounts coverage only for authenticated non-synthetic LAN
  Linux/unknown devices. Settings follows the catalog endpoint's validated
  enablement rather than guessing the manager profile. App keys device drawers
  by device ID. The existing AuthBoundary remounts its private tree when the CSRF
  identity changes, even if the new session has an identical expiry timestamp;
  the explicit panel session keys are therefore additional lifecycle protection.
  There are no introduced external content links, raw filename displays, browser-storage exports, model
  exports, install buttons or green security claims.

The core production dependency/AST tripwire was also reviewed and executed. It
permits the fixed foundation parser, not its inventory reader, matcher or native
comparator. This complements source review; it is not a general safety proof.

## Independent regression evidence

Added `tests/security/offline_catalog_boundary_test.go` with exported-core
regressions and ordinary generated-key loopback fixtures. Its Linux build tag
matches the existing operational HTTP helper. Checks cover opacity and immutable
views; commit-time metadata; CAS/cancellation preservation; strict untrusted JSON;
real TLS and explicit HTTP-test managed/basic gates; header and body rejections;
admission-before-body; logout during an admitted body; slot recovery; and actual
device-bound unknown, complete-zero, partial, retained, aged and revoked coverage.

Added `web/src/offline-security-review.test.tsx` with 16 independent tests using
synthetic response streams and local File objects only. They cover exact raw
body/headers, multibyte
upload limits, denied caller headers, bounded stream cancellation, understated
Content-Length, protected-epoch invalidation during CSRF-body consumption, 401,
conservative authority/count/freshness DTO behavior, and actual AuthBoundary
private-epoch replacement of a selected-file form on a same-expiry session change.

Commands run against this source candidate:

```sh
go test -race ./internal/offlinecatalog -count=1
go test -race ./internal/api -run 'Offline|SecurityCoverage' -count=1
go test -race ./tests/security -run '^TestIndependentOffline' -count=1
go vet ./internal/offlinecatalog ./internal/api ./tests/security
GOOS=windows GOARCH=amd64 go test -c ./tests/security -o /tmp/offline-boundary-windows.test.exe
GOOS=darwin GOARCH=arm64 go test -c ./tests/security -o /tmp/offline-boundary-darwin.test
cd web
npm test -- --run src/offline-security-review.test.tsx src/offline-security-integration.test.tsx src/security-coverage.test.tsx src/api-bounded.test.ts
npm run typecheck
```

These checks passed. The final focused frontend run contained 82 tests, including
the new integration suite. Windows/macOS results are compilation evidence only;
those binaries were not executed.
The API/component owners' broader acceptance and integration suites are separate
evidence. This review does not relabel mocked UI tests as browser acceptance.

## Source identity and remaining gates

The reviewed workspace is a source export without Git metadata; no new commit or
remote revision is claimed. SHA-256 identities of reviewed implementation files:

```text
884df131366514789a29ad641470adb024a3409bb19040267b825189b1bc29e9  internal/offlinecatalog/catalog.go
6ff6c70c6bee3d5cee6aea682573357b782fa7b94d8407e7fe653806e6090f94  internal/offlinecatalog/parse.go
3af56c832216645c18138676a926a057b7399933c836d6faa230ef4248204312  internal/api/api.go
25e82ce28ca73032e447a2ca70b8e019b5e3ff6f8c7dee2b92704cdc97a2130f  internal/api/operator.go
81e1228e48a78db38713846f0b9fedd754b0756d2fb313ee83dcd7f4c216fec1  internal/api/security_catalog.go
c548a86dfbb2e5184102a58dba482d1ecba7111f5a7794d2dd13685cb245ce88  internal/api/security_coverage.go
6a53f2f1785e2e7f0337af05844b2f75b755ad77cc7eafc4170290d5abe22241  web/src/api.ts
47cfdab3c645e03dc5ce193e4580d5e25d36b88a33998e588bb09dcf3c668be6  web/src/auth.tsx
f1300f7ce345f482f56f0b5c8c9c1b5d45a29e4fd5434ebe810a7756ace73e83  web/src/security-coverage.tsx
83365cf9755fb20eedcaf0b97e29d83a26be5442b7fe84b64a2e181ef6846ca9  web/src/security-coverage-types.ts
9e60ad602b25529cab0767e440b628d6d733c0d4407ba39e96f13c8e15ac939e  web/src/App.tsx
ec457576de81818d911c59d51666e20790f725af4698947ecb4a942e99647470  web/src/details.tsx
```

No live advisory request, package inventory/scan, comparator invocation, update
operation, installation, Docker action, real service/account/credential change,
runtime private data export or frozen-archive modification was performed by this
review. A fresh dependency-vulnerability retrieval was not authorized and was not
performed; it remains an explicit verification limit. Real vendor origin,
exact client release/source mapping, native cached update adapters, comparator
acceptance for a future matching path, and real-data/browser/deployment acceptance
remain separate gates.
