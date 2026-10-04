# Offline security candidate: final acceptance cross-check

Date: 2026-10-04. Scope: the unpublished offline catalog and honest coverage
source candidate. This document is an additive acceptance overlay; it does not
change the frozen candidate or replace its focused security review.

## Result

The final source and safe aggregate-event cross-check passed. No unresolved
finding remains in the reviewed catalog/coverage boundary. The corrected
covered-source-count UI validation and same-expiry session-replacement regression
are included in the frozen source.

All 456 unique files in the source manifest independently matched their recorded
byte counts and SHA-256 values, with no missing entries or manifested symlinks.
The focused review and both independent test files match the final reviewed
versions. Source identity:

```text
72d9beccf0054aa584dc3d27c02d0d39f3734c2384ec3f3c06bf3800b9162259  source manifest
2fb4cdcf7c1f44003d3465800ed49f020e811511d451f347b6091f9d6c146832  docs/offline-security-review.md
6118490ed94d86e4e223264d8e3710b788ea3557ba7c548bad4b4c63c1dff909  tests/security/offline_catalog_boundary_test.go
fb13ac7be6869ecddb775b8e12ecd94a1ebf907087256909dd7285376e4a2420  web/src/offline-security-review.test.tsx
a6100fb666cfd209d11d0d4f1071f6e20c50742bf8bd216a6b429871014980fb  sanitized acceptance proof
```

The source manifest's initial aggregate-pending label describes when it was
captured. The separate sanitized proof and this overlay record the completed
aggregate without rewriting that source identity.

## Independently checked aggregate evidence

Only event action/name/count fields and the fixed exit status were inspected
from the private Go result stream. Raw test output was not exported.

- Go race aggregate exit status: 0; 38 package pass events, 2,065 test/subtest pass
  events, zero failure events and zero malformed event lines.
- All five independent offline boundary test roots passed in that aggregate.
- Actual three-binary guided and operational workflows passed with both TLS and
  explicit isolated HTTP-test transport. These four workflow results were checked
  directly by their named pass events.
- The private result log was mode 0600. The recorded serial race command used
  Go 1.27.1 on Linux amd64 with umask 022, one build/test package worker and
  `-buildvcs=false`; no weaker filesystem assumption was substituted.
- Seven test skip events were preserved: the two container lifecycles, explicitly
  approved disposable systemd installation gate, three subprocess-helper entry
  points, and the non-Linux-only runtime test. Four package-level skip events were
  also present. Skipped stages are not passing runtime acceptance.

The hash-verified sanitized proof additionally records passed vet and module
checksum checks; all 351 frontend tests in 16 files; typecheck and production
build; and seven native Linux command builds. It records compile-only Windows
amd64/macOS arm64 security-test binaries and a Linux arm64 manager build. Those
cross-built binaries were not executed. The review's own final focused UI run
passed 82 tests, including real AuthBoundary integration, before source capture.

## Boundaries retained

The catalog is memory-only and permanently unverified with unknown freshness.
Uploaded provider/release labels, hashes and timestamps do not confer vendor
authority. Device binary observations do not establish source mapping, exact
release, installed-artifact origin, offered updates or confirmed CVE totals.
Missing capabilities retain unknown/null results rather than green zero counts.

No fresh advisory/dependency retrieval, new scan, hosted-browser acceptance,
Docker runtime, privileged systemd acceptance, OS reboot, package update/install,
real deployment or real vendor-data acceptance was added by this cross-check.
The fresh advisory check remains blocked with no result claimed. Actual local
TLS/HTTP-test workflow evidence does not imply production exposure approval.

Derived local binaries, TypeScript build metadata and web production outputs are
outside the 456-file source manifest and are excluded from the source-only
publication package. Only manifested source, this acceptance overlay, the
sanitized proof and cover notes belong in that package. Final archive identity
and membership are a separate read-only publication check. No runtime logs,
credentials, raw telemetry or imported catalog bytes belong in the archive.
