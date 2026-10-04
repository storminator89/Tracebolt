# Independent package store/API contract review

Review date: 2026-10-04. Scope: the in-progress, fresh-store
`managed-operations-v2` candidate, not a published runtime or a deployment.

## Scope and method

The independent exported-contract tests are in
`tests/security/package_store_boundary_test.go`. They use ordinary generated
Ed25519 fixture credentials, synthetic snapshots, disposable databases and owned
loopback TLS/HTTP-test endpoints. No package collector, native inventory read,
APT command, advisory scan, host change or frozen source archive participates.
Only the test file and this review note were changed by this review.

Reviewed store/API authority, replay, retention/accounting and export policy.
Pure package decoding, source readers, sender staging and transport-envelope
contract tests have a separate review. No claim of vendor authenticity, actual
Linux collection, CVE coverage, offered updates or complete repository security
review follows from these tests.

## Boundary results

The final focused race suite passes (6.125 seconds) with these checks:

- Fresh profile bindings only; restart refuses all cross-profile substitutions
  among basic, managed-v1 and managed-v2, without altering the existing database.
  Record limit 26 is refused.
- Exact captured package facts and every mutable returned member are isolated.
  A new unknown snapshot clears previous package facts. There is no package
  LastGood merge.
- Freshness uses both source and receipt time. The exact 120-second boundary is
  covered, including future-clock uncertainty. At 24 hours the view hides the
  snapshot without deleting the exact durable frame. Historical exact retries
  retain the original receipt after reopen. Source quality is never aged into a
  fabricated collection-quality value.
- Wrong certificate, legacy/basic profile mismatch, old capture/generation,
  old sequence, stale source, backward receipt and duplicate package keys are
  rejected without changing authority, replay, receipt, exact frame or cache.
  A second-handle revocation overrides prior transport authorization and rejects
  both an exact retry and a new observation.
- Explicit package privacy/profile consent is required under TLS and HTTP-test.
  Package reads keep operator authentication/origin/site/method boundaries and
  forbid query parameters. Known legacy identities remain `not_configured`;
  unknown identities are 404. Storage failure is fixed 500, not missing data.
- Package and baseline reads share the same one-read admission slot. Of 32
  simultaneous mixed reads behind a held database lock, 31 return typed BUSY;
  the package HTTP response is fixed 429 with `Retry-After: 2`. Revocation keeps
  its separate progress slot and commits after lock release.
- Managed-v2 blocks AI analysis before reading case text, independent of case
  existence. Packet construction rejects managed-v2 provenance on the case,
  embedded case evidence, or selected evidence before copying private text.

## Exact retained-byte accounting

Six independent accepted captures retain one healthy operational section from
each generation. The last generation has exactly:

- 32,768 canonical operational bytes;
- 16,384 canonical package bytes;
- 81,920 canonical LastGood-record bytes;
- 131,072 retained logical bytes in total.

A valid next frame keeps both current components at their respective byte caps,
but moves one ordinary label byte into the retained software section, producing
131,073 logical bytes. Admission fails atomically with no partial receipt,
replay, identity, frame or cache update. Reopening preserves the exact old retry
receipt. At 24 hours, pruning of retained-only operational sections permits a
new capture without resurrecting expired sections.

At the 25-device limit the logical total is exactly 3,276,800 bytes, below the
4,194,304-byte global ceiling. The global ceiling is unreachable through valid
25-device/per-device-cap admissions; no quota or identity limit was weakened to
manufacture a global overflow.

## Dense native acceptance

Every identity has a distinct generation/payload hash and an exact 73,728-byte
raw frame. JSON whitespace fills only the outer wire frame; the operational,
package and LastGood logical targets above use ordinary validated metadata.
The acceptance runs include durable reopen, concurrent PackageView, actual
network ingress and operator Terminate, then verify exact retry, rejected old
frame, retained quotas and the revoked identity tombstone's capacity cost.

All four native cases passed on the receipt-clock-corrected run, 76.886 seconds
total. First-attempt durations:

| Topology / transport | Reopen | Package read | Actual ingress | Revoke |
| --- | ---: | ---: | ---: | ---: |
| Same handle / TLS | 243.824 ms | 451.077 ms | 603.162 ms | 148.260 ms |
| Same handle / HTTP-test | 247.598 ms | 309.228 ms | 776.857 ms | 160.242 ms |
| Cross handle / TLS | 232.759 ms | 339.542 ms | 742.907 ms | 158.396 ms |
| Cross handle / HTTP-test | 237.459 ms | 329.816 ms | 795.599 ms | 152.947 ms |

Every first attempt succeeded. No native BUSY allowance, arbitrary storage
error allowance or production timeout change was introduced.

## Dense race acceptance

All four separate cases passed under the unchanged default 10-minute Go test
timeout per invocation. Every first attempt succeeded, including both
cross-handle cases. No BUSY retry allowance was exercised.

| Topology / transport | Command elapsed | Reopen | Package read | Actual ingress | Revoke |
| --- | ---: | ---: | ---: | ---: | ---: |
| Same handle / TLS | 272.257 s | 3.580469 s | 2.344622 s | 9.490464 s | 4.672073 s |
| Same handle / HTTP-test | 271.786 s | 3.546780 s | 7.074290 s | 11.762146 s | 2.346367 s |
| Cross handle / TLS | 279.985 s | 3.614806 s | 2.320761 s | 9.260838 s | 4.632930 s |
| Cross handle / HTTP-test | 277.682 s | 3.580884 s | 2.344343 s | 11.862764 s | 4.748814 s |

The SQLite BEGIN busy limit remains 5 seconds
and the actual test HTTP client timeout remains 20 seconds. Shared-handle race
operations require first-attempt success. The pre-existing race-only,
cross-handle policy permits only exact typed initial BUSY, byte-identical
identity/frame/receipt/cache preservation, followed by one exact retry after
contention; arbitrary `ErrStorage` is never accepted.

### Superseded fixture runs retained for auditability

The first native timing invocation reached successful operations in every case,
but its post-measurement rejected-old-frame assertion used truncated capture
time as a new receipt timestamp. The store correctly rejected backward receipt
time. The fixture was fixed to supply the actual receipt time, and all native
cases were rerun successfully as recorded above.

The initial aggregate race command used the default 10-minute package timeout:

`go test -race -buildvcs=false ./tests/security -run '^TestIndependentPackage' -count=1 -v`

It was intentionally interrupted with Ctrl-C (exit 130), before that timeout,
after the first dense case and during the second population. The first measured
same-handle TLS race operations were all successful: reopen 3.633862 s, read
2.351806 s, actual ingress 9.310078 s, revoke 6.995027 s. Its post-measurement old
frame check encountered `ErrStale` because dense race population exceeded the
120-second observation window; the fixture had incorrectly demanded only
`ErrReplay`. The corrected assertion allows exactly `ErrReplay` or `ErrStale`
and requires unchanged durable rows. The aggregate invocation is not reported
as a pass, and no runtime behavior was changed for either fixture correction.
A subsequent corrected same-handle/TLS setup was also interrupted with exit 130
before measurements to give the UI and process-gate owners their requested clean
window. It contributes no acceptance result. All four corrected race cases were then
rerun separately and passed as recorded above.

## Reproduction

Use the Go 1.27.1 toolchain pinned by this repository, with
`GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off` and `-buildvcs=false`.

Focused non-capacity race checks:

`go test -race -buildvcs=false ./tests/security -run '^TestIndependentPackage(StoreLatest|StoreRejected|StoreProfile|StoreExact|StoreFresh|HTTP|AISource)' -count=1 -v`

Native dense matrix:

`go test -buildvcs=false ./tests/security -run '^TestIndependentPackageStoreDenseCapacityAndActualIngress$' -count=1 -v`

Run dense race cases individually, preserving the default per-command timeout:

`go test -race -buildvcs=false ./tests/security -run '^TestIndependentPackageStoreDenseCapacityAndActualIngress$/^same-handle$/^tls$' -count=1 -v`

Repeat that last command for `same-handle/http-test`, `cross-handle/tls`, and
`cross-handle/http-test`. Do not substitute one topology or transport for another.
Avoid concurrent compiler-heavy/UI test work during these timing measurements.

## Remaining limits

No source defect was found in the reviewed store/API slice. Native and race
capacity matrices, final focused race checks, and `go vet -buildvcs=false
./tests/security` passed with Go 1.27.1 on linux/amd64. The reviewed package,
operational, frame-validation and telemetry store sources and package,
enrollment and AI API sources retained identical SHA-256 hashes throughout the
measurement window.

Native process/source-reader acceptance and UI lifecycle review are separate
from this review's evidence. The package contract's isolated-only status text
needs reconciliation with candidate integration status before publication.
Final runtime/archive identity and any wider aggregate checks belong to the
owning integration task; no frozen archive was edited by this review.


## Final frozen-source acceptance addendum — 2026-10-04

This documentation-only addendum supplements the historical review above; it
changes no runtime, tests, limits or prior evidence. The reconciled component
and transport contracts now identify the integrated, unpublished candidate.

Independent freeze verification matched every source entry: 504 files in v1,
then 507 in v2. The v2 manifest SHA-256 is
`33db870a56524924b091b2c44c117fcd665053f9d1bfc58791a00a9123041be9`.
V2 adds exactly `internal/linuxpackages/testdata/debian13.os-release`,
`ubuntu2404.os-release` and `synthetic.status`; no existing file changes or
removals occurred. All 76 added/changed source files relative to the recorded
base are explicit overlay entries. The prior archive's cover, embedded proof
and embedded manifest are intentionally replaced as provenance artifacts.
The final store test/report bytes and the seven recorded store/API runtime
hashes matched the freeze before this separate documentation addendum.

The first full normal aggregate is preserved as **failed**: exit 1 in 302.293
seconds, with four failing test/subtest events in the package-parser tests caused
only by those three omitted synthetic files. This was an export-assembly defect.
After the three-file repair, a **new whole-repository normal serial aggregate**
passed: exit 0 in 302.573 seconds, 40 passed package events and 2,434 passed
test/subtest events, eight skipped test events and four no-test package skips,
with no failure events or source changes. The command was
`go test -json -p 1 -buildvcs=false ./... -count=1 -timeout=15m`.

This fresh normal aggregate is distinct from the focused race suites and all
four separately passed dense race cases documented above. No new full-repository
race invocation is claimed. The earlier interrupted/fixture-correction runs
remain recorded; all four final dense cases succeeded on every first attempt,
without using their narrow typed-BUSY retry allowance or changing the 5-second
BEGIN / 20-second client bounds.

Preserved result metadata also confirms vet, module checksums, native builds,
Windows/Darwin security-test compilation, Linux/arm64 manager compilation, all
491 UI tests, typecheck and production build. Cross-compilation is not native
execution. All recorded checks report no source changes.

The exact-v2, opt-in three-binary TLS and signed-HTTP workflow passed in 47.073
seconds. Its four count-only observations were release `unknown`, inventory
`unknown`, selected rows 0 and complete false. No package names or raw fields
were exported. These observations do not establish a healthy empty inventory,
positive Debian/Ubuntu package collection, CVE coverage or offered updates.
Systemd, container, browser and reboot acceptance are not supplied by this pass;
opt-in systemd/container tests remained skipped in the normal aggregate.

The independently checked sanitized proof SHA-256 is
`3c9aead0539af198bbe9f8b918134b867c8342c561ec3d3154b995ad87697242`.
No network/advisory, publication or deployment action was taken by this review.
