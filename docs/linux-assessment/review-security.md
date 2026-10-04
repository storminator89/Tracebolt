# Independent conditional advisory review boundary

Reviewed 2026-10-04 UTC in the source workspace. This review covers
`internal/offlinecatalog/review.go`, the read-only
`GET /api/devices/{id}/security/review` handler, its managed-profile wiring, the
existing package read/admission path, and the boundary with authoritative
`assessment.AssessDebian`. It does not approve deployment, publication, a real
advisory scan, or a claim about an installed host. The accompanying HTTP contract
is [review-http-contract.md](review-http-contract.md).

## Result

No implementation defect was found in this reviewed conditional boundary.
Independent exported-core and actual loopback API fixtures passed, including a
focused race run. The result is deliberately limited: reported source metadata
can yield conditional review candidates against one unverified catalog; it cannot
yield confirmed affected-CVE counts, offered updates, verified installed origin,
or proof that an endpoint is secure.

An invalid generation prefix in the owner's initial API test fixture was reported
and corrected by the owner before these checks. That was a fixture issue, not a
runtime validation bypass. This independent review changed only its own test
file and this document.

## Authority and data flow

- The selected `managed-operations-v2` handler is the only configured runtime
  path that acquires a review slot and reads package observations. Older profiles
  return `not_configured`; unknown device identities remain 404.
- Observation admission already requires the current activated enrollment,
  certificate hash, immutable profile, allowed lifetime, and increasing replay
  lineage. Package reads revalidate the current durable record, return independent
  copies of the latest package component, and preserve original sequence and
  receipt. The conditional view does not recollect or merge old source facts.
- The pure core revalidates the complete bounded `linuxpackages.Snapshot`.
  Healthy release facts must be exactly `debian`, `13`, and `trixie`. Missing,
  inconsistent, derivative, Ubuntu, unknown-source and incomplete-installation
  inputs do not gain an applicable installed candidate by inference.
- Rules are indexed by the reported source package. Comparisons receive the
  literal reported **source version** and literal declared fix. A binary rebuild
  version, binary package-name coincidence, or declared archive version cannot
  supply a substitute. Existing source grammar stays intact; a portable ordering
  limitation does not erase accepted metadata.
- The catalog parser's foundation-parser call is interchange validation only.
  Its provenance-bearing parse result is discarded. The review core does not
  call `AssessDebian`, construct authoritative inventory provenance, or invoke
  its native comparator. Production HTTP wiring injects the pure portable
  comparator through the existing interface.
- Catalog origin remains `unverified`, publication/freshness unknown, and
  installed-artifact origin unknown. `synthetic:true` catalogs produce no live
  rows. Invented test documents declaring `synthetic:false` test this unverified
  branch only; the flag never establishes trust.
- Unsupported epochs/legacy-colon versions and other comparator errors retain
  the candidate as `comparison_unavailable`, make inspection partial, and expose
  only a fixed reason. A returned integer zero with an error is not equality.
  Missing comparators and invalid comparison results are similarly unknown.
- Sentinel `0` and successfully compared equal/above thresholds are omitted;
  omission is not a fixed/not-affected assertion. Open/undetermined declarations
  remain candidates. `complete` describes the selected conditional inspection,
  never complete CVE coverage. Both authoritative count fields remain explicit
  nulls, including when no candidate is returned.

The existing coverage endpoint continues to report unknown vulnerability and
offered-update coverage. Repeated review requests neither modify durable
observations nor create cases. The existing package-profile AI-export gate remains
closed before case lookup. Static inspection found no network, package-manager,
subprocess, AI-provider, native collector, or case-write action in the new path.

## Bounds, cancellation, and lineage

The catalog's existing 2 MiB/10,000-rule validation cap bounds indexing. Source
snapshots retain their existing 16 KiB/128 selected-row validation cap. Review
work independently stops at 128 returned candidates, 4,096 inspected pairs and
1,024 comparator calls. The final JSON result is at most 64 KiB; byte trimming
keeps the largest ordered whole-row prefix and leaves actual work counters intact.
The HTTP envelope is checked against 65 KiB before response emission. These are
deterministic work/output caps, not a claim of constant execution time or a
particular maximum process RSS.

The review API acquires one manager-wide slot before configured package-store
work. It returns `review_busy` rather than queuing an unbounded backlog. Store
pressure is separately `storage_busy`. A fixed four-second cooperative context
is passed through both reads and pure review. Core loops check cancellation;
the injected comparator must honor it. The core does not create background
goroutines or enforce termination of a deliberately noncooperative injected
comparator. The production comparator is bounded and cooperative.

The core captures an immutable catalog pointer and expected revision, does not
hold its catalog lock during comparison, and rechecks revision before returning.
Clear and even byte-identical replacement invalidate old results. Every error,
including cancellation or revision change, returns a zero result. Returned
metadata, release pointers, reason lists, rows and qualifications are independent
of retained catalog and supplied snapshot storage. As documented, a caller must
not concurrently mutate a supplied snapshot while `Review` runs.

The API re-reads current package authority after computation and compares device,
sequence, original receipt, and complete snapshot identity. It independently
rechecks both receipt/collection freshness, catalog revision, context, and active
operator session before output. A changed observation/catalog discards the
result. This is a versioned read with a final check, not an atomic transaction
across enrollment state, catalog state, operator logout and network emission.
A later change may occur after that final check. Clients must preserve and
invalidate lineage, including freshness expiry, rather than treating a retained
response as perpetual authority.

## Independent test coverage

`tests/security/conditional_review_boundary_test.go` contains eight top-level
tests with deterministic ordinary supplied-data and disposable loopback fixtures:

- Literal source-only ordering despite a much newer binary version and an archive
  version bait; deterministic advisory ordering and qualification preservation.
- Exact catalog revision/metadata and generation/collection lineage; mutation of
  returned values cannot alter retained state or supplied release pointers.
- Accepted unsupported installed/fixed versions remain visible and unknown;
  nil/error/out-of-range comparators cannot manufacture equality or expose details.
- Missing/inconsistent/unsupported release facts, synthetic catalogs, unknown
  inventory, partial selected inventory, source-name mismatch and incomplete
  package state preserve their limitations.
- Each independent work limit, exact pair/comparison counts, and maximal whole-row
  byte-prefix behavior; the comparison-limit pair count includes the last pair
  inspected before its comparison was refused.
- Nil/pre-cancelled/expired contexts, deterministic cancellation during comparison,
  stale revision, mid-comparison clear, byte-identical replacement, and invalid
  supplied snapshot all discard the complete result.
- Actual loopback TLS and explicitly separate HTTP-test operator routes exercise
  awaiting/missing/synthetic/unverified states, original receipt and source
  lineage, the inclusive 120-second freshness boundary, stale suppression,
  newer-snapshot replacement, revocation, profile isolation, session/Host/Origin/
  cross-site rejection, query/body/method rejection and unknown-device behavior.
- Repeated reads preserve durable observations and case rows; authoritative
  coverage stays unknown; the existing AI gate rejects before a closed case
  store can be read; logout and a closed observation store return fixed failures.

Deterministic internal provider/slot hooks remain the API owner's tests in
`internal/api/security_review_test.go`. The owner reported that the focused API
race run passed three repetitions in 1.604 seconds, including zero provider reads
when admission is busy, deadlines of at most four seconds, receipt-only changes,
stale-at-finish observations, typed errors from the current-state read, and
session invalidation. This independently authored exported-API suite does not
claim to force every intermediate scheduling point or replace those tests.
All cryptographic material in the loopback fixtures is ordinary ephemeral
generated fixture material. No previously blocked malformed/existing-v1 crypto
boundary, real inventory, APT state, advisory endpoint, network provider, native
oracle, privilege change, container or frozen candidate was exercised here.

## Validation record

After the parent cleared the shared dense-candidate timing window, these checks
passed on Go 1.27.1, Linux amd64, with the pinned offline toolchain. The ordinary
run reported `ok` in 0.747 seconds and the race run in 4.493 seconds. Vet exited
successfully without diagnostics.

To reproduce, put Go 1.27.1 on `PATH` and provide the cached dependencies locked by
`go.mod` and `go.sum`; these commands deliberately disable dependency downloads.
The workspace-only toolchain helper is not required or included in source exports.

```sh
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2
go test -p=1 -count=1 -run '^TestIndependentConditionalReview' ./tests/security
go test -race -p=1 -count=1 -run '^TestIndependentConditionalReview' ./tests/security
go vet -p=1 ./internal/offlinecatalog ./internal/debianversion ./internal/api ./tests/security
```

These focused results are not a full-repository aggregate, deployment or
cross-platform runtime result. No background test/compiler process was left
running by the reviewer. The source workspace has no Git metadata; exact reviewed
production identities are:

```text
d39020eebc856ddd2047712c64358b4d3c084a0c118d942df9f434b352c5d890  internal/offlinecatalog/review.go
2338fd8513f127a1cb6284de6d897d48c77856ad76c3972cf791766631ffe8c6  internal/api/security_review.go
68c719fecffcaa60c96f20144d6e97564e84b3babaa781780ee2dc67ff9b929b  internal/api/operator.go
ddd2024946ce123d9286090f0270e2613ca52944fc7d4969bea97a011e99a492  internal/enrollmentstore/packages.go
a1cd5e6098074b2177a40b676faa1fabb7d8cfadb4147ee7afc930ce0e6fb39e  internal/debianversion/compare.go
60de9f16bfebb05ddaa097d6da27d1bbecb6bc2b6ca93f0627953fb37bd91fa2  internal/assessment/matcher.go
```

## Final frozen-candidate acceptance addendum

Later on 2026-10-04 UTC, the combined candidate received a separate exact-source
acceptance run. This reviewer inspected its terminal status files, counted Go
JSON event records, checked the UI JSON result, and verified all 532 frozen source
file sizes and SHA-256 values against the candidate manifest. No tests were
rerun for this addendum, and the frozen tree was not edited.

The candidate manifest identity is
`9c899da0c74e0722906d76e319470b348e059e6870733922e857e04e32bea87e`.
Its base package-source archive identity was independently checked as
`42a12dbbbfad1b8057bb36816ad1eef725c07f666a32b567220a35b85e6836e0`.
The exact source delta is the 29 declared overlay files: 25 additions and four
modifications, with no removed source files or undeclared changes. All reviewed
runtime identities above and the independent boundary test identity were
unchanged. The final source archive may carry this acceptance addendum as an
explicit documentation-only overlay; it is not a new tested runtime revision.

Verified terminal results:

- The full **normal**, serial Go aggregate exited zero in 304.558 seconds:
  2,685 passing test events and 41 passing package events, with no failures.
  Eight test events and four package events were skipped. This is not a
  full-repository race run; focused race evidence remains separately identified.
- Vet, local locked-module checksum verification, native builds, Windows amd64
  and Darwin arm64 security-test compilation, and Linux arm64 manager compilation
  all exited zero. Cross-compilation does not establish runtime acceptance on
  those targets.
- All 571 UI tests passed with zero failures. Type checking and the production
  build exited zero. These checks are not real-browser acceptance.
- The exact-source three-binary loopback gate exited zero in 47.295 seconds,
  with three passing test events and one passing package event, for TLS and the
  explicitly separate signed HTTP-test profile. The sanitized proof records
  four count-only package observations: release and inventory quality unknown,
  zero selected rows, and incomplete collection. This is not positive native
  dpkg coverage or evidence that conditional review matched real packages.
- All three terminal status records reported no manifested source changes;
  the reviewer's independent post-run hash check confirmed that result.

The final sanitized proof identity is
`3ac1d25796a4d040ece48e93b0856b7a8079c2a3de934fc4ad8893295397f709`.
Its source, event-count, duration, toolchain, step-status and limitation metadata
agree with the inspected evidence. Raw logs, observations, runtime stores,
credentials, binaries and dependency directories are not part of this report.
Hashes establish content identity, not publisher-signature authenticity.

Remaining gates include positive fixed-source package collection on supported
Debian 13/Ubuntu 24.04 hosts; new real-browser and current Docker runtime
acceptance; corrected native systemd installation and OS-reboot acceptance; a
fresh dependency-advisory result; and publication/deployment. The normal
container test remains opt-in and skipped. Cached offered updates and
authoritative CVE applicability are still unimplemented/unestablished. Catalog
origin remains unverified, installed-artifact origin unknown, and confirmed
affected-CVE and offered-update counts null. Nothing in these passing local
checks broadens those boundaries or authorizes an external action.
