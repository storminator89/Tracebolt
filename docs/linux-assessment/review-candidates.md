# Conditional offline advisory review

This step adds the pure, bounded `offlinecatalog.Store.Review` core. It does not
change `assessment.AssessDebian`, normalized catalog grammar, package source
collection, catalog provenance, or the frozen package-observation candidate.
There is no API or UI implementation in these core files. Any separate runtime
integration must enforce its own activated-profile, freshness, authorization,
snapshot-generation, concurrency and response-envelope checks.

No network request, APT operation, package inventory read, filesystem operation,
external scan, credential access or publication is performed. The caller must
inject an `assessment.VersionComparator`; this core never constructs a native
comparator, starts a subprocess or selects a fallback. Its comparator must honor
the supplied context, and the integration should impose a request deadline.
There is no goroutine or wall-clock read in this core.

## Method and ownership

```go
func (s *Store) Review(
    ctx context.Context,
    expectedRevision string,
    snapshot linuxpackages.Snapshot,
    comparator assessment.VersionComparator,
) (ReviewResult, error)
```

`expectedRevision` must be the nonempty revision the caller intends to inspect.
The core captures the immutable catalog pointer and its revision together under
the store read lock. It independently calls `linuxpackages.Validate` before
using an observation and copies the selected package rows and release pointers.
Callers must not concurrently mutate the supplied snapshot during the call.

Comparator calls run without the catalog lock. A catalog replacement or clear,
even one reusing the same parsed candidate, advances the revision and invalidates
the review. The core rechecks revision and cancellation under the read lock
immediately before returning. Every error returns the zero `ReviewResult`, never
old or partial rows. Like any snapshot operation, a change may occur after this
final check; the integration must recheck the relevant store and observation
generation at its own response boundary.

The returned catalog metadata, release pointers, reason-code array, candidate
array and each qualification array are independent caller-owned copies. Mutating
a result cannot mutate the store, original snapshot, or a subsequent result.
Strings refer only to immutable values. Byte-trimmed rows cannot be recovered by
reslicing the returned array.

## Exact result contract

The exported types and JSON field names are in
`internal/offlinecatalog/review.go`. No member is omitted from JSON.

| Result member | Meaning |
| --- | --- |
| `schemaVersion` | `tracebolt.offline-review.v1` |
| `scope` | `conditional-reported-source-catalog-review` |
| `status` | `unavailable`, `partial`, or `complete`; completeness describes this bounded conditional inspection only |
| `reasonCodes` | Ordered, deduplicated, fixed diagnostics; never raw comparator errors |
| `revision` | Captured catalog-store revision |
| `catalog` | Copied existing `Metadata`, including catalog ID, exact-upload SHA-256, import time and declared release, or null |
| `catalogUsage` | `unavailable`, `unverified-conditional-review`, or `synthetic-fixture-not-for-live-review` |
| `snapshot` | `generationId`, `collectedAt`, copied `release` facts, `inventoryComplete`, and selected `inventoryRows` |
| `installedArtifactOrigin` | Always `unknown` |
| `snapshotFreshness` | Always `unknown`; the core does not evaluate age or endpoint admission |
| `candidates` | Non-null array of conditional review rows, possibly empty |
| `affectedCves` | Always null |
| `offeredUpdates` | Always null |
| `pairsInspected` | Package/rule pairs inspected, including non-candidates and candidates later removed by the byte cap |
| `comparisons` | Calls actually made to the injected comparator |
| `limits` | `maxRows: 128`, `maxPairs: 4096`, `maxComparisons: 1024`, `maxBytes: 65536` |

A candidate has exactly these fields:

- `package`, `architecture`
- `reportedSourcePackage`, `reportedSourceVersion`, `sourceMapping`
- `advisoryId`, `declaredStatus`, `declaredFixedVersion`, `qualifications`
- `basis`, `reason`

There is no verdict, binary-version comparison, trusted origin, archive-version
evidence, download target or offered-update field. The declaration of a fix is
unverified catalog content, not an installable or offered update. Candidate row
count is neither an affected-CVE count nor a unique-advisory count; distinct
binary/architecture rows can reference the same reported source and advisory.

## Applicability and candidate meaning

Only healthy release facts with the exact values `ID=debian`, `VERSION_ID=13`
and `VERSION_CODENAME=trixie` route to review. The catalog's declared release must
match that codename. ID-like values, display strings, derivatives, Ubuntu,
missing values, empty values and inconsistent combinations do not imply support.
Missing/unavailable/unsupported facts yield explicit reasons, never zero CVEs.

Only reported `installed` package rows participate. Incomplete package records
are skipped with a partial reason. The existing source mapping is retained
verbatim. A `binary-default` mapping is still an unauthenticated local report.
No `+bN` suffix is stripped and no source version is inferred from a different
binary version. Only the exact reported source version is compared with the
declared fixed version.

Candidate bases are deliberately limited:

| Basis | Condition |
| --- | --- |
| `conditional_reported_source_below_declared_fix` | `resolved` with a nonempty, non-`0` declared fix; the injected comparator returns -1 for reported source versus declared fix |
| `declared_unresolved` | `open` or `undetermined`, with no declared fixed version |
| `comparison_unavailable` | Comparator is absent, fails, returns an invalid order, or the declaration has an uninterpretable status/fix combination |

A successful comparison of zero or one omits a review row; it does not return a
fixed/not-affected conclusion. The normalized `resolved`/`0` declaration sentinel
also produces no candidate or installed not-affected claim. Other statuses and
contradictory declaration combinations remain review-only unknowns. Qualification
tokens are copied declarations, not independently verified evidence.

Even a `complete` inspection or empty candidate array establishes no CVE
coverage, security state, exploitability, source authenticity, package origin,
running-process activation, or update availability. Catalog origin remains
`unverified`, its freshness `unknown`, its publication time null, and all
confirmed-CVE and offered-update counts remain null. Import time and a matching
name/version never upgrade any of those facts.

### Synthetic isolation

`linuxpackages.Snapshot` describes managed observations and has no synthetic
inventory authority. Consequently a catalog declaring `synthetic: true` always
returns `unavailable`, the fixed `synthetic_catalog` reason, its explicit
synthetic metadata/usage label, and no candidates or comparator calls. Merely
tagging synthetic matches would not be enough to prevent fixture/live mixing.

The parser cannot authenticate an uploader's `synthetic: false` declaration.
Such input remains visibly unverified and conditional. Tests use invented
records with both values to exercise the boundary; no test establishes real
vendor authorship, live inventory, or actual CVE applicability.

## Bounds and deterministic truncation

The validated input snapshot already permits at most 128 selected rows and
16 KiB of canonical JSON. Catalog parse limits remain 2 MiB, 10,000 rules and
10,000 covered sources. The review builds a bounded index of rule indices; it
does not copy or interpret archive-version arrays.

Packages retain the validator-required name/architecture ordering. Within each
package, rules are sorted by advisory identity. Evaluation stops before exceeding
128 result rows, 4,096 inspected pairs or 1,024 comparator calls. If another pair
exists after the row cap, the core conservatively returns partial, even if the
uninspected pair would not produce a row. Exactly reaching a cap with no further
work does not itself mean truncation. The pair that needs an unavailable 1,025th
comparison is counted as inspected, but the comparison is not called and no
uncomputed row is emitted.

After evaluation, the core bounds the complete `encoding/json.Marshal` result
to 65,536 bytes. On overflow it adds `review_byte_limit`, marks partial and keeps
the largest fitting ordered whole-row prefix. Bounded binary search examines at
most eight candidate prefixes for 128 rows, plus initial/final checks. Work
counters keep their actual inspection meaning; trimming is not a recomputation.
The API envelope is outside this core byte budget.

Cancellation is checked at entry, between bounded indexing/evaluation work,
after comparator calls, throughout byte-bound checks, and just before returning.
Sorting is bounded by the fixed catalog size. An injected comparator that
ignores context cannot be forcibly interrupted without leaking work; enforcing
the comparator's context contract remains an integration requirement.

## Reasons and errors

Every result includes `installed_artifact_origin_unknown` and
`snapshot_freshness_not_evaluated`. A present catalog additionally includes
`catalog_origin_unverified` and `catalog_freshness_unknown`.

Unavailable reasons:

- `catalog_unavailable`, `synthetic_catalog`
- `release_unavailable`, `release_facts_missing`, `release_facts_inconsistent`
- `unsupported_release`, `catalog_release_mismatch`, `inventory_unavailable`

Partial reasons:

- `inventory_partial`, `package_installation_incomplete`, `source_package_not_covered`
- `comparator_unavailable`, `comparison_failed`, `declared_rule_uninterpretable`
- `review_row_limit`, `review_pair_limit`, `review_comparison_limit`, `review_byte_limit`

Partial inventory remains partial when no selected row matches, including when
the selected row array is empty. Full-source inventory totals are never turned
into review coverage or fabricated matches.

Errors return zero output: `ErrUnavailable` for nil/uninitialized store;
`ErrChanged` for absent, stale or replaced revision;
`ErrReviewContextRequired` for nil context; the snapshot validator's fixed
invalid/limit errors; context cancellation/deadline errors; and the fixed
`ErrReviewEncoding` if serialization cannot be produced. Comparator diagnostic
content is never returned. Missing catalog is an unavailable result, not an
error.

## Boundary tripwire and checks

`internal/offlinecatalog/safety_test.go` previously allowed only catalog parsing.
Its narrowly reviewed extension allows `sort`, `linuxpackages`' exact snapshot
DTO/validator/release selectors, and `assessment.VersionComparator`. All
existing bans on native comparator construction, inventory acquisition,
authoritative matching, network, processes, filesystem and external-service
dependencies remain. Only one call site for the existing normalized parser is
allowed. Production code cannot import the portable comparison implementation;
tests may inject it like any other `VersionComparator`.

Focused tests cover exact source-versus-binary use, epoch/tilde injection,
binNMU-looking source preservation, nil/failed/unsupported/invalid comparators,
release routing and missing facts, synthetic isolation, unknown provenance,
nullable counts, sentinel and >=fix omissions, replacement/clear/cancellation,
all resource bounds, byte-prefix maximality, deterministic ordering and mutable
input/output isolation. They do not read package inventory or use native dpkg.

Validation on the cloud Linux workspace with Go 1.27.1:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 \
  go test -p 1 ./internal/offlinecatalog
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 \
  go test -race -p 1 ./internal/offlinecatalog
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 \
  go vet -p 1 ./internal/offlinecatalog
```

These focused checks passed, including the race detector. They are not an
aggregate runtime, API/UI, deployment, or real endpoint assessment claim.
