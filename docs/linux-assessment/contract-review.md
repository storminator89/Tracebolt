# Linux package observation contract review

Reviewed 2026-10-04 UTC in the source workspace. This is a design and pure-parser
fixture review, not native package acceptance, transport enablement, deployment
approval, dependency-vulnerability scanning, or evidence of real CVE detection.
Existing runtime/API/UI and frozen candidates were not changed by this review.

## Decision

The isolated release/dpkg parsers and pure package DTO/validator/export-budget
slice have passed their source review and focused independent fixture checks.
The separate fixed-source reader may proceed as an isolated implementation under
`collector-boundary.md`; its implementation is not reviewed by this result.
Do not wire a collector or new profile into
the sender, manager, enrollment, API or UI until that exact contract is reviewed.
Cached APT observation and offline review-candidate matching are separate gates;
neither is needed to finish the first package observation milestone.

The revised fixed-budget, fresh-store proposal is smaller and clearer than
changing the meaning of an existing schema or adding an in-place profile
migration. The following decisions are required invariants, not implemented
capabilities.

## Profile and compatibility boundary

- Basic enrollment retains telemetry v1 and its existing exact shape.
- `managed-operations-v1` retains telemetry v2 and its existing limits.
- Proposed `managed-operations-v2` uses a new exact frame/config/profile mapping,
  a distinct manager/store directory, and freshly approved enrollment. Its final
  frame/config names must be fixed before integration.
- The operational-v1 subdocument remains unchanged, including its
  `collectionProfile: managed-operations-v1` label. It is the contained baseline
  scope of the new profile. Only the durable enclosing enrollment binding grants
  authority; a nested or incoming profile label never does.
- A store's profile, schema and mode binding remain immutable. Supporting old
  profiles in a binary does not permit mixed profiles in one store. Do not adopt
  an existing mode marker, change an invitation, recast a certificate, reuse a
  sender ledger under a new binding, or reset its sequence.
- Consent must identify the additional exact release and source-package fields,
  the process-visible namespace limitation, application-revealing labels,
  retention, and the existing HTTP-test confidentiality warning. It must not
  describe cached candidates or CVE assessment as available before their gates.

The relevant current boundaries are `enrollmentcrypto.ValidCollectionProfile`,
`enrollmentstate.Binding`, `enrollmentconfig`'s mode binding,
`enrollmentstore.Open`, `lanstore.FrameMatchesCollectionProfile`, and the
profile-bound sender configuration/ledger. Merely adding a profile constant
would leave these constraints unresolved.

## Exact bytes, generation and counts

For the new profile only, require these limits on both raw incoming JSON members
and their canonical typed JSON encodings:

- Basic observation: 16 KiB
- Unchanged operational-v1 subdocument: 32 KiB
- Package snapshot, including metadata and release fields: 16 KiB
- Entire frame: 72 KiB, with at most 128 exported package rows

The component reservations sum to 64 KiB; the remaining 8 KiB is envelope
headroom, not permission to overfill a component. The old basic/operational
limits remain unchanged. Row trimming must be deterministic, occur before
staging, and preserve original count, time and partial-scope facts. If valid
minimal envelopes cannot fit, fail collection without staging or consuming a
new sequence. No opportunistic cross-section budget allocator is needed.

Package generation must equal the enclosing operational generation. Package
collection time must equal the operational collection time and be no later than
the basic bundle generation time; the existing sample-age/skew checks apply.
The basic bundle has no generation identifier. All package source facts must
belong to that one read attempt; a changed or failed source cannot reuse old rows
under a new generation. A generation label binds a report, not host authenticity.

The exact DTO still needs fixed field names, enums and cross-field validation:
required package object even on failure; explicit release missing versus empty;
defined completeness and count semantics; duplicate package identity rejection;
deterministic ordering; and safe string/count/timestamp bounds. Full-source
parse bounds are not export bounds. Count installed-plus-incomplete selected
dpkg records separately from excluded residual records. After a full successful
parse, exported count is `len(items)` and omitted count is parsed minus exported.
Failure must not expose a valid-looking parsed prefix or a fabricated zero.
Successfully parsed residual-only input can represent zero selected records.
`complete` describes this declared dpkg scope, never all software on the host.

## Latest-only retention and admission

Keep the package snapshot solely in the latest retained exact frame. The new
frame requires it, including an explicit unavailable result. A newly accepted
unknown package observation replaces prior package facts. Do not add a package
LastGood cache, hidden package history, per-package table or merged generations.
Latest-only limits the number of snapshots, not their lifetime. Under the current
store model the latest exact frame remains until replacement, including for a
retained revoked identity; the operational LastGood expiry does not delete it.
Consent must not promise 24-hour package deletion, and freshness aging is not
data deletion. A different lifetime policy would require a separate retry and
retention design.

The logical quota formula is:

`canonical operational JSON + canonical existing LastGood record JSON + canonical package JSON`

Keep 128 KiB per device and 4 MiB globally. New operational-plus-package
reservations total at most the former 48 KiB operational allowance. At 25
identities, fully occupied logical device quotas total 3,276,800 bytes, below the
global quota. This is not a bound on SQLite/WAL bytes, base64 credential rows,
responses, parse allocations or peak memory. Existing dense fixtures already
reach the old device quota exactly and cannot establish the new byte formula.

Admission must validate the new frame/profile/platform/generation within the
existing authority/revocation/replay transaction. A quota failure rolls back
identity, frame, replay, receipt and retained cache together. Do not silently
evict old operational sections to force admission. Revalidation on reopen,
transaction-local parse cloning and operator reads must include the package
object and its bytes. Required dense evidence uses 25 distinct frames, exact-cap
and over-cap cases, reload, receipt-preserving retry and read/revoke/ingress
contention without weakening current admission or busy handling.

## Exact retry remains exact

An already staged frame is never reparsed and rematerialized into a new format,
trimmed, relabeled, retimestamped or assigned a replacement sequence. Legacy
decoding and exact byte/whitespace preservation stay intact after upgrading the
binary. A changed profile cannot adopt the old ledger.

The current sender may discard stale pending observations while retaining the
consumed sequence floor. Preserve that explicit policy; do not promise
indefinite retry. A manager's accepted historical exact retry preserves the
first collection and receipt times and cannot refresh package freshness. The
HTTP-test signature timestamp window remains a separate limitation. Freshness
or DTO validation changes must not move ahead of the store's historical
exact-retry decision in a way that rejects previously accepted bytes.

## Distribution and advisory boundaries

Only exact `debian`/`13`/`trixie` can select the existing Debian rule scope.
Exact `ubuntu`/`24.04`/`noble` permits independent package/cache observation
acceptance, not use of Debian advisory rules. Derivatives, partial release
fields, inconsistent tuples, display names and version suffixes do not supply
vendor identity. Even an exact tuple remains endpoint-reported metadata.

The pure package rows deliberately have no origin/trust fields. An enrolled key,
source mapping, equal version or package name does not verify an installed
artifact's vendor provenance. Uploaded offline catalogs stay unverified and
synthetic catalogs cannot assess real observations.

A later candidate-only adapter must bind each result to the exact observation
generation and actual immutable catalog revision/digest used. It must define
candidate-row counts separately from unique CVEs, cap work and returned rows,
retain reasons and partial scope, and remain candidate-only. A no-match result
among selected rows is not zero device vulnerabilities. Advisory fixed versions
cannot manufacture offered updates. Current `offlinecatalog` deliberately has
no public rule accessor or matcher bridge; matching is not enabled by adding
source fields. There is no need for native version subprocesses to provide a
name-based unverified review candidate. Keep package/candidate text excluded
from AI packets and existing basic-profile allowlists.

## Cached APT adapter is deferred

Fixed argv and a clean environment alone do not prove that `apt-cache` is a
bounded read-only adapter. Its documented default is implicit cache generation
when a needed cache is missing or old, and `--no-generate` changes that behavior.
The eventual adapter must demonstrate its actual no-write behavior rather than
assuming it from the command name. [Debian apt-cache manual](https://manpages.debian.org/trixie/apt/apt-cache.8.en.html)

APT also reads system configuration fragments; its settings include external
compression helpers and an unlimited-by-default cache growth limit. Therefore
the later review needs an exact configuration/input contract that retains the
intended pinning semantics while bounding helper execution, input paths, CPU,
memory and process lifetime. Supplying a clean environment or a late `-c`
argument alone is not that contract. [Debian apt.conf manual](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)

Require fixed trusted executable/arguments; validated package-and-architecture
identities; bounded batch/process count, stdout and stderr; a total deadline;
and discarded raw diagnostics, repository URLs and descriptions. Cache
observation time, index age and reported candidate version are different facts.
Missing/future/partial cache metadata must remain unknown. Pinning, held state,
old/equal/new candidates and concurrent cache changes need independent fixtures.
A candidate does not prove downloadability, installability, vendor authority,
application or activation. No refresh, install, network probe, trust change or
native cached-APT invocation was performed for this review.

## Implementation gates

1. Completed at the second checkpoint below: freeze the exact package DTO and implement only its pure validator and
   deterministic 16 KiB/128-row exporter over the supplied parser results.
   Exercise complete/partial/unknown/null/count, identity, time and exact-byte
   cases. Preserve no-prefix-on-source-error behavior.
2. Review the final profile/frame/config matrix and consent text, then implement
   the isolated new-profile transport/store path with ordinary generated
   fixtures. Cover raw JSON type/null/duplicate/unknown-member rejection,
   generation binding, old-profile compatibility, sequence/retry and quotas.
3. The fixed-source reader can be developed separately against inert fixtures
   after the pure DTO gate. Review its code and enable native reads only in an
   explicitly authorized disposable Debian/Ubuntu environment. Native file
   consistency, namespace and process workflow evidence remain necessary before
   runtime wiring. APT, offline matching and UI have their own later gates.

Avoid a profile migration service, shared-store mixed profiles, schema relabeling,
new package LastGood retention, dynamic budget reallocation, origin booleans,
automatic advisory fetching or a general subprocess framework in this slice.

## Review evidence

Read the new `internal/linuxpackages` parsers and ordinary synthetic fixtures,
the native-adapter and revised wire proposals, and the current operational/assessment,
enrollment/profile, frame validation, sender retry, store quota and offline
catalog boundaries. The workspace has no Git metadata, so no commit identity is
claimed. The package-contract document is being narrowed to the smaller
release/inventory-only DTO; its earlier speculative cached-candidate fields are
not approved wire fields. Source-bound parser hashes at this review checkpoint:

```text
ab6038e5407ee9c3ca36643cb015bd03256055aedd7b11ec65952e3b9ac3f2e9  internal/linuxpackages/model.go
6dc220db8d5cddafe7eb954be5f7875fc806873af1c30be79e0a4eb1427c79f3  internal/linuxpackages/osrelease.go
4b199a7eb3d7771bd9a83f96370e696900962eaea87e08dbc0c7cd6607c054bb  internal/linuxpackages/dpkg.go
dbeb30ea35b08a0f0d23ca4f7060ff9d5c9b05b3b420d2fc42ab497c3af15ec2  internal/linuxpackages/osrelease_test.go
4436afce98a02cafb95e6c01b9c442874b82847f920a773e727611b74e480b8f  internal/linuxpackages/dpkg_test.go
```

Independent focused commands used the existing Go 1.27.1 toolchain, with module
network lookup disabled:

```sh
go test -buildvcs=false ./internal/linuxpackages -count=1
go vet ./internal/linuxpackages
```

Both passed initially and were rerun successfully after the sole narrow
correction: the wildcard-architecture check now rejects every tuple component
named `any`, including compound wildcard fixtures, rather than only literal
`any`. No unresolved blocker remains in the reviewed pure parser slice. The final
focused test completed in 0.105 seconds; vet returned success.
[Debian architecture wildcard definition](https://manpages.debian.org/trixie/dpkg-dev/dpkg-architecture.1.en.html#Debian_architecture_wildcard)

No runtime, live inventory, APT command, advisory retrieval, credential operation,
service or OS change was part of these checks. Full repository, race, native and
transport acceptance are not implied by the focused parser test/vet result.

## Second checkpoint: isolated DTO and reader design

Reviewed the final `snapshot.go`, `validate.go`, `decode.go`, `trim.go` and owner
fixtures after the `collector_busy` reason was added. `package-contract.md` now
describes the inventory-only component, uses the exact `basic-readonly-v1`
profile name and keeps cached APT fixtures behind a separate later gate. The
earlier broad cached-candidate DTO is superseded. No blocking issue was found in
the final pure component. UTC input deliberately means a `Z` timestamp accepted
by the typed time parser, not one unique RFC3339Nano lexical spelling.

Added `tests/security/linux_packages_boundary_test.go` using only exported pure
functions, ordinary generated DTOs/inert strings and repository-source AST
inspection. Independent coverage includes:

- Every required root member and null/type requirements; absent versus explicit
  empty release fields; nested and escaped duplicate keys; case aliases; trailing
  input; integer syntax/overflow; malformed UTF-8 and surrogate/control values.
- Rejection of additional trust, source-hash and future candidate fields.
- Swept installed/observed-count feasibility for complete and truncated scopes;
  unknown/denied null counts; independent release and inventory outcomes.
- An ordinary valid canonical snapshot of exactly 16,384 bytes, exact raw decode,
  one-byte raw/canonical overflow, honest byte trimming and unchanged source
  counts, generation, time and duration.
- Idempotence and mutable-pointer/slice isolation, no omitted backing-array rows,
  and rejection of malformed rows even when they fall in a would-be-trimmed tail.
- Exact binary/source version preservation, `all` architecture, no leaked ignored
  fields/hold/origin/update/CVE assertions, and no derivative/vendor routing.
- A narrow AST tripwire limiting production imports and assessment symbols to
  the supplied-reader parser, grammar and fixed limits. This guards regressions;
  it is not a complete effect-system or security proof.

Independent commands against this checkpoint, using Go 1.27.1 and offline module
settings:

```sh
go test -buildvcs=false ./tests/security -run '^TestIndependentLinuxPackages' -count=1 -v
go test -race -buildvcs=false ./tests/security -run '^TestIndependentLinuxPackages' -count=1
go vet ./internal/linuxpackages ./tests/security
```

All passed. The final independent race run, including the AST tripwire, reported
1.076 seconds and no race diagnostic. These focused runs execute neither current
native collectors nor the proposed source reader, transport or advisory paths.
The owner separately reported package race/vet/arm64 cross-build and bounded
decoder fuzz results; those are not represented as independently repeated here.

The reviewed collector design resolves the required path/consistency boundary:
only the fixed sources; two exact standard release symlink targets; fallback only
on a validated-parent leaf absence; pinned no-follow trusted directory/leaf
descriptors; bounded regular-file reads; final descriptor and current path/link
checks after both sources; invalid caller identity/time rejected before I/O;
independent failure clearing; one nonblocking single-flight slot with an explicit
busy snapshot; and no abandoned read workers or hard filesystem-deadline claim.
It cannot establish atomic two-file or physical-host authenticity. Tests must use
the private inert provider or explicit disposable descriptor fixtures, never call
production `Collect`, and introduce no exported configurable root or test hook.

Final reviewed source identifiers for the second checkpoint:

```text
b3eac4481ee7d56e6796f51c8ef459209f6518239c9eb49984fd6888f30b1582  internal/linuxpackages/model.go
03d96c538c6760c936ac35a1668c900e0000cadce4a878272f2429bfa70a4718  internal/linuxpackages/snapshot.go
1e6fb9d677cd2b759695b2687665e05c48d27bba387ef31dfb75104e1c74dfdf  internal/linuxpackages/validate.go
b75d967d84323c72429de92f63f46f1b18e512c8306c689f5f5b47a0bf75d6b3  internal/linuxpackages/decode.go
8403a852d131a9cf3d80b89f044a17724ebc117595670b4009cc7cca852386bc  internal/linuxpackages/trim.go
1fab848cab187e48392bc2e13b04079932d1e813511efe4d8cf644824b9d40b5  internal/linuxpackages/snapshot_test.go
57036e7227b193ee58644736fa4d20e15327e9086cb529dc3c619076b984dfe1  docs/linux-assessment/package-contract.md
3396e0f6d0bfee847002d1e6ee529f836461abf673a5f7f585132e90ab4ee31e  docs/linux-assessment/collector-boundary.md
0623ba6c4e5e95329652c1e60248843b83528be98e94fdff4770cec4d542eec7  tests/security/linux_packages_boundary_test.go
```
