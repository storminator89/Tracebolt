# Independent portable Debian ordering review

Reviewed 2026-10-04 UTC in the source workspace. Scope is the isolated
`internal/debianversion` primitive, its existing opt-in literal oracle, the
accepted-version boundary of the existing source parsers, and injection through
the existing `assessment.VersionComparator` interface. This is not a runtime
integration, advisory scan, package inventory inspection, publication, or claim
that any installed package is affected, fixed, available or installable.

## Decision and integration caveats

Static review found no ordering defect in the documented supported subset. The
portable primitive uses the existing comparison interface and should remain an
injected ordering dependency of `assessment.AssessDebian`; it must not become a
second authoritative matcher or acquire provenance/applicability decisions.
Independent executable checks are recorded separately below.

The following differences require explicit preservation at integration:

- `assessment.ValidDebianVersion` accepts decimal epochs larger than
  `2147483647` within its 512-byte whole-version bound. The portable comparator
  deliberately reports `debian_epoch_unsupported` for those values. The ceiling
  is a conservative portability choice, not a claimed Debian Policy maximum.
- The existing validator and supplied-reader dpkg parser accept legacy upstream
  colons after a valid epoch, such as `1:1:2`. Portable comparison reports
  `debian_version_unsupported`. It must not replace the observation validator or
  make an otherwise accepted installed observation disappear. Malformed epoch,
  revision-colon and other syntax failures remain invalid.
- The identical diagnostic string `debian_version_invalid` does not make
  `debianversion.ErrVersionInvalid` the same Go error sentinel as
  `assessment.ErrVersionInvalid`. A consumer must check the actual returned
  error, not assume `errors.Is` works across these distinct sentinels or match
  error text as authority.
- Portable comparison rejects nil context and returns observed
  `context.Canceled`/`context.DeadlineExceeded` unchanged. Native comparison
  wraps unavailable/failed/cancelled execution as `ErrComparatorUnavailable`.
  These are intentionally different failure details, not equivalent successful
  ordering. The existing matcher already handles all comparator errors as
  `needs_review` with `debian_comparison_failed`.
- Every error has integer result zero. Zero is equality only when the error is
  nil. There is no identity-string, earlier-epoch or earlier-upstream shortcut
  that allows the other operand to escape grammar/support validation. When both
  operands fail, validation reports the left operand first.
- Keep source mappings, literal binary rebuild/vendor suffixes, release and
  provenance checks, freshness, inventory scope, advisory authority, and exact
  result/count semantics in their existing owning layers. Sorting does not
  establish those facts or authorize Ubuntu-to-Debian rule routing.

The review did not change the comparator, parser, matcher, or any runtime
registration. The independent tests exercise existing matcher behavior through
synthetic fixtures; they do not implement a competing matching algorithm.

## Ordering and bounds inspection

`parse` checks the entire byte alphabet and both component boundaries before
comparison. Epoch digits are compared without converting them to a machine
integer. Leading zeros do not bypass the epoch limit. The final hyphen splits
upstream from revision, while earlier hyphens remain literal upstream text.
Missing epoch/revision compare as zero.

The alternating text/decimal algorithm preserves tilde-before-end ordering,
end/digit rank before letters, ASCII letters before punctuation, case-sensitive
letter order, and decimal magnitude by significant-run length then digits.
Zero-only numeric tails compare equal to empty tails, but an intervening zero
does not erase a text-run boundary. It is neither lexical string ordering nor
semantic-version ordering.

Each accepted operand is at most 512 bytes. Input scans and run comparisons are
linear, do not recurse, and retain slices plus constant auxiliary state. Longer
upstream/revision digit runs cannot overflow. Context checks occur during scans
and comparisons and before successful return; no goroutine, timer or background
work is created. Cancellation that races after the final check is the ordinary
context-operation completion race, not a guarantee of atomic cancellation.

Production imports are only `context` and `errors`. Source inspection found no
filesystem, subprocess, network, environment, clock, runtime registration or
external dependency access in the production comparator. The import allowlist
and AST checks in the independent test are regression tripwires, not a formal
effect-system proof.

## Independent fixture coverage

`tests/security/debian_version_boundary_test.go` adds:

- A compile-time assertion against the actual `assessment.VersionComparator`,
  plus 18 independently specified order pairs, reversed pairs and reflexivity.
- Supported/unsupported/invalid distinctions, full 512-byte input acceptance,
  513-byte rejection, epoch boundaries and padding, colon syntax, and complete
  validation despite identity or a decisive earlier component.
- Supplied-string parsing through both `assessment.ParseDpkgStatus` and
  `linuxpackages.ParseDpkgStatus`, preserving accepted observations outside the
  portable ordering subset. Neither test calls a native collector.
- Existing `assessment.AssessDebian` injection for below/equal fixes and
  unsupported installed/fixed versions. Unsupported comparison must retain the
  installed version, produce `needs_review`/partial coverage, and avoid a
  fabricated exact-zero affected count.
- Nil/pre-cancelled/expired context, deterministic intermediate cancellation,
  and a deliberately loose linear context-poll budget for maximum-size inputs.
- Source AST checks for the production import boundary and absence of
  goroutine statements or initialization functions.

Only inert synthetic records are used. No dpkg database, APT state, real
inventory, advisory endpoint, privileged action, malformed-key boundary,
container or frozen candidate is read or exercised by these fixtures.

## Optional oracle review

The existing optional oracle remains the only native check in this package. It
requires both build tag `debianversion_oracle` and
`TRACEBOLT_DPKG_VERSION_ORACLE=1`, admits no generated/fuzz/external input, and
uses the fixed checked-in literal corpus (51 pairs, with a 64-pair cap).
The earlier report said 52; the checked-in corpus has 51 pairs, and the owner
corrected `version-order.md` without changing the corpus.

The fixed `/usr/bin/dpkg --compare-versions` invocation has literal `lt`/`gt`
operators, no shell, no output capture, clean environment, fixed working
directory, closed stdin, per-pair/whole-run deadlines and bounded process wait.
The executable must be regular, executable and not group/world writable.
Missing executable is a skip; other execution failures are failures. It neither
reads package inventory nor invokes an APT operation. The executable metadata
check is not cryptographic provenance and does not defend against a privileged
local replacement between check and execution; this is a development-only
fixture oracle, not a production trust mechanism.

No additional oracle runner or corpus was added. The owner's recorded passing
51-pair oracle is supporting evidence, not a proof of equivalence for every
possible input or every native dpkg implementation.

## Validation record

After the shared compiler/timing window was explicitly cleared, the following
checks passed on Go 1.27.1, Linux amd64, with offline dependency configuration.
The ordinary and race test processes reported `ok` (0.007 seconds and 1.027
seconds respectively); vet exited successfully.

To reproduce, put Go 1.27.1 on `PATH` and run from the repository root with the
locked dependencies already available locally:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2
go version
go test -p=1 -count=1 -run '^TestIndependentDebianVersion' ./tests/security
go test -race -p=1 -count=1 -run '^TestIndependentDebianVersion' ./tests/security
go vet -p=1 ./internal/debianversion ./tests/security
```

No oracle was rerun because no specific ordering mismatch was found. No full
repository suite, cross-platform execution, runtime integration, real inventory,
network/advisory scan or frozen-candidate publication is asserted by these
focused results. The test/vet command chain completed; no background test or
compiler process was left running by the reviewer.

Reviewed source identity (no Git metadata exists in this scratch checkout):

```text
a1cd5e6098074b2177a40b676faa1fabb7d8cfadb4147ee7afc930ce0e6fb39e  internal/debianversion/compare.go
1146312ccf21788820214dc453a1d8346f6959288f397bf8bfc518e5a2eabb1b  internal/debianversion/compare_test.go
1dce80e6921a869fff05461aa9d3de1ac58eba805aa3dd56e729a79ccfe51c9b  internal/debianversion/oracle_test.go
10525e144cac69809a9db30534349f663b8a23f7346b8841ed3d3c5431185dcc  internal/assessment/debversion.go
60de9f16bfebb05ddaa097d6da27d1bbecb6bc2b6ca93f0627953fb37bd91fa2  internal/assessment/matcher.go
```

This review does not authorize runtime wiring or frozen-candidate changes.
The exact later consumer must separately preserve existing matcher semantics,
source acceptance, fail-closed unsupported outcomes, provenance, release scope
and end-to-end assessment bounds before integration.
