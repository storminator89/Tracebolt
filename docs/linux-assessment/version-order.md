# Isolated portable Debian version ordering

Status: source and synthetic tests in `internal/debianversion`; **not wired into
any runtime, collector, store, API, UI, catalog ingestion or matcher**. Existing
parsers and `assessment.NativeDebianComparator` are unchanged. Frozen candidates
are unchanged. This primitive is intended for later reviewed offline-candidate
work where the scratch manager image does not provide `dpkg`.

## Contract and supported subset

The stateless zero-value `debianversion.Comparator{}` provides:

```go
Compare(context.Context, string, string) (int, error)
```

It structurally satisfies `assessment.VersionComparator` without importing that
package. Success returns exactly `-1`, `0`, or `1`; an error always returns `0`,
which is **not** an equality result. A caller must check the error. There is no
runtime registration, fallback, subprocess, network, filesystem or environment
access, clock lookup, timer, dependency addition or mutable shared state in the
production package. Comparison uses bounded slices and integers for indexes,
not integer conversion of version numbers. Work is linear in the two bounded
inputs, with constant auxiliary storage and no recursive parsing.

Local acceptance requirements:

- Each complete input is 1 through 512 bytes inclusive. No trimming or Unicode
  normalization occurs; only explicitly listed ASCII characters are accepted.
- Epoch, when present, consists of decimal digits and has value from `0` through
  `2147483647`, ignoring leading zeros. This is a deliberate conservative
  portability limit, **not a Debian Policy or universal dpkg limit**.
- The upstream part must begin with an ASCII digit. Subsequent bytes are ASCII
  letters/digits or `.`, `+`, `-`, `~`. The final hyphen is the revision boundary.
- An explicit revision is nonempty and contains ASCII letters/digits or `.`,
  `+`, `~`. A revision need not begin with a digit.
- Upstream/revision digit runs can consume the entire remaining byte budget;
  they never overflow or wrap. No scientific notation or semver interpretation
  is added. Letters such as `e` are ordinary version text, not exponents.

No input is short-circuited by exact string equality or an unequal earlier
component: both operands must be accepted before successful ordering. The left
operand is validated first, so when both fail the first failure is returned.

Fixed diagnostics, containing no input or private metadata:

| Error | Meaning |
| --- | --- |
| `debian_version_invalid` | Empty, oversized, non-ASCII/forbidden bytes or malformed component syntax |
| `debian_version_unsupported` | Otherwise legacy-valid upstream-colon syntax outside this comparison subset |
| `debian_epoch_unsupported` | Syntactically valid epoch exceeds the local supported maximum |
| `debian_context_required` | Caller supplied a nil context |

`context.Canceled` and `context.DeadlineExceeded` are returned unchanged when
observed. Cancellation is polled before work, while scanning/comparing runs and
before returning success. No background goroutine survives a call. Nil context
is rejected rather than silently disabling cancellation. As with other Go
context-aware operations, cancellation racing after the final check may occur
after a result has been computed.

## Specification and explicit compatibility differences

The implementation was written independently from the public
[Debian Policy version specification, section 5.6.12](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version),
reviewed 2026-10-04. Epoch is compared first, then upstream, then revision.
Missing epoch and revision compare as zero. Upstream/revision comparison
alternates non-digit and decimal runs. Tilde precedes every other item, including
end-of-part; ASCII letters precede allowed punctuation. Leading decimal zeros
are insignificant. This implementation compares significant digit lengths, then
digit bytes; it does not convert those runs into machine integers.

Policy describes digit-leading upstream as a recommendation; this package makes
it mandatory, matching the existing project validator. Policy's listed upstream
alphabet excludes colon. The
[Trixie dpkg `deb-version(7)` manual](https://manpages.debian.org/trixie/dpkg-dev/deb-version.7.en.html#DESCRIPTION)
and `assessment.ValidDebianVersion` additionally allow upstream colons when an
epoch exists. For example, `1:1:2` remains acceptable to that broader source
validator but returns `ErrVersionUnsupported` here. An invalid epoch or a colon
in a revision remains malformed. An unsupported comparison must leave ordering
unknown; it does not invalidate an otherwise accepted installed observation.

The same manual loosely describes missing revision as preceding a present one.
For the exact `1` versus `1-0` boundary, this package follows Policy's explicit
zero-equivalence rule and has a dedicated optional native fixture. Neither
document fixes an architecture-independent epoch maximum, so values above this
package's documented bound are unsupported even when a particular native tool
might accept them. These choices must not silently tighten source parsers.

No dpkg implementation source was copied or translated; no third-party library
or license was added. The optional oracle invokes an already-present executable
only for independently authored synthetic fixture comparisons.

## Meaning and integration gates

The result is only an order relation on accepted strings. It is not:

- semantic-version compatibility, vendor origin or artifact authentication;
- proof of source mapping or permission to strip `+b1` or vendor-looking text;
- an APT candidate, offered update, security update, downloadable/installable
  package, allowed downgrade or resolved hold;
- a CVE match, fixed/affected conclusion, update count or coverage claim.

No advisory scan, inventory read, APT operation or host mutation is needed to use
this component. Ubuntu-looking text in a synthetic fixture tests literal ordering
only; it does not route Ubuntu observations into Debian advisory rules. A future
consumer still needs the separately reviewed applicability, provenance,
source-mapping and fail-closed error contracts in the
[package observation contract](package-contract.md).

## Bounded validation

Ordinary tests use synthetic literals for epochs, leading zeros, tilde, letters,
punctuation, missing revisions, binNMU, Debian/vendor-looking revisions, long
decimal runs and invalid inputs. Generated boundary tests cover 512-byte values,
513-byte rejection, long zeros/text/tilde and alternating runs. A fixed finite
matrix tests reflexivity, antisymmetry, transitivity and equality substitution.
Deterministic cancellation tests exercise intermediate polls without sleeps.
The fuzz target includes invalid seeds and checks bounded result/error and order
properties; fuzz inputs never reach any native executable.

Focused pure validation, after any shared timing window has cleared:

```sh
## Requires Go 1.27.1 on PATH and cached locked dependencies.
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
go test -count=1 ./internal/debianversion
go test -race -count=1 ./internal/debianversion
go vet ./internal/debianversion
```

`oracle_test.go` is excluded unless the `debianversion_oracle` build tag is
selected, and additionally requires `TRACEBOLT_DPKG_VERSION_ORACLE=1`. It uses
only the checked-in synthetic literal corpus (maximum 64 pairs), a fixed
`/usr/bin/dpkg --compare-versions` command, `lt`/`gt` predicates, clean environment,
fixed working directory, closed stdin and discarded output. It has a shared
500 ms per-pair deadline, 10-second total deadline and 100 ms process wait bound.
The executable must be regular, executable and not group/world writable; absence
is a reported skip with no installation or fallback. There is no shell, package
database operation, real package input, native fuzzing or advisory access.

[The official dpkg comparison action](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html#compare-versions)
documents boolean exit results; the oracle treats execution errors separately.
It is a compatibility check for this fixed corpus, not proof of every native
implementation or proof of package authenticity.

```sh
TRACEBOLT_DPKG_VERSION_ORACLE=1 go test -count=1 \
  -tags=debianversion_oracle -run '^TestCompareDpkgOracle$' \
  ./internal/debianversion
```

Run only on an authorized development environment after any protected timing
window ends. Neither an ordinary package test nor production comparison invokes
the native oracle. Record actual pass/fail/skip separately from intended commands;
this document alone is not a validation result.

### Recorded isolated check, 2026-10-04

After the shared timing gate was explicitly cleared, the final package passed
focused unit tests (100.0% statement coverage), race tests and ordinary/tagged
`go vet` on Go 1.27.1, Linux amd64, with `GOTOOLCHAIN=local`, `GOPROXY=off` and
`GOSUMDB=off`. All 51 synthetic literal pairs agreed with the fixed native
comparison oracle. The same tagged test without its environment opt-in correctly
reported a skip. A five-second, single-worker pure fuzz run completed 193,361
executions without failure; no fuzz input was passed to dpkg.

Production import inspection returned only `context` and `errors`; a Go-source
search found no consumers of `localrmm/internal/debianversion`. No full-repository
suite, cross-platform execution, real package inventory, APT operation, advisory
scan, runtime integration or frozen-candidate publication is asserted by these
results. This scratch checkout has no Git metadata, so this entry identifies the
scoped files and toolchain rather than claiming a commit-specific release gate.
