# Selected package plan and APT hook observation core

Status: **inert source/fixture foundation only**. `internal/packageplan` has no
production caller, native evidence collector, command, hook installation, package
executor, network client or filesystem adapter. It does not enable package
planning/execution in the manager, agent, helper, API or UI. The existing
`actionpermit.Plan` and durable service-only workflow remain unchanged.

A separate [inert package workflow candidate](selected-package-update-workflow-inert.md)
adds typed selection/preview records, protected SQLite persistence and a fully
labeled simulation workflow. Its production operator boundary remains unavailable;
it supplies no native adapter, signed execution authority or live host execution.

This slice implements a bounded immutable data contract and a pure comparison of
supplied observations. It is not an executable plan, authenticated provenance,
operator approval, execution admission, or native acceptance. A successful
`Match` means only that the supplied observations match the supplied plan.

## Implemented contract

`tracebolt.selected-apt-plan.v1` describes `package.upgrade-selected`, for the
conservative Debian 13 / Ubuntu 24.04 release identifiers in the reviewed
[controlled-action architecture](controlled-linux-actions.md). It binds:

- Endpoint identity, incarnation, root-policy digest and exact release
- Creation and exclusive expiry, with a maximum 120-second lifetime
- Original inventory time/digest and complete coverage, clean dpkg state/digest,
  known hold state/digest, and complete authenticated metadata-refresh time
- Reviewed local hook-policy digest and the entire hook configuration-block digest
- Up to 32 sorted, unique binary-name/architecture identities, each already
  installed and unheld, with exact old/new binary versions, source name/version,
  source-mapping semantics and multiarch type
- Target archive SHA-256, bounded nonzero size, relative archive filename, exact
  source/index identity digest, signed Release digest, Packages index digest/path,
  release and explicit native-authentication evidence status

These evidence fields are claims that a future protected native adapter must
establish. Hash syntax and a string saying authenticated do not verify a
signature, repository, actual archive bytes or source-to-binary relationship.
No adapter exists in this slice. Never construct this input by relabeling cached
update/CVE rows or a complete-inventory consistency receipt. Those existing
observations lack the required holds, authenticated refresh, archive identity,
lock-state and hook-policy evidence. No conversion from those types is provided.

The existing bounded `debianversion.Comparator` validates all binary and source
versions and requires a strict binary upgrade. Unknown/unsupported versions,
equal binary versions, new dependencies, removals, downgrades, held overrides,
architecture changes and release upgrades are unsupported. Source-field mappings
may differ from binary identity; binary-default mappings must exactly match it.
Equal source versions are permitted for an explicitly bound binary rebuild.

`Encode` validates the historical description at its creation time. `Decode`
requires the exact Go JSON encoding, including field order, spelling and every
field, within 128 KiB. Re-encoding equality rejects unknown/duplicate/missing/
case-folded fields, nulls, alternative escaping, padding and trailing data. It is
not a general cross-language JSON canonicalization scheme. `Digest` is SHA-256
of `Tracebolt selected APT plan v1`, a NUL byte, and those canonical JSON bytes.

`CheckFresh` and `Match` additionally reject a current time before creation or at/
after expiry. Inventory age is at most 60 seconds and authenticated refresh age
at most 300 seconds, inclusively. Observations must not postdate creation;
positive bounded Unix seconds prevent arithmetic overflow. All checks preserve
the original times, and reject unknown/partial/stale evidence. A historical
`Encode`/`Decode` success is never current admission. A trusted clock and durable
clock-rollback protection remain native-runner requirements.

## APT v3 subset and matching

`ParseHook` requires exactly `VERSION 3` with LF framing, a bounded configuration
section, an empty separator line and complete final LF. It accepts only the nine
v3 fields: binary name, old version/architecture/multiarch, comparison direction,
new version/architecture/multiarch, and action. Only strict upgrades, absolute
conservative `.deb` unpack paths and `**CONFIGURE**` are supported. Protocol
`none` and `no` both map to canonical `no`. Other versions, missing versions,
new installs, removal/error markers, unknown actions or unsupported forms fail.

The configuration section is validated as percent-escaped `key=value` lines,
splitting at the first literal equals sign. It is **not** interpreted as a policy.
Its SHA-256 covers every raw directive, in order, including each terminating LF,
excluding `VERSION 3\n` and the empty separator line. Duplicate list entries,
percent-escape spelling, literal plus signs and additional equals signs in values
remain significant. No URL/form decoding or map overwriting occurs. The matching
plan must contain exactly that entire configuration digest.

Limits are 256 KiB per hook input, 128 KiB/2,048 lines of configuration, 8,192
bytes per line and 64 explicit operations. Paths are bounded to 1,024 bytes and
must already be clean. Traversal, repeated separators, control/whitespace bytes
and percent-encoded paths are unsupported; nothing is normalized into acceptance.
Literal colons are supported for epoch filenames. These lexical checks do not
establish filesystem ownership or resolve paths.

`Match` requires exactly one unpack and one later configure for every selected
name/architecture. Multiarch packages and cross-package interleaving are supported;
repeated, extra, omitted, reordered-per-package or changed tuples are rejected.
There must be exactly one `ObservedArchive` for each unpack path. Duplicate,
reused, missing/extra paths and mismatched SHA-256 or sizes fail closed.

`ObservedArchive` is a future trusted-adapter input, not a hook claim or incoming
request DTO. This core does not open or hash files. Its tests supply explicit
synthetic digest observations and prove comparison behavior only. Archive/index
signature verification, hashing protected actual bytes, ownership checks and
preventing replacement between hashing and dpkg consumption remain unimplemented.

Repeated pure `Match` calls can both succeed. That is intentional stateless
comparison, **not** replay protection. Repeated operations within one hook stream
fail. A durable consume-once admission and runner are required before any real
execution; this package cannot be wired directly to a launch operation.

## Still pending before package execution

- Explicit fresh planning with approved repositories, complete authenticated
  refresh, target/source/index/archive verification and a complete solver result
- Exact selection/current installed/hold validation, supported tool versions,
  disk-space checks, and clean dpkg state under native execution locks
- Reviewed current hook configuration, mandatory non-replaceable guard invocation,
  current root policy and trusted path/FD/ownership/TOCTOU handling
- Named operator package capabilities and immutable approved-job integration,
  signed permit domain/schema, durable admission, independent runner lifetime,
  lock waiting, cancellation semantics and crash/reboot reconciliation
- Per-package results, post-install verification, current inventory and reboot
  evidence, and explicit noninteractive configuration-file policy
- Independently reviewed native acceptance on each supported Debian/Ubuntu APT
  version before any installation or host privilege provisioning

The hook is a package-action observation fence, not a sandbox. Pre-invoke hooks
can run before it; generic configure-pending work and triggers may occur later,
and package maintainer scripts can change broad system state or restart services.
Clean dpkg and an approved hook policy cannot be inferred from this protocol.
There is no claim that nothing else changes, no suppression of normal triggers,
no automatic retry/rollback/reboot, and no actual APT operation in this slice.

## Source and fixture validation

Run `go test -race ./internal/packageplan` with the repository Go version.
Fixtures are invented examples of the published v3 format, not captured native
APT transactions. Tests cover strict wire/limits, unknown versions, stale/future
and exact-cutoff times, source mapping/binary rebuilds, digest-field mutations,
malformed protocol, duplicate configuration lists, interleaved multiarch work,
repeated/missing/extra operations, archive mismatch/bijection and canceled context.
Fuzz targets cover the plan decoder and hook parser without any host operations.

Primary protocol references:

- [APT configuration and package-info protocol](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)
- [APT 3.0.3 hook writer and dpkg sequencing](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/deb/dpkgpm.cc)

These sources describe protocol/ordering behavior; they are not evidence that
this source-only candidate has passed native acceptance.
