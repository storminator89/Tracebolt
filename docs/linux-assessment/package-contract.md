# Linux package observations: component and integration contract

Status: **locally implemented package-observation candidate**. The pure
`internal/linuxpackages` component performs no I/O. Separate packagecollector,
frame-v3/sender-v4, fresh managed-operations-v2 store, operator API and Admin UI
consumers are implemented. Source-specific reviews and acceptance limits are
recorded in contract-review.md, transport-review.md, store-review.md and
ui-review.md; this is not a deployed release or an update/CVE assessment.
Nothing in this document grants permission to run APT, widen enrollment consent,
publish inventory or change a host. Frozen operational/offline-catalog archives
are unchanged. This is separate from the existing operational-v1 software rows.

## 1. Exact platform and meaning

The only first-target routing hints are these exact decoded triples:

| ID | VERSION_ID | VERSION_CODENAME | Routing hint |
| --- | --- | --- | --- |
| `debian` | `13` | `trixie` | Debian 13 inventory; existing Debian review matcher only |
| `ubuntu` | `24.04` | `noble` | Ubuntu inventory; independent cached-candidate work only |

`ID_LIKE`, `NAME`, `PRETTY_NAME`, `VERSION`, `UBUNTU_CODENAME`, architecture and
package-version suffixes are never substitutes. Do not strip point-version,
epoch, tilde, binNMU or vendor-looking suffixes. Missing/empty fields yield
`incomplete`; a recognized release version with the wrong codename, or recognized
codename with the wrong version, yields `inconsistent`; other triples are
`unsupported`. These labels describe this adapter's routing, not OS authenticity.
Containers, chroots, mounted images and restricted namespaces remain
`agent-visible`; this component never establishes host-wide coverage.

Ubuntu rows must never enter Debian CVE rules. Ubuntu CVE coverage remains unknown
until a separate vendor-specific feed adapter and corpus are reviewed. For Debian,
an unverified installed artifact plus an operator-uploaded catalog can yield only
review candidates/unknown coverage. An enrollment signature authenticates bytes
from that identity, not vendor origin, an uncompromised machine or artifact content.
There is no client-controlled `verified`, `trusted`, `official` or origin field.

## 2. Implemented pure parser surface

`ParseOSRelease(context.Context, io.Reader) (ReleaseFields, error)` returns exactly
three nullable strings: `id`, `versionId`, `versionCodename`. A null is absent;
`""` is explicitly empty. Successful parsing of an empty/comment-only file returns
all nulls and an incomplete target, never a fabricated Linux/Debian default.

The systemd specification defines literal assignments, forbids expansion and
quoted-string concatenation, gives `/etc/os-release` precedence over
`/usr/lib/os-release`, and permits symlinks. It requires unique keys but recommends
last-entry recovery for repeats. This parser deliberately rejects duplicates,
including ignored keys, instead of recovering an ambiguous observation. It accepts
one unquoted, single-quoted or double-quoted literal, preserves shell-style literal
escapes, and rejects inline comments, multiline values, malformed syntax and
nonprinting input. Selected identifiers allow only lowercase ASCII letters,
digits, dots, underscores and hyphens. This is a strict observation subset, not a
shell implementation. [systemd os-release specification, Debian Trixie edition](https://manpages.debian.org/trixie/systemd/os-release.5.en.html)

`ParseDpkgStatus(context.Context, io.Reader) ([]PackageRow, error)` reuses only
`assessment.ParseDpkgStatus`, then projects these seven fields:

| JSON field | Meaning |
| --- | --- |
| `name` | Binary package name |
| `version` | Exact installed binary version |
| `architecture` | Exact binary architecture; foreign architectures stay separate |
| `sourcePackage` | Explicit Source name, otherwise the binary name |
| `sourceVersion` | Explicit parenthesized Source version, otherwise binary version |
| `sourceMapping` | `source-field` if Source was present, otherwise `binary-default` |
| `installState` | `installed` or `incomplete`; residual/config-only rows excluded |

Debian Policy permits the Source version to be absent when equal to the binary
version and the whole Source field to be absent when both name and version match.
Consequently an absent field does **not** license removing `+b1` from a version.
An explicit empty Source is invalid. Names must have at least two characters;
this wrapper tightens the shared parser's one-character acceptance for retained
rows. `source` and any architecture with a hyphen-separated `any` component are
rejected as installed binary architectures; `all` remains valid. The
remaining architecture grammar is syntactic, not proof that an architecture is
supported on this endpoint. [Debian Policy control fields](https://www.debian.org/doc/debian-policy/ch-controlfields.html#source),
[dpkg architecture wildcard definition](https://manpages.debian.org/trixie/dpkg-dev/dpkg-architecture.1.en.html#Debian_architecture_wildcard)

The wrapper discards the shared parser's whole-file digest and origin DTO.
Unselected content cannot become a fingerprint or provenance assertion. It does
not use the assessment filesystem collector or native version comparator. Dpkg
selection/hold information is not retained by the reused parser: this stage cannot
assert `not-held`, even if a source fixture contains `hold ok installed`.

### Source bounds, independent of export bounds

| Source | Total input | Line | Records/keys | Selected values |
| --- | --- | --- | --- | --- |
| os-release | 65,536 bytes | 4,096 bytes before LF | 256 unique assignment keys, key length 128 | 128 bytes per selected value |
| dpkg status | 33,554,432 bytes | shared scanner cap 65,536 bytes | 100,000 stanzas, 256 fields/stanza | name/source name <=256; architecture <=64; version/source version <=512 bytes |

Both use a one-byte overflow probe. The dpkg scanner's line cap includes its scan
buffer/newline behavior; it is an upper bound, not a promise that every 65,536-byte
line is accepted. Over-limit/malformed input and read errors return no parsed
prefix. Errors are fixed codes, never input text. Inherited dpkg oversized-line
scanner errors currently map to `dpkg_source_read_failed`; the cap still applies.
A reader must have a caller-owned deadline: cancellation checks cannot interrupt
an arbitrary blocking `io.Reader`. No parser opens files or starts commands.

An empty dpkg input is `dpkg_source_empty`. A complete valid source containing only
residual rows returns a non-null empty list. Only the latter establishes zero
installed/incomplete rows in that observed dpkg namespace. Neither establishes
zero CVEs, updates, applications or running vulnerable processes.

## 3. Implemented isolated observation DTO

The pure snapshot, strict decoder, validator and deterministic exporter are
implemented. The new profile-bound frame and operator view consume this exact
component; older profiles retain their original contracts. No file is opened or
command executed by these pure components.

Exact required top-level members of `tracebolt.linux-packages.v1`:

| Member | Type and constraint |
| --- | --- |
| `schemaVersion` | Fixed `tracebolt.linux-packages.v1` |
| `scope` | Fixed `agent-visible-dpkg`, never host-wide |
| `generationId` | `sample_` plus exactly 32 lowercase hex digits; capture label, not content hash |
| `collectedAt` | Nonzero UTC timestamp, year 1970 through 9999; incoming encoding ends in `Z` |
| `durationMs` | Integer 0 through 2^53-1; does not authorize that execution time |
| `release` | Required release object below |
| `inventory` | Required inventory object below |

`release` has exactly `quality`, `reason`, `fields`. `fields` always contains
`id`, `versionId`, `versionCodename`, each a selected-identifier string or explicit
null. Healthy release parsing requires reason `none`, but may legitimately have
missing or empty fields, which remain incomplete applicability. Unknown/denied
release must clear all three fields to null. Release availability is independent
of inventory availability. `Target()` derives routing locally; incoming target,
origin, trust, host-coverage and supported-platform assertions are not fields.

`inventory` has exactly these members:

| Member | Meaning |
| --- | --- |
| `quality` | `healthy`, `unknown`, or `denied` |
| `reason` | One fixed code below |
| `complete` | Entire successfully parsed declared dpkg row scope is exported |
| `truncated` | Successful full source parse, with rows omitted during export |
| `countExact` | Full source counts are known exactly |
| `observedCount` | Nullable full-source installed+incomplete row count; residual rows excluded |
| `installedCount` | Nullable full-source installed row count; incomplete rows excluded |
| `items` | Non-null array, at most 128 of the seven-field PackageRow values |

Healthy source invariants:

- `countExact=true`, both counts non-null, and
  0 <= installedCount <= observedCount <= 100000.
- `len(items) <= observedCount`. Exported count is `len(items)`; omitted count is
  derived as observedCount minus that length, never accepted as another claim.
- Complete requires `complete=true`, `truncated=false`, `reason=none`,
  observedCount equal to exported length, and installedCount equal to exported
  rows whose installState is installed.
- Incomplete export requires `complete=false`, `truncated=true`,
  `reason=item_limit|byte_limit`, and observedCount strictly greater than length.
- Exported installed rows cannot exceed installedCount. The difference between
  installedCount and exported installed rows cannot exceed omitted rows. This
  rejects impossible totals even when the snapshot is truncated.
- Rows are sorted by binary name then architecture, with duplicate identities
  rejected. `binary-default` requires source name/version to equal binary
  name/version; `source-field` preserves explicit mapping. No suffix inference.

Unknown or denied inventory has `complete=false`, `truncated=false`,
`countExact=false`, both counts null, and `items=[]`. A source parsing limit is a
source failure, not a successful partial inventory; it must not expose a prefix.
A valid residual-only full source may be healthy/complete with both counts zero.
No state creates an update or CVE count.

Quality/reason vocabulary is fixed:

- `none`
- `source_missing`, `permission_denied`, `not_supported`, `timeout`
- `invalid_source`, `read_failed`, `source_changed`
- `item_limit`, `byte_limit`, `not_implemented`, `collector_busy`

Denied requires permission_denied. Unknown requires another non-none code;
healthy permits none or the inventory-only export limit reasons. No free-text
source diagnostic, path or command is accepted. Known fresh/stale is not a client
quality: a future API must derive observation age without rewriting capture time.

Pure entry points:

- `Decode([]byte) (Snapshot, error)` bounds **raw** JSON at 16 KiB, rejects malformed
  UTF-8, unknown/missing/case-variant keys, duplicate decoded keys at every depth,
  wrong types/nulls, non-integer numeric syntax, trailing data and excess nesting.
  Nullable fields must still be present. It then performs typed validation and
  bounds canonical JSON at 16 KiB. No partial snapshot is returned on error.
- `Validate(Snapshot) error` checks exact typed/cross-field semantics, sorted rows,
  identity/value bounds and the canonical byte limit. It is insufficient by
  itself for untrusted raw JSON; use Decode at that boundary.
- `Trim(Snapshot) (Snapshot, error)` first validates every supplied local row up
  to the 100000-record source bound, including rows that might later be omitted.
  It clones mutable input, sorts, and keeps a deterministic prefix fitting both
  128 rows and 16 KiB. It preserves original generation/time/duration and both
  full-source counts. Byte-limit reason outranks item-limit reason. Repeated
  trimming is idempotent. Returned slice capacity contains only exported rows.

A complete successful parse is a prerequisite to constructing healthy source
counts; neither typed DTO validation nor a client claim proves that collection
actually happened. Authentication/authority, release applicability, enclosing
profile/generation equality, sample age and replay checks remain later frame
boundary responsibilities.

There is deliberately **no cachedCandidates object** in this schema. Cached APT
requires a separate later DTO/version review and cannot delay or implicitly widen
the inventory-only transport milestone. The later direction is selected binary
identity, exact installed/candidate versions, explicit candidate availability,
comparison newer/equal/older/unknown, hold held/not-held/unknown, local cache age
and quality, configured-cache-only basis, and installability unknown. Diagnostic
counts must be nullable and scoped to the selected cache identities. No source
URL, origin/security-update boolean or unqualified missing-updates count belongs
in that later shape.

## 4. Export, privacy and generation boundary

Source parser limits are deliberately larger than the proposed transmission
budget. A 100,000-row local parse must never be poured into the old 48 KiB
operational envelope. Proposed newly consented frame reservations are:

- basic telemetry: <=16 KiB raw and canonical JSON;
- unchanged operational-v1 component: <=32 KiB raw and canonical JSON in the new
  outer profile only, using an explicitly reviewed deterministic trim;
- package component: <=16 KiB raw and canonical JSON including metadata and
  release fields, at most 128 package rows;
- complete new frame: <=72 KiB raw and canonical JSON including all overhead.

These are simultaneous maxima, not guaranteed row capacity. A future encoder
must sort rows by binary name then architecture, choose a deterministic fitting
prefix, recompute derived export counts/partial flags while preserving full-source
counts, and measure final encoded bytes. Reserve unknown
section metadata before rows. If even
the metadata cannot fit, reject the frame, rather than omit the entire component
and let an old report appear current. No multi-page completeness claim or manager
merge across generations is authorized by this proposal.

The same new capture label binds release and inventory. It must
equal the unchanged operational component's generationId; collectedAt equals its
original collectedAt and must not exceed basic Bundle.GeneratedAt.
All source/capture times must pass existing age/skew rules without refresh on retry.
A collector must pin each opened source, validate regular-file/race constraints,
and recheck file identity, size and mtime after the capture; timestamps alone are
not an atomic snapshot. A changing source invalidates dependent rows. Manager
assessment must use release+mapping from the **same** accepted component and
authenticated envelope sequence, never join a fresh release to an older package
list. Source mtimes and client times are unverified observations; receipt time,
enrollment identity, sequence and replay rules remain separate server facts.

OS/application names, package/source names and versions can reveal products,
internal software, tooling, security exposure and organizational activity. They
are approved-profile metadata, not harmless public identifiers. Discard all other
os-release/dpkg fields, descriptions, maintainers, email addresses, repository
URLs, mirror hostnames, private paths, file lists and stdout/stderr diagnostics.
Do not transmit machine-id, hashes of ignored content, APT configuration, pins,
source-list text, cache filenames or trust-store material. Future anonymous source
labels, if needed, must be per-snapshot opaque labels, not stable hashes of private
URLs; this first candidate DTO does not need source labels at all.

## 5. Smallest cautious cached APT candidate proposal

**No runner is implemented and no APT command was run for this work.** The first
candidate stage should consult only an already-present binary cache, using fixed
`/usr/bin/apt-cache --no-generate policy` arguments plus validated identities.
Ordinary apt-cache can implicitly regenerate caches; `--no-generate` disables
that behavior. A successful command is an offline configured-cache observation,
not proof a package is downloadable/installable. [APT apt-cache manual](https://manpages.debian.org/trixie/apt/apt-cache.8.en.html)

Proposed execution gates, to be verified against actual Trixie and Noble APT
versions on separately authorized disposable environments:

1. Trusted fixed executable, no shell, nonprivileged identity, clean environment
   (`LC_ALL=C`, fixed PATH, no inherited APT_CONFIG/loader variables), fixed cwd,
   closed stdin, discarded stderr, bounded stdout held only in memory.
2. A separately reviewed child-process sandbox must deny network and persistent
   writes and constrain file reads/child execution. If unavailable, return unknown;
   do not weaken host security or run an unconfined fallback. Merely saying
   "apt-cache is read-only" is insufficient evidence for arbitrary local config.
3. Keep actual policy semantics; do not substitute a synthetic empty preferences
   tree and call it the host's candidate. Configuration load order and path
   redirection require explicit review. `APT_CONFIG` is read before ordinary
   fragments; command-line options are applied last. Binary cache generation can
   be disabled in configuration, so an absent cache is a normal unsupported case
   for this narrow first mode, not permission to rebuild it. [APT configuration](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)
4. Query at most the same 128 deterministically selected installed identities,
   in batches of <=32 and <=12 KiB argv, with a 5-second capture deadline, <=4
   child calls, <=256 KiB stdout per call and <=1 MiB total output. Any output or
   timeout breach discards that call; incomplete batches make selected-scope
   coverage partial/unknown, never complete. Validate name and architecture
   grammar before argument construction. Include architecture explicitly only
   where release-specific fixtures prove the exact identity, especially `all`.
5. Parse only exact requested identities, Installed and Candidate. Reject
   duplicates, unexpected identities and installed-version mismatches. Ignore
   version-table source text in memory; never log/export its URLs. A missing
   requested row is unknown, distinct from an explicit `(none)`.
6. Preserve epoch/tilde/revision ordering. Exact equal strings can be identified
   directly; unequal ordering requires the existing reviewed Debian comparator
   boundary or a separately proved pure comparator. No lexical/semver ordering.
   Comparator execution needs its own runner review/budget; it is not authorized
   by this design or exercised by these parser tests.

APT chooses by policy priority before version order; high-priority pins can select
older versions. Phasing can depend on source/version and local machine-id. Thus
"maximum listed version" is not an APT candidate, and a candidate alone does not
explain why another version was excluded. Keep the actual local policy context
or mark it unknown; never export or replace machine-id. [APT preferences manual](https://manpages.debian.org/trixie/apt/apt_preferences.5.en.html)

Holds are a separate dimension: `apt-mark showhold` reports selections and hold
prevents automatic changes, while a newer candidate may still be listed. The
minimal mode leaves hold unknown. A later approved bounded selection parser can
reuse the same captured dpkg Status facts; do not run extra tooling or infer
`not-held` from absence in an incomplete result. [APT hold semantics](https://manpages.debian.org/trixie/apt/apt-mark.8.en.html)

Ubuntu documents phasing for staged rollout and says its security updates are not
phased. That does not authorize classifying arbitrary cached rows as security
updates from suffixes, source labels or hold state. Release-specific acceptance
must verify phasing, pinning and holds separately. [Ubuntu phased updates](https://ubuntu.com/server/docs/explanation/software/about-apt-upgrade-and-phased-updates/)

Cache freshness is independent of capture time. Recent binary-cache/directory
mtime is not evidence every configured index refreshed successfully, and opening
an old cache now does not refresh it. Missing indexes/cache, unreadable state,
future timestamps, modified sources and mixed-age indexes must remain explicit.
The first existing-cache mode reports freshness unknown, or stale if bounded local
age evidence exceeds a reviewed 24-hour product threshold; that threshold is an
observation policy, not vendor validity. No network refresh, index re-signing,
credential/source-list change, install simulation, upgrade or download is included.
An advisory's fixed threshold never creates a candidate row.

## 6. Compatibility and consent gate

- Manager support for the new schema/profile must land before any sender enables
  it. Unknown schema/profile/fields are rejected; unsupported peers continue the
  already-authorized legacy path without silent collection expansion.
- Proposed outer profile `managed-operations-v2` requires its own consent text,
  enrollment binding and matrix review. Existing `basic-readonly-v1` and
  `managed-operations-v1` clients keep their current bounds and meanings.
- The initial pilot uses a fresh manager/store directory plus fresh enrollment,
  one profile per store. Do not adopt old mode markers or ledgers under a new
  profile; an in-place profile migration is a separate later design.
- The nested operational-v1 document still says `managed-operations-v1`; a new
  outer profile must explicitly allow this immutable component. Never relabel
  that old document with a v2 value or mutate stored v1 data.
- Within the sender's existing freshness policy, a pending old frame remains exact
  durable bytes across restart/retry. Existing expiry handling may discard an
  expired pending observation without reusing its sequence or refreshing its
  timestamps. Do not
  regenerate it, upgrade it in place, reset sequence, or silently discard it
  during enrollment/profile migration. Drain under its valid binding, or require
  a separately reviewed migration/quarantine flow if the old identity is revoked.
- New enrollment/profile authorization must not revive a revoked identity, reuse
  another identity's sequence or bypass per-agent/frame quotas. Persisted/package
  rows and consent/profile changes must roll back together on transaction failure.
- Packages remain solely in the latest exact frame, with no LastGood merge. A
  fresh unknown component replaces prior package facts. Retained logical bytes
  equal canonical operational snapshot + existing canonical LastGood + canonical
  package snapshot; preserve 128 KiB/device, 4 MiB global and 25-device pilot
  limits. Reject a no-longer-fitting combination atomically without silent
  eviction. Package/candidate text stays excluded from AI packets until separately
  allowlisted and consented. See [transport proposal](wire-proposal.md).
- Keep old report views explicitly unassessed for release/source mapping; never
  infer `binary-default` from the old four-field operational software row. Only a
  successful capture of an actual absent Source field establishes that default.

## 7. Fixture corpus and remaining acceptance gates

Implemented synthetic files and table/fuzz seeds under `internal/linuxpackages`:

- Exact Trixie/Noble triples, quoted/unquoted literals, literal escapes, missing
  versus empty fields, derivatives, ID_LIKE-only/display-only facts, unsupported
  releases and inconsistent version/codename pairs.
- Duplicate selected/ignored keys, malformed/injected values, continuation and
  concatenation, non-UTF8/control/CRLF input, input/key/value/line bounds, read
  failures/cancellation and no successful prefix on error.
- Explicit Source version, explicit Source with default version, actual absent
  Source, empty/malformed/duplicate fields, epoch/tilde/binNMU preservation,
  multiarch identities, installed/incomplete/residual states and ignored-field
  privacy invariance. No whole-source digest or authority field is returned.
- Strict snapshot shape, missing/duplicate/escaped/case-variant JSON keys, wrong
  nulls/types, malformed UTF-8, complete/truncated/unknown count combinations,
  impossible omitted-row installed totals, canonical/raw byte boundaries,
  deterministic cloning/trimming, repeated trim and unchanged capture metadata.

Acceptance is phase-specific. The later integration reviews cover strict frame,
profile, retry, quota and UI fixtures; the pure-parser checks alone do not prove
those boundaries. The following gate list preserves their scope, while supported
positive native collection, APT, matching, browser and deployment remain open:

- Later APT gate only: pure APT-output fixtures for older/equal/newer/no candidate, corrupt/missing
  cache, omitted/duplicate/mixed-architecture rows, `all` identity, real pinning,
  separate holds, Noble phasing, tool failure, stale/future/mixed-age cache data,
  partial batch/export and version-comparison failure.
- Frame integration: enclosing profile/generation/time equality and source-change
  capture behavior. The isolated DTO/count/byte/exporter tests do not prove these.
- Legacy/v2 coexistence, strict duplicate/unknown-key handling, exact pending-byte
  restart retries, preserved sequence/profile consent, revoked identity and quota
  rollback, raw+canonical aggregate size limits and explicit failure rendering.
- Nonprivileged native reads on explicitly authorized disposable Debian13 and
  Ubuntu24.04 systems, with read/write/network/process behavior observed and only
  pass/fail/count artifacts retained. This sandbox's absent package database does
  not establish positive native coverage. No live advisory lookup or full dependency scan is part of this work.

Focused verification: approved Go1.27.1, offline module settings,
`go test -race -buildvcs=false ./internal/linuxpackages`, focused `go vet` and
linux/arm64 cross-build passed for the parsers plus snapshot/strict decoder/trim
extension. These are synthetic pure tests, not actual system monitoring, CVE
coverage or an APT integration pass.
