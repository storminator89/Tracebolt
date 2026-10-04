# Read-only assessment foundation

Implemented 2026-10-03 in `internal/assessment`. The offline catalog API now uses `ParseDebianSnapshot` solely for strict normalized-document validation. The package inventory adapter, comparator and vulnerability matcher remain disconnected from the application telemetry and assessment UI. The coverage panel reports those missing facts explicitly; it does not yet expose missing-update or confirmed-CVE counts and does not meet the complete detection release gate by itself. The parent design is [update-vulnerability-plan.md](update-vulnerability-plan.md).

## What exists

- Independent installed-inventory, offered-update and vulnerability-result types, with explicit nullable counts.
- Coverage (`assessed`, `partial`, `unknown`) independent of freshness (`fresh`, `stale`, `unknown`), including source fetch/validation/expiry times and original assessment time. `Quality.Status()` derives an abbreviated status; consumers must also show coverage when stale.
- Fixed-path, bounded local Debian dpkg inventory, retaining only Package, Status, Version, Architecture and Source. Residual configuration records are excluded; incomplete installation states are retained distinctly; foreign architectures are preserved.
- Debian source-package matching against an immutable, digest-pinned, normalized snapshot. This **is not a parser for the live Debian tracker export**. No feed importer, fetcher, signature verifier or license grant is included.
- An injectable Debian comparator and a native implementation using only `/usr/bin/dpkg --compare-versions`, with fixed operations, no shell, isolated environment, discarded output and a shared 500 ms deadline per comparison.
- In-memory last-good assessment retention. A failed refresh never replaces the prior snapshot/findings with an empty result. Read time does not advance fetch or assessment time.
- Windows/macOS-compatible interfaces. Native Windows, macOS, Ubuntu, Mint and RPM software/update/CVE adapters remain unimplemented here. Unsupported platforms produce unknown coverage, not green zeros.

## Safety boundaries

There are no network dependencies, downloads, update queries, package installations, APT operations, service changes, reboot operations or disk writes in this package. The only process boundary is the fixed native version comparator. Its executable must be a regular executable file without group/world write permission; system-file integrity remains an OS trust assumption. There is no user-selected executable, path, command, argument operator or environment.

The matcher itself performs no I/O; an injected comparator is a trusted implementation dependency. The native comparator is an explicitly bounded subprocess implementation of that dependency. A repository safety regression checks imports, process construction and mutating OS APIs. This tripwire complements review; it does not prove arbitrary future code safe.

The local reader opens only `/var/lib/dpkg/status`, rejects a non-regular/symlink target and detects replacement/change across the read. It has a 32 MiB total byte ceiling, 64 KiB line ceiling, 100,000-stanza ceiling, 256-field ceiling and bounded selected values. Invalid UTF-8, malformed/duplicate case-insensitive fields, duplicate identities, selected-field continuations, incomplete required fields, cancellation and reader errors invalidate the snapshot. No successful prefix is returned. Raw errors, stderr, ignored fields and file contents are never used as display text. An empty/absent/unreadable database is unavailable, not a successful empty inventory.

A nonempty, valid database containing only residual configuration can legitimately enumerate zero installed packages. This is distinct from an empty or missing database.

The snapshot parser accepts at most 2 MiB, 10,000 rules and covered source names, depth 16, bounded strings and bounded nested arrays. It rejects duplicate keys, case variants, unknown fields, unsupported schema, trailing documents, invalid UTF-8, digest mismatch and duplicate rule identities. It has no XML implementation: OVAL/XML, DTDs and entities are rejected as invalid input. It does not follow any URL. Match results are capped at 100,000 rows, with a five-second total matcher deadline; budget exhaustion becomes explicit partial coverage.

## Origin and authority are essential

A dpkg record plus `/etc/os-release` cannot authenticate where an installed artifact came from. `LocalDebianInventory.Collect` therefore produces **no verified origin evidence**. It does not infer origin from version suffixes, package names or maintainer text.

A definitive Debian result requires:

1. Exact Linux / Debian / version 13 / Trixie platform identity. The current contract expects the release major version `13`; a future platform adapter must normalize a full version such as `13.6` separately and preserve the original identity elsewhere.
2. Exact binary name/version/architecture and source name/version bound to verified vendor metadata and the installed artifact by a trusted upstream adapter. Merely finding the installed version in an index is insufficient. Both `VerifiedMetadata` and `InstalledArtifactVerified` must be justified, along with a repository label and evidence identifier.
3. A covered source package and a Trixie record for the advisory.
4. An authoritative source manifest and known freshness. Expired evidence remains explicitly stale; unknown freshness yields a review candidate and dominates stale evidence when combining sources.
5. An installed package state and a valid Debian-aware version comparison where required.

The trusted adapter supplies `SourceSnapshot` separately from the JSON. A JSON field cannot assert its own authority. Real vendor authority additionally requires the exact approved public Debian export URL and `https_origin_only` or `vendor_signature_verified` evidence from that adapter. This package **does not perform either verification**. Do not populate those trust values from an untrusted request or imported manifest. A SHA-256 checksum is a content identity, not proof of vendor authorship. The future importer must hash the normalized bytes actually evaluated and separately retain its original upstream snapshot and provenance.

Synthetic input can exercise definitive rules only against synthetic inventory. The test fixture is explicitly labelled `synthetic`, uses invented package names and the intentionally synthetic `CVE-2099-99990001`, and cannot be used to assert accuracy against a real CVE or endpoint. Public artifacts contain no real inventory or customer data.

## Matching semantics

- Match the Debian tracker source name and source version, not the binary name or binNMU version. Source-field defaults follow the dpkg record semantics.
- `resolved` means a vendor archive fix exists; an installed version below that threshold is still affected. Equal/newer source versions are fixed **on disk only**. Activation always remains unknown in this foundation.
- `resolved` with `fixedVersion: "0"` is the not-affected sentinel for the matched source package and release. This is not a global claim that every version of the software was never vulnerable. It never creates a version-zero patch or an update offer.
- `open` with no fixed threshold stays a candidate in this first implementation. It retains `no_fix_published`, but does not assume every unusual/local installed version belongs to the affected version universe. `no-dsa`, postponed and other qualifications remain attached to the match.
- Undetermined status, absent target release, unsupported status, inconsistent fields, missing comparator, unknown origin and unknown freshness remain reviewable/unknown.
- Archive version listings are retained as archive facts; they are never substituted for the endpoint's installed version.
- Advisory fix references remain separate from `OfferedUpdates`. A published fix is not evidence it is offered, installable, configured, entitled or activated.
- Results are one row per binary component/advisory. Unique affected CVE counts deduplicate the same CVE across installed components; temporary vendor issue IDs never invent a CVE.
- `assessed` means the stated snapshot/source-package scope was evaluated. Explicit exclusions remain. An inventory source not covered by the snapshot is unassessed. No advisory matches is not a general safety claim.
- Unknown/unrun capabilities have null counts. If all present packages are unassessed, affected CVEs remains null. A positive partial count is a lower bound within assessed evidence, and stale counts require a visible age label.

The normalized format requires an explicit nonempty `coveredSources` list and explicit `rules` array. A future importer must justify negative coverage before including a source with zero rules. Do not turn an incomplete download or a missing release partition into a complete empty rules list.

## Last-good retention

`AssessmentCache.Commit` requires a parsed snapshot and a corresponding assessment, rejects a source mismatch or older fetched snapshot, and stores copies of mutable result data. `RecordFailure` stores only allowlisted failure codes; arbitrary text becomes `refresh_failed`. `View` returns a copy and recomputes age from the original sources. It preserves the original assessment time, findings and counts. A failure before the first success leaves both snapshot and assessment absent.

The cache is in-memory only. A future persistent implementation needs an atomic snapshot/result promotion, rollback policy, explicit source validation and recovery tests. Inventory and findings must remain within the authorized self-hosted system; they are not inputs to a public feed request.

## Proposed integration, pending API-owner agreement

1. Add separate inventory, offered-update and CVE capability/result slots. Wire explicit unknown states first. Do not overload the existing diagnostics health status.
2. Let an endpoint inventory adapter call `LocalDebianInventory.Collect` with validated OS identity and collection scope. Authenticate and strictly validate transport before considering any origin evidence. Do not silently substitute the server's inventory for an endpoint.
3. Give the server matcher a previously validated, pinned local snapshot and inventory. Use `AssessDebian(ctx, inventory, snapshot, comparator, now)`. Do not put network refresh or an update search inside this call.
4. Keep `UnimplementedUpdates(now)` until a separately reviewed cached-catalog/native update adapter exists. Zero updates is not the default value.
5. Make the server, not a client-supplied JSON boolean, responsible for vendor-provenance evidence. A separate repository/artifact provenance adapter is still needed; the local dpkg reader alone must remain candidate-only.
6. Preserve source IDs, hashes, age, coverage, qualification/reason codes, exclusions and null counts through persistence and presentation. Show partial and stale together. Use concise text such as “No matches in assessed source-package rules”; never “secure” or “all CVEs fixed”.
7. Include the native adapter and feed ingestion only after their own security, licensing and platform acceptance review. No inventory-derived external queries or automatic patching are implied.

No existing API, UI, model, telemetry, collector, command or `go.mod` file was changed for this foundation.

## Verification recorded 2026-10-03

Focused checks:

- `go test -race ./internal/assessment`: passed.
- `go vet ./internal/assessment`: passed.
- `go test ./...`: passed against the shared tree at this checkpoint.
- Windows amd64 and macOS arm64 package test binaries cross-compiled successfully; they were not executed.
- Two bounded three-second fuzz sessions passed: 114,744 dpkg parser executions and 63,587 snapshot parser executions. These are short smoke fuzz runs, not exhaustive assurance.
- `go test -cover ./internal/assessment`: passed; statement coverage 89.7% at this checkpoint.
- Native comparator oracle: `/usr/bin/dpkg` version 1.22.22 (amd64), ordinary sandbox user, fixed `--compare-versions` calls only. Epoch, tilde, numeric revision, Debian backport suffix, backport ordering, binNMU, native revision equality and epoch dominance cases passed. This establishes version-comparison behavior only.
- Missing-database native acceptance: `/var/lib/dpkg/status` is absent in this restricted Debian cloud environment. `TestLocalMissingDatabaseIsUnavailable` passed with null installed count and `package_database_unavailable`. No host package inventory, actual missing-update count or real endpoint CVE status was established.
- Fixture checks cover the old/equal/new fix threshold, not-affected sentinel, source/binary mapping, foreign architecture/incomplete/residual states, wrong/unknown origin, other releases and distributions, all-unassessed false-zero prevention, duplicate/invalid/over-limit parsers, fixture-to-real authority mismatch, unknown/stale age (including mixed unknown-plus-stale fixed/not-affected regressions), last-good failure retention, result mutation isolation, cache races and bounded match output.

An independent focused security review found and verified the correction of a mixed-age freshness bug; its exported-contract race checks passed and identified no remaining blocker for this isolated checkpoint. This is not a deployment or live-data validation.

No native Windows/macOS/Ubuntu/Mint inventory or update acceptance was run. Cross-compilation is build evidence only. No update scan, APT refresh, installation, bulk feed download, live advisory ingestion or public inventory export occurred.

## Primary semantics references

These are the authoritative references identified in the parent research, not a claim that live feed schema compatibility has been tested:

- [Debian Security Tracker scope](https://security-team.debian.org/security_tracker.html)
- [Official Debian tracker export generator discussion/commit](https://alioth-lists.debian.net/pipermail/debian-security-tracker-commits/2025-February/126499.html): export structure and archive/release status
- [Official Debian tracker schema explanation (2014)](https://lists.debian.org/debian-security-tracker/2014/02/msg00000.html): artificial version `0` encodes not-affected status for the applicable record
- [Debian tracker example (Bug 812410, 2016)](https://lists.debian.org/debian-security-tracker/2016/01/msg00018.html): `fixed_version: "0"`, `status: "resolved"` and the expected not-affected result
- [Debian JSON export maintainer discussion](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=761859): additional discussion of the JSON interface
- [Debian policy, Source field](https://www.debian.org/doc/debian-policy/ch-controlfields.html#source)
- [Debian policy, Version field and ordering](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version)

No real vendor feed data is redistributed by this package. Feed licensing and attribution remain separate work before import/publication of a catalog. The synthetic fixture is a behavioral test, not vendor-licensed data.
