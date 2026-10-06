# Published-fix Linux CVE matching

This package has no downloader, inventory collector, scheduler, update installer,
or disk store. The adjacent ingestion adapter may fetch the fixed official feed
and persist exact source bytes; this package only parses and evaluates them.

## Supported inputs and meaning

- Debian 13 / trixie: Security Tracker JSON source package -> CVE ->
  `releases.trixie`. Only `resolved` with a supported nonzero `fixed_version` creates a
  comparison. `resolved` describes the archive, so an older installed source
  version still matches. `fixed_version: "0"` means vendor-not-affected.
  Open, undetermined, and uninterpretable records produce coverage gaps.
- Ubuntu 24.04 / noble: an array of Canonical `UBUNTU-CVE-*` OSV records,
  `affected.package.ecosystem` exactly `Ubuntu:24.04:LTS`, source package names,
  `ECOSYSTEM` ranges, and explicit fixed events. Missing fixed events can mean
  needs-triage, so they never create confirmed version-match warnings. Pro/FIPS,
  USN, livepatch, withdrawn, and other-release records are outside this slice.
  Introduced bounds are honored if supplied. Unsupported/open mixed ranges are
  conservatively omitted rather than treating one fixed interval as complete.

Provider documentation:

- https://security-tracker.debian.org/tracker/data/json
- https://security-team.debian.org/security_tracker.html
- https://documentation.ubuntu.com/security/security-updates/osv/
- https://security-metadata.canonical.com/osv/
- https://github.com/canonical/ubuntu-security-notices
- https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/master/lib/python/bugs.py
- https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/master/lib/python/debian_support.py

The tracker accepts historical version tokens matching `[A-Za-z0-9:.+~-]+`;
its version wrapper does not enforce this application's stricter comparison
grammar. A tracker-style token within the existing 512-byte field bound that
cannot be compared is retained as `vendor_fixed_version_unsupported`, with no
fixed-version threshold. It is never normalized, compared or turned into a
warning/fixed result. Wrong types, whitespace/control text, out-of-grammar
punctuation and oversized fields still reject the snapshot. The tracker maps
not-affected separately to `"0"`; literal sentinel text is not accepted as a fix.

No vendor prose, raw imported URLs, urgency, inferred severity, or CVSS is
included in a finding. Advisory links are constructed from validated CVE IDs and
fixed official origins. Canonical data is attributed CC-BY-SA-4.0. Debian tracker
data licensing is not verified; this package does not settle redistribution
rights or check in any real feed data.

## Import and state

The local bundle is an object with exactly these keys:

```json
{
  "schemaVersion": "linux-cve-bundle-1",
  "provider": "debian-security-tracker",
  "fetchedAt": "2026-10-05T07:00:00Z",
  "payload": { "source-package": { "CVE-2026-1000": { "releases": { "trixie": { "status": "resolved", "fixed_version": "1.0-2" } } } } }
}
```

Use `canonical-ubuntu-osv` with an OSV array for Ubuntu. A syntactically complete
arbitrary subset is always `imported_records_only`, never full feed coverage.
The local import path is `operator_imported_unverified`; setting a URL or trust
field in the bundle cannot grant official-feed authority. SHA256 hashes the
exact JSON payload value bytes, excluding surrounding envelope whitespace. It
is an identity/integrity check, not a signature.

Only `ParseOfficialDebian` accepts transport authority from the dedicated
fixed-URL HTTPS adapter (or restoration of its protected cache). Its metadata is
`https_origin_only` / `official_feed_records`. This still does not prove the
origin of an installed package or comprehensive vulnerability coverage.

Manual imports are bounded at 32 MiB. The fixed-origin official Debian parser
has a separate 96 MiB decoded JSON budget, based on the hosted 81,530,876-byte
identity response. It parses that JSON directly without constructing another
full-sized import envelope. Structural budgets remain unchanged: 250,000 raw
records, 32 nesting levels, 16 million
JSON values, and 30 seconds of parser work. Reads check cancellation between
underlying reader calls; the caller must supply a deadline-aware body if a read
can block. Oversized, empty-target, duplicate-key (including case aliases),
malformed, invalid-time, truncated, and trailing-data imports fail closed.

Snapshots are opaque and immutable. Store promotion is per release, anti-
rollback, and atomic. A new snapshot cannot replace a later fetched time or
change content at the same fetched time. `ReplaceWith` checks rollback, runs the
persistence callback under its lock, then publishes; callback failure retains the
last-good index. Callbacks must not re-enter the store. `SnapshotView` captures
index and display metadata together. Failure reasons are sanitized tokens.
Standalone `Store` is in-memory: persistence/restart recovery belongs to the
adapter. Reading or restoring old source data does not refresh `fetchedAt`,
`expiresAt`, or its payload digest. A new parser validation may update
`validatedAt` without changing source freshness.

## Evaluation boundaries

A complete inventory manifest and every generation-bound row are required. Row
grammar, order, installation count, byte count, and canonical row SHA256 are
rechecked. Comparison uses the injected Debian-aware comparator, preserving
epochs, revisions, and tildes. No SemVer or lexical ordering is used. Tests also
exercise native `dpkg --compare-versions` through NativeDebianComparator.

Known backport/PPA/local-rebuild markers and incomplete installations are skipped
with explicit gaps. Ordinary source/version coincidence cannot authenticate an
installed artifact, so every finding is `distribution_package_version_match`.
It does not assert exploitability, stock repository provenance, running-kernel
activation, restart state, or that APT currently offers an installable fix.

Result rows are version matches deduplicated by CVE + source + installed source
version. This preserves mixed-version multiarch observations. The UI groups
these rows by CVE + source for one warning with all version/fix pairs; row count
is not a distinct warning count.

`unassessedRecordCount` counts distinct source-package/CVE records encountered
for supported installed sources that could not be fully evaluated. Multiple
installed source versions do not multiply this count. It includes unsupported
fix/status/range interpretations and failed comparisons; a not-affected `0`
record is not an unassessed record. The UI shows this number even when there are
zero warning matches. It is a lower bound only if processing is incomplete.
A bounded binary list or omitted warning detail does not change that count's
completeness. Interrupted or budget-blocked checks remain pending, rather than
being counted as uninterpretable vendor data.

The v2 result adds `coverage`: exact planned/completed source-version/advisory
check counts; executed non-memoized comparator calls (including failed calls); total matching rows and unique
source/CVE warnings before display trimming; separate skipped-installation,
nonstandard-version and missing-source package counts; and deduplicated vendor
reason counts. One record can have different comparison outcomes for multiple
installed versions, so reason subtotals can overlap. The sum of package gaps is
`skippedPackageCount`; an eligible package with an unassessed advisory is not a
skipped package. `evaluatedSourceCount` still means sources with at least one
interpretable record, not fully covered source packages.

`evaluationComplete` means every planned check was visited, including records
that remain unassessed because vendor data or comparison is unusable. It never
means complete vulnerability coverage or a secure endpoint. No matching-release
feed record is a source gap, not a not-affected conclusion. Partial planning is
unavailable and cannot publish invented exact progress totals.

The evaluator bounds work at 3 seconds and 2,000 memoized Debian comparisons.
It emits at most 100 version matches, 20 binaries per match, 128 binaries total,
and 230 KiB of serialized result, with explicit truncation. Display limits do not
stop assessment; totals continue under the same CPU/comparison budgets. A true
comparison/time cutoff reports incomplete processing and exact remaining checks.
This first slice does not yet resume such interrupted processing. Each visible match
retains at least one installed binary. Coverage is always partial. Feed freshness
(48 hours) and inventory freshness (24 hours) are independent; stale evidence
retains historical matches with stale labels. Missing or invalid prerequisites
never become a green zero-warning/secure verdict.
