# Offline catalog core

`internal/offlinecatalog` implements the in-memory catalog boundary described in
[offline-security-contract.md](offline-security-contract.md). It accepts one
bounded normalized Debian 13 / Trixie catalog. This core does not assess an
endpoint, compute vulnerabilities, enumerate packages, offer updates, or install
anything. Application HTTP authentication, mutation leases, and body admission
belong to its caller.

## Exported interface

- `New() *Store` creates an enabled, empty store with a generated revision.
- `Parse(ctx, raw, now) (Candidate, error)` copies and validates the raw normalized
  JSON bytes; `now` is supplied by the server. A successful candidate is immutable
  and opaque. Callers must not mutate the input concurrently with this call; after
  it returns, the input can be overwritten without affecting the candidate.
- `store.View(now) View` returns only detached catalog metadata and the current
  revision. It never returns source names, rules, raw bytes, or a filename.
- `store.Replace(ctx, expectedRevision, candidate, now) (View, error)` atomically
  promotes a parsed candidate when the revision still matches. Its `importedAt`
  is the server-supplied successful commit time in UTC. It generates a new revision.
- `store.Clear(ctx, expectedRevision, now) (View, error)` atomically clears the
  catalog and generates a new revision, even when it is already empty.
- `DisabledView(now) View` returns the explicit disabled representation with empty
  revision and null catalog. A nil or zero-value store behaves as unavailable;
  callers construct enabled stores with `New`.

The error sentinels are `ErrInvalid` (`invalid_catalog`),
`ErrUnsupportedRelease` (`unsupported_catalog_release`), `ErrTooLarge`
(`catalog_too_large`), `ErrChanged` (`catalog_changed`), and `ErrUnavailable`
(`catalog_unavailable`). Context cancellation/deadline errors are returned
without wrapping. Errors never include imported values, filenames, paths,
underlying decoder text, or parser internals. The HTTP adapter owns status mapping
and fixed public messages, including its own `catalog_busy` admission response.

Store value copies share a single private state pointer and mutex. Copying a
constructed store does not split synchronization. Candidates share only immutable
private data. Candidate and Store pointer/value formatting, including `%+v` and
`%#v`, is opaque; their JSON serialization is `null`. The supported metadata
serialization is the separate `View`, whose fields match the integration contract.

## Validation and limits

The package accepts no more than 2,097,152 raw bytes. The normalized root has exactly
four fields: `schema`, `synthetic`, `coveredSources`, and `rules`. The schema is
`debian-tracker-normalized-1`; `synthetic` must be an explicit JSON boolean;
coverage and rules must be explicit arrays. Covered sources must be nonempty;
rules may be an explicit empty array. The scope label describes accepted
interchange data and does not prove that a covered source has been exhaustively
checked by a vendor.

`assessment.ParseDebianSnapshot` remains the mandatory shared validation pass.
Its existing finite limits, UTF-8 checks, strict known fields, duplicate JSON key,
case-variant and record-identity rejection, version validation, trailing-document
rejection, maximum 10,000 rules/sources, nesting bounds, string bounds, and bounded
nested arrays remain in force. The upload boundary adds exact root fields,
explicit types/null rejection, and a requirement that every rule's release is
exactly `trixie`. Optional rule fields remain optional where the normalized parser
permits that; present string and array fields cannot silently become zero values
through JSON `null`. XML and DTD/entity input is rejected rather than processed.

A SHA-256 digest is computed from the exact validated bytes, including whitespace.
The catalog ID and revisions use separate 128-bit cryptographic random values,
encoded as 32 lowercase hexadecimal characters. The caller supplies neither.

Parsing checks cancellation before copying, between bounded parsing passes, and
while checking releases. The existing foundation parser itself has no context
parameter; cancellation is observed when that finite synchronous pass returns.
Mutations check cancellation before taking the lock and again immediately before
promotion. Cancellation and mutation have normal atomic-operation semantics:
cancellation observed before the commit prevents it; cancellation after a commit
does not roll it back. Failed parsing, stale revisions, invalid candidates, and
cancellation never replace the prior catalog with an empty result.

`MaxInFlight` is 1 and is reported in the view. The HTTP adapter must admit at most
one complete import body read/parse at a time and perform authentication and
revision rechecks under its operator lease. The standalone `Parse` function has
no process-global admission lock and does not consume an HTTP body itself.

## Authority and privacy

Every view permanently reports `originAssurance: "unverified"`,
`freshness: "unknown"`, and `publishedAt: null`. Import time is not vendor
publication, fetch, or signature-verification time. Provider and declared release
are validated format/scope labels, not evidence of authorship. A digest is content
identity, not authentication. Profile, trust, public URLs, timestamps, verification
flags, identifiers, digests, and filenames are not accepted root fields.

The existing foundation parser requires its `synthetic_fixture` validation marker
for a document declaring `synthetic: true`. This package supplies that marker only
to the temporary validation call, with no URL or source timestamps, then discards
the resulting provenance-bearing snapshot. It retains a separately decoded private
document and counts. It exposes no parsed snapshot, provenance object, source
getter, rule getter, or matcher bridge. Uploaded synthetic and non-synthetic
catalogs both remain unverified. Synthetic data cannot establish real endpoint or
real CVE status.

No uploaded file bytes or raw names appear in returned metadata or diagnostics.
No original raw file is retained after Parse. The normalized document and metadata
exist only in process memory. Clearing or replacing drops the store's reference;
callers must also release their Candidate values for garbage collection. This is
ordinary managed memory and makes no secure-erasure guarantee. Restart clears the
store. There are no network requests, URL following, file writes, package commands,
native comparator calls, signature verifications, or outside metadata lookups.

## Verification

All fixtures are invented synthetic data. Focused tests cover exact JSON metadata,
server-derived digest/time, random ID shape, persistent unknown/unverified state,
explicit null/boolean/array validation, duplicate keys and identities, unsupported
releases, 2 MiB and 10,000-record boundaries, nested bounds, immutable input/view
copies, opaque pointer/value diagnostics, shared-state Store copies, compare-and-
swap races, clear semantics, and cancellation before/during parse and before commit.
A narrow AST safety regression checks production dependencies and limits access to
foundation capabilities. This tripwire complements review; it is not a security
proof.

Verified with the repository workspace Go 1.27.1 SDK on Linux amd64:

- `go test -race ./internal/offlinecatalog`: passed.
- `go vet ./internal/offlinecatalog`: passed.
- `go test -cover ./internal/offlinecatalog`: passed, 95.8% statement coverage.
- Three-second bounded fuzz smoke run: passed, 66,069 executions. This is not
  exhaustive assurance.

These are isolated core checks; API/UI integration and real endpoint/vendor-data
acceptance are separate gates. No live advisory retrieval, package inventory,
update scan, installation, deployment, or external data transmission was performed.
