# Complete Linux package inventory: isolated pure contract

Status: candidate source-only component, not an enabled runtime feature. These
new files are based on the frozen 556-file release manifest
`a4a7374e9b2f1f4f03e55730b817cd0a99bd6f9ac6a0c83bb23f23778f0bf083`.
No existing runtime, collector, transport, profile, endpoint, database, UI,
dependency or frozen release files are changed by this component. A distinct,
reviewed consent/profile/version integration is required before use. Existing
managed-operations-v2 consent does not grant this expanded collection/export.

## Meaning and source seam

The complete dataset is every retained installed **and incomplete** binary
package row from the supported, fully completed agent-visible dpkg status parse.
Residual/config-only records stay excluded. This is not all software, all host
namespaces, authenticated artifact origin, or proof of zero CVEs/updates.

`SourceInventory` is local full-source input, not a wire DTO. It has the original
generation ID, `CollectedAt`, `DurationMS`, independent release observation, and
all `[]linuxpackages.PackageRow` rows. Call:

```
manifest, chunks, err := fullinventory.Build(ctx, source, sourceOperationErr)
```

The caller must pass the successful, entire `linuxpackages.ParseDpkgStatus`
result **before any Trim or legacy snapshot export**, and propagate the source
operation's final error, including collection/read/stat/source-change checks.
A returned prefix plus a nonnil error fails. A nil row list fails. Cancellation,
invalid rows, duplicate identities, unsupported budgets or any failure returns
an empty manifest and nil chunks; there is no successful prefix mode.

This pure API cannot prove that a caller honestly passed the complete source or
an uncompromised endpoint supplied it. Source acquisition and consistency gates
remain mandatory integration work. The source parser's existing limits remain
in force: 32 MiB input, 100,000 stanzas, 64 KiB scanner-line ceiling and 256
fields/stanza. This package does not invoke or replace that parser or perform I/O.

Valid residual-only source parsing returns a **nonnil empty** list. Its generation
has zero chunks, observed/installed counts and canonical row bytes, and the digest
of the domain-prefixed empty row stream. An empty/missing/failed raw source is
not the same thing. Even a valid empty inventory makes no zero-CVE/update claim.

Release availability is independent: complete package rows may coexist with
unknown/denied/missing release fields. The existing `ReleaseFields.Target()`
semantics remain authoritative for routing; names and versions cannot invent a
Debian or Ubuntu release. Missing release metadata blocks applicable matching,
not retention of complete package inventory. Ubuntu never enters Debian rules.

## Row and metadata validation

The existing `linuxpackages.Validate` remains the sole package grammar,
source-mapping, binary-architecture and install-state validator. Because its
private row validator is not exported, `fullinventory.ValidateRow` wraps each
row in a bounded, synthetic one-row complete legacy snapshot. This does not
apply the legacy global 128-row/16-KiB export cap to the generation. Metadata is
validated separately through an empty complete snapshot using the actual
identity/time/duration/release values. No source parser or version comparator is
reimplemented. Debian versions, epochs, tildes, revisions and `+b1` remain exact.

Rows sort lexically by `(Name, Architecture)`, exactly as in `linuxpackages`.
Equal name with different architecture is valid. Equal name+architecture is a
failure, even with a different version, and uniqueness/order extend across chunk
boundaries. Installed count excludes incomplete rows; observed count includes
both. Build derives both counts from the complete local rows.

## Exact wire structures

Both use schema `tracebolt.complete-linux-packages.v1`; manifest scope is
`agent-visible-dpkg`. The `sample_` plus 32 lowercase hex generation ID is retained
from the original collection; no upload/promotion clock replaces source time.
All keys are mandatory and case-sensitive, including zeros and null release
identifiers. There are no extensible metadata, origin or assessment members.

Manifest key order for canonical hashing:

1. `schemaVersion`, `scope`, `generationId`, `collectedAt`, `durationMs`
2. `release` with `quality`, `reason`, `fields`; fields contain `id`, `versionId`,
   `versionCodename`, preserving null versus explicitly empty strings
3. `observedCount`, `installedCount`, `chunkCount`, `canonicalRowBytes`, `rowsSha256`

Chunk key order:

1. `schemaVersion`, `generationId`, `manifestSha256`
2. `ordinal`, `chunkCount`, `rowOffset`, `previousSha256`
3. `items`, `sha256`

Each chunk is nonempty, contiguous and sorted. Ordinals start at zero. Offset is
its first global row index. The first previous hash is the empty string;
subsequent values equal the immediately preceding chunk's hash. Every chunk
repeats the same declared count and manifest hash. The last chunk has no special
sentinel; exactly `chunkCount` validated chunks close the generation. There are
no empty padding chunks, including for an empty generation.

`DecodeManifest` / `DecodeChunk` enforce raw byte limits before parsing; exact
member sets; duplicate rejection at all depths; exact types and nullability;
UTF-8; at most six nested containers, 16 object members and 128 array elements;
string token limits; and typed validation. Integer fields use unsigned decimal
JSON integer tokens, never negative/negative-zero, fractional, exponent, quoted,
null or overflowing numbers. Timestamps require explicit UTC `Z`. A trailing
second document, trailing junk, unknown or case-folded keys fail. On errors the
returned struct is zero, never a partially decoded observation.

Whitespace, escaped equivalent strings and key order may vary within raw limits;
they do not change the canonical digest. Incoming code must not use plain
`json.Unmarshal` in place of these strict decoders.

## Canonical bytes and domain-separated hashes

Canonical JSON means Go `encoding/json.Marshal` of the declared ordered structs,
with no pretty printing or omitted fields. Valid strings are ASCII under the
existing row/metadata validators. Time is normalized by `time.Time.MarshalJSON`
(RFC3339Nano UTC). `PackageRow` fields keep their existing struct order:
`name`, `version`, `architecture`, `sourcePackage`, `sourceVersion`,
`sourceMapping`, `installState`.

The following `\x00` is one NUL byte, not four printed characters:

- Row stream: `SHA256("tracebolt.complete-linux-packages.rows.v1\x00" ||
  canonical(row0) || LF || canonical(row1) || LF || ...)`.
  `canonicalRowBytes` counts each canonical row plus its LF, excluding the domain.
- Manifest: `SHA256("tracebolt.complete-linux-packages.manifest.v1\x00" ||
  canonical(manifest))`. Every immutable manifest member is covered.
- Chunk: `SHA256("tracebolt.complete-linux-packages.chunk.v1\x00" ||
  canonical(chunk-with-only-sha256-member-excluded))`.

Digests are 64 lowercase hexadecimal characters. No raw source digest or
unselected source field is retained. A hash authenticates neither OS nor vendor
nor host namespace. Unit tests contain independently calculated fixed vectors.

## Full-generation state machine

`NewValidator(ctx, manifest)` validates and detaches metadata. `Add(chunk)`
requires the next ordinal exactly once, correct manifest/generation/count/offset/
previous-hash linkage, chunk self-hash, global ordering and budget compatibility.
It streams row SHA state, counts and the last name/architecture; it retains no
row arrays. Counters are bounded before subtraction/addition. Any error, including
cancellation, poisons this instance permanently. Retry/idempotency belongs to a
transactional owner, not this state machine.

`Finish()` verifies exact chunk/row/installed/byte totals and the whole row digest.
Only then does it return a `Complete` receipt with private fields and `Valid()==true`.
The zero receipt is invalid. Premature Finish is a terminal `ErrIncomplete`.
Missing, extra, conflicting or reordered chunks never become a completed dataset.
Completed/failed instances cannot be reused. Value copies of a Validator handle
share the entire private state (hash, counters and terminal status); copying cannot
split counted rows from hashed rows. Handles are not safe for concurrent use.
Input metadata and returned receipt
metadata are detached from caller pointer mutation. Rows returned by Build own
their row-slice descriptors; changing the input row slice does not change them.

The receipt is consistency evidence only. A caller must atomically stage rows and
publish the current-generation pointer only alongside a matching valid receipt.
Failed/in-progress generations cannot replace a prior complete observation or
be interpreted as zero updates/CVEs. Source age, replay, consent, authenticated
device identity and current revocation status require the enclosing authority.

## Explicit budgets and work bounds

| Resource | Hard ceiling / behavior |
| --- | --- |
| Raw manifest | 4 KiB |
| Raw chunk | 64 KiB |
| Rows per chunk | 128, with earlier byte-based split |
| Selected rows per generation | 100,000 |
| Chunks per generation | 1,024 |
| Canonical row stream | 32 MiB, including row LFs |
| Canonical manifest + chunks | 48 MiB (`MaxCanonicalWireBytes`) |
| Unique accepted raw manifest + chunks | At most 64 MiB + 4 KiB (`MaxGenerationRawBytes`) |
| Private checkpoint | 2 KiB |
| Source reading | Existing parser's separate source limits; no source I/O here |

Build reserves 2 KiB of the 64 KiB chunk ceiling for the bounded envelope, splits
before exceeding the remaining row payload or 128 rows, and checks the actual
final encoding too. Limits reject the **whole generation**; they never select a
128/256-row global prefix. A dpkg source within its input cap can still exceed a
separate supported canonical-generation budget and must fail explicitly.

The 48 MiB limit counts canonical encodings, not whitespace/escape-padded network
traffic. Per-object raw limits and 1,024 accepted chunks bound a unique generation
to 64 MiB + 4 KiB, but this pure package has no transport retry counter. Runtime
integration must independently enforce aggregate ingress, request/rate/deadline,
per-device/global pending-generation, retention and disk quotas before parsing.
Rejected/retried requests do not acquire unlimited work entitlement.

Memory is structurally bounded, not a measured hard RSS promise: Build owns up to
100,000 row descriptors (seven strings each), at most 32 MiB logical canonical row
payload, at most 1,024 chunk descriptors, sorting indices and one bounded chunk
encoding at a time. It does not retain all canonical row encodings simultaneously.
The caller owns the already-materialized source rows and their backing storage.
Decode works on one 64-KiB object at a time with bounded JSON depth/member/array
allocations. The streaming validator retains one manifest, fixed SHA256 state,
counters and a last identity of at most 320 bytes, not the generation's rows.
Temporary Go allocator/GC overhead and caller-supplied backing storage are not
RSS-isolated by these APIs. Measured peak memory and a configured lower admission
budget remain required before enabling collection or storage in production.

Work is bounded by at most 100,000 row validations plus `O(N log N)` sort and
linear encoding/hash passes for Build; Add has at most 128 row validations and
bounded encoding/hash work. No version comparison, subprocess, network request,
repository lookup or disk scan occurs. Callers must not multiply these maxima by
unbounded parallel generations, retries or restore transactions. Context is
checked between rows/chunks and after sort; sort is bounded but not preempted by
this package's own checks.

## Trusted-manager checkpoint seam

`Checkpoint()` returns manager-private versioned canonical JSON;
`RestoreValidatorFromTrustedCheckpoint(ctx, manifest, bytes)` restores it.
`Progress()` exposes accepted chunks, observed/installed rows, canonical row/wire
bytes and last chunk digest for comparison with persisted transaction counters.
The checkpoint contains a partial SHA block that may include selected row bytes:
never expose it in request responses, logs or artifacts.

The exact format version is
`tracebolt.full-inventory.checkpoint.sha256-go1.v1`. This version pins the current
108-byte Go SHA256 binary state with `sha\x03` magic and big-endian byte count.
Unsupported versions/formats fail rather than guessing across toolchain changes.
Restoration requires exact canonical JSON, strict shape/types, matching manifest
hash, safe/feasible ordinal/count/byte relationships, valid last identity and
previous hash, exact domain-inclusive SHA byte count and canonical binary state
padding. Initial state is byte-for-byte initial; final state must already match
the declared full totals/digest. Checkpoint slices are detached.

This API accepts **only trusted manager persistence**, never request bodies or
client-supplied checkpoints. Accepted chunk/row bytes, progress and checkpoint
must be saved in one authority-checked transaction. This is continuity from a
trusted database, not independent proof against arbitrary database/checkpoint
tampering. A stronger threat model requires an authenticated checkpoint or a
bounded independent rescan. The surrounding storage layer owns crash consistency,
idempotency, trusted manager time, anti-replay and all quota/revocation checks.

## Local checks and integration gates

Focused tests cover a 100,000-row dataset including its final row; >128/>256
retention; dynamic byte splitting; source failure and whole-budget rejection;
empty residual-only generations; independent release availability; exact row
semantics; cross-chunk ordering/duplicates/linkage; missing/extra chunks; metadata
binding; cancellation/aliasing; strict malformed JSON; integer overflow; known
hash vectors; and checkpoint initial/intermediate/final restoration/corruption.
Fuzz targets exercise strict manifest/chunk decoding without I/O.

These are pure fixture checks. They do not establish runtime deployment,
real source consistency, throughput/RSS/storage capacity, HTTP frame compatibility,
new-profile consent, vendor advisory coverage, updates or vulnerability accuracy.
