# Shared pure bulk-row foundation

This document records the pure foundation originally introduced after the
bounded cached-update preview. The [complete cached-update extension](complete-cached-updates-extension.md)
now wires it into separately opted-in capture, transfer, storage and dashboard
paging. The pure planner itself performs no I/O and grants no collection scope.

## Reuse without parallel state machines

`internal/bulkrows` contains one pure bounded planner for validated value rows:
validate the whole input, copy/sort descriptors, reject duplicate identities,
choose row/byte chunk boundaries, and hash canonical rows in a fixed domain. Each
adapter supplies fixed limits and pure row validation/ordering/encoding functions.
These are compile-time policies, not a wire-selected plugin registry. The helper
has no source paths, executable, network, filesystem, authentication or storage
capability. It returns no usable prefix on failure or cancellation.

The existing dpkg `fullinventory.Build` now uses the helper but keeps its original
manifest/chunk types, ordered JSON, domain strings, limits, digest chain, exact
receipts, source checks and all transport/state/storage behavior. No process or
mount refactor is included. The unchanged dpkg streaming validator/checkpoint code
continues to verify the planned output independently.

Compatibility is pinned to exact canonical bytes captured from the unchanged
424bff2 builder before extraction. `original-424-wire-sha256.json` records complete
wire SHA-256, manifest digest, byte length and chunk boundaries for empty/1/128/
129/513 rows, reversed input, long versions forcing byte boundaries, and unknown/
denied release metadata. These are synthetic fixtures, not endpoint inventory.
They detect changes to field order, omission, hashes, boundaries and byte counts.

## Complete update adapter

The separate pure `updategeneration` adapter uses the same planner for the full
known-candidate set. Its input includes the original validated bounded snapshot,
all pre-trim rows, an explicit complete-source assertion and the operation error.
A missing/failed source, incomplete prefix, count disagreement or inconsistent
preview prefix is rejected. The assertion is not provenance or proof of OS
administrator consent; the integrated collector/runtime supplies it only after
the consented cached-only source operation and final source recheck succeed.

Its own versioned manifest preserves original release/cache timestamps and all
comparison counts. Unknown candidate comparisons stay explicit and partial.
Completion means all declared known candidate rows arrived consistently; it does
not mean every installed package was comparable, metadata is fresh, the endpoint
is fully patched, or vulnerabilities were assessed. The integrated complete-row
scope is distinct from preview consent and remains default-off.

Bounds remain small per operation: 64 KiB chunks, at most 128 rows per chunk,
16,384 candidate rows, 32 MiB canonical rows and 48 MiB canonical generation wire.
The adapter validates independent chunks and generation linkage and returns a
completion receipt only for the full validated generation. Empty success is
separate from absent or failed source data.

## Current integration and remaining gates

The [complete-row runtime](complete-cached-updates-extension.md) reuses the
protected spool and manager generation/staging/cursor algorithms through a fixed
update codec. It adds independent full-row consent and a durable floor, six-hour
capture cadence, exact-byte retries, atomic promotion, original-age retention and
generation-pinned operator paging. Preview consent does not authorize full rows.
The adapter reads existing APT metadata only; it never refreshes or installs.

Native Debian 13 and Ubuntu 24.04 acceptance remains separate from source, fixture
and compatibility tests. Strict source/config limits and explicit unknown,
unsupported and stale outcomes remain; a complete known-candidate generation
does not prove every installed package was comparable or an update installable.
