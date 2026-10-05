# Managed-v3 system-observation storage candidate

This unpublished source candidate adds service/socket storage only to a fresh
managed-v3 schema 3. It has no deployed-schema migration and cannot upgrade or
relabel released basic-v1 or managed-v2 identity/state. Tests use generated normal
identities and temporary SQLite databases, never host inventory or deployment.

## Transaction and authority

`Store.SaveSystemObservation` accepts the exact original systemwire request body.
It decodes the strict typed snapshot, derives its system-specific generation from
the authoritative device and independent sequence, and hashes the exact body.
An existing `BEGIN IMMEDIATE` transaction restores the authoritative enrollment
ledger, rechecks profile 3, Linux platform, activation, exact issued leaf hash,
issuer verification, current expiry/revocation and this domain's replay floor.
There is no authority cache and no package or telemetry clock/floor dependency.

Only a strictly increasing sequence and strictly later original collection time
can replace a receipt. New collection times must be no more than two minutes old
and cannot be in the future. An exact latest-body retry returns the identical
original receipt even after collection becomes stale. A same-sequence different
body, including different whitespace, conflicts. A lower sequence conflicts.
These checks continue after cleanup and restart. Revocation/expiry always wins
over idempotent retry. Precommit metadata validation also prevents an enrollment
lifecycle transition from predating a committed system receipt.

## Normalized bounded retention

Three exact-schema tables are added only during fresh schema-3 creation:

- `enrollment_system_authority`: at most 25 small typed metadata records, each
  capped at 16 KiB; holds independent sequence, exact-body digest and original
  receipt plus latest snapshot metadata and last-complete references.
- `enrollment_system_sections`: at most two retained complete sections per
  device; exact original generation, sequence, observation time, source metadata,
  row count and logical serialized bytes.
- `enrollment_system_rows`: typed canonical row JSON indexed by immutable section
  ordinal, with an 8 KiB per-row rejection ceiling. Services are limited to 8,192
  rows and sockets to 16,384; the earlier 512 KiB per-section/1 MiB snapshot byte
  limits also apply. These are rejection ceilings, not supported-size promises.

The latest complete section and its retained last-complete section share one row
set. A failed latest section has zero rows and only explicit failure metadata;
its previous complete section remains separate with its original generation and
age. Therefore a snapshot never needs to be stored twice. Successfully observed
empty sections remain distinct from source failure, whose count is unknown/null.
Socket PID attribution quality remains independent from enumeration coverage.

The device logical-byte ceiling is 2 MiB and the 25-record pilot global ceiling
is 50 MiB, counting canonical authority metadata and exact serialized sections.
Before ingestion commits, SQL count/length/ordinal aggregates verify every
reserved normalized section and exact global admission; endpoint row blobs are
not decoded by that check. Routine authority restoration reads only small bounded
metadata and never restores/parses all service/socket rows. A target page validates
each fetched row before use. Storage corruption produces a storage error, never
an invented empty healthy section. Database/WAL/page admission remains under the
existing profile-3 physical capacity checks.

## Operator status and bounded queries

`Store.SystemView` returns `tracebolt.system-inventory-view.v1`, collection profile,
server time, independent sequence/receipt time, latest section metadata and separate
last-complete summaries. Status is `unknown`, `awaiting`, `fresh`, `stale`, `revoked`
or `expired`. Freshness uses original collection time: over two minutes is stale;
at 24 hours source metadata and rows become invisible. Revoked or expired
identities expose no source metadata or pages. Neither retries nor read queries
refresh original collection or receipt time.

Metadata reads have one store-global permit, held for the entire read. That one
reader may wait up to 750 ms for the existing inventory admission slot, including
when periodic maintenance is waiting for SQLite. Its queued channel handoff is
served before newly arriving nonblocking work. No extra SQL transaction is active;
additional metadata readers and exhausted admission waits still return typed busy.
Caller cancellation remains cancellation, not retryable busy. Paging, writes and
maintenance keep their existing admission, cadence and batch bounds.

Trusted service time is reacquired after SQL authority loading, after commit, and
immediately before API output. Certificate expiry clears source metadata, original
24-hour retention still applies, and fresh/stale labels age without changing the
original collection time, receipt or sequence. A clock rollback cannot revive
expired observations. This short wait avoids requiring a later HTTP retry merely
to cross a routine maintenance burst; sustained overload remains explicit.

`Store.SystemPage` takes section, explicit generation ID, search, fixed filter,
limit and cursor as request-body values, never URL values. It scans at most 2,048
indexed rows and returns at most 100 rows. Stable ordinal ordering persists for
the immutable generation. A search page may be empty and nonexhausted; callers
must continue with its cursor rather than infer no global matches.

Search is case-insensitive, trimmed UTF-8 up to 128 bytes, excluding control,
format and replacement characters. It searches typed service names/runtime/
enablement and socket protocol/family/kind/addresses/ports/state/owner PID/name.
Server filters are services `all`, `active`, `failed`, `enabled` (including
`enabled-runtime`), and sockets `all`, `tcp-listeners`, `udp`, `connections`.
The store's empty filter is equivalent to `all`; the HTTP contract may require an
explicit filter. `totalRows` is the entire retained section, not a claimed global
filtered-match count. `returnedCount` and `scannedCount` describe only the page.

Cursor HMAC uses the trusted per-instance key with a separate system-cursor
purpose domain. It binds device, section, generation, normalized query, exact
filter, page limit, next ordinal and expiry. Lifetime is 15 minutes, capped by the
original section's 24-hour visibility deadline. Cursor length is capped at 2 KiB.
Generation replacement/retention expiry conflicts explicitly; no empty successful
page substitutes a different generation. Invalid, tampered or expired cursors
are explicit errors. Pages retain separate service/socket typed arrays; unused
arrays are empty, not null. The transport can choose a smaller limit to meet its
response byte ceiling (for example 25 socket rows).

## Maintenance and isolation

`Store.SystemCleanup` is trusted local maintenance with no agent route. It may
clear only expired payloads; it retains the original receipt, exact digest,
independent floor and enrollment authority, including after identity revocation
or certificate expiry. A later authorized new report still requires a higher
sequence and later collection time. Maintenance cannot erase a replay floor.

These methods expose operator-only metadata and rows. They do not add raw source
or system inventory to AI inputs. Routes, session/CSRF checks, TLS/signatures,
response limits, collector consent, durable exact-frame sender retries and UI
presentation are separate integration responsibilities.

## Focused validation

`go test -buildvcs=false ./internal/enrollmentstore -run '^TestSystem' -count=1`
covers exact replay/restart, body-change conflicts, fresh-time and identity
binding, independent package clocks/floors, separate last-complete ages, 3,000-row
pagination with a bounded empty continuation, server filters and cursor binding,
cleanup/floor persistence, cross-handle authority, concurrent same-sequence
conflicts, revoked replay/page rejection, source/metadata corruption, oversized
section rejection and atomic exact-accounting failures. Full
`./internal/enrollmentstore` tests also exercise the unchanged legacy and package
store behavior. These are synthetic local tests, not live-host acceptance.
