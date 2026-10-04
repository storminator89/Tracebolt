# Complete dpkg inventory: integration proposal

Design only. The current released/held basic and managed-v2 protocols retain
their existing semantics. This proposal does not authorize real collection,
service installation, transport exposure or credential provisioning.

## Scope and consent

A new explicit collection profile must name complete supported dpkg inventory,
not silently reinterpret the selected-row managed-v2 profile. Exact initial OS
support remains Debian13/Trixie and Ubuntu24.04/Noble. Snap, Flatpak, AppImage,
manually copied applications and arbitrary filesystem scans are not covered by
dpkg completeness and must have independent unsupported/unknown indicators.

Use the already selected seven package/source fields. Do not add account names,
files, executable paths, command lines, environment, repository URLs, trust flags,
log bodies or external AI exports. The user may opt into a fresh disposable test
identity; no existing profile/ledger is reset or adopted.

## Coherent source generation

The native adapter reads the existing fixed protected release/dpkg sources,
validates the full source and stable source identity, and builds all chunks before
starting upload. It operates on full parser rows BEFORE the existing selected-row
Trim function. Counts are derived from the full supported scope. A valid
residual-only source can be complete with zero rows; missing, empty or malformed
raw input is failure, not zero. A source change or resource exhaustion aborts the
new generation. Partial source prefixes never become complete inventories.

The pure contract owns ordering, chunk size, count and digest validation. Limits
are explicit rejection ceilings. A failed new generation preserves the previous
complete generation with its original age. Neither retries nor arrival time can
refresh collection time.

## Transport to review before implementation

Do not enlarge the existing72KiB telemetry frame or put an entire package database
in it. Use separate fixed-purpose inventory endpoints and bounded chunk messages.
Keep the existing TLS agent ingress and normal server/agent certificate checks.
The signed HTTP-test transport needs a separately versioned, domain-separated
proof that binds exact configured audience, method, fixed path, leaf fingerprint,
inventory generation sequence, generation/manifest identity, chunk ordinal and
raw body digest. It must not authorize existing telemetry or operator routes. Finalize, abort and
status are separately purpose-bound authenticated operations that include the same
generation sequence, generation ID and manifest identity; they are not unauthenticated
control shortcuts.

A short-lived transport proof time is distinct from the original inventory
collection time. Retrying a retained chunk may create a fresh transport proof but
must preserve the exact chunk bytes, original collection time and generation.
HTTP-test still has no confidentiality or server authenticity; it is not upgraded
to TLS-equivalent security by chunk signatures.

Maintain an independent durable inventory-generation sequence domain. Sharing
telemetry's sequence would allow one channel's pending messages to invalidate the
other. Generation identity is immutable and cannot be reused with different
manifest bytes. Keep a durable per-device inventory sequence floor even after
old rows expire or are cleaned up, so an old generation cannot be reintroduced as
current. Exact retries never extend the staging TTL or reset this floor.

All chunk admission uses activated matching-profile identity, exact current
certificate and revocation checks in the SAME SQLite transaction as staged writes
or completion. Verification/body work has bounded global admission; an identity
slot is reserved only after possession is proven. No unbounded DB wait queue and
no remote-claimed identity or freshness. Existing initial-BEGIN busy semantics
remain distinct from uncertain write/commit errors.

## Storage and read models

Use normalized chunk/row storage and bounded indexed pages, not restoration of
all devices' full inventories into memory on every request. Each device has at
most one upload generation and one current complete generation. Pending and
retained logical quotas, physical database/WAL budget and pruning work need
explicit integration measurements before runtime enablement.

Completion atomically validates every ordinal/hash/order/count and swaps the
current pointer. A receipt is returned only after commit. A failed/uncertain
commit cannot advertise completion. Exact retries are idempotent and preserve
receipt/collection ages. Interrupted uploads have a bounded expiry; pruning
cannot erase the last successful view as if a missing upload meant zero packages.

The operator UI distinguishes current-complete generation from new transfer
state (pending/failed/unavailable) and independently shows age/staleness. Search
and pagination are pinned to a completed generation and deterministic binary
name+architecture ordering. A page size is a transfer/display limit, not the total
inventory limit. An expired/deleted generation makes the cursor explicitly
invalid; never mix pages from a newer generation. Search matches selected inert
fields only; no executable query fragments or remote URLs.

Completeness describes stored supported dpkg scope, not vendor provenance,
uncompromised endpoint state, update availability or CVE absence. Conditional
advisory review must still report missing trust/release/feed coverage and must
never derive a zero-finding conclusion from a partial/new upload.

## Scheduling and lifecycle

Upload a generation as a bounded batch, separately from the30-second metrics
cadence. Define an explicit inventory interval, staging TTL and freshness policy, including a server-checked maximum future collection skew
independent of transport proof time;
copying the120-second metrics expiry would make large valid batches impossible.
Any proposed numbers need measurement and review before being represented as
supported capacity. Preserve one in-flight collection, cooperative cancellation,
fixed local sources, bounded spool/disk usage and no accumulating goroutines.

Persist the selected generation and exact chunks under the existing private
service identity before sending. Hold the sender's lifetime lock and bind spool
state to exact instance/origins/profile/key. Restart resumes the same pending
bytes; changed binding or missing/replaced source/spool state fails closed.
Per-generation and overall private spool/disk budgets cannot be exceeded by
starting another generation, and a storage failure cannot discard an ambiguous
pending generation to make room. Installer upgrade
must preserve both sequence domains and any exact pending inventory generation.

## Gates

1. Pure parser/chunk and transactional storage tests, including zero-row,
   ordering, missing/duplicate/conflicting chunk, quota, expiry and rollback.
2. Authenticated ingress/atomic revocation, transport-domain and exact retry tests.
3. Indexed complete-generation pagination/search and browser interruption tests.
4. Synthetic large complete generations beyond128/256 rows, proving all rows can
   be enumerated exactly once and missing chunks never promote a prefix.
5. Explicit native full-source and real systemd lifecycle acceptance, with bounded
   sanitized evidence only. No existing source/CI result implies these new gates.
