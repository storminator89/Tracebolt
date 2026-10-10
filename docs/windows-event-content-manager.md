# Selected Windows event content manager

This source candidate connects separately granted selected-event messages to the
Windows manager and administrator API. It does not grant native event reads,
change existing five-scope Setup, or establish native Windows acceptance.

## Durable authority

The separate Windows enrollment database gets three strictly checked normalized
tables. SQLite's application ID is a durable initialization marker, so dropping
even all extension tables cannot cause used state to be silently recreated.
An immutable optional marker in each used Windows credential independently
requires its exact authority row. A request-presence flag distinguishes deliberate
metadata purging from accidental request-row loss. Every authority row requires
its matching marked Windows credential; Linux credential bytes remain unchanged.
Linux stores retain their existing schemas. Authority is bounded to 25 Windows
identities. Request and independent capability sequence floors are canonical
decimal text, avoiding SQLite signed-integer overflow. Cancellation, expiry,
metadata purging and restart preserve these floors. A durable trusted-time floor
rejects clock rollback.

An independently authenticated capability report commits the exact consent,
grant, certificate, sender binding, monotonic sequence and original capture time.
Its five-minute freshness is never refreshed by an exact retry. An explicit
administrator create resolves 1–16 channel/record selections against the accepted
header snapshot inside the same transaction as the expected floor and exact
generation/digest check. Later ordinary telemetry replacement does not alter the
immutable selected identities. The request's original fifteen-minute expiry
never changes.

Claiming commits the foundation's pending-to-claimed transition before returning
work. The endpoint must separately durably consume that grant before reading.
Acceptance validates the original selection and policy, commits the digest-only
receipt, and only then permits publication to bounded memory. Exact result retry
requires the original canonical wire-result digest and returns the original
receipt. It never refills a missing cache. Each memory entry is limited to
512 KiB, with at most 25 entries and the source's separate 64 KiB text ceiling.
Neither messages nor encoded results enter SQLite, telemetry or AI export.
Request-header metadata is purged at its original 24-hour header-retention
cutoff; independent authority rows and replay floors remain.

## Session and disclosure lifetime

Memory ownership belongs to the authenticated administrator session, never an
identity supplied by the browser. Logout, session lifetime cancellation and
expiry discard content and cancel remaining authority. Startup cancels old
pending/claimed work because session ownership cannot survive restart; accepted
digest receipts remain retryable without restoring content. Disclosure requires
the original request, header retention, certificate and session to remain valid.
Grant replacement, disable or certificate revocation invalidate old requests.

When cancellation cannot commit immediately, content and ownership are still
removed. Maintenance retries cancellation of unowned pending/claimed work while
holding the ownership mutex. Each pass validates the full store once and batches
authority checks, expiry, metadata purge and exact-identity orphan cancellation
in one transaction, including at the 25-device ceiling. Fresh time and live
sessions are checked again after that transaction without per-device reloads.
An owner that expires during storage loses memory immediately; the next batch
retries its durable orphan cancellation. A current administrator may explicitly cancel an
orphaned exact request identity; that operation never restores content ownership.
Another live session cannot take over or cancel an existing owned capture.

## Operator API

The routes are GET /api/devices/{id}/windows-event-content and POST subroutes
/create, /cancel and /query. All require shared administrator sessions; none of
the POST routes belongs to named-read authorization. Mutations and content queries
use exact JSON, same-origin CSRF checks and server-derived ownership. Final
response checks run after encoding. Trusted clocks are resampled after mutex and
store waits; queued older call timestamps cannot falsely erase live content,
while genuine backwards time remains rejected. Browser record IDs remain decimal strings,
including values above JavaScript's exact integer range. Content must be rendered
as untrusted plain text and cleared on navigation. Ambiguous create outcomes
require status reconciliation and best-effort exact-identity cancellation.

Create requires expectedFloor, expectedHeaderGenerationId,
expectedHeaderSnapshotDigest, selections (channel and recordId),
acknowledgeContent and acknowledgePlaintext. The plaintext acknowledgement is
mandatory for HTTP-test. Cancel and query accept only identity. Status includes
an opaque sessionBinding and sessionExpiresAt; neither is an authentication token.
A committed receipt without surviving content is explicitly result_lost.

Manager startup explicitly initializes the extension before exposing endpoint
polling. Its maintenance lifecycle expires requests, rechecks authority and
clears invalid memory. Shutdown clears the cache before closing the store.

## Verification boundary

Synthetic fixtures cover claim races and response loss, independent capability
age/replay, immutable header selections across later telemetry, original expiry,
clock rollback, grant replacement, missing-used-schema rejection, uint64 floors,
digest commit failure, metadata purge, receipt retries without rehydration,
server-side session ownership, slow response rechecks and named-read exclusion.
Run the focused package suites with the pinned Go 1.27.1 toolchain:

    go test -race ./internal/enrollmentstore ./internal/enrollmentservice ./internal/windowseventcache ./internal/api

Fixtures and cross-compilation are not permission to read native logs or evidence
of installed-service/native browser end-to-end acceptance. A separately approved
exact-source Windows gate remains necessary before release.
