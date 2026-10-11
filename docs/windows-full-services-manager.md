# Windows complete Win32 service generations: manager source candidate

This additive manager path belongs only to the existing activated Windows
inventory identity. It does not change Linux profile admission or initialize
endpoint consent. `InitializeWindowsFullServices` creates the exact optional
SQLite schema; a credential's immutable used bit prevents missing used tables or
floors from being reconstructed. Old telemetry v1–v7, health selections and startup
configuration bindings remain separate.

## Transaction and disclosure boundaries

The protected enrollment database holds independent consent revisions, capture
sequence floors, original scope/failure receipts, staged manifests/chunks and
normalized rows. The first authenticated scope recomputes the existing Windows
sender binding from transport profile, the trusted configured agent-ingress origin,
certificate and device. The agent-ingress origin may differ from the enrollment/UI
origin. Every transport operation must install that configured origin in trusted
context; absent, malformed or mismatched context fails closed. The exact ingress
origin is durably pinned with the independent authority record and never inferred
from a client Origin/Host/header or reconstructed from missing used state.
Every chunk, exact retry, failure, operator page and query resolves live activated
Windows identity and certificate authority within `BEGIN IMMEDIATE`. Scope must
match the last acknowledged exact local consent. A higher consent revision can
suspend or replace that scope without resetting the capture floor.

Before first staging insertion, the manifest's complete row/chunk/byte reservation
must fit device/global limits. Every accepted chunk preserves its exact canonical
request and original receipt. Reordered or conflicting replay fails. The final
chunk validates canonical whole-generation count, order, case-folded unique
identity, row bytes and digest before atomically promoting the generation. An
explicit zero-row chunk is the only empty complete generation. Failure and pending
attempt status remain separate from a prior complete observation and never
refresh its capture, receipt or expiry.

The transaction's final callback rechecks current identity/certificate authority,
original source/staging expiry and operator session before COMMIT. No provisional
receipt or row escapes failed COMMIT. The store rechecks the trusted clock after COMMIT and then runs a fresh read-only
authority transaction, including current certificate, grant and generation, before
releasing rows or receipts. Final guards sample the trusted clock again only
after acquiring the SQLite connection and completing BEGIN/load, then immediately
before COMMIT; both samples recheck live authority and the original deadlines.
A held connection cannot authorize output with the pre-wait time. Observed time
can advance but cannot roll back within the operation. These guards remain
read-only and preserve original capture, receipt, reservations and replay floors. The ingress uses a dedicated read-only final receipt
authorization seam after marshaling; it does not replay Apply to authorize output.
The HTTP operator handler performs a further read-only current-authority check at
its final clock boundary, then checks session activity immediately before output. A request body cannot supply
the trusted clock or session context.

## Paging and retained lifetime

POST `/api/devices/{id}/windows-full-services/query` is read-only but requires the
current operator session, exact Origin, CSRF token and JSON body. Named read
operators may use this precise route. Private search/cursor values are rejected
in URLs. The fixed typed request and response are in `windowsfullservices`.

Before a search/count can claim absence, a streaming integrity pass verifies
every canonical row, derived search/name/identity/PID/state column, exact ordinal
order, full count, canonical byte total and original digest. Work is bounded by
8192 rows and8MiB canonical bytes; it does not retain the whole generation in
memory. Search and count run only after that pass under the same authority
transaction. Literal Unicode simple-fold search counts matches across the entire
bounded complete generation. Six fixed sorts use raw UTF-8 binary name/state order or
numeric PID, with unavailable state/PID last in either direction and exact name
ascending as the tie-breaker. Pages contain at most100 rows and256KiB; HTML JSON
escaping can yield a shorter nonterminal page. MAC cursors bind exact device,
grant/revision, manifest/generation, query/sort/limit, matching offset, operator
session and original expiry. Expiry is bounded by15minutes, original24-hour
capture expiry, certificate expiry and session expiry. Replacement of current
immediately invalidates continuation; there is no retired-page grace.

## Reservations, physical caps and cleanup

The optional storage reserves at most24MiB/device, three generations/device,
128MiB global logical bytes,200000 rows,4096 chunks and75 generations. Reservations
cover four canonical row copies plus manifest/chunk/receipt overhead and remain
held until physical cleanup finishes. Existing authority, retained telemetry,
event metadata and resource-history bytes count against the global allowance.
These are fail-closed rejection ceilings, not simultaneous supported-capacity
promises: an8MiB canonical source can exceed the24MiB normalized reservation.

Windows keeps its existing192MiB database/WAL/sidecar caps; these were not raised
to Linux's512MiB database/640MiB WAL limits. Windows transactions now use the
same conservative FULL-synchronous WAL reservation with cache spill disabled,
while retaining their own page limit. The Linux authority predicate is unchanged.

Trusted manager maintenance runs one bounded cleanup step per second and retains
the existing event-content maintenance's five-second cadence. Each cleanup step
removes at most256 rows and16 chunks from one eligible noncurrent generation.
Expired staging/current data and revoked identity data become eligible; scope and
capture floors and original receipts remain. One8192-row retired generation can
be reclaimed in32 steps. Multiple maximum-size devices may still exhaust quotas;
there is no promise of15-minute retired grace or universal maximum-size cadence.

## Evidence and remaining native gate

Source-only fixtures cover2051 invented rows through durable generation storage,
restart/exact retry, later-row search, protected operator HTTP paging, named-reader
admission, Origin/CSRF rejection, session/certificate/cursor expiry, failed latest
attempts, explicit zero, grant/sequence isolation, quota-before-write, bounded
8192-row cleanup and actual deferred-constraint SQLite COMMIT rollback. Independent negative
regressions cover identity revocation committed at the post-COMMIT clock sample,
a corrupted search column hidden from filtering, and expired pending state before
maintenance. Additional cases cover a distinct configured ingress origin, missing
trusted context, changed/malformed origin, missing durable binding and revocation
at the operator handler’s final clock sample. Go-exported
page vectors cover the2051-row first/late/search pages, failed-latest preservation
and escaped-byte-short continuation for the frontend tests.

These checks never enumerate the manager host or Windows host. Composed TLS and
signed-HTTP sender ingress tests are separately owned evidence. Native limited
LocalService SCM enumeration, installed Windows lifecycle and real browser/device
acceptance remain separate authorized gates.
