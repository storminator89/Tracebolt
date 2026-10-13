# Complete-source service episodes in the Windows inbox

This manager-only source increment makes explicit complete-service v2 episodes
visible in the everyday fleet **Windows incidents** panel. It is an additive
combined projection, not another evaluator, service ledger or endpoint scope.
The existing [v1 inbox](windows-incident-inbox.md) and acknowledgement APIs retain
their exact bytes, target keys and behavior. The fleet UI explicitly chooses the
new v2 API; it does not silently fall back to v1 after failure.

## Source-qualified history and current confidence

The v2 inbox includes the existing contact, disk, CPU, RAM and selected-service
families. Old rows carry `sourceKind: assessment_v1` and preserve their original
v1 target/seen identity. Complete-service rows carry `sourceKind:
windows_full_services`, `domain: service-complete`, and original opening,
last-bad, optional recovery and independently qualified current provenance.
Original capture start/end, final manager receipt, grant/revision, generation,
sequence, digest and row count remain separate. Native service name limits remain
256 UTF-16 code units / 1,024 UTF-8 bytes; complete names are read through the
separate v2 service review and never widen the old control-target contract.

Current confidence comes from the complete service engine's existing qualified
view. Its deadline is the earliest of current evaluation +120 seconds, current
capture +300 seconds, current receipt +300 seconds, original source expiry and
live credential expiry. A retained historical source can never renew this
confidence. Grant loss, a newer partial/failed attempt, stale or missing source,
manager restart or an unevaluated new generation leaves the episode visible as
unknown under the same live original enrollment. Unknown does not close history.
Revoked/replaced enrollment identities expose no retained rows.

The combined page is explicitly read on demand. Reads select at most eight names
per tagged complete-service device (at most 25), and reuse bounded source integrity
verification. No read creates state, evaluates, repairs, prunes or writes anything.
Disabled history needs no selected rows. The existing coordinated evaluator and
source cadence are unchanged.

## Seen is an independent, durable action

A shared administrator can mark one exact retained row seen. Named operators can
read only. Seen never means closed, recovered, suppressed or externally notified.
Full-service targets use a separate v2 hash namespace bound to original device,
invitation, issued-certificate anchor, `service-complete` domain, exact incident
and opening time, and the opening observation's local grant/revision. A new grant,
replacement identity, sibling domain or later episode cannot inherit an old seen
record. Same-identity certificate renewal preserves history; its current leaf is
still checked for each operation.

A separate canonical acknowledgement table stores at most 2,500 complete targets,
each at most 2,048 bytes. Existing v1 acknowledgements are not rewritten. There is
one tagged service ledger per device, so the combined episode bound remains
25 devices ×100 episodes ×five families =12,500, not 15,000. Physical acknowledgement
metadata retains its independent old 12,500/new 2,500 caps because old orphan metadata
can remain until a deliberate acknowledgement in its own namespace prunes it.
Retained seen records never age out. Source closed-history retention remains
30 days/100 rows/256 KiB; oldest closed episodes may be pruned earlier for bytes.

Mutation lock order is enrollment authority then operator SQLite. The inbox lease
pins original identity, exact active leaf/expiry and current complete-source
snapshot through commit: the exact generation when available, explicit absence
when unavailable. An unavailable or disabled source can still acknowledge retained
history, without granting evaluation or collection. Missing used-state storage
is an error, never fabricated absence. A future-dated capture/receipt cannot be
admitted as an absent acknowledgement source, because it could become eligible
while a locked read or SQL wait consumes time; ordinary reads still show unknown.
Post-SQL-wait and final guards check actual
monotonic time, five-second request/lease bounds, session, credential and source
freshness. Changed source/authority rolls back the write. A post-commit response
race remains uncertain and reconciles through GET only; the UI never retries POST.

## Additive closed API

- GET `/api/fleet/windows-incidents/complete` returns
  `tracebolt.windows-incident-inbox.v2`, using the same exact scope/ack/offset/limit
  filters, active/all/0/25 defaults, 1–50 page size, 12,500 offset bound and 256 KiB
  response cap including its terminating newline.
- POST `/api/fleet/windows-incidents/complete/acknowledge` accepts exactly `key`
  and returns `tracebolt.windows-incident-ack.v2`. Old row keys update their
  unchanged v1 metadata; complete row keys update only the v2 table. Live shared
  administrator, same-origin JSON, CSRF and exact retained target are required.

Counts precede filters, ordering remains newest opening then key, and paging is a
current snapshot rather than an immutable cursor. Complete rows show their source
label and expandable provenance. Old supported service rows retain their v1 review
link. Complete rows offer the [separate v2 exact service review](windows-service-incident-review.md#explicit-complete-source-v2-review),
with full native-name read support and unchanged separately approved control
limits. Complete episodes
remain excluded from old external notification policies and Linux/AI exports.
The independently opted-in [complete-service notification bridge](windows-complete-service-notifications.md) uses separate approval and the shared Windows outbox.

## Verification and remaining gates

Focused source tests cover strict namespace/canonical storage, original opening
grant, restart/idempotency, unchanged source bytes, native names, source loss,
actual current-leaf mismatch, used-state loss, exact roles/requests, final source,
clock and session rejection, SQL waits and bounded retention. Recorder API tests
use direct requests and responses, no listener. UI tests consume Go-exported JSON.
Hosted synthetic changed-view capture source is separate from native Windows,
release and deployment acceptance. Source fixtures establish none of those gates.

## Hosted changed-view evidence

The existing Windows service browser gate reuses its Chromium instance for exactly
8 additive component/hook captures: active/unseen and unknown/seen, EN/DE at
1440×1100 and 390×844. Unknown-source provenance is expanded and checked, then
collapsed for a readable status capture. Original service names remain unshortened;
normal-size status and controls must fit without horizontal clipping or full-page
shrinking. This mounts the real inbox and protected request adapter, not the whole
App. Every request is intercepted, with no acknowledgement/action POST allowed.

Focused PR and full Validate tiers require the canonical scene manifest, source
commit/tree, exact compiled-source inventory/digest, PNG dimensions/hashes and
8 exact artifact filenames. Missing, foreign, stale or failed evidence fails the
normal browser gate; failure uploads still list only those exact image names.
These source contracts are not hosted pixel review or native acceptance.
