# Windows process presence watches

This manager-only source slice saves up to eight exact executable names for one
Windows device and derives their **presence in the latest complete caller-visible
Toolhelp snapshot**. It is default-off. It reuses only the separately consented
[complete process source](windows-full-processes-contract.md). It never enables
collection, changes a local grant, reads the host, opens process handles, changes
CPU/RAM policy, or invokes an action, notification or AI provider.

This is a **live presence view**, not continuous process monitoring or incident
history. No execution state exists in this source. A matching name does not prove
that a process is running, responding or healthy. A process may have exited after
the snapshot. PIDs do not join retained measurements or become stable identities.

## Explicit saved-selection consent

The Processes inventory contains a collapsed “Process presence watches” panel.
Its summary prominently states “Snapshot · no alerts or incident history”. The
combined “Refresh processes and watches” action reloads the latest inventory and
the saved watch view through existing protected reads; it does not save consent,
retry a write or start host collection. An authenticated operator can read saved
selections. A shared administrator can
choose names from a fresh, complete inventory, across its bounded pages, then
explicitly acknowledge storing those names and comparing already-consented
snapshots. Consent is unchecked and reset after source changes, interrupted review
or a save. Names are exact and case-sensitive, with the original 259 UTF-16-unit /
1,036 UTF-8-byte source limit. They are not search patterns, paths or commands.

Enabling or replacing selections requires every chosen name to be positively
visible in the exact reviewed generation. The request pins the whole immutable
manifest/hash, original receipt, grant and grant revision. The saved policy binds
the original enrollment identity and source grant. A new local grant cannot
silently acquire the old policy. Disabling requires live operator/device authority
but needs no usable process generation.

Only the policy, exact names, original identity, source grant, revision and change
time are saved by this feature, at most 32 KiB per device and 25 used device
policies. Process rows, PIDs, counts, observations and incidents are not retained
in the watch store. Canonical bytes and an independent used marker make a missing
used policy fail closed instead of silently recreating it. Database writes use
revision comparison and live authority checks after SQL waits and before commit.

## Presence and uncertainty

Every current view verifies the entire canonical complete generation and its
index/hash agreement before counting selected names. Work remains bounded by the
source's existing 32,768 rows / 8 MiB limit, without keeping all rows in memory.

- **Observed in snapshot:** at least one exact-name row. The matching row count is
  shown; unavailable names elsewhere do not erase this positive evidence.
- **Not observed in complete snapshot:** zero matching rows and no unavailable
  names anywhere in that complete caller-visible generation. This is scoped
  snapshot absence, not proof that a program is stopped or absent from the host.
- **Unknown:** missing, pending, failed, stale, corrupt, changed-grant or otherwise
  untrusted source. Zero known matches with any unavailable name is also unknown.
  Unknown never means recovery or healthy execution.

Original capture and final manager receipt must each be **less than five minutes
old**, with the original inventory expiry and current credential still valid.
Newer pending or failed attempts suppress an older complete generation. Reads do
not refresh capture/receipt times or create watch policy/evidence. Selected-source
reads do advance the existing complete-process ledger's monotonic clock fence,
just like inventory paging, so a clock rollback cannot revive stale evidence.
All-disabled/empty-selection views do not scan process generations.

Responses have at most a 30-second display lease, bounded by source freshness,
credential expiry and operator-session expiry. The browser hides private counts
and mutation authority on expiry, session changes, focus/visibility loss, clock
uncertainty and navigation. Requests are bounded and canceled on unmount. A refresh
cannot renew a frozen manager time reference. Temporary paging gaps disable review
but preserve draft names when the confirmed source generation is unchanged.

## API and uncertain writes

- `GET /api/devices/{id}/windows-process-watches`
- `POST /api/devices/{id}/windows-process-watches/policy`

Writes require exactly `enabled`, `names`, `expectedRevision`, `consent` and
`source`, plus existing session, Origin and CSRF controls. Disable uses an empty
name list, false consent and null source. Query-string aliases, duplicate or
unknown top-level fields and incorrectly typed values are rejected. Named
read-only accounts cannot save policy.

An enrollment transaction leases current leaf, original identity, grant and exact
complete source through the bounded operator-store operation. A lost response or
late guard failure can follow a committed write. The UI labels the result uncertain,
withholds mutation authority, and requires a GET to reconcile the saved revision.
It never retries a write automatically. A new deliberate review and fresh consent
are required for another save.

## Verification boundary and future integration

Focused portable Go and jsdom tests cover source counts beyond 128 rows, PID zero,
case sensitivity, unidentified names, complete-source failure/pending/staleness,
clock fences, original identity/grant, explicit consent, CAS, used-state loss,
post-wait/final authority checks, protected API fields, StrictMode, paging drafts,
EN/DE labels and uncertain saves. The frontend contract consumes Go-generated
fixtures. No browser automation, Windows native collection, installed-host grant,
installer, host service change or deployment acceptance is established.

A future incident evaluator can consume the same typed source provenance and
presence result, but must add its own explicit derived-history scope, advancing
capture confirmation, durable lifecycle, uncertainty and retention contract. This
slice does not claim that incident or alert parity already exists.
