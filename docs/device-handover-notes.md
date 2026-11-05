# Device handover notes

The Windows device Overview has a **Notes** section for operational handover:
what was checked, an unresolved question or the next technician's next step.
This is manager-owned operator writing, not endpoint telemetry, an incident,
an endpoint command or a claim about device health. Notes are visible to
authenticated readers of the manager; customer labels do not isolate them.
Do not enter passwords, credentials or other secrets.

## Using notes

- The shared administrator can add a note, archive it, or restore an archived
  note. Named operators retain read-only access. This feature adds no role,
  capability or permission grant.
- Save is explicit. Text cannot be overwritten or permanently deleted. To
  correct an entry, add a new note and archive the old one. Attribution says
  **Shared administrator**, not an invented individual author.
- Archived entries remain readable through **Show archived**. Original creation
  time is retained, and the latest archive/restore time is separately displayed.
- Each original device identity retains at most 25 notes of 2,000 UTF-8 bytes
  and 250 accepted changes. Archived notes and their receipts count toward these
  limits. No automatic eviction, text truncation or quota recovery is implied.
- A failed or interrupted save may already have succeeded. **Check saved result**
  only reads; it never repeats the write. A receipt confirms the saved change.
  Before the original request expires, an unchanged read remains uncertain and
  writes stay blocked. After expiry, an explicit authorized check can confirm
  that no receipt exists and permit a new change. It does not restore or resend
  submitted text, and it does not claim that a request was cancelled.

Notes currently require an admitted Windows inventory identity. Linux, macOS,
manual-v1 and Rust Basic support is not implied. The Windows scope reuses the
existing atomic enrollment-authority lease; adding another platform requires a
separate reviewed identity boundary, not weakening the current check.

## Data and access boundary

The private resource is `GET/POST /api/devices/{agent_id}/handover-notes`.
Requests reject query parameters and alternate route forms. Every POST uses
same-origin JSON/CSRF, an active shared-administrator session, an exact reviewed
revision and a session-bound, expiring review token. Existing named-write denial
and named read behavior are unchanged. No notes enter Device/Overview, cases,
agent frames, CSV, support bundles, notifications or AI export.

Notes use a separate canonical SQLite record keyed by manager/transport/profile
and the exact original issued identity. Hostname changes and same-identity leaf
renewal retain the record. A replacement original identity cannot inherit it.
Revoked, expired, ambiguous and unavailable identities cannot expose retained
notes. This is an admission check, not an assertion that an endpoint is online.
There are at most 100 retained notebooks across the manager store, including
unavailable historical identities. The 512 KiB stored-record and response bounds
cover JSON escaping; the frontend uses the same endpoint-specific response cap.

All source stores are verified distinct before acquiring existing Windows
authority and cross-source identity-exclusion leases in a stable order. They
remain held through the operator-store transaction, guarded read and response
serialization. Locks and the operator mutation gate are released before network
output; exact original identity, current leaf expiry, clock and session are
checked again immediately before returning the response.

Every change has an immutable operation ID and request digest within the same
transaction as the note. Exact duplicate intent returns the current journal and
its original receipt without creating a new change. Reusing the ID for another
intent conflicts. Compare-and-swap revisions prevent lost updates. Only a
proven precommit rejection uses `device_notes_rejected`; postcommit or uncertain
failures use `device_notes_unconfirmed`, never a definite rejection.

The browser retains only pending operation ID, opaque original-identity key and
original request expiry in session storage, scoped to its authenticated session
and device. It never
stores draft text, note contents, credentials or review bindings. Storage failure
makes writes unavailable. Leaf renewal invalidates the displayed review without
losing an unresolved operation. Opaque identity correlation is stable across
manager process restart and cannot grant write authority. Durable manager
receipts survive restart; browser/session recovery is not cross-device sync.

Post-expiry absence is meaningful only under the current single-writer manager
contract. Notes reads and writes serialize under the same original-identity
authority lease, and a shared manager clock floor records every advertised
server time. Every mutation checks that trusted clock floor immediately before
commit, so a late request cannot commit after a terminal negative read even if
the wall clock moves backwards. The floor shares the lifetime of the process's
random review-signing key; a restart resets both and invalidates old reviews.
Never reset only the floor or reuse this proof for independent manager processes
or signing keys. A forward clock jump fails closed until time catches up.

Only the deliberate **Check saved result** flow clears an absent-receipt fence,
using a fresh authorized read for the same original identity strictly after the
original request deadline. The browser waits beyond the deadline's millisecond
to avoid rounding a nanosecond deadline early. Background reads, client time,
an unchanged revision before expiry and receipt absence alone are not proof.

Views have an original, maximum 60-second expiry bounded by identity and session
expiry. Displayed notes clear on privacy/session/navigation loss. There is no
background polling, collection or automatic mutation. Refresh reads the manager.
An unsent draft remains only in component memory across ordinary view expiry and
an explicit refresh; saving requires a fresh view of the same original identity.
Session, identity, navigation and privacy loss clear the draft. A submitted or
uncertain operation is not restored as a new editable draft after reconciliation.

## Verification boundary

Focused tests exercise source admission, roles, CSRF, strict routes, original
identity renewal/replacement, clock and authority failure before and after
commit, durable receipt reconciliation, bounds including escaped text, CAS and
archive/restore persistence. Adversarial cases cover clock rollback across
handlers, signing-key restart, an admitted writer ahead of a negative read,
and a delayed writer behind it. DOM/transport tests exercise both languages,
uncertain saves, browser storage failures, interrupted views and deliberate
post-expiry recovery including fractional-second deadlines.

These are source and fixture checks. No browser automation, native endpoint
execution, host installation, release or deployment is part of this change.
