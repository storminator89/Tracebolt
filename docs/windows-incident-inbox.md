# Windows incident inbox and operator acknowledgement

This manager-side source increment adds a compact, on-demand **Windows incidents**
inbox below the fleet device list. It projects the existing durable Windows
contact, system-volume disk, observed-group CPU, physical-RAM and selected-service
episodes. The inbox itself adds no collector, native permission, enrollment, policy, endpoint
action, Linux Health input or AI scope. Separately approved Windows notifications
now consume future source transitions; see [notification policies](windows-notifications.md).

The adjacent [planned-maintenance panel](windows-maintenance.md) records bounded
device/domain windows separately. It does not suppress or alter this inbox or join maintenance to incident rows by
mutable device ID. Notification dispatch suppression uses exact original identity
and domain in its separate transaction.

The additive [complete-source v2 inbox](windows-complete-incident-inbox.md) is
now the fleet UI's explicit combined projection. It preserves the v1 contract below
and adds separately source-qualified complete-service history and acknowledgements.

## Seen is independent of closed

A shared administrator can explicitly acknowledge one exact retained episode.
Acknowledgement means **seen**, never resolved, recovered, suppressed or healthy.
Named operators can read but cannot write acknowledgements. An acknowledgement
survives manager restart and same-identity certificate renewal; it never applies
to a later episode, a sibling metric or a replacement enrollment.

The separate canonical acknowledgement table binds the original device ID,
invitation and immutable issued-certificate anchor, exact source domain, incident
ID and original opening time. Disk, CPU and RAM can all generate the same local
`wcapacity_...` ID; the domain remains part of the key. Only an opaque target hash
is exposed. Existing strict v1 assessment records and per-device APIs are unchanged.
The original source observation/evaluation/closure times are never rewritten by a
read or acknowledgement. There is no acknowledgement-to-alarm/AI/action bridge.

## Coverage, lifecycle and retention

Active, recent (opened or closed within seven days), resolved/closed and all
retained views can each be filtered by acknowledged/unacknowledged. Active episodes
remain active after acknowledgement. Contact closes as `reports-resumed`, percentage
checks recover as `within-policy`, service checks recover as `running`, and a
policy edit closes as `policy-changed`, explicitly not recovery.

The inbox separates retained incidents from current source confidence. Unknown or
unavailable evidence never closes history. Each row carries its original last-bad
capture (where applicable), accepted receipt, manager evaluation and any recovery
capture/receipt separately. A `statusValidUntil` deadline derives only from the
current qualified v1 evaluation and current source evidence; historical episode
samples cannot renew current confidence. Browser aging can only remove confidence.
The underlying check's exact semantics and source coverage remain unchanged.

Coverage counts distinguish currently admitted Windows devices, unavailable
identities, unknown checks and disabled policies. No rows or zero active incidents
is not a whole-fleet health assertion. Missing/revoked/replaced identities expose
no retained rows. An unavailable/corrupt source returns an unavailable inbox,
never a fabricated empty success. The row links to the existing device Health tab. Service episodes also offer an
[identity-bound service review](windows-service-incident-review.md) with the existing
independently approved controls; opening the review creates no action preview or grant. The Status filter separates
active/closed/recent/all retained views. Compact opening dates include the local
UTC offset; expandable evidence retains every original exact timestamp and the
full device ID. Coverage and unknown source status remain visible.

Five bounded ledger families retain at most 12,500 episodes across 25 devices
(100 per family per device). Existing 30-day closed-history pruning happens only
on authorized evaluation/policy changes; disabled history can be older. Inbox
reads never prune, repair, evaluate or create source state. Acknowledgement records
are bounded to the same 12,500 maximum; only a deliberate acknowledgement may
remove orphan metadata for episodes no longer retained. Retained acknowledgements
are not evicted by age. Replacement identities cannot inherit orphan records.

## Private API and transaction boundary

GET `/api/fleet/windows-incidents` accepts only `scope`, `ack`, `offset`, `limit`,
with single canonical values; defaults are active/all/0/25. Page size is 1–50,
offset 0–12,500, and the complete response is at most 256 KiB. Counts precede
filters; `total` counts the selected filter and `nextOffset` marks another page.
Ordering is newest opening then opaque key. Paging reflects each current snapshot,
not an immutable cursor across concurrent episode changes. Refresh restarts paging.

POST `/api/fleet/windows-incidents/acknowledge` accepts exactly `key` and returns
the durable acknowledgement timestamp. It requires a live shared-administrator
session, same-origin JSON, CSRF and exact retained identity/episode admission.
It is idempotent for the same target without refreshing the first seen timestamp.
The caller does not replay uncertain POSTs; it reconciles through a read only.

Mutation lock order is enrollment authority then operator SQLite. A fresh
`BEGIN IMMEDIATE` enrollment lease holds original/current credential authority
through the acknowledgement commit; revocation/replacement/renewal cannot race
between admission and commit. The guarded operator transaction reloads the exact
retained episode after connection waits, samples the actual acknowledgement time,
and rechecks the live session, current locked authority, expiry and clock before
commit. A rollback behind the acknowledgement timestamp fails closed. A final
source/session check also guards response release. A five-second request context
bounds source and SQLite waits while preserving session cancellation. No enrollment state is
written by the lease. UI leases expire with session/device authority, visibility,
logout and navigation; obsolete filter/page responses cannot restore private data.

## Verification boundary

Focused store/API/enrollment fixtures cover colliding metric IDs, restart,
idempotency, new episodes, unchanged source ledgers, current authority, concurrent
revocation serialization, SQL-wait expiry, final guards, clock rollback, canonical
corruption, exact queries, filters and paging. The Go-generated wire fixture binds
the TypeScript parser. Component fixtures cover EN/DE rendering, source deadlines,
seen-versus-closed separation, uncertain saves and interrupted private reads.

These are source and synthetic fixture checks. They do not establish native
Windows collection, installed-service lifecycle, deployment or actual browser
rendering. Hosted ordinary CI screenshots and native acceptance remain separate.
