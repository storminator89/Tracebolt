# Reviewed one-time Windows group maintenance

The Fleet groups toolbar offers **Start group maintenance** only after a shared
administrator selects a group. Choose 1–25 currently admitted Windows members,
one existing maintenance scope, a purpose and a duration. No member or consent
checkbox starts selected. Linux and unavailable membership counts remain visible.
An unavailable original identity is never replaced by a new device with the same
mutable ID.

Review freezes the group revision, exact original-identity target keys, maintenance
revisions, chosen scope and purpose, and one absolute UTC end. The compact end also
shows local time and an explicit offset. Exact IDs, keys, revisions and UTC time
remain available in the details disclosure. The administrator then checks separate
consent and starts the reviewed sequence once.

Each target starts when its own manager transaction accepts it. Every target uses
the identical reviewed end; later targets receive shorter windows. The end is never
recomputed or extended. The existing one-minute minimum and 24-hour maximum are
checked again at each commit. An overlapping active window blocks that target.

This is a one-time snapshot, not an atomic group operation or an ongoing membership
rule. Before each write the client reads the original-identity projection again;
the server also checks the exact group revision and original stored membership
inside that individual maintenance transaction. Group edits, removal, replacement,
revocation, expiry or a changed target revision cannot silently substitute or
expand the selection. Earlier confirmed starts are retained when a later target
is blocked. There is no rollback, recurring schedule, background job or retry.

## Private additive API

GET `/api/fleet/groups/{id}/maintenance` returns a closed
`tracebolt.fleet-group-maintenance.v1` projection, capped at 256 KiB. It contains
`serverNow`, `authorityExpiresAt`, `groupId`, `groupName`, `groupRevision`,
`excludedLinuxMembers`, `unavailableMembers`, and `members`. Each current Windows
member has `deviceId`, `name`, and all six existing opaque maintenance `targets`,
ordered by device ID and then domain. The server resolves each stored original
membership against current group admission and current Windows original-identity
authority. Private invitation, certificate and membership anchors stay private.
An empty admitted set remains empty; reads never initialize or prune state.

POST `/api/fleet/groups/{id}/maintenance/start` accepts exactly `groupRevision`,
`key`, `revision`, `endsAt`, and `intent`, for one target only. It reuses the
single-target maintenance implementation, enrollment-to-operator lease, live
shared-administrator session, same-origin JSON/CSRF checks, immutable end, overlap,
history and notification-outbox behavior. Within the same operator transaction it
reloads and verifies the exact manager, group revision and original member binding.
Group reads never become a collection or host-action grant. The successful response
uses the same closed group projection. Existing strict single-target maintenance
v1 requests and responses are unchanged. No table, migration or scheduler is added.

## Outcomes, interruption and privacy

Each selected target reports a confirmed start, blocked/conflict, unconfirmed, or
not attempted. The sequence stops on conflict, lost access, Stop or uncertainty.
Stop retains earlier outcomes; an interrupted in-flight request may already have
committed. A response can also fail a final authority check after commit, so a
conflict must be reconciled by reading the current state. Neither a matching GET
nor a matching revision is proof that this attempt caused the start. Readback
never automatically changes an uncertain result into confirmed success or sends
another POST. A used review cannot be applied again; starting fresh clears the
selection and consent.

Private rows and reviews clear on navigation, hidden/blurred views, session changes,
authentication loss, original authority expiry or clock failure. Reads cannot extend
the first projection's original authority deadline. Closing the dialog stops unsent
work. The existing Windows maintenance panel handles deliberate individual early
ends and retains each original end in bounded recent history.

Only separately approved matching Windows notifications are suppressed. Checks,
evidence and incident truth continue unchanged. Already in-flight delivery cannot
be recalled, and early end or expiry sends no backlog. Linux health, AI, policy
settings, host actions, collection grants and notification-recipient approval are
unchanged.

## Verification boundary

Focused store and direct-handler fixtures exercise original identity replacement,
transaction-time membership/revision drift, overlap, replay, expiry, session and
clock guards, and notification semantics. UI fixtures exercise explicit EN/DE
selection and consent, exact common ends, partial results, Stop, GET-only uncertain
readback, single-use review and privacy interruption. The existing canonical fleet
group capture manifest adds only four views: unchecked EN desktop, reviewed DE
mobile, results EN desktop and results DE mobile.

These are source and synthetic fixture checks. Actual hosted browser execution and
pixel review, deployment and native Windows acceptance are separate gates. No host
installation, credential, grant, notification delivery or runtime activation is
performed or authorized by this feature.
