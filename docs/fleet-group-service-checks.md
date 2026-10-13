# Reviewed one-time group service checks

This page describes the retained preview-v1 group path. The separate explicit
[complete-source v2 group workflow](windows-complete-service-health.md) provides
paged choices beyond the preview without promoting v1 authority.

The Fleet groups toolbar offers **Apply service checks** after a shared
administrator selects a manual group. Choose 1–25 exact currently admitted Windows
members, load the existing choices for those members, then select up to eight
exact service names per device. Device selection, enablement and final confirmation
start unchecked. Review shows desired settings and each previous policy/revision.
Existing selected names can be removed or disabled when their latest inventory is
unavailable. Newly selected names and re-enablement require fresh unambiguous rows.

This reuses the existing [selected-service health](windows-service-health.md)
source: the bounded caller-visible preview, at most 128 reported Win32 service
rows, and its original capture/receipt age. It is not complete service-generation
monitoring. Partial positive rows can be choices; missing, duplicate, stale,
ACL-invisible or out-of-preview names remain unknown. Missing inventory never
means that a service is healthy, stopped, removed or absent. Exact case is retained.
No new endpoint collection, service action or native grant is added.

## One reviewed foreground sequence

The review freezes the group revision, original-identity opaque keys, exact member
names and IDs, each desired service list/enablement and each policy revision.
Separate explicit confirmation applies that review once, sequentially. Before
every write the current exact-member view is reread. The server checks original
group membership and group revision inside the same policy transaction under the
existing enrollment-to-operator lease. Actual post-wait/final clocks, live operator
session, current leaf, original identity and source-admission checks are shared
with ordinary per-device policy saves.

Per-device outcomes are changed with a confirmed response, currently matching
without a write, conflict, unconfirmed or not attempted. Conflict, uncertainty,
lost access or Stop halts remaining writes; earlier outcomes remain visible.
A failure after commit is possible, so matching GET readback never proves that the
attempt succeeded and never authorizes a repeated POST. There is no rollback,
durable job, automatic retry, inheritance or implicit new-member adoption.

Close, navigation, hidden/blurred view, session loss, time rollback and original
authority expiry discard the private review. Rereads can tighten but cannot extend
its first authority deadline. Policy changes retain the existing unknown-state,
advancing-source confirmation, durable floors and non-recovery `policy-changed`
closure behavior. A save itself does not evaluate health or act on a service.

## Bounded additive API

GET `/api/fleet/groups/{groupId}/service-checks` returns the closed
`tracebolt.fleet-group-service-checks.v1` projection: `serverNow`,
`authorityExpiresAt`, `groupId`, `groupName`, `groupRevision`, excluded Linux and
unavailable counts, and at most 25 members. Each member carries `key`, `deviceId`,
`name` and its existing service `policy`. Private original identity bindings stay
private. Replacement identities do not inherit old membership or policy visibility.

GET `/api/fleet/groups/{groupId}/service-checks/{key}` returns the closed
`tracebolt.fleet-group-service-choice.v1` projection with the same group/time
metadata and one member with `inventory` (existing fresh preview or null).
Inventory is loaded only for deliberately selected members; reads do not collect,
initialize policy, repair state or promote any grant. Each response is at most
256 KiB, including its framing newline.

POST to that exact member route accepts only `groupRevision`, `expectedRevision`,
`enabled`, `services` and `consent: true`. It applies one member and returns its
same bounded choice view. Shared administrator, same-origin JSON, CSRF and live
mutation authority are required. Named operators can read; they cannot write.
Group edits, removal, identity replacement, stale revisions or uncertain source
admission fail closed. Existing per-device v1 requests and responses are unchanged.
No table, migration, scheduler, endpoint protocol or notification grant is added.

## Verification boundary

Store tests cover original membership, revision drift after SQLite waits, identity
replacement, final guard rollback, exact-case names, unchanged saves and stale
inventory disable/re-enable behavior. Recorder-only handler tests cover bounded
projections, read-only defaults, exact requests, roles/CSRF/origin, original
membership, renewal and final authority/source checks. EN/DE workflow/component
tests cover explicit selections, single-use review, uncertainty, Stop, partial
outcomes, source expiry during CSRF and privacy interruption.

These are source and synthetic fixtures. Actual rendered browser acceptance and
native Windows acceptance remain separate gates. No host action, runtime permission,
external notification, release or deployment is performed by this feature.

The existing hosted fleet-groups gate adds exactly four changed-view captures:
review with its final one-time approval unchecked, and partial per-device outcomes,
each at EN 1440×1000 and DE 390×844. These use the canonical capture matrix and the
runner's exact filename classifier. The selected-service phase fully intercepts
App startup, including authenticated shared-administrator metadata, enrollment
(disabled) and fleet identity reads. The only synthetic writes update in-memory
service policies: first confirmed, second conflict, third not attempted. Original
preview age and authority expiry are never refreshed by fixture reads.

An inert jsdom check boots the real compiled App entry point against that same
route adapter and executes the hosted semantic selectors in both languages. All
fetches are intercepted; other live transports are blocked. It verifies wiring,
unchecked approval and partial outcomes, not pixels. The four screenshots remain
pending hosted browser execution; no local browser or host operation is required
or authorized by this fixture extension.
