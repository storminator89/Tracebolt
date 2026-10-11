# Manual fleet groups and reviewed Windows health settings

This manager-side source increment adds manual named groups to the Devices view.
Groups are organizational metadata. They do not authorize collection, endpoint
control, enrollment, AI, notifications or an automatic policy. Existing device
`Group` labels remain presentation-only and are not imported.

The private manager store holds at most 25 groups with at most 50 admitted members
per group (the two existing 25-device enrollment authorities). A membership binds
the manager/transport/collection profile, invitation and original issued identity;
renewed leaf certificates and hostname/IP labels do not change that identity.
Revoked or replaced identities cannot inherit membership. Reads expose only
currently admitted device IDs/names plus a count of unavailable members, never
private identity bindings or old names. Ambiguous IDs fail closed. Editing a group
replaces its reviewed visible member set. Unavailable identity bindings are retained
by default; removing them requires an explicit reviewed choice. A replacement
identity is never silently added.

GET `/api/fleet/groups` and `/api/fleet/groups/{id}` return bounded private
projections. Shared administrators may create, rename, replace membership or delete
with same-origin JSON, CSRF, a live session lease and exact optimistic revision.
An update also requires `removeUnavailableMembers`: false preserves unavailable
private bindings; true explicitly removes them.
Named operators may inspect/filter groups but cannot mutate them. Reads never
create, repair or prune a group. Corrupt storage fails closed. Group records are
not migrated or inferred from historical labels.

## One explicit setting, reviewed devices only

The administrator chooses one existing Windows percentage policy: caller-quota
system-volume disk usage, observed-group CPU, or physical RAM. They select the
currently eligible Windows members, enabled/disabled state and a whole threshold
from 50 through 99. Review freezes the exact group revision, device IDs/names,
setting and each current per-device policy revision. New members never inherit a
setting. Selected service checks remain separate because exact service-name
admission differs per device.

Apply rechecks the group and then uses the existing per-device GET/POST policy
endpoints sequentially with each reviewed `expectedRevision`. There is no new
bulk-authority endpoint, dynamic policy, generic job, rollback or durable retry.
Each member reports changed, currently matching, conflict, not attempted or
unconfirmed. A conflict, access loss, cancellation, navigation or uncertain write
stops remaining writes. An uncertain POST may only be reconciled by GET; a matching
readback does not prove that this attempt wrote it. Already committed earlier
members remain changed, so a stopped operation can be partially complete.

The existing policy endpoints also recheck live session/time and certificate
expiry after acquiring the operator SQLite connection and immediately before
commit. Those final callbacks acquire no enrollment locks. Policy evidence,
independent metric revisions, original age and non-recovery closure semantics are
unchanged; see [disk](windows-capacity-health.md) and
[CPU/RAM](windows-resource-health.md).

Portable store/API and component fixtures verify the source workflow. They are
not native endpoint, real browser rendering, installed-service or deployment
acceptance. No release, host grant, automatic response or migration is included.
