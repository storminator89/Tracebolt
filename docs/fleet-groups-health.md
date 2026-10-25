# Manual fleet groups and reviewed Windows monitoring policies

The Devices view offers manual named groups and an explicit monitoring-policy
apply flow. Groups are organizational metadata. They do not authorize collection,
endpoint control, enrollment, AI, notifications or an automatic policy by membership alone. A separate explicit [ongoing monitoring opt-in](fleet-group-monitoring.md) can bind reviewed Windows members and metrics. Existing
device `Group` labels remain presentation-only and are not imported.

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

## Inventory filter states

A selected group stays selected while its membership is refreshed, expires or
becomes unavailable. Until a current valid roster confirms its members, the
inventory shows **Checking group membership**, **Group membership unavailable**
or **Selected group unavailable**, rather than a zero-device/search result.
The count is unknown (`—`), no device rows are admitted through that filter,
and CSV export remains disabled. The selected group ID stays visible; expired
device or group names are not retained for this notice.

Use **Refresh group membership** to read the existing private group projection
again. If the overview itself failed, **Refresh overview** first restores that
source and then rechecks membership. Neither operation writes or retries an
action. **Clear group filter** removes only the group selection, preserving
search, platform, status, source and sort choices. It deliberately returns to
the devices allowed by those remaining filters.

A valid group with no visible members has its own empty state. Retained
unavailable members are counted separately and never described as absent
devices. A verified group whose members do not match the other inventory
filters still shows the ordinary **No matching devices** result. These states
are available in English and German. Existing per-device reviews, permissions
and job controls remain authoritative; a group is never an action grant.

This is current-source dashboard behavior, not a change to any published
endpoint package or proof of native collection. Frontend regressions exercise
the real auth/request/group-resource path with invented responses:

```sh
cd web
npx vitest run src/fleet-group-inventory.test.tsx src/fleet-groups.test.tsx --maxWorkers=1
```

## Explicit policies, exact selected devices

After opening Fleet groups, a shared administrator can use **Apply monitoring
policies** for the selected group or for all currently admitted Windows devices
when no group is selected. A group is an optional selection filter. Creating a
group is not required. This one-shot flow creates no inheritance. Separately reviewed ongoing assignments are described in [group monitoring](fleet-group-monitoring.md).

The existing dialog contains three compact, initially unchecked policy rows:
caller-quota system-volume disk usage, observed-group CPU, and physical RAM.
For each included policy, the administrator explicitly chooses enabled/disabled
and a whole threshold from 50 through 99. Enable starts unchecked too. Unselected
policies remain untouched. They select 1–25 exact current Windows devices, then
review all chosen settings together. Contact is read-only in this workflow. The separate reviewed
[Apply service checks](fleet-group-service-checks.md) flow selects exact names
individually for each existing group member from its bounded consented preview.
Recipient configuration, external delivery and automatic responses are excluded.

Review copies the optional group revision, exact device IDs/names, selected
settings and every device/metric policy revision before any write. The compact
preview shows the desired settings once and the previous policy/revision for each
selected device and metric. It grants no host collection, privilege, service
control, native execution, AI export or notification permission.

Apply rechecks the group or current device roster and then uses the existing
per-device GET/POST policy endpoints sequentially with each reviewed
`expectedRevision`. Policy leases are keyed by both device and metric, so a later
CPU or RAM read cannot overwrite an earlier disk certificate/metadata expiry
check. Original session expiry, individual certificate expiries, source metadata
age and the existing monotonic clock guards still bound the whole review.

Each device/metric reports changed, currently matching, conflict, not attempted
or unconfirmed. A conflict, access loss, cancellation, navigation or uncertain
write stops every remaining policy/device. An uncertain POST may only be
reconciled by GET; matching readback does not prove that this attempt wrote it.
Earlier confirmed results remain visible after a later conflict or explicit Stop,
including partial completion within one device. Privacy events such as navigation,
blur or session loss still clear the private view. There is no rollback, durable
job or automatic retry. A reviewed selection can be applied only once; a new
review resets policy and device selections.

The existing policy endpoints recheck live session/time and certificate expiry
after acquiring the operator SQLite connection and immediately before commit.
Those final callbacks acquire no enrollment locks. Policy evidence, independent
metric revisions, original age and non-recovery closure semantics are unchanged;
see [disk](windows-capacity-health.md) and [CPU/RAM](windows-resource-health.md).

## Verification boundary

Focused workflow/component checks cover exact multi-policy selection, independent
thresholds/enable flags, revision conflicts, distinct metric expiry leases,
partial success, Stop, uncertainty, single-use review and the existing session/
identity guards. The hosted fixture requests a canonical source-bound EN/DE desktop/mobile image
matrix: group editing, unchecked/selected policy draft, exact preview, per-device
results and separate ongoing-inheritance consent, review, status and stop. Producer
and evidence validators share that scene matrix. Source contract checks do not
establish rendered pixels.

Source tests are not native endpoint, installed-service or deployment acceptance.
Actual hosted rendering and native acceptance remain separate gates. No release,
host grant, automatic response or migration is included.
