# Optional ongoing Windows group monitoring

This manager-only source feature is off by default. A manual fleet group still
creates no monitoring authority. The separate collapsed **Group monitoring**
section lets a shared administrator select disk, CPU or physical-RAM definitions,
exact current Windows members and unchecked ongoing-sync consent, review them,
then save. Existing **Apply monitoring policies** remains a one-shot operation.

The saved consent covers future edits of the selected manager policy definitions
for those exact device/metric assignments. It grants no endpoint collection,
identity, service action, update, AI or notification permission. Disk remains
caller-quota system-volume usage, CPU the observed processor group, and RAM
physical memory not immediately available. Existing threshold, confirmation,
unknown-evidence, durable-floor and `policy-changed` non-recovery rules are reused.

## Ownership and current state

Separate definitions and assignments preserve the original group and percentage
v1 storage/API contracts. No rows are inferred from existing groups or policies.
There is at most one active owner per device/metric and 75 retained assignment
slots across 25 Windows device IDs. Definitions remain within the existing
25-group bound. Assignment revisions are retained after disarming, including
group deletion, so stale reviewed requests cannot reuse an empty revision.

Only explicitly assigned existing members synchronize. New members, newly selected
metrics and re-added members need a fresh reviewed opt-in. Membership binds the
original enrollment identity; legitimate leaf renewal preserves it, while a
replacement cannot receive the previous identity's assignment or history.

The compact view shows desired/current policies and pending, inherited, manual
override, stopped or conflicting ownership. Unavailable identities are counted
without releasing their old names or private identity material. Definitions may
be edited while previously opted-in assignments are unavailable; those assignments
remain eligible only if the same original identity becomes available again.

Every successful ordinary per-device policy Save detaches that metric atomically,
including a same-value Save whose policy revision stays unchanged. **Stop
inheriting**, membership removal and group deletion leave the last applied policy
unchanged. Re-adding a member never restores a detached assignment.

## Commit and scheduler boundaries

GET `/api/fleet/groups/{id}/monitoring` is read-only. POST to the same route needs
shared-admin authority, same-origin JSON, CSRF, explicit consent for definitions
or opt-ins, and exact group/definition/assignment/current-policy revisions. Named
operators can inspect but cannot change ownership. An uncertain POST is reconciled
only with GET; neither browser nor server blindly repeats it.

One bounded sequential reconciliation pass runs inside the existing 30-second
Windows scheduler before percentage evaluation. It adds no parallel worker. With
no active assignments it performs no additional enrollment-source read. Applied
assignments are not replayed. Pending work survives restart as desired state.

Each policy update and applied assignment revision share one operator transaction.
The enrollment-to-operator lease freezes original identity, current leaf, expiry
and revocation through that commit. The transaction rechecks exact membership,
definition, assignment and current-policy revisions. Live clock, cancellation and
operator session checks run after connection waits and immediately before commit.
No enrollment query occurs while holding operator SQLite without the prior lease.
Concurrent manual saves or group removal either win before reconciliation and
reject it, or run afterward and detach ownership while preserving the applied
policy. A failed guard rolls back both policy and ownership metadata.

## Verification boundary

Portable synthetic tests cover opt-in, restart, same-value override and stale
reconciliation, ownership conflicts, removal/re-add/deletion, 75-target bounds,
original identity and renewed expiry, final expiry/rollback/session guards,
enrollment revocation serialization, unchanged evidence floors and non-recovery
closure. Component tests cover consent, exact review, one-use save, desired/current
status, stopping inheritance, access/privacy interruptions and GET-only uncertain
readback.

These are source fixtures. Actual hosted UI rendering and native Windows-to-Linux
acceptance remain separate reviewed gates. No collection grant, credentials,
installer, ACL, actual notification, native execution, migration or release is
included.
