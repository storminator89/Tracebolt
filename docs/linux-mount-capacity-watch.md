# Selected Linux mount-capacity watch

This is an independent, default-off **manager-side source feature**, not a
published endpoint capability or native acceptance result. The Health tab can
watch one explicitly selected non-root local mounted-filesystem location per
Linux device using already accepted complete-volume generations. No new endpoint
collection, profile, local grant, enrollment rule or operating-system privilege
is introduced.

## Operator workflow

Open **Selected mount capacity** in Linux Health. Choose one measured local mount,
a warning percentage (50–99) and a lower recovery percentage, then explicitly
acknowledge local retention and save. No mount or retention checkbox is selected
initially. Up to 64 eligible locations within a 48 KiB chooser budget are offered; a visible limit message
appears if more exist. The current retained generation is consumed as a baseline:
enabling never turns that old sample into an alert.

Two later fresh, advancing complete generations at or above the warning threshold
open a local incident. Two advancing generations at or below the recovery value
recover an existing incident. Values in between retain an open incident and reset
pending confirmation. Manager restart also resets pending confirmation before
its first successful evaluation; existing incidents remain. The shared manager loop evaluates every 30 seconds, with
one bounded source transaction per device. The existing endpoint's 60-second
complete-overview cadence is unchanged. Repeated reads or replayed frames earn no
confirmation. Clock rollback, gaps over two minutes, a changed mount ID, a
nonadvancing capture, and missing/expired/denied evidence reset confirmation.
Unknown evidence never recovers an incident.

**Mark seen** records acknowledgement without resolving anything. **Stop this
watch** closes its open incident as monitoring stopped, not recovered. Changing
the target or thresholds retires the previous policy and starts a new baseline.
Reads never enable, evaluate, acknowledge or prune. Policy changes require the
existing shared administrator, same-origin/CSRF protection, exact revision and a
current opaque source token. Uncertain writes are reconciled by GET only; the
browser never automatically retries them.

## What the target means

The target is the exact mount path, filesystem type and namespace-local
major:minor grouping hint, bound to the original enrolled device identity. It is
not a filesystem UUID, physical disk identity, host-wide discovery, SMART health
or disk-I/O measurement. A replacement at the same location can eventually
provide new capacity evidence; changed mount IDs restart confirmation. No
capacity is summed across overlapping mounts.

Only unique, measured, non-root local locations are eligible. Duplicate paths,
redacted home/user paths, remote, virtual, memory-backed, unknown, zero-capacity
or unavailable measurements are excluded. Overmount ambiguity is checked across
the entire accepted complete generation, not just its first page. Root Health
retains its original scope and thresholds. A missing selected mount means unknown,
not a guessed unmount event or full disk.

The capacity percentage is the collector's existing `(total - caller-available)
/ total` value. It reflects the agent's mount namespace and caller-available
capacity, not necessarily all free filesystem blocks. Group/path changes require
a fresh explicit selection rather than silently following another filesystem.

## Storage, authority and boundaries

A separate bounded operator-store ledger supports 25 device records and up to
100 recent incidents per device within a 128 KiB record. Whole closed incidents
are omitted first when the byte or count ceiling is reached; the omitted count
remains visible. Closed incidents become eligible for removal
after 30 days; unresolved incidents are retained. Cleanup runs on authorized
monitor passes, including disabled policies. A stopped manager or unavailable
source authority delays cleanup. This is not secure erasure of SQLite pages,
backups or snapshots. Private mount paths stay in this local ledger and response.

Canonical records and paired used markers fail closed on inconsistent storage.
Exact command retries do not advance revisions, and final source/session checks
run before the operator transaction commits. Original enrollment identity,
current credential expiry, complete-generation digest/count and original capture
age remain authoritative. A newer failed or incomplete generation makes current
watch evidence unknown rather than refreshing an older retained generation.

This watch sends no notifications, invokes no AI, writes no endpoint state and
performs no remediation. It is **not** included in existing Linux Health
maintenance, investigations, fleet groups, alarm delivery or the cross-platform
incident queue. Its UI says explicitly that Health maintenance does not pause it.

## Verification

Source tests cover opt-in/baseline behavior, advancing generations, replay,
hysteresis, acknowledgement versus recovery, stopping, missing data, gaps,
rollback, mount replacement, canonical storage/restart and final lease failures.
Real enrollment-store fixtures validate complete volume generation provenance,
whole-generation duplicate exclusion, redacted paths, stale evidence and pending
transfers. The authenticated API fixture covers login/CSRF, read purity, explicit
configuration, exact command retry and forbidden queries, and produces the JSON
used by frontend contract tests. Component checks cover consent, selection,
invalid hysteresis, session loss and GET-only uncertain-write reconciliation.
No browser/native target, real host deployment or release is established by these
fixtures. No credentials, new paid services or external delivery are involved.
