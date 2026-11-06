# Reviewed staggered Windows update windows

The Windows update worklist can distribute its selected devices across successive
UTC dispatch windows. This is a source UI increment over the existing per-device
scheduler, not a new rollout daemon, native grant or automatically approved policy.
The original [scheduled background](windows-scheduled-background-updates.md) and
[exact selected-update](windows-selected-update-jobs.md) contracts remain unchanged.

## Operator flow

1. Select Windows devices and enable **Use one shared UTC window**.
2. Enter the first window's UTC start and end. The unchanged duration is 1–60
   minutes and every planned start must be in the next 24 hours.
3. Optionally enable **Spread devices across successive UTC windows**. The outer
   option then reads **Plan UTC installation windows**. Choose
   1–50 devices per window and a gap of 0–1440 whole minutes after each window.
4. Review every window's exact UTC times and named device IDs before freezing.
   Devices use the displayed selection order; the last group can be smaller.
5. Freeze the reviewed selection. Open each device deliberately, choose an exact
   cached GUID/revision, read its current readiness and approve that device's exact
   frozen window using the existing initially unchecked acknowledgement.

For a first window of 10:00–10:05 UTC, two devices per window and a five-minute
inter-window gap, the first two devices use 10:00–10:05, the next two use
10:10–10:15, and so on. The entire plan is invalid if any start exceeds the original
24-hour horizon. Nothing is silently clamped, shortened, skipped or shifted.
The clock and all proposed windows are checked again when freezing.

The old common-window mode remains available when staggering is unchecked. No
planning option is offered without the existing scheduling capability. Individual
local grants, current certificate expiry and actual scheduling availability are
still checked by the existing device/session/server path, not inferred from a
fleet plan.

## What a wave guarantees

The browser freezes each exact device-to-window assignment. Later device ordering,
filtering, group membership or disappearance cannot compact the plan or assign a
vacant slot to a different device. Each child session receives its own immutable
fixed window; no later device is opened, reviewed or approved automatically.
A missing device cannot receive a write, and its slot remains visible.

A dispatch window is not an execution timeout, concurrency limit or application-
health test. Installation can continue after its window and overlap a later wave.
Later independently approved schedules do not wait for earlier success and do not
automatically pause after an earlier failure. Exact start time is not guaranteed.
The UI states these limits beside both the draft and frozen plan.

After a window starts, no new approval can use that window. Later windows retain
their original times. The existing per-device approval path enforces this using
its validated server clock; the fleet display does not grant authority.

## Lifecycle and uncertainty

This is temporary browser planning. Freezing sends no request and stores no plan
in browser persistence or a new database. An operator/session replacement clears
it, and a new selection starts with staggering off. Closing, navigating, blurring
or losing authentication stops the active child and its subsequent requests under
the existing lifecycle. Saved jobs or already delivered permits are not canceled.

A lost schedule response retains its original exact job/window reference and can
only be reconciled with GET. Switching devices, selecting a new plan or a later
wave cannot replay an uncertain write. No download, EULA acceptance, reboot,
rollback, grant migration, native retry, window extension or scheduling-revocation
behavior is added.

## Scope and validation

The feature changes local planning and passes existing fixed-window props. It adds
no API, DTO, backend table, scheduler, credential, collector, signing rule or native
operation. Tests cover deterministic grouping, numeric/identity/time bounds,
UTC/DST behavior, immutable assignments, bilingual plan review, exact per-device
schedule POST bodies, unchecked approvals, duplicate clicks, changed membership,
revoked capability, interrupted session checks and GET-only uncertainty.

Source and synthetic interaction tests do not establish native WUA execution,
installed-service acceptance, actual concurrency, application health or deployment.
The existing separately authorized native gates remain required.

## Why this slice

[NinjaOne documents staggered patch schedules](https://www.ninjaone.com/docs/patch-management/patch-deployment/automated-patch-deployment/)
for spreading patch activity. This smaller Tracebolt workflow lets an operator
review deterministic device windows while retaining independent exact approvals.
It is distinct from local cache filters and saved-job history review.

[Datto's pilot-group guidance](https://rmm.datto.com/help/en/Content/2SETUP/BestPractices/Best_Practices_Filters_or_Groups.htm)
also describes testing before broader deployment. A genuinely result-gated pilot
rollout is separate future work: it needs a durable exact plan and per-device job
binding, explicit release of later stages, conservative treatment of missing or
uncertain results, and lifecycle/race checks at the server's issuance boundary.
A component-local success badge cannot safely provide those guarantees.
