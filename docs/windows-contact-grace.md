# Windows missed-report grace

This manager-side source feature lets a shared administrator choose how long a
Windows device may go without an accepted report before a new overdue-report
incident begins confirmation. Open **Health → Accepted-contact history → Report
delay settings**, choose **2, 5, 15 or 60 minutes**, review the effect and explicitly
confirm **Save wait**. Two minutes remains the unchanged default until that action.

A longer grace can reduce unwanted incidents for intermittently connected
devices. It does not make old data current or prove that a device is online.
The existing collector cadence, endpoint grants and reporting protocol do not
change. This is a per-device setting, not group inheritance or a scheduled
maintenance window.

## Evidence, consent and retention

The only source is the existing authenticated manager's original accepted receipt
and sequence, already used by [accepted-contact history](windows-contact-history.md).
No host read, inventory category, endpoint permission, identity, provider call or
new data-sharing recipient is added. The explicit manager approval changes the
missed-report expectation only. Existing independently approved notifications
retain their own policy; saving this setting creates no notification transition.

- A report is still recent only while its original accepted receipt is at most
  **120 seconds** old. Between that limit and a longer configured grace, current
  contact assessment is **unknown**, never healthy or recent.
- After receipt age exceeds the selected grace, **60 seconds of continuous
  manager confirmation** is still needed to open an incident. The unchanged
  30-second evaluator cadence applies; the choice is not a precise alarm timer.
- Recovery still requires reports at most 120 seconds old for 60 seconds of
  continuous evaluation. A longer grace does not relax recovery.
- Every deliberate setting save resets waiting/confirmation credit and requires
  a newly accepted, fresh report after the save before opening another incident.
  This prevents an already long-silent device from opening immediately under a
  newly reviewed expectation. The view says when this first new report is awaited.
- An existing open incident remains open through a setting change. The change
  neither closes nor recovers it. Actual fresh post-change reports are needed
  before recovery confirmation can restart.
- Missing authority, manager restart, clock rollback, stale evaluation and
  evaluation gaps preserve the existing unknown-state rules. Repeated reads or
  duplicate telemetry do not advance the original receipt or create evidence.

The retained source categories, **100 incidents per device**, **30-day recovered
history**, open-until-recovery rule, 25-device bound and 128 KiB state ceiling are
unchanged. New incidents additionally retain the chosen grace and policy revision
so their opening expectation is reviewable. The setting retains its revision,
change time, latest request ID and a nonsecret receipt sequence floor. No raw
inventory, endpoint data or extra observation history is copied into the ledger.

## Compatibility and uncertain saves

Untouched devices retain the exact version-1 state and
`tracebolt.windows-contact-view.v1` response. Explicit configuration creates a
version-2 state and `tracebolt.windows-contact-view.v2` response with the reviewed
policy. Legacy incidents keep their original 120-second meaning. New incidents
name their own grace and revision; later edits cannot rewrite that history.

The policy remains bound to the original guided identity. Existing renewal
semantics are unchanged; a replacement identity cannot adopt a setting. An
independent used marker is committed with the first explicit policy. Missing
used state or an orphaned policy fails closed instead of silently restoring the
old default. No migration, repair or reset command is introduced.

`GET /api/devices/{id}/windows-contact` stays read-only. The new shared-admin-only
`POST /api/devices/{id}/windows-contact/policy` requires exactly
`expectedRevision`, `requestId`, `graceSeconds` and `acknowledged: true`, with
current Origin, CSRF and session checks. Named readers cannot change the setting.
No authorization allowlist is widened.

The existing enrollment-to-operator lease freezes current device authority
through the bounded store transaction. Clock, authority and session are checked
after storage waits and immediately before commit. A lost response or failed
final guard can leave a committed result. The browser sends once and reconciles
with GET and the saved request ID/revision; it never retries the POST on its own.
An exact latest request replay is idempotent. Older revisions and changed reuse
of the latest request ID conflict.

If a fresh authorized GET does not match that request, the result remains
unconfirmed. The administrator can explicitly start a new review, which discards
only the browser's local attempt and requires a new unchecked approval and new
request ID against the current revision. An unchanged GET never proves that the
earlier request failed. Competing requests cannot both consume the same revision.

## Verification boundary

Focused pure-model, store, API and frontend tests use invented records only.
They cover explicit opt-in, legacy byte compatibility, all four grace choices,
freshness/recovery separation, post-change reporting, open history, exact replay,
revision conflict, lost-used-state fencing and final authority/transaction guards.
Browser rendering, native endpoint behavior, live notifications, installed-host
acceptance, deployment and publication are separate, unclaimed gates.
