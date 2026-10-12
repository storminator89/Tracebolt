# Selected cached Windows update scheduling: source candidate

This is a separate, default-off, bounded prospective-approval extension of
[selected cached update jobs](windows-selected-update-jobs.md). It does not
establish native Windows acceptance, release readiness, a persistent elevated
executor service, or permission to change a real endpoint.

## Fresh consent only

The unchanged manual `NewPlan` and `tracebolt.windows-selected-update-consent.v1`
keep their original JSON bytes when scheduling is absent. Existing manual grants,
Read admin, cached inventory and service control are not scheduling authority.
There is no migration, adoption, reconsent or reset path.

Fresh post-enrollment selected-update provisioning may explicitly choose
`--allow-scheduled-updates` on both read-only review and create-only apply.
Apply additionally requires the separate initially false
`--acknowledge-scheduled-updates`, alongside all existing installation, relay and
process-query acknowledgements and the exact reviewed plan digest. Merely
selecting scheduling for the plan does not acknowledge its authority. Supplying
its acknowledgement without the selected plan, or during read-only review, fails.

The reviewed plan adds only optional `scheduleScope` and `scheduleDisclosure`.
The resulting consent uses `tracebolt.windows-selected-update-consent.v2`, the
unchanged install scope and binding, plus
`windows-selected-cached-update-schedule-v1` and `scheduleAcknowledged: true`.
The original grant expiry, public-key pins, protected create-only roots and
ownership checks remain. Registration carries this exact fresh local consent;
manager finalization cannot manufacture it. Completed setup verification requires
that the saved plan and executor consent agree about scheduling.

The observer is still restricted LocalService. The elevated executor must be
separately administrator-launched in the foreground with the existing explicit
launch/process-query approval. Setup never starts it or creates a persistent
executor service. A running observation service alone cannot install updates.

## Review and bounded prospective approval

A named operator needs both `windows_update_install` and the separate
`windows_update_schedule` capability. Neither is inferred from Linux or service
permissions. A fresh signed readiness report must first produce the existing
short-lived preview. Scheduling then needs its own unchecked acknowledgement;
the immediate-install acknowledgement is not reused.

The operator selects explicit UTC start and end values. Start must be later than
approval and within 24 hours; the fixed window is 1–60 minutes. Its end may not
outlive the original grant or the approving current certificate. Approval saves
one immutable exact update GUID/revision, baseline readiness, original actor,
window, authority generation and digest. It immediately consumes one of the
existing 32 lifetime approvals, even if later canceled, blocked or expired.
A pending schedule blocks other manual work for this update authority.

There is no exact-time timer guarantee. At the first eligible authenticated
observer poll within the fixed window, the manager creates one fresh signed
readiness challenge. The original named actor must still have both capabilities.
Effective removal of the original approving actor’s install or scheduling
permission at manager startup irreversibly blocks that pending intent; adding the
permission back does not revive it. Expired or retired members retain their
history without preventing other registry devices from operating.

Fresh known readiness must match the reviewed baseline, ignoring capture time
only; changed or unknown facts require a new review and never authorize automatic
substitution or retry. A matching report may issue one short-lived signed
installation permit, bounded by the fixed window and current authority. Original
prospective approval and later permit issuance are separately visible timestamps.
The existing consume-before-delivery and attempt-before-native-call rules apply.
Installation may continue beyond the window; the window limits dispatch, not WUA
completion. No download, EULA acceptance or automatic reboot is authorized.

## Cancellation, revocation and saved evidence

The compact EN/DE selected-update view shows the original UTC window, scheduling
outcome, original approval and any later permit issuance. Cancellation names the
exact saved job ID and schedule digest. It can race the one-time claim. Once
claimed, it is too late to stop installation; killing a process or reaching a
deadline does not prove Windows stopped or rolled back an update.

Separately acknowledged scheduling revocation is irreversible for this original
local grant and blocks pending schedules. It does not stop a claimed installation,
remove old approvals, reset lifetime capacity or revoke the independent manual
install scope. `schedulingRevoked: true` is explicit saved revocation evidence;
absence of scheduling availability alone does not prove a revoke committed.

A lost schedule, cancel or revoke response becomes GET-only. The UI retains the
exact original job/selection/window or cancel digest for reconciliation and never
resends on blur, navigation, remount or status refresh. Another historical job
cannot replace an unresolved write's reconciliation anchor. A saved preview does
not prove an approval failed. A matching claimed/completed result after a lost
cancellation reports the race outcome without suggesting cancellation succeeded.

Additional operator routes under `/api/devices/{id}/windows-update-jobs` are:

- `POST /schedule`: exact `previewId`, `previewDigest`, `startAt`, `endAt`, and
  `acknowledged`
- `POST /cancel-schedule`: exact `scheduleId` and `scheduleDigest`
- `POST /revoke-scheduling`: `acknowledged`

All three require both capabilities, live named-session/Origin/CSRF checks, bounded
strict bodies read outside the short mutation lease, and final authority checks.
Existing GET status/history routes expose only bounded public evidence, never
execution envelopes, keys, signatures or source error prose. The legacy manual
route payloads and histories without schedule extensions remain unchanged.

## Verification boundary

Inert Go and React fixtures establish source behavior only. Native acceptance
still needs separately authorized fresh local scheduling consent, exact protected
state and process-query checks, an explicitly launched elevated foreground
executor, real cached readiness/installation, renewal and retirement races,
cancellation-versus-claim, disconnect and lost-result cases. No host changes,
Windows installation, downloads, reboot, account changes, trust changes or native
acceptance follow from this source candidate.

The separately consented [fresh background scheduling profile](windows-scheduled-background-updates.md)
reuses this scheduler with a dedicated activated service and shared reusable-MSI
fence. Existing standalone v2 grants still require their foreground executor.
