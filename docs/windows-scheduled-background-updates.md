# Fresh scheduled background cached Windows updates

Source candidate only. No host setup, credentials, ACL/SCM changes, native update,
Windows acceptance or release is established. All native acceptance below remains
separately approved and pending.

## Fresh explicit profile

This combines the existing bounded UTC scheduler with the separately activated
[background cached-update service](windows-background-cached-updates.md) and
reusable MSI under their existing shared mutation fence. It creates fresh consent
`tracebolt.windows-selected-update-consent.v5`, background provision plan v2 and
paired review plan v4. Existing foreground v1, standalone scheduling v2,
coordinated foreground v3 and manual background v4 consent retain their exact
bytes and reject this combination. There is no adoption, upgrade, reset or retry.

The unchanged background registration v2, service config v1, observer relay v3,
background roster/activation v3 and manager registration receipt remain strict.
Their full nested consent, exact participant, public config and registration
digests bind this fresh profile. Reusing these wrappers does not reuse an old
signature, receipt, key, grant, original identity or setup root.

Follow the background paired setup with the same reviewed offers and source-built
artifacts. Add both `--background-updates --allow-scheduled-updates` to read-only
review and apply. Apply requires the exact new combined digest and every existing
background/reusable-MSI acknowledgement, plus the separately unchecked
`--acknowledge-scheduled-updates`. An acknowledgement during review, scheduling
without background selection, or any missing acknowledgement is rejected before
setup. Standalone `--selected-updates-provision --allow-scheduled-updates` retains
its original foreground behavior.

Both services stay disabled and the observer remains stopped after staging.
Finalize MSI then WUA, preserve both exact completed manager registrations, and
activate each service only through the separately approved background activation
steps. The original fixed service, image, pipe, protected state and observer
rights are unchanged. LocalSystem risk and the observer's restricted identity
remain explicit; no new service, token, privilege or automatic activation exists.

## One immutable window and one attempt

A named actor must have both `windows_update_install` and
`windows_update_schedule`. Fresh signed readiness produces the existing exact
GUID/revision preview. Separate prospective approval fixes the baseline facts,
actor, original grant and current certificate bound, and UTC start/end. Start is
within 24 hours and later than approval; duration is 1–60 minutes. The end cannot
outlive the original grant or approving leaf. It consumes one of the original
32 lifetime approvals immediately, including cancellation, expiry or blocking.

A cached shared-owner view cannot predict future availability, so it does not
reject a prospective reservation. At the first eligible authenticated observer
poll inside the window, the existing scheduler issues one readiness challenge.
The executor consumes it before inspection and saves the exact signed report.
Changed/unknown facts do not authorize a substitute update or another inspection.

Before saving an installation permit, the manager requires the same named
capabilities, matching fresh readiness, and a signed active-idle shared-status
capture taken inside this window and less than 60 seconds old. The enrollment
commit fence repeats expiry and shared-status freshness after blocking checks.
Missing, stale, busy or unknown evidence issues no permit and leaves the original
intent unclaimed. On the next ordinary relay pass, current shared status precedes
reconciliation of the same already-saved report. This can issue once only while
that report, challenge, original window, current leaf and grant are still valid.
It never regenerates readiness, refunds capacity, extends a window, or retries an
installation. Expired evidence and removed actor permissions cannot revive.

The original consume-before-delivery and attempt-before-native rules apply.
The actual COM edge independently rechecks exact shared ownership, current local
authority and the signed dispatch deadline after all blocking work. MSI may win
a race after the manager's snapshot; a consumed blocked WUA permit is not retried.
Installation can continue past the window. No download, EULA acceptance, reboot,
application-health assertion, rollback, automatic unlock or retry is authorized.
Native return/cleanup uncertainty retains the durable owner and original result.

Cancellation and irreversible scheduling revocation retain their original exact
job/digest, claim race and no-refund semantics. Lost writes become GET-only UI
reconciliation. Stopping or losing the service does not establish cancellation or
native completion. Original grant expiry is never extended by TLS renewal.

## Compact central view

The EN/DE Updates summary identifies the background service with approved UTC
windows. Unknown availability, aged signed evidence, exact window, shared owner
and saved outcome remain visible; details stay collapsed. A configured service
or recent signed capture is not proof it is running now. Manual background v4
continues showing manual approvals only, even for an actor who can schedule.

## Shared fleet planning, independent approvals

The Devices worklist can freeze one UTC start/end with the explicitly selected
Windows devices and displayed group revision. It is temporary browser planning;
selecting a group or window sends no request and creates no manager authority.
Open one device at a time, select its exact cached revision, obtain fresh
readiness and explicitly review its initially unchecked prospective approval.
The same frozen window is displayed for each device; unsupported, revoked or
expired scheduling authority cannot fall back to immediate installation.

No automatic next-device action or bulk approval is added. Per-device summary
rows retain the last-read job, fixed window, result/reboot truth and unconfirmed
write state independently. Unconfirmed writes are GET-only until reconciled;
closing or changing the selection does not cancel an already saved schedule.
The existing registry limit of 25 independently configured device bindings,
32 lifetime approvals per grant, original deadlines and native-edge fence remain.

## Essential native acceptance, pending

With separate approval on a disposable Windows x64 non-domain-controller:

1. Stage the exact fresh profile; reject missing scheduling consent, old receipts
   and changed participant/config/registration digests. Confirm both services are
   disabled until approved activation and the observer retains its old rights.
2. Approve one exact cached, downloaded, accepted-EULA update for a bounded UTC
   window. Verify fresh readiness, both named capabilities, original lifetime and
   current-leaf checks, including renewal and final-time races.
3. Hold the MSI owner: no WUA permit/native admission. Release with exact settled
   evidence; reconcile the same still-valid readiness and admit once. Recheck a
   race where MSI acquires the owner after the manager snapshot.
4. Exercise cancellation versus claim, expired reports/window, actor removal,
   lost responses/restarts and cleanup uncertainty. No replay, refund, substitute,
   window extension or elapsed-time unlock may result.

Synthetic fixtures and cross-builds establish source behavior only.
