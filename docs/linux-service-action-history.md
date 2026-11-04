# Saved Linux service-action history

The Linux **Services → Service action** panel has a deliberate **Saved
service-action history** read for named operators with the existing
`restart_service` capability. Open the history, choose an exact numbered receipt,
and close or refresh it. The workflow is available in English and German.
It adds no action approval, local grant, notification, export or retry control.

## What is retained and shown

This is a projection of the existing manager service-action ledger, not a new
Security Audit or an endpoint event collector. Up to **64 approvals** are retained
for the original device incarnation and command key. Every existing slot is
included, newest sequence first; there is no hidden page, truncation or archive
fallback. At capacity, the existing ledger blocks new approvals and receipts stay
readable. Unapproved previews are not approvals and never appear as saved jobs.

Each receipt includes the exact original service, action ID, sequence, approving
operator, approval time, start deadline, delivery claim when present, and up to
three existing agent-result phases with their original **manager receipt times**.
The original device/key/envelope digests are available as receipt details. No
signed envelope, public/private key bytes, preview, arbitrary output, raw content
or new endpoint data is returned.

- Approved and claimed actions do not prove execution or delivery completion.
- Admitted and dispatching reports do not prove the command completed.
- Agent-reported command completion does not prove a successful restart or
  present service health. The reported state remains explicitly agent-reported.
- Not-started, expired and intervention-required outcomes remain distinct.
- Claim and manager receipt timestamps are not native start/completion times.
  Missing reports never become success or authorization for another attempt.

## Access and snapshot behavior

`GET /api/devices/{agent_id}/service-actions/history` requires the existing named
`restart_service` capability and current authenticated operator surface. Shared,
read-only and unrelated maintenance accounts cannot read it. The existing
service-action status/preview/approval wire contracts remain unchanged.

The handler uses the same current-device, original-incarnation/key and credential
admission as the existing service-action `ViewAt` read. It validates the entire
record and original observation clock, encodes a closed response capped at
128 KiB, and checks the operator session again before publication. Missing,
revoked, expired or unreadable authority is an error, never an empty history.
There is no alternate identity lookup or enrollment/state repair. As with the
existing status read, `ViewAt` can durably normalize an unclaimed approval's
original expiry. Reading creates no job, preview, permit, claim or agent result.

The UI makes one explicit bounded same-origin read after checking the exact named
session, with redirects refused and no polling. Receipt expansion is local.
Every snapshot shows its original manager time and is cleared after at most one
minute or the remaining session lifetime. Refresh clears the previous receipt;
it cannot renew frozen or cumulatively stalled source time. An advancing
snapshot is still a status read, not a new agent observation. The existing API
does not supply a current-leaf expiry deadline or a push revocation signal;
the one-minute browser limit is not exact device-certificate-expiry awareness.
Device authority is checked on each deliberate read, and source revocation or
loss between reads is not detected until the next read.

Close, authentication/access-epoch change, device/session replacement, hidden
page, blur or navigation clears displayed rows and aborts pending reads.
Restoring focus requires an explicit refresh, and late responses cannot reopen
content. Only original binding/time metadata remains for continuity checks;
private receipts are not persisted in browser storage or exported.

## Verification boundary

Focused source/API/component tests cover admission, all 64 slots, original
identity and receipt ordering, unavailable outcomes, lifecycle interruption,
bounded transport and clock/session limits. These are portable/loopback fixtures,
not installed-service, native Linux action, browser or release acceptance. No
service was restarted and no host permission or persistent endpoint key was
created for this feature. The separately approved
[service-action setup and native gate](guided-service-action-setup.md) remain
required for an actual controlled action.
