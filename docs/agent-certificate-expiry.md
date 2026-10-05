# Agent certificate expiry in device details

The authenticated LAN device overview shows public certificate expiry already
recorded by the manager. It performs no additional request: the existing device
metadata GET carries an optional `agentCertificate` object with `source`,
`expiresAt` (UTC timestamp or null), and `checkedAt` (manager UTC timestamp).

- Manual approval reads the approved leaf certificate's retained `ExpiresAt`.
- Guided enrollment reads `Intent.NotAfter` only after committed issuance exists.
  An issuance intent, invitation deadline, approval time, contact time or seven-day
  default cannot stand in for a certificate expiry.
- Older managers, unissued credentials and malformed/missing metadata show unknown.
- At the explicit manager check, expiry at or before that time is expired; expiry
  within the next 48 hours is expiring soon. Later expiry is labelled as more than
  48 hours remaining. The display is a checked snapshot, not a live countdown.
  The existing **Refresh device metadata** action obtains a new checked snapshot.
  A browser clock change cannot extend the certificate or invent renewal.

Expiry, approval/revocation, activation, accepted report freshness, installed
service state and host health remain separate. For example, a revoked certificate
can retain a future expiry; it remains denied by existing authority checks.
Reading or refreshing the display never changes issuance, trust, device IDs,
collection consent, replay state or the certificate's original expiry.

Automatic credential renewal and stable-identity rotation remain unavailable.
Guided mode directs the operator to plan a separately authorized replacement
enrollment with an administrator; it does not offer an automatic recovery action.
Manual mode requires a separately authorized certificate replacement and a fresh
manual approval, which receives a new opaque device ID. Existing identity/history
is not automatically merged. No enrollment, renewal or permission button is added.
See [LAN trust](lan-trust.md) and the [native enrollment client](enrollment-v2/native-client.md)
for the existing operational boundaries.

The shared model's optional field is operator-only: support bundle encoding,
local telemetry decoding and LAN telemetry decoding reject endpoint-supplied
certificate metadata, including a JSON null field. Ordinary endpoint wire frames
omit the field and retain their existing contract.
