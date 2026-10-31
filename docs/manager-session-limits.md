# Manager session fairness and revocation (TB-26 slice)

This source implementation completes the independently testable session slice of
[#153](https://github.com/storminator89/Tracebolt/issues/153), **not TB-26 as a
whole**. Manager DB/issuer/enrollment/maintenance readiness, bounded operational
queue/storage/disk-full metrics, the endpoint-status dependency #136 and the
remaining capacity/retention/load evidence behind #145 remain separate gates.
No endpoint release, host provisioning or production acceptance follows.

## Bounds and identity

- All retained session entries, including revocation/expiry tombstones whose
  admitted work is still draining, share the existing global limit of **32**.
- Named accounts have at most **4** entries each. Admission uses the immutable
  configured actor ID after successful password verification, never a username,
  body actor field, client address or `X-Forwarded-For` header.
- The global budget reserves a first session for **every other configured account
  without an entry**. Repeat sessions additionally leave at least **1** global
  first-session slot unused even when that dynamic reserve is empty. With all
  32 configured accounts represented, the global limit naturally permits only
  one session per account. A single account cannot fill the budget and exclude
  all the others.
- Legacy shared mode retains its existing 32-entry cap. It is one shared account;
  the server cannot infer fair individual-human identities behind that password.
- Expiry is absolute, not sliding: the production default remains **30 minutes**,
  with the existing bounded internal TTL setting (1 second–1 hour). Listing,
  lookup and denied admission do not extend it. Restart discards all sessions.
- Existing per-peer/global attempt limits and one-at-a-time Argon2 work remain.
  An attacker can still contend for those bounded anonymous budgets; the session
  fairness contract does not claim starvation-proof authentication scheduling.
  Peer identity continues to come exclusively from `RemoteAddr`, not forwarding
  headers. Valid credentials at capacity receive `429 session_capacity` with an
  instruction to sign out of unused sessions or wait for expiry; invalid
  credentials do not disclose account existence or occupancy.

## Authenticated API

The API uses the existing exact operator Host, TLS profile, session, canonical
path, no-store and same-origin boundaries. It creates no public metrics endpoint
or new listener. It is not a user/actor label source for monitoring.

`GET /api/auth/sessions` returns a bounded JSON object:

```json
{
  "items": [{"id": "<32 lowercase hex>", "actorId": "<configured actor ID>",
             "expiresAt": "<absolute UTC expiry>", "current": true, "revoked": false}],
  "globalLimit": 32, "perActorLimit": 4, "firstSessionReserve": 1,
  "canManageAll": false
}
```

Items are sorted by opaque session ID and include only the caller's account.
Shared mode omits `actorId`, reports `perActorLimit: 32` and reserve `0`.
A separately configured named `manage_sessions` capability may list all accounts'
current entries (still at most 32). No token, CSRF value, password verifier,
username, client IP, device/customer data or request history is returned. The
session ID is a display/revocation selector, never an authentication credential.
There is no dedicated dashboard session-management UI in this slice.

`POST /api/auth/sessions/revoke` accepts exactly
`{"sessionId":"<ID from the authorized session view>"}`. Use the existing
`Content-Type: application/json`, exact `Origin` and current `X-CSRF-Token`.
Other-account and absent selectors both return `200 {"revoked":false}` to an
ordinary account. `manage_sessions` permits cross-account revocation, but is
never implied by read, update, alarm, service or legacy display metadata. Unknown
fields, noncanonical IDs, unsupported methods and unauthorized requests fail.

A successful revoke first marks/cancels the exact target under authenticated
admission, then releases the caller gate before draining already-admitted target
mutations. This permits self-revocation without deadlock. Concurrent logout and
revokers wait on the same target gate. Success never precedes the end of admitted
short target work, and no new target admission is possible after marking. The
current browser cookie is cleared on self-revocation; copied session values and
existing requests remain subject to the same revocation gate/lifetime.

Revocation removes only current sessions, not the configured account or durable
authority. It neither cancels completed/irreversible authorized effects nor grants
an automatic retry. The account may log in again using valid credentials. To
remove the account or change its rights, separately update its protected startup
configuration and restart the manager. This implementation does not perform that
operation, create credentials or alter production settings.

## Evidence boundary

Source tests exercise per-actor and global first-session reserves (including 32
configured actors), capacity recovery at absolute expiry, account-scoped redacted
views, explicit cross-account grant, self-revoke, concurrent revokers and mutation
barrier draining. Real-loopback TLS API fixtures cover authentication, exact
Origin/CSRF/body/method guards, inaccessible-account non-disclosure, repeated
revocation reconciliation, copied-cookie denial and untrusted forwarded headers.
Frontend metadata tests keep the new opt-in capability compatible with the strict
browser session parser. These are synthetic source/loopback fixtures, not a
customer deployment, native endpoint acceptance or a full security audit.
