# Optional live-account factors and reset

This is the local factor path supporting TB-14 / #141. Enrollment and reset
have a [non-browser terminal client](operator-factor-client.md), including
protected local proposal/handoff custody; the APIs remain available. The cockpit login source supports an optional
OTP input selected by validated server-wide protocol metadata; that frontend
change is not yet typechecked, built or browser-tested. This is not
acceptance of the broader MFA/recovery/UI work in #140, full named administration
in #133, an installed deployment or a browser-tested login experience. Existing
factorless static v1/v2 and live v3 accounts are not silently migrated or enrolled.
No service, listener, host permission or external provider is added.

## Explicit protocol and custody

The versioned profile `tracebolt.operator-factor.totp-sha256.v1` fixes HMAC-SHA256,
eight decimal digits, a 30-second UTC step, and a 32-byte random secret. It follows
[RFC 6238](https://www.rfc-editor.org/info/rfc6238/) with the bounded counter rules
below. An authenticator must explicitly support these parameters; six-digit or
SHA-1 defaults are not guessed or accepted. TOTP is phishable: this does not claim
WebAuthn origin binding, OIDC assurance or hardware-backed authentication.

A credential custodian must separately provision the authenticator and a private
proposal adjacent to the live journal:
`<journal>.factor-<existingActorId>.json`. The API cannot supply a secret, path,
actor mapping or grant. The proposal has the same unchanged private-file,
ancestor-ownership, no-symlink and single-link checks as credential proposals.
Its maximum size is 4096 bytes. Its exact ordered fields are:

1. `version`: `tracebolt.operator-factor-proposal.v1`
2. `authorityId`: the current pinned authority ID
3. `actorId`: the existing account's ID
4. `expectedRevision`: that account's current positive revision
5. `secret`: the approved 32-byte secret, canonical uppercase Base32 without padding

Whitespace is permitted, but unknown, duplicate, reordered, null or noncanonical
fields/encodings and trailing values are rejected. Never put actual material in
Git, command arguments, environment variables, URLs, logs or support artifacts.
This contract is not permission to provision a real account or distribute secrets.
The terminal client's explicit `prepare` operation supplies protected random
custody material and a private handoff without displaying it. Delivery to the
intended authenticator remains an approved human possession step. Stale proposal
replacement requires explicit review and preserves the original bytes; no
authority history is deleted. The running manager does not manufacture the
material or expose it in HTTP. See the client runbook for prerequisites and limits.

## Enrollment and login

`POST /api/auth/factors/enroll` is available only on the live TLS operator surface.
Like login it requires the exact configured Host/Origin, TLS 1.3 and a strict
`application/json` body, here with exactly:

- `username`, `password`, `otp`, `expectedRevision`.

It does not trust an ambient cookie. The current account password, the exact
protected proposal and actual possession of its new factor must all validate.
The ordinary authentication attempt/hash budgets apply. Only an account without
a factor, or one explicitly awaiting re-enrollment after an authorized reset,
can enroll. Disabled or uncertain accounts cannot use this route for recovery.
An active factor cannot be replaced through enrollment.

Success atomically audits `factor_enroll`, advances the account epoch/revocation
floor, binds the factor generation and consumes the enrollment OTP. Prior target
sessions and approvals are withdrawn. No session cookie is issued. The operator
must subsequently sign in with a fresh, unused OTP; reusing the enrollment code
fails. Other accounts and their cookies are not changed.

In live v3, `POST /api/auth/login` retains required `username`/`password` and adds
optional `otp`. For a factor-bound account it is mandatory in effect: neither
this API nor direct `LoginNamed` calls can issue a password-only session. Static
v1/v2 JSON schemas remain exact and do not accept `otp`. Existing factorless v3
requests need not add an empty field. Null, duplicate, unknown or mistyped fields
remain rejected. Invalid factor credentials never mint a cookie.

Only TLS live v3 advertises `loginFactorProfile: "totp-sha256-8"` in its session
views, before and after login. This is server-wide protocol support, not a lookup
of an individual's enrollment. Static v1/v2 and development omit the field; live
authority cannot be configured on the plaintext test handler. The cockpit source
validates that exact profile and named/LAN/HTTPS combination before presenting an
optional eight-digit string field. Leading zeroes remain intact; empty codes are
omitted so legacy requests remain unchanged. Codes are cleared on submit, lock,
bootstrap, logout, account change and hidden/pagehide transitions, and are never
persisted or broadcast. A profile change during login fails closed. Source review
does not substitute for the pending frontend compilation/build gate.

The verifier considers only the current step and its two immediate neighbors,
uses constant-time code comparisons and accepts only steps strictly above the
persisted floor. Successful consumption is durable before session creation;
parallel or restarted replay fails. This `factor_use` advances the journal
sequence, **not** the account revision, so signing in does not revoke existing
sessions/jobs. A full session account is rejected before needless OTP writes;
the final capacity and current-revision checks still apply. Storage uncertainty
fences the affected account rather than allowing password-only fallback.

## Real factor reset

`POST /api/auth/accounts/reset-factor` requires the current named
`manage_accounts` session, exact Origin and that session's CSRF token. Its strict
4096-byte JSON object contains exactly:

- `actorId`: the existing **target** account
- `expectedRevision`: its exact reviewed revision
- `password`, `otp`: fresh authentication of the **requester**, not the target

The cookie or grant alone does not authorize a reset. The requester's password
and currently unused OTP are checked again, and the proof is consumed once. A
short proof deadline, clock-rollback guard and final current-authority checks
apply both before fencing and after draining older dispatch admissions. A stale
target revision or failed operation can consume its proof: do not automatically
retry or reuse it. A fresh review and fresh proof are required.

An accepted reset atomically audits the actual requester with `factor_reset`,
advances the target account revision/floor and factor generation, withdraws all
target sessions/approvals, and sets `enrollment_required` with no active secret.
The other administrators remain usable. The last actually usable account
administrator cannot be removed. Old or newly supplied OTPs cannot log into a
pending account, and neither password reset nor a role update removes this
factor requirement. Re-enrollment uses the protected proposal and possession
flow above; it does not unblock a disabled account or restore old job epochs.

Retired secret digests remain bound to the account and cannot be re-enrolled,
even using a new correctly revision-bound proposal. Active and retired factor
keys cannot be shared across the roster. At most sixteen retired factors per
account are retained; exceeding that bound fails closed before target fencing.
No history-clearing, implicit reset, recovery-code or break-glass bypass exists.
Loss of all authorized factors requires a separately reviewed recovery path,
not editing/deleting the protected journal or used marker.

## Journal, compatibility and evidence boundaries

Factor authority is in the same protected, exclusively locked journal as account
revisions/audit. Generic factor/account JSON and diagnostic formatting omit the
secret; only the private journal/proposal wire format contains it. Account views
expose factor state/generation, never the secret, OTP or retired-key history.
Backups must therefore classify the journal and proposals as credential material,
preserve their entire history/counters and use the existing protected custody
boundary; this does not implement or authorize a backup/restore operation.

Canonical `factor_use` deltaframes contain only the pinned header, audit,
generation and new step, not a copy of every account/secret. Replay reconstructs
the previous snapshot and validates the same narrow transition as the writer.
Mixed, initial, foreign-actor, wrong-epoch/generation and nonmonotonic records are
rejected. Factorless historical frames remain byte-compatible; older binaries
reject actual factor/delta frames rather than silently ignoring MFA.

The journal is still bounded to 32 MiB total and 128 KiB per frame. Deltaframes
reduce per-login growth but do not provide unlimited capacity or compaction.
Capacity/integrity/fsync uncertainty fails closed and requires inspection. No
automatic truncation, reseeding, floor rollback or external monotonic-witness
guarantee is claimed.

Native targeted tests cover official SHA256 vectors, public protected files,
TLS API enrollment/login/reset, independent accounts, request identity/CSRF,
parallel and restart replay, re-enrollment, retired keys, exact delta replay,
proof expiry during actor drain, uncertainty and unchanged legacy schemas.
See [the validation record](tb14-local-validation.txt) for actual commands/results.
These are protocol/source fixtures, not browser or installed-system acceptance.
