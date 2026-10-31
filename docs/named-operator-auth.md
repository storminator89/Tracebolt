# Named operator authority

Status: optional source implementation for controlled-action authorization. No
service restart, package planning/execution, privileged helper, signing key,
account-management UI or host configuration is enabled by this change.

## Two explicit startup modes

The manager still reads the existing `operatorAuthFile` through the protected
local-file loader. The default, existing `tracebolt.operator-auth.v1` object
(`schemaVersion`, `profile`, `passwordHash`) remains unchanged: password-only
login and the same existing operator read/administration routes. A shared login
has no named human actor and receives **none** of the new maintenance grants.

An administrator may explicitly replace that file with the versioned named-only
format below. This is a format illustration, not ready-to-use credentials:

```json
{
  "schemaVersion": "tracebolt.operator-auth.v2",
  "profile": "tls",
  "operators": [
    {
      "id": "operator_0123456789abcdef0123456789abcdef",
      "username": "operator-name",
      "passwordHash": "<separately provisioned Argon2id verifier>",
      "capabilities": ["read", "restart_service"]
    }
  ]
}
```

Stable IDs must be `operator_` followed by 32 lowercase hexadecimal characters
with at least one nonzero digit;
usernames are case-sensitive lowercase ASCII letters/digits, with `.`, `_` and
`-` allowed after the first character, at most 64 bytes. IDs and usernames must
be unique. The bounded file supports 1–32 operators and at most 32 KiB. Unknown
or duplicate fields, nulls, unknown/duplicate capabilities, mixed v1/v2 fields,
unsupported versions and malformed verifiers fail closed before listeners start.
All operators must explicitly include `read`. There is no wildcard or admin role.

The existing Argon2id verifier bounds, password bounds, global/per-peer login
rate limits, one-at-a-time hash budget and 32-session ceiling remain in effect.
Named sessions additionally have a four-session per-account ceiling. The global
budget reserves one first session for every configured account not yet present;
repeat sessions cannot consume these slots. Repeat-session admission additionally
leaves at least one global first-session slot when that dynamic reserve is empty;
a first session may consume the reserve.
Revoked/expired sessions with admitted work still draining count toward the
ceiling until their barrier completes. Existing shared mode keeps its 32-session
ceiling; it is one account, not distinguishable human actors.
Named verifiers must use the same memory/iteration/parallelism parameters within
a configuration. Unknown usernames use a dummy verifier with the same bounded
work factors and receive the same credential failure as an incorrect password.
Supplying the dummy verifier's matching password does not authenticate an unknown
name. A missing username is an invalid request; it never selects shared login.
No account name, actor ID or grant list is disclosed before authentication.

The file must retain the existing secret-file protections: manager-owned,
owner-only permissions, no symlinks/hardlinks and no unprotected replaceable path
components. The loader reads configuration; it never generates credentials,
creates users, changes permissions or writes configuration. Provisioning and
migration require a separate administrator decision. Keep real verifiers out of
Git, terminal output, screenshots, logs and support artifacts.

## Capability and existing-route mapping

The [method/route and actor matrix](named-administration-matrix.md) inventories
the current enrollment, trust, customer, AI, account and export boundaries for
TB-06. It documents current denials, not new administration grants or migration.

- `read`: supported authenticated read views admitted by `namedReadRoute`, still
  subject to route-specific restrictions. Customer catalog/Windows-assignment
  GETs explicitly require shared administration; privileged application-check
  settings require their separate capability. GET/HEAD classifier admission does
  not make HEAD a supported API method. Read also admits exact read-only JSON
  POST queries, including `/api/devices/{agentId}/journal/query` and
  `/api/devices/{agentId}/inventory/{section}/query`, where `section` is `system`,
  `overview`, `packages` or `complete-updates`. These queries still require
  the existing Origin, CSRF, profile, identity, generation and expiry checks.
- `plan_updates`: explicit permission for the separately configured typed Linux
  package-update `prepare` route. It does not imply execution authority.
- `execute_updates`: explicit permission for that workflow's exact reviewed
  `approve` route. Existing profile, current identity, approval and replay fences
  still apply; a capability alone does not configure or authorize a native helper.
- `restart_service`: the separately configured, approved typed service-action permission.
- `manage_alarms`: explicit browser alarm configuration and synthetic-test permission.
  It does not enable delivery by itself; destination/payload approval and the protected
  complete-profile manager settings are required. See [alarm delivery](alarm-delivery.md).
- `manage_sessions`: explicit permission to list/revoke other accounts' current
  manager sessions through the bounded [session API](manager-session-limits.md).
  It does not change accounts, credentials, capabilities or future login rights.
- `manage_application_checks`: explicit access to application-check destinations and
  browser configuration. Existing read, alarm, update and service grants do not imply
  it. Save persists a disabled draft; a separate enable requires current-revision
  manager-origin and destination acknowledgement, plus plaintext acknowledgement
  on the isolated HTTP-test profile. Status stays destination-free and readable
  with `read`. A supplied startup configuration is immutable in the browser.
  The existing shared pilot administrator can configure checks without a named
  grant, following its explicit administrator route mapping. No account or grant
  is created or changed by this feature.

No grant implies another. A named account is not an existing shared-login
administrator. Named accounts cannot create/cancel journal collection, change
agent enrollment/trust, edit health settings or case notes, configure/invoke AI,
import/synchronize feeds or perform other existing administrative writes. Reading
already captured journal content is distinct from enqueueing another capture.
Signing out is always available with valid same-origin/CSRF credentials.

V2 intentionally has no shared-password fallback or implicit legacy-admin
capability. An existing installation that needs current enrollment/log
administration should keep its v1 configuration until a separately reviewed
named-administration mapping is available. This narrow slice does not offer
account-management or a live migration UI. Existing v1 deployments keep their
current routes and password-only form.

## Session identity, expiry and revocation

The server derives each actor ID and capability set from an immutable defensive
copy of startup configuration after checking username and password. Login JSON
cannot supply actor, role or capabilities. Session responses add `loginMode`,
`actorId` and `capabilities`; shared sessions have a null actor and only the
`read` display capability, while retaining their legacy route behavior. The
browser conditionally asks for a username in named mode. UI metadata is a display
snapshot, never an authorization token or proof of current permission.

Cookies, CSRF tokens, session lifetime cancellation, TTL, duplicate-cookie
rejection, same-origin checks and the logout admission barrier are reused. Logout
revokes that session and waits for short already-admitted work to drain. New
capability admissions fail after logout, expiry or context cancellation. The
capability guard uses private server-held grants, not caller-editable arrays.

**Configuration is static until the manager is restarted.** Editing the file
alone does not revoke an active account, rotate its verifier or change a grant.
To remove/disable an account or change its permissions, an administrator updates
the protected file and restarts the manager. All sessions are memory-only and
must sign in again; old cookies cannot be looked up in the new manager. There is
no live reload or claim that editing a file affects an already-running process.
The authenticated [session API](manager-session-limits.md) lists and revokes exact
current sessions, scoped to the same account unless `manage_sessions` was
explicitly configured. Logout still affects the current session only. Session
revocation is not account disablement: valid credentials may sign in again.

Typed administrative endpoints use fail-closed capability admission. Application
check settings require the exact grant for reads as well as writes because their
review DTO contains destinations. Mutations additionally require current
Origin/CSRF, strict typed bodies and a current revision; they derive the audit
actor from server-side session identity. The session gate is acquired only after
bounded request-body parsing and is released before response I/O. Logout/revocation
cannot admit a delayed request body. Check generation replacement cancels and
joins prior work before confirmation; it does not probe targets in the request.

## Transport and acceptance limits

The operator file's `profile` must exactly match the manager profile. Production
`tls` keeps authenticated HTTPS and the Secure `__Host-` cookie. A separately
acknowledged disposable `http-test` configuration keeps its distinct cookie and
prominent plaintext warning. A named identity does not repair HTTP secrecy:
anyone who steals an unencrypted operator session can act within its granted
scope. Never migrate HTTP-test material or state into production by relabeling it.

This change does not opt any endpoint into privileged work. The future signed
transport-profile binding, protected helper policy, explicit local-machine opt-in,
immutable expiring approval, durable dispatch and native acceptance requirements
in [Controlled Linux actions](controlled-linux-actions.md) still apply.

Focused tests cover strict protected v1/v2 loading, unknown-user/no-fallback
behavior, server identity, defensive grants, session/capability expiry and logout,
restart-based removal/permission changes, denied legacy writes, allowed read
queries, CSRF and HTTP-test/TLS separation. These source/fixture checks are not
native installed-service, real operator migration or controlled-action acceptance.
