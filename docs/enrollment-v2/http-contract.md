# Enrollment v2 HTTP integration contract

Status: implemented opt-in integration over the reviewed lifecycle and durable
store/service, enabled only with explicit guided-v2 manager configuration. The first
runtime cap is **25 retained records**, including canceled/revoked tombstones,
and the first client integration targets Linux. This is one environment and one
operator, with no customer/tenant hierarchy.

## Surfaces

The existing exact-origin operator listener provides server-authenticated HTTPS.
A dedicated `/v2/enrollment/` router on that listener accepts only native-client
proof requests. It is not behind the separate agent listener's mandatory mTLS
handshake. It rejects browser cookies, `Origin`, authorization bearer headers,
forwarded authority claims, redirects, noncanonical paths, transfer encoding,
encoded bodies, ambiguous headers and bodies above 16 KiB. No CORS is enabled.
The operator `/api/enrollment/` routes still require the normal session, exact
Origin, CSRF and post-body mutation lease. Native proofs never authorize them.

The explicitly configured `http-test` profile has its own issuer, credentials,
state, cookie and warning. HTTP exposes invitation material, passwords, sessions
and observations and provides no manager/server authenticity. Proof of client key
possession does not repair that transport weakness. No automatic downgrade occurs.

## Operator routes

All JSON fields below are required, exact-case and reject duplicates/null/unknown
fields. Request IDs are `request_` followed by 32 lowercase hexadecimal digits.
The server chooses opaque invitation/device/intent IDs and serial numbers.

- `GET /api/enrollment`: `{enabled, schemaVersion, platforms, recordLimit,
  items, serverNow}`. `items` are public `tracebolt.enrollment-state.v2` snapshots. An
  unconfigured issuer yields `enabled:false`, not automatic provisioning.
- `POST /api/enrollment/invitations`: `{requestId, platform}`. Initially platform
  is `linux`. Returns `{schemaVersion, snapshot, invitationSecret, bootstrap}`
  once, with a trusted RFC3339 `serverNow` clock anchor, after the verifier and invitation commit. The secret is shown only in
  this response; readbacks, URLs, logs, browser storage and export never contain
  it. On an uncertain/lost response the operator cancels the invitation and
  creates another; request replay cannot recover its secret.
- `POST /api/enrollment/{invitationId}/approve`: `{requestId,
  expectedRevision, expectedKeyFingerprint}`. The UI presents the full SPKI
  SHA-256 fingerprint and context-bound 128-bit comparison value from the native
  client. Approval persists the selected bound key and server-assigned device ID.
- `POST /api/enrollment/{invitationId}/terminate`: `{requestId,
  expectedRevision, action}` where action is `canceled`, `rejected` or `revoked`
  and must be valid for the current phase. Returns the committed snapshot.

The bootstrap is public, versioned configuration: manager instance ID, exact
operator/enrollment origin, exact agent origin, profile, collection profile,
public server trust information, public issuer trust information and invitation
ID. A native bootstrap reader must validate it and display its trust/fingerprint
context before transmitting an invitation. It never accepts a trust root learned
from an unauthenticated HTTP response as HTTPS trust. Downloadable secret-bearing
files remain disabled; a hidden prompt is the first supported token handoff.

## Native proof routes

`POST /v2/enrollment/challenge` accepts `{invitationId, claimId, purpose}` with
purpose `claim`, `status`, `credential` or `activation`. It returns
`{schemaVersion:"tracebolt.enrollment-challenge.v2", context, purpose, serverNow}`.
Context is `{managerInstanceId, profile, origin, collectionProfile, invitationId,
claimId, challenge, expiresAt}`; expiresAt is UTC Unix seconds. Challenges last
60 seconds, are purpose-bound and single-use, with 256 retained globally,
30 creations per peer per minute, 120 manager-wide creations per minute and
256 peer windows. At most two native proof operations enter the durable store
concurrently; additional work gets a fixed 429 rather than an unbounded queue. The peer is socket
RemoteAddr, never a forwarded header. A challenge does not reveal whether an
invitation exists and does not authorize any lifecycle change. A manager restart
invalidates outstanding challenges; the client obtains a fresh challenge while
retaining its same semantic operation/request/key.

- `POST /v2/enrollment/claim`: exact `tracebolt.enrollment-claim.v2` proof defined
  in enrollmentcrypto. Invitation possession plus CSR signature and a fresh
  context-bound key-possession proof binds the first claim atomically. Same
  semantic claim may retry with a fresh challenge; another key cannot take it.
- `POST /v2/enrollment/status`: exact `tracebolt.enrollment-status.v2`, purpose
  `status`. Returns the current snapshot only after a durable current-state
  authorization check. A pending client sees pending. An approved client can
  resume issuance: fixed intent commits before signing, deterministic DER commits
  before delivery. The signer never chooses CSR identity/privileges. Terminated
  status is visible to its bound key but grants no subsequent operation.
- `POST /v2/enrollment/credential`: the same status proof schema with distinct
  purpose `credential`. Returns only the already committed public certificate
  and fixed public intent/issuer chain needed for local validation. The store
  checks the active lifecycle and persists delivery metadata before any DER is
  returned. Every valid retry returns identical DER; only the most recent
  delivery request ID is deduplicated for delivery-count metadata. Delivery does
  not activate a device or update telemetry freshness.
- `POST /v2/enrollment/activate`: exact `tracebolt.enrollment-activation.v2`,
  binding the complete immutable intent digest, certificate hash, request ID and
  fresh challenge. A certificate by itself is not possession. Activation commits
  before telemetry can be accepted.

The status proof has exactly these string fields: schemaVersion,
managerInstanceId, profile, origin, collectionProfile, invitationId, claimId,
keyFingerprint, requestId, purpose, challenge, proof. The public key is loaded
from the committed claim; request-supplied fingerprints are never trust sources.
Signing uses domain-separated, length-prefixed transcripts, canonical base64 and
strict validated Ed25519 keys. There are no generic signing or command endpoints.

## Failure and retry behavior

Responses contain fixed codes/messages, never raw provider/SQLite/OS exceptions,
invitation tokens, keys or proof bodies. Validation errors are 400, invalid or
expired client proof 401, lifecycle/CAS or retained-record capacity conflicts 409, bounded request rate
limits 429, unavailable store/signer 503. Operator authentication remains 401 and
origin/CSRF failures retain existing status semantics. A transport error is not
proof of revocation. Native clients stop on validated terminal lifecycle states.

Revocation, current certificate identity, sequence, original collection time,
body hash and observation commit share the same SQLite transaction. No bridge
from a cached enrollment decision to an independently committed observation DB
is permitted. Exact telemetry retries preserve the first receipt time; delivery
or retry time never refreshes old observations. Credential generation/state
migration must preserve sequence floors and drain/discard exact pending bytes
under an explicit later versioned contract.

## Remaining integration gates

Before endpoint enablement: worst-cap transaction/wait measurements, independent
store/service review, actual HTTPS/HTTP fixture boundary tests, issuer custody
configuration, client private-first-write staging/restart tests, operator UI
review, and two-binary Add→claim→approve→activate→scheduled-report acceptance.
Service/installer templates and native reboot acceptance remain separate from a
foreground loop. No live credentials, system service or LAN listener are
provisioned by this document or the code-only fixtures.
