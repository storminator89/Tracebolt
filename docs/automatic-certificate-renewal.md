# Automatic certificates: fresh TLS source candidate

This source candidate renews a freshly consented Linux or Windows guided identity
with the same private key. It is not a released installer or native-host acceptance
claim. Existing release pins are unchanged. Use matching reviewed source artifacts;
the dashboard does not send renewable bootstrap data to the old pinned release.

## Explicit fresh setup

The manager must be created with `tracebolt.enrollment-config.renewable.v1`,
`automaticRenewal: true`, and production TLS. Its protected mode marker records
this policy and the exact agent origin. Changing an existing mode is rejected;
there is no migration, adoption or automatic policy promotion.

The public bootstrap is `tracebolt.enrollment-bootstrap.renewable.v1` with
`renewalPolicy: "same-key-v1"`. The local installer requires a separate unchecked
renewal consent or the explicit `--automatic-certificate-renewal` option in its
reviewed command. A mismatch fails before setup writes. The local disclosure
permits repeated seven-day certificates for this same identity/key until explicit
revocation or the original issuer/explicit scope authority expires. The signed
initial claim binds that consent and both exact origins. HTTP-test renewal is
unsupported and fails without a transport downgrade.

The fresh Linux Read admin and Windows twenty-scope Read admin grants retain
exactly their originally approved collection and helper scopes. Certificate renewal
does not grant a new scope, extend a separately expiring grant, rotate a private
key, upgrade a binary, replace an issuer, install a service or repair missing state.
Those operations remain separate, explicitly authorized work.

## Identity, credentials and deadlines

The original manager, origin/profile, device ID, SPKI and identity generation stay
fixed. Only the credential generation, serial, DER and current validity advance.
The original certificate file, enrollment ledger, ready marker, scope receipts,
consent bytes, sender bindings and independent replay/capture/action floors are
not rewritten at renewal. Original job, cursor, capture and retained-history ages
are not refreshed. Every transport request still needs the currently activated
leaf and its actual unexpired validity. A valid signature is no expiry grace.

A fresh policy's absolute identity horizon is its original issuer expiry. Leaves
remain bounded to seven days and are clipped by the issuer. Renewal starts inside
the 48-hour remaining window with a bounded fifteen-minute spread. Transport
failures retain the same durable request and use bounded, persisted backoff.
Issuer exhaustion or clock/revision rollback blocks further renewal; it does not
silently introduce another trust root or reset the identity.

The current limit remains 25 retained identities per configured store. Renewal and
revocation use the existing identity record, including when all slots are occupied.
There is no capacity increase or automatic tombstone removal.

## Commit and recovery

1. A short-lived purpose-specific challenge binds the exact identity, key,
   current credential generation, revision and origin. The same-key proof and
   immutable manager policy are both required.
2. The manager persists a fixed issuance intent before signing. Its serial,
   validity and request ID cannot change on retry. Committed retries return the
   exact stored DER rather than calling the signer again.
3. Issuance creates a candidate. It is not a telemetry credential. Candidate
   proofs can reconcile its own status and request activation; activation still
   rechecks the valid predecessor, revocation, issuer and trusted clock at final
   commit. Activation retires the predecessor atomically.
4. The client persists its transaction and exact candidate under protected storage.
   It keeps collection workers alive during unchanged/retrying preparation checks.
   Before activation it cancels and joins the foreground sender and all helpers,
   validates existing used state, then publishes one atomic generation manifest.
   Persistent pending artifacts keep their exact bytes and floors. Memory-only
   content interrupted by this actual cutover retains the existing bounded
   result-lost/consume-once behavior; it is never silently recaptured or re-aged.
5. A lost committed activation reply reconciles through the already issued new
   credential, even after the old certificate expires. An expired predecessor
   cannot issue or activate a new generation. Missing used files, malformed
   manifests or interrupted protected-store integrity writes fail closed and
   preserve evidence; no initializer is a recovery fallback.

The generation manifest and transaction are separate from historical identity
artifacts. A crash between successful durable writes can reconcile their exact
committed generation. A low-level filesystem/ACL integrity failure remains a
visible local-state blocker. Restoring an old complete private-state backup is
not supported as transparent rollback recovery.

Disabling future renewal is separate from revoking the identity. Disable keeps the
current credential usable until its original expiry. Revocation denies every
generation immediately. The device's existing certificate panel reports checked
current expiry and healthy/due/retrying/blocked/expired/revoked renewal state, with
bounded identity/generation details. Contact freshness and host health remain
independent.

## Optional native package actions

The separate native APT package-action store is unsupported for these fresh
renewable identities. Its existing split-store authority check is not an atomic
credential-retirement fence. Setup and runtime fail closed for the immutable
renewable policy, including after renewal is disabled. Complete read-only
inventory, cached-update observation and supported enrollment-owned service actions
remain available. This feature does not redesign package mutation transactions.
See [selected native package updates](selected-package-updates-native.md).

## Verification boundary

Essential synthetic tests cover service/client renewal, current-vs-anchor
transport admission, exact lost replies and restart, final expiry/revocation and
clock checks, full-capacity renewal, protected-state failure, original scope/floor
and pending-byte preservation, and Linux/Windows setup consent. Relevant target
cross-builds prove compilation only. Native host enrollment, protected Windows
ACL behavior, installed-service restart, real issuer operation and release
acceptance still require their separately authorized native gates.
