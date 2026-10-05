# UI-approved service try-restart workflow

Status: default-off source integration and synthetic acceptance candidate. This
connects the reviewed [root helper](controlled-action-helper.md) to the manager,
agent, and selected-service UI. It does not install or enable anything on a host.
No real service action, command-key provisioning, root grant, socket or systemd
unit installation is established by the tests described here.

## One deliberate operation

In the Services inventory, a named operator with `restart_service` can select one
locally allowlisted service, review its exact preview, acknowledge the possible
interruption and explicitly approve `service.try-restart`. Shared login and the
synthetic development manager cannot authorize this operation. There is no shell,
arbitrary command, start/enable, package action, cancellation, automatic retry,
fleet scheduling or generic remediation workflow.

The UI remains unavailable until the manager action configuration and existing
state are present, and the endpoint reports a fresh matching local helper grant.
Availability is an agent-reported hint, not execution authority or proof that a
helper/systemd backend is healthy. The helper performs the independent root-local
checks again for the actual signed submission.

`operation_completed` means the fixed synchronous systemctl operation exited
zero. It does not prove a restart occurred, or that the service/application is
healthy. The active/inactive/failed/unknown observation is separate. Every manager
result is labeled agent-reported; this slice has no helper-signed attestation.
A claimed job without a result has an unconfirmed outcome. A helper's ambiguous
outcome is `needs_intervention`, blocks another action, and cannot be cleared by
creating a replacement job. No reconcile/reset API is included.

## Durable authorization and delivery

1. The root helper projects only bounded public capability metadata over its
   credential-checked local IPC. The agent reports it through the authenticated
   service-action ingress. Original capture age is at most 60 seconds; repeating
   the same report does not renew its freshness.
2. `POST /api/devices/{id}/service-actions/preview` accepts only `unit`. The manager
   derives a 60-second immutable preview from its enrolled endpoint/incarnation,
   current helper policy/target digests and server-authenticated named actor.
3. `POST .../approve` accepts only `previewId` and `previewDigest`. The current
   session, exact Origin/CSRF and `restart_service` capability are checked under
   the existing short authorization lease. Actor, target and permit fields never
   come from approval JSON. The exact preview is compared again to current policy.
4. Approval stores the original preview, approval record and exact signed permit
   atomically in the enrollment database. The domain-separated Ed25519 permit
   lasts no longer than the smaller of 60 seconds and the helper policy limit.
   Approval retries return the original saved job; they never renew a deadline,
   renumber a sequence or sign a second permit. No usable permit is returned on a
   failed or uncertain commit.
5. Agent `peek` receives metadata only. The first successful `claim` transaction
   durably consumes delivery and alone returns the saved signed envelope. A
   duplicate claim never returns it. The agent submits that fresh grant once to
   the helper, whose own independent durable ledger controls actual dispatch.
6. After any lost claim/submit/result response, or an agent restart, claimed-job
   polling permits only helper status reads. It never reconstructs submission
   authority or creates a new job. A lost claim before helper admission may remain
   unconfirmed; that is deliberately not reported as a successful action.
7. Result ingress binds current enrollment/certificate, job ID, sequence and
   envelope digest. At most three strictly monotonic observations are retained per
   job. Exact repeats are idempotent; regression and conflicting terminal results
   are rejected. Unclaimed expiry and observed preview expiry advance a durable
   clock floor, so a manager clock rollback cannot revive authority.

Operator preview/approval/status responses and agent peek never contain a permit
or execution envelope. Closing the browser does not cancel an approved job. An
uncertain approval response is reconciled by reading saved status, not silently
posting another approval. Changing service/device, dismissing a preview, expired
sessions and repeated clicks cannot approve an older hidden selection.

The same protected enrollment database holds an optional exact-schema action
metadata table and one canonical record per explicitly initialized endpoint
incarnation. Each record retains up to 64 immutable approved jobs and a monotonic
sequence. Exhaustion fails closed; there is no pruning/reset endpoint. Root policy
and transport-profile changes retain the same manager/key/endpoint-incarnation
history. Changing a command key or enrollment incarnation needs a separately
reviewed migration. Restoring an older complete backup is not transparent live
recovery; this slice does not solve rollback-resistant backup restoration.

## Explicit manager configuration

The normal LAN configuration has an optional `serviceActionsConfigFile` absolute
protected path. Omission leaves service actions off. When set, startup requires a
named-operator configuration, guided activated complete-profile enrollment,
protected command configuration/key, and already initialized action state.
Missing schema or endpoint records are never created by a capability report,
preview, approval, claim or normal startup.

The separate protected JSON command configuration has this exact shape (all
values below are placeholders; this is not a provisioning command):

```json
{
  "version": "tracebolt.service-actions-config.v1",
  "enabled": true,
  "managerId": "manager_<existing-32-hex-instance-id>",
  "transportProfile": "production-tls",
  "httpTestAcknowledged": false,
  "privateKeyFile": "/absolute/protected/command-signing.key"
}
```

The private key is separately preprovided raw 64-byte Ed25519 private material,
not a seed, PEM file, enrollment issuer, TLS key or a newly generated fallback.
Startup validates its public/private relationship and rejects reuse of the
configured enrollment root/issuer or TLS public key. Configuration and key file
protection/content are rechecked before signing and fresh claims. Closing the
manager synchronizes with key readers/signers and then clears private bytes.
Private material, raw command configuration and permits are never UI fields.

The manager's `InitializeServiceActions` and create-only
`InitializeServiceActionIdentity` functions are trusted provisioning library
seams used by synthetic fixtures. No runtime, API, ingress, installer or CLI calls
those initialization functions. There is intentionally no production setup or
repair command in this slice. Existing-only `OpenServiceActions` is the runtime
path. Dropping a used row is a hard stop, not permission to reconstruct history.

## Transport and local consent

Production requires the existing HTTPS operator session boundary and verified
agent mTLS. Service-action HTTP requests use their own purpose-separated proof
headers/domain and fixed `/v3/service-actions/{capabilities,peek,claim,result}`
paths; journal/inventory proofs cannot authorize them. HTTP is supported only
under the existing explicit disposable test profile, plus matching manager,
root helper and local client grants with separate HTTP-risk acknowledgement.
There is no TLS fallback or insecure verification switch. Plaintext operator
session theft can authorize actions inside such a disposable grant; do not use
that profile for production.

The endpoint incarnation is exactly `sha256:` followed by the existing activated
leaf certificate DER's SHA-256 hex digest, not a hostname or hash-of-hash.
Manager/key/endpoint/incarnation are independently pinned in the local root grant.
The agent additionally requires an existing protected
`/etc/tracebolt/action-client.json` grant before any action helper/network I/O.
Its separate foreground action loop is joined during shutdown and never changes
the existing read-only telemetry loop's authority.

Read [controlled-action-helper.md](controlled-action-helper.md) for the precise
local client grant, fixed helper socket, root peer verification, inherited socket
requirements, policy/target fingerprints, default-off helper and exclusive
`lan-agent --action-helper` runtime. The main agent remains unprivileged.

## Remaining operational enablement and acceptance gates

The source is not a request to perform these steps. They require a separate
explicitly authorized setup and native acceptance plan:

- Independently provision a distinct command signing key and root public pin
- Configure the named maintenance operator and the correct transport profile
- Review one simple service's complete relevant execution/effect/input scope;
  provision its disabled/enabled root policy and matching local client grant
- Initialize manager action schema and the exact current endpoint identity record,
  and initialize the separate root helper ledger without resetting existing floors
- Provision the root-owned action helper service and inherited socket with the
  documented nonroot agent UID/GID pins; no group/root grant to the main agent
- Verify native Unix writer credentials, protected paths and the actual supported
  systemd version; run the first real approved action only on a disposable target
- Check interruption, host/agent/helper restarts, ambiguous outcomes and service
  observation honestly before considering broader use

No installation or key-generation command is added here. The first operational
setup remains unavailable until those distinct gates have been implemented,
reviewed and explicitly authorized. Source tests and UI clicks cannot stand in
for this native acceptance.

## Verification contract

Tests use invented identities, temporary protected stores and fake executors;
no test invokes real `systemctl`. The end-to-end fixture covers both production
mTLS and explicit signed HTTP ingress, named operator preview/approval, immutable
permit delivery, one fake helper invocation, status-only recovery, durable result
and metadata-only operator readback. It also checks actor injection, read-only
accounts, CSRF, duplicate approval/claim/result and revoked enrollment.

Core/store regressions cover loss of used identity rows, original preview/permit
binding, signer deadline substitution, signed-but-canceled persistence, expiry
observations plus clock rollback, policy/profile changes without floor resets,
strict result lifecycle and helper expiry after a timely claim. API tests verify
that deadline-straddling responses use exactly the transaction's observed time,
and that obsolete unapproved previews cannot trap the UI after policy changes.

Native AF_UNIX tests remain explicitly skipped in this container where socket
creation is denied. Full aggregate checks, exact patch identity and any remaining
resource/time-budget failures are reported with the implementation handoff;
focused checks alone are not claimed as complete deployment acceptance.

The dedicated [service-action verification gates](service-action-verification.md)
require exact no-skip hosted Unix evidence and a new real Playwright action flow
with a fake executor. Their scoped results are separate from existing browser
coverage and from installed root/systemd acceptance.
