# Selected Windows service actions: manager source candidate

This is a default-off source candidate. No native host, persistent grant, key,
service account, ACL, service installation or actual start/stop/restart was created
by its source tests. Native acceptance and setup require separate explicit approval.

## Separate authority

The Windows domain uses its own command key, signature domain, enrollment marker,
job table and `/v1/windows-service-actions/{capabilities,peek,claim,result}` ingress.
It admits only currently activated Windows inventory identities through the
Windows authority check. Linux `restart_service`, Linux action envelopes and
inventory collection grants cannot authorize it. Operators need the explicit
`windows_service_control` capability on an already configured named account.
Shared accounts and the synthetic development manager cannot approve actions.

The local broker exposes exactly one reviewed target and immutable installation,
grant, configuration and endpoint-incarnation binding. That availability report
is only a hint; the restricted local broker independently verifies the signed
operation, local grant, protected state and target before any native request.
Reported results are agent-reported, without a helper-signed attestation.

## Explicit source setup

The protected LAN configuration optionally names
`windowsServiceActionsConfigFile`. It requires `windowsInventoryEnabled` and
existing guided Windows enrollment. Omission leaves service actions disabled.
The separate protected manager configuration has these exact fields:

```json
{
  "version": "tracebolt.windows-service-actions-config.v1",
  "enabled": true,
  "managerId": "manager_<existing instance>",
  "transportProfile": "production-tls",
  "httpTestAcknowledged": false,
  "privateKeyFile": "/absolute/protected/windows-command.key"
}
```

The preprovided key is raw 64-byte Ed25519 private material. It must differ from
configured Linux service/package-action, issuer, root and TLS keys. Setup does not generate
keys, change operator permissions, rewrite configuration or grant an endpoint.
The local endpoint setup and the supplied public Binding must agree exactly.

The source-only `windows-action-manager-setup` executable provides an explicit
read-only existing-database plan when invoked with `--lan-config`,
`--enrollment-config` and `--binding-file`. The binding file is protected canonical
JSON in `windowsaction.Binding` field order, with no trailing bytes. The plan
includes the exact public binding, plan digest and every currently configured named
operator with Windows service control permission. It checks the existing Windows
identity, certificate incarnation, public command pin and absence of any existing
manager action domain. It does not create or recover SQLite files during planning.

The plan digest also binds the operator list and transport, so a changed plan needs
a new explicit approval.

After separate review, the same executable accepts `--apply`,
`--approve-plan <exact public plan digest>` and
`--ack-windows-service-control`. Disposable HTTP additionally requires
`--ack-http-action-risk`, matching both configured HTTP acknowledgements. A stolen
plaintext operator session can authorize control inside this narrowly granted
scope. Production retains verified TLS/mTLS; there is no TLS fallback.

Apply atomically creates the Windows action key metadata, first exact identity
record and immutable credential marker. It refuses an existing domain, including
an exact prior setup, and cannot repair missing used rows or tables. Ordinary
manager startup only opens and validates already initialized action state.
Keep the state and its used marker; never reset or downgrade it to re-enable a job.
This first-target path does not support adding more endpoints, changing targets,
key rotation or reusing an old incarnation. Those require a separately reviewed
migration rather than another initialization.

## Operator workflow and durable recovery

The Services view displays a separate eligible target from broker authority.
Select it, choose start, stop or restart, review the exact preview and explicitly
acknowledge interruption before approval. A read does not revive a saved preview.
Dismissal, device/session changes, history navigation, focus loss, expiry and
repeated clicks cannot approve an old selection. A lost approval response requires
a status read; the UI never automatically creates or approves a replacement job.

Operator API:

- GET `/api/devices/{id}/windows-service-actions`: metadata-only current view
- POST `.../preview`: exact `{ "target": "ReviewedService", "operation": "start" }`
- POST `.../approve`: only the returned `previewId` and `previewDigest`

Stop and restart use the same preview operation field. Actor identity always comes
from the named session; the existing short authorization lease, Origin and CSRF
checks remain in force. The stored preview expires after 60 seconds. Approval
atomically persists it and one exact signed envelope, with an original 60-second
start deadline bounded by current enrollment authority. Repeated exact approval
returns the saved job and does not sign again, advance sequence or renew expiry.
Neither operator views nor agent peek responses contain execution envelopes.

The agent's first successful claim transaction consumes delivery before returning
the saved envelope. A repeated claim never returns it. An interrupted claim or
submit can only recover broker status under the original identity. Manager and
broker histories independently retain monotonic floors and original deadlines.
Observed stale or expired authority cannot revive after a manager clock rollback.
Missing used state hard-stops. Restoring an entire older backup is not transparent
live recovery and is outside this candidate's rollback-resistance guarantees.

At most 64 jobs are retained, without pruning/reset APIs. Results preserve separate
attempted, native-request-accepted and target-state-observed flags for stop and
start. Running/stopped observations do not establish application health. Claimed
jobs with missing results remain unconfirmed. A provisional dispatching outcome
can advance monotonically to a definitive terminal result; terminal intervention
cannot be cleared and blocks all subsequent jobs.

## Source evidence boundary

Focused Go tests exercise exact approval, three operations, one-time claims,
protected optional-byte compatibility, missing-used state, signer substitution,
clock rollback, independent capability/actor/Origin/CSRF guards and read-only setup.
Real local TLS and purpose-signed HTTP fixtures pass the manager envelope through
the actual broker with an inert native backend, then read durable results.
Frontend tests cover all three operations, double clicks, interruption, stale
responses, lost approval and status-only recovery. These are source/runtime
fixtures, not actual Windows SCM, pipe, ACL or installed-service acceptance.
