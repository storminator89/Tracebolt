# Same-identity Windows Read admin continuation

This is an unreleased **source candidate**, not an accepted recovery procedure
for a user endpoint. It adds a separate `--read-admin-recover` controller path.
Fresh Setup remains create-only. Historical receipt/consent bytes and ordinary
active-service startup semantics remain unchanged. Do not replace the staged
service executable or run a source-check build on a pilot to try this candidate.

## Exact admitted subset

Only current installer receipt 12 with the original acknowledged TLS twenty-one
read scopes, prepared complete staged service version 2, and phase
`claim-started` or `activation-started` is admitted. Sender/grant progress must be
empty. Automatic-renewal and HTTP-test profiles, historical receipts, existing
extension roots, interrupted grant writes and startup transitions are excluded.

The controller opens the existing installer store with creation disabled and
holds its exclusive, manifest-verified lease throughout. Canonical intent and
receipt must agree on the original installation, layout, executable and disabled
configuration. Exact-owned SCM inspection verifies the protected executable,
configuration and SID; the service must remain stopped and disabled.

The enrollment reader opens only the existing protected enrollment store. The
saved claim must already be confirmed and its pending-service marker valid. It
produces an opaque hash of the original bootstrap/claim/key/CSR binding, plus the
original pending deadline; it never prints the ledger or key. Recovery stops at
that original deadline **even for an already activated identity**. This stricter
recovery limit does not change ordinary active-service startup.

A receipt phase is not proof of claim confirmation. Missing claim acknowledgement,
missing/used state or expired authority fails before the first recovery write.
There is no invitation prompt, replacement identity, deadline extension,
enrollment-state reconstruction, deletion or security-software exception.

## Review and one attempt

For a separately approved native gate using a verified matching controller:

```powershell
& '<verified-controller.exe>' --read-admin-recover
& '<verified-controller.exe>' --read-admin-recover --apply --approve 'sha256:<exact-plan-digest>' --acknowledge-read-admin-recovery
```

The first command plans only. Fixed disclosures explain all original scopes and
recovery effects. JSON contains phase, original deadline, plan digest and
`review-required-one-attempt`. The digest binds exact intent/receipt bytes and
original claim/key binding/deadline. Replanning does not extend it. Apply
recomputes those bindings under the lease and requires exact approval plus the
separate acknowledgement. Flags do not replace actual host authorization.

Before any enrollment network call, apply durably records
`recovery-activation-started`. An uncertain write stops before network activity.
That phase is not admitted again: another invocation cannot retry the attempt,
even if no network result was received. There is no reset or refund.

The recovery-specific `ResumeServiceRecovery` adapter uses the existing protocol
with only the saved key/claim and original TLS bootstrap. It cannot request an
invitation or create an identity; bound-key status reconciliation remains intact.
Its context and every enrollment-store write/telemetry-initialization admission
are bounded by the original pending deadline, including already activated
identities. Sender initialization outside that store has its own immediate guard;
an end guard rejects late success even with all artifacts already present.
These guards do not recall an in-flight request or an already admitted native
write. Ordinary `ResumeService` and active-service startup retain their original
expiry behavior. After readiness and same-binding/
deadline readback, extension roots must still be absent. The original activated
sender is recorded before `grants-started`. The existing guarded create-only
twenty-scope extension coordinator then completes only the original read profile.
No action, executor or external-AI scope is enabled.

Exact grants, sender identity and original deadline are rechecked before the one
startup transition and before the one Start request. Durable
`startup-transition-started` precedes startup configuration; a complete configured
receipt precedes Start. Failure retains the last phase, including partial grant
evidence when it can be recorded. A late failure may leave an automatic or running
service and must not be described as no change. `configured-start-requested`
proves a request, not accepted observations, provider coverage or reboot persistence.

The provisional `--read-admin-recovery-status` snapshot does not check these
eligibility conditions. Its finite label is now `no-resume-authority`; it is not
a recovery approval token. Previously published binaries are unchanged.

## Native gate before pilot use or release

Record exact source/controller/service hashes and matching manager contract on
an explicitly approved disposable Windows machine. Keep protection enabled;
resolve execution-context policy through its administrator. A matching hash or
unsigned build does not establish trust or normal host execution.

1. Interrupt the matching fresh Setup after a confirmed claim. Retain original
   receipts, stopped/disabled service and absent scope roots. Independently check
   the same public identity and manager claim evidence.
2. Prove repeated plans leave installer/enrollment bytes, scopes and SCM unchanged
   and make no manager calls. Check exact TLS and the original pending deadline.
3. Approve one exact plan and the same identity at the manager. Confirm all 21
   original grants, advancing real observations and actual LocalService coverage/
   provider failures. Verify keys/claim were not replaced.
4. Interrupt at fence write, enrollment transport, grant boundaries, startup
   transition, configured write and Start. A second recovery must reject retained
   progress without repeating mutations. Preserve indeterminate outcomes.
5. Reject unconfirmed/expired/deadline-stopped claims; changed key/bootstrap,
   receipt/binary/SID; existing scopes; HTTP/renewal/historical profiles; stale
   approval; isolation-induced missing SCM; and changed installer leases.
6. Check cancellation, expiry during store Close, protected-file/handle-release failures, manager revocation,
   denied providers and unavailable manager without reset or replacement keys.
   Reboot persistence remains a separate native lifecycle gate.

Injected tests and cross-builds do not satisfy this gate. No packaged/native
recovery, user-host continuation, real provider acceptance or release is proved
by this increment. Expired or unconfirmed pilots remain blocked.
