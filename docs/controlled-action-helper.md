# Controlled service-action helper library

Status: source implementation and synthetic fixtures only. Base:
`04b83fe60ba5637583ac901a1ef698a7d8b7b70f` (2026-10-05).

This extends the [permit/consumption foundation](controlled-action-core.md) with
`internal/actionhelper` and an independently reviewed durable attempt lifecycle.
The initial standalone slice was unwired. The later source workflow now adds
explicit CLI/agent/manager/UI wiring as described at the end of this document;
there is still no host setup command or native deployment acceptance.
No actual service restart, privileged setup, key provisioning, root account,
group, socket or unit change was performed to implement or test it.

## Narrow contract

The only action is `service.try-restart` for one explicitly allowlisted canonical
`.service` name. The production adapter invokes a fixed `/usr/bin/systemctl`,
without a shell, PATH lookup, caller arguments or inherited environment:

```
/usr/bin/systemctl --system --no-ask-password --no-pager --job-mode=fail try-restart -- UNIT.service
```

The unit argument comes from the strictly decoded signed permit and exact local
allowlist. Paths, options, templates, instances, escaped names and glob patterns
are unsupported. `try-restart` leaves a nonrunning unit unstarted. An inactive,
failed or transitional preflight target gets `not_started`; if it becomes inactive
at systemd submission, systemd may complete the operation as a no-op. Accordingly
`operation_completed` means only that the fixed synchronous systemctl operation
exited zero. It does not assert that a restart occurred or that the application
is healthy. The subsequent active/inactive/failed/unknown observation is separate.

The adapter always uses `--job-mode=fail`, never replace, isolate,
ignore-dependencies, reload, start, enable, daemon-reload or arbitrary commands.
The environment is exactly `LANG=C`, `LC_ALL=C`, `SYSTEMD_COLORS=0`, with working
directory `/`. Output is bounded and never returned or persisted as diagnostics.
Any nonzero exit, client error or 30-second observation timeout after invocation
is `needs_intervention`. The systemd job may continue after its systemctl client
is killed or lost; no cancellation, retry, repair or success is inferred.

## Root-local authority

The Linux `Run` library entry point requires real/effective/saved UID
and GID all equal to zero. It reads only these already provisioned locations:

- `/etc/tracebolt/action-helper.json`: canonical root policy, at most 64 KiB
- `/etc/tracebolt/action-command.pub`: separately provisioned raw 32-byte Ed25519
  public command key, never an enrollment issuer or a request-selected key
- `/var/lib/tracebolt-action-helper`: existing dedicated action ledger
- One inherited listening AF_UNIX stream descriptor at FD 3, named
  `action-helper`, at `/run/tracebolt-action-helper/action.sock`

Nothing creates or repairs these resources. Missing state is a hard stop. Files
must be root-owned single-link regular files with exact mode 0600. Directory
walks use anchored no-follow descriptors, root ownership and no group/other
writes; every ancestor and both policy/key files are rechecked for replacement
or metadata/content changes. The authority revision includes protected object
identity. Agent UID/GID are explicit nonroot numeric pins. Kernel SO_PEERCRED must
match both and contain a valid PID. Socket metadata must be root-owned, group
AgentGID, mode 0660, single-link; descriptor type, listening state, path and systemd
activation environment are verified. No listener is created, chmodded or unlinked.

A local peer alone cannot authorize an action. Every submission carries the
unchanged strict `tracebolt.execution-permit.v1` envelope. The manager signature
binds manager/key, endpoint/incarnation, job/sequence, exact plan, named operator,
approval digest, root policy and original exclusive start deadline. The signer
remains trusted to derive operator authority and approval from server state.
The helper does not independently prove human approval or protect against a
compromised command signer.

## Default-off production and disposable HTTP policy

`Policy.Enabled` defaults false. The complete canonical policy is hashed into
the signed `RootPolicyDigest`, including `transportProfile` and the explicit
`httpTestAcknowledged` boolean. This transitively binds profile without changing
the permit schema. `production-tls` rejects the HTTP acknowledgement;
`disposable-http-test` requires it. Unknown profiles fail closed.

The disposable acknowledgement means that anyone stealing the unencrypted
operator session may authorize actions within this enabled test scope. It is an
explicit local-machine grant, never a production fallback or an implicit result
of upgrading the manager. There is no second console ceremony for each signed
job inside that scope. No such local grant was created here.

The same manager/key/endpoint-incarnation ledger and sequence/clock floors are
retained across policy, allowlist and transport-profile changes. New policy
cannot reset replay history. Revocation is checked live before future invocation.
Policy expansion/enablement requires helper restart to refresh its verifier
snapshot, retaining the existing ledger. Changed manager/key/incarnation is
rejected; rotation and enrollment migration are not implemented.

This local library cannot establish how the browser reached the manager.
Verified browser-to-manager and agent-to-manager TLS, profile-aware manager
admission, and the signing/job/API/UI integration are still separate gates.
There is no HTTP/TLS transport code, insecure TLS option or production TLS bypass here.

## Local service review and fingerprints

This first profile deliberately supports only a simple service reviewed by a
local administrator. Each target manifest includes:

- A review-record digest and the target's exact canonical name
- Up to 16 sorted unique canonical `.service` entries in the reviewed effect scope
- A SHA-256 fingerprint of fixed loaded identity/configuration/relationship
  properties for each entry
- Up to 32 sorted unique persistent input paths and content hashes, including
  `/usr/bin/systemctl`, every observed fragment/drop-in and all execution inputs
  identified by the local review

The manifest's canonical hash is the permit's `UnitPolicyDigest`. Files must be
root-owned, no-follow, single-link regular files, at most 32 MiB each, and neither
group/other writable nor set-ID. Supported input roots are `/etc`, `/usr` and
`/opt`; symlinks and noncanonical/whitespace paths are unsupported. No hashes or
files are inferred from the request beyond matching the already approved plan.

Fixed `systemctl show --all --property=...` reads stable loaded identity,
fragment/drop-in, service Type/User/Group and relationship properties. All keys
must be present once; unknown, repeated, truncated or oversized output fails.
Empty property values are retained. Volatile Exec timestamps, PIDs and status
fields are excluded. Require loaded, non-transient, no pending daemon reload,
exact Id and a sole matching Names entry. Rejecting all aliases is a conservative
initial support limit, not a general systemd safety requirement. Unsupported
systemd property sets fail closed until separately reviewed.

Tracebolt, SSH, systemd infrastructure, D-Bus and common network/VPN/firewall
names are conservatively denied in target and reviewed effect entries. This
supplements administrator review; it is not a universal connectivity classifier.
Review completeness, script behavior and the full relevant input/effect scope
are explicit administrator assertions. Fingerprints detect deviations from that
review; they do not prove its correctness or analyze arbitrary shell scripts.
There is no generic dependency safety analyzer, filesystem freeze or atomic
systemd-configuration lock. Root administrators remain trusted. A target whose
safety depends on unreviewed mutable inputs is outside this profile.

## Durable lifecycle and concurrency

The existing store's protected files, exclusive lifetime lock, file fsync,
atomic rename and directory fsync remain unchanged. New `State.Begin` yields a
private in-memory `Attempt` only after fresh durable admission. Duplicates,
legacy `Admit` records, status reads, failures and reopening never yield one.
Attempt copies share single-use transition state. IPC cannot supply completions,
policy, backend selection or lifecycle edits.

One mutation slot exists per helper. Extra new work is rejected as busy rather
than queued; exact duplicates return their original durable status. At most four
connections are admitted, with bounded framing and read/write deadlines.

1. Consume the signed job and sequence durably as `admitted`.
2. Recheck live authority, original deadline and the durable clock floor; verify
   reviewed unit/configuration/input pins and current active state.
3. Durably mark `dispatching`. Resample time and repeat concrete preflight, then
   recheck the current protected authority, exact signed permit and latest clock
   high-water immediately before the one backend invocation.
4. Persist `operation_completed` with a separate bounded observed state, or
   `needs_intervention` for every ambiguous invoked outcome.

Before invocation, this live process may durably record `not_started` with
canceled, expired, policy_changed, preflight or inactive reason. This includes
failure of the last check after the dispatch marker. The consumed sequence is
never returned. A crash in that gap is unknown, not proof of non-execution.

Caller cancellation before invocation records `not_started` where possible.
After invocation, network disconnect and caller/server-context cancellation do
not cancel systemd's job: the helper waits independently for the bounded client
outcome and retains it. There is no cancel-job IPC in this slice. Process death
or observation timeout leaves uncertainty. Shutdown waits for synchronous
handlers; it never abandons a goroutine to claim the slot is free.

Any reopened `admitted` or `dispatching` record becomes `needs_intervention` and
blocks all later new jobs. An uncertain write poisons the live store. Result
write failure does not convert an operation into success; status/recovery remains
conservative. There is no reconciliation, automatic replay, pruning or reset API.
Completed and definitely-not-started jobs allow a later greater sequence.

Ledger v1 history is read losslessly. Only a fresh runner admission writes the
same ledger as v2 with bounded lifecycle metadata. Existing envelopes, original
consumption times, sequence and clock floor stay intact; migration never yields
an attempt for old work. Clock reversal is checked against the most recent
transition, including after dispatch durability. A start deadline never kills an
already submitted operation. At most 64 jobs are retained; exhaustion fails closed.

## Verification and remaining gates

All backend calls in tests are fakes. The actual systemctl adapter is compiled
but never invoked. Policy/input/state fixtures use ordinary-user temporary files;
framing, disconnect and concurrency fixtures use in-memory net.Pipe connections.
Native AF_UNIX peer/listener fixtures explicitly skip only when the environment
returns EPERM/EACCES for socket creation. This container returned EPERM even via
the reviewed execution route, so those native checks have not passed here.

Focused Linux commands, Go 1.27.1:

```
go test -race -count=1 ./internal/actionpermit ./internal/actionstate ./internal/actionhelper
go vet ./internal/actionpermit ./internal/actionstate ./internal/actionhelper
go test ./internal/actionhelper -run '^$' -fuzz '^FuzzRequestFrame$' -fuzztime=10s -parallel=2
```

Fixtures cover signature/binding rejection, profile policy changes without floor
reset, duplicates, copied/concurrent attempts, crash boundaries, lossless migration,
before/after durable faults, cancellation, expiry during fsync, clock reversal,
revocation before dispatch, separate observation/result semantics, protected-file
replacement/modes/links, alias/input/dependency drift and strict bounded IPC.

Still required: actual Unix peer/listener tests on a permitted environment;
independent native systemd/version/service review and disposable-VM acceptance;
separately authorized key/state/socket/unit provisioning; and complete native
acceptance of the separately wired manager/agent/API/UI workflow.
APT planning/execution, cancellation/reconciliation and fleet scheduling remain
outside this slice. Source, fixture and cross-build checks do not establish any
real machine was installed, restarted or safely accepted.

Primary systemd references:
- [try-restart, show --all, and job-mode semantics](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemctl.xml)
- [systemctl mapping to TryRestartUnit and synchronous job waiting](https://raw.githubusercontent.com/systemd/systemd/v257/src/systemctl/systemctl-start-unit.c)

## Later source wiring: explicit helper mode and agent client

The separately reviewed service-action workflow now wires this library into
`lan-agent --action-helper`. The mode is exclusive: any extra arguments reject
before normal agent state access. It still requires root identity, preprovided
root policy/public key, existing ledger and exactly one inherited protected
socket. It never creates accounts, grants, state, sockets or units. No running
host was enabled by these source changes.

Peer-authenticated read-only `capabilities` IPC projects bounded manager/key/
endpoint/incarnation/profile/root-policy bindings, enabled grant, original
CapturedAt time, local maximum permit lifetime and up to 16 unit/policy hashes.
It exposes no public-key bytes, file paths or input manifests. The 8 KiB response
bound covers the maximum service list. Capabilities are metadata, not permission
or a systemd/application-health probe; no systemctl call occurs for that operation.
The manager must check the original capture age and current enrollment, rather
than treating a re-signed HTTP retry as fresh source data.

The unprivileged `actionclient` uses only the fixed protected socket. It validates
root socket metadata and peer identity, then authenticates every response data
chunk with root UID/GID and stable writer PID via SCM_CREDENTIALS. SO_PEERCRED
alone would identify the creator of a systemd-owned listener, not necessarily its
response writer. Passed descriptors, truncated control messages, extra bytes,
missing EOF and malformed/mismatched result identities reject. Any failure once
a Submit write starts is uncertain; the client never retries submission.

The ordinary complete-profile foreground agent remains read-only by default.
A separately provisioned root-owned 0640 agent-group file,
`/etc/tracebolt/action-client.json`, opts this exact existing sender into the
controlled-action path. The canonical v1 client grant binds enabled state, sender
binding, manager origin/ID, endpoint, current leaf-certificate SHA-256 incarnation,
command-key ID, exact root-policy digest, production/test profile and numeric
agent UID/GID. HTTP requires its explicit acknowledgement and the existing HTTP
agent acknowledgement. No runtime or consent command writes this grant.

Absent or disabled grant produces no action helper/network I/O. Invalid grant
fails closed. A root policy update requires corresponding local scope review;
permissions are never inherited from a manager upgrade or a changed display name.

After all existing complete-profile sender ledgers are validated and the normal
exclusive sender lock is held, foreground mode starts exactly one separate,
joined action loop. It is outside the read-only agentloop Attempt callback and
never changes telemetry envelopes. Each poll is bounded to 45 seconds and then
waits 15 seconds; no action queue or catch-up burst accumulates. Foreground exit
cancels and joins it before releasing ownership. One-shot reporting does not poll
for actions.

New execution requires a current matching helper projection, capability report,
manager peek and one durable manager claim. The agent rechecks its root-local
grant and loaded certificate/configuration binding and expiry before claim and
immediately before its sole helper Submit. Manager claim transactions independently
check current remote endpoint authorization. An issued short-lived signed permit
is not retroactively canceled by operator logout or manager-side revocation;
live local grant/policy revocation remains the pre-submit control.
It matches the exact manager/key/endpoint/incarnation, policy, plan, job/sequence/
envelope digest and original start deadline. The root helper independently
verifies the signature, local policy, replay state and live target checks.

Once the manager says a job is claimed, only status recovery is allowed. Neither
process restart, a lost claim response nor a lost helper response recreates a
submission. If the claim was committed but its envelope never reached the agent,
the outcome remains unknown; it is not automatically replayed. The root helper's
exact durable result may be reported repeatedly without another service action.
A disabled/stale/changed current action-policy projection blocks new execution
but does not strand historical status for a claimed job while the local client
grant remains enabled. Disabling the client grant itself stops both execution
and status I/O.

HTTP-test action requests have their own signed domain, paths and headers, and
remain unencrypted with an unauthenticated server. TLS requests use the existing
verified TLS transport and reject HTTP-test proof fallback. Full manager-side
jobs, approval/capability gates and UI are described in
[the workflow document](service-action-workflow.md). Native socket/systemd and
separately authorized host setup acceptance remain outstanding.

Helper capability readiness is tied to the actual State verifier snapshot, not
merely whichever root policy was loaded most recently. A policy change between
State.Open and helper construction rejects startup; a later changed enable/profile/
scope digest makes capabilities unavailable until the same ledger is reopened
with the new policy. Historical Status remains independent and never resets its
sequence floor. This prevents advertising an enabled grant that the live verifier
cannot actually admit.
