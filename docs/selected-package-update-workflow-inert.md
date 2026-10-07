> Historical simulation foundation. The native source candidate and remaining gates
> are described in [selected-package-updates-native.md](selected-package-updates-native.md).

# Selected package update workflow: durable simulation candidate

Status: **held source candidate with a complete synthetic workflow, not native
APT execution**. Production reports `executionMode: unavailable` and cannot
prepare, approve or install packages. There is no native constructor, runtime
simulation flag, privileged runner, hook installer or host setup command.

## Concrete implementation

The Updates workspace now supports exact detected-package selection, preparation,
immutable review, explicit risk acknowledgment, approval and durable status/result
recovery. Real APIs and SQLite persistence are exercised end to end with an
in-process simulator. The UI labels every synthetic preparation and result as
simulation; no simulated install is represented as a real machine change.

Selection is limited to 32 sorted, unique name/architecture identities. Cached
candidate rows are selection hints only. Requests cannot provide commands,
options, archive paths, repository URLs or native evidence. The protected native
preparation adapter remains the next missing component.

The existing `packageplan` contract still binds exact old/new versions, source
package/version mapping, source identity, signed Release/index/archive digests,
archive size, clean dpkg/hold claims, reviewed hook policy and original evidence
age. Its 128 KiB limit remains distinct from the unchanged 4 KiB service permit.
No service-action transport or helper schema was widened.

A preview additionally binds endpoint/incarnation/manager/local policy/transport,
preparing operator, conffile policy and human-readable source label/suite/component
under its own digest. The retained preview remains available with historical jobs
so result cardinality and each expected version can be compared to approval.
The simulation generates explicitly synthetic evidence and timestamps. It never
relabels a real cached inventory row as authenticated preparation.

## Durable storage and transaction boundary

`internal/packageupdatestore` provides a real protected SQLite adapter for one
exact binding. Explicit `Create` and `OpenExisting` are separate source-level
APIs, used only by fixtures here. Production startup never initializes this state.
Existing files are never adopted, chmodded, migrated or reinitialized.

The direct directory must be private (0700), files private (0600), the ancestor
chain trusted, and paths free of symlinks/hardlinks. Linux holds an exclusive file
lock for the handle lifetime; other platforms fail closed. Schema, binding,
canonical bytes, file identity and record digest are verified. SQLite uses a
bounded database, DELETE journaling and synchronous FULL.

A CAS accepts only the expected revision and an independently valid successor:
exact prior intent/preview/approval/claim/result prefixes, monotonic clock and
revision floors, no revocation removal and no history pruning. New jobs follow a
previously persisted terminal state; expiration is observed and committed first.
The source-stage record cap remains eight jobs with no reset/prune operation.
Production retention and externally anchored rollback protection remain pending.

A durable active-session guard is set before a writable handle is returned. Only
a clean Close after entirely known-success writes clears it. Any process crash,
ambiguous commit, path/integrity change or poisoned handle leaves reopening fenced.
Even a crash after a successful commit is conservatively fenced. This proves
fail-closed crash behavior, not automated recovery or continued availability.
There is no recovery, reset, backup-adoption or reconciliation API. A complete
older database backup cannot be recognized without an external trusted floor.

## Manager, dispatcher and result semantics

The zero-value `packageupdate.Manager` stays unavailable. `NewSimulation` is the
only nonzero constructor and accepts synthetic fixture data plus the durable
store. It creates a fixed in-process simulator internally. It cannot accept a
native runner, subprocess command or evidence adapter from configuration.

Preparation saves intent before describing the synthetic plan. Exact retries
recover the existing request and never refresh its evidence or expiry. Approval
compares request ID, preview digest, original actor and freshness. It saves no new
approval on retry and never interprets approval as successful execution.

The explicit `StartPendingSimulation` dispatcher is called only by tests. It
commits a first claim before calling the simulator. An ambiguous claim write does
not call Start. Repeated dispatch of a claimed ID does not restart it. The typed
Runner start/status interface is a future boundary, not execution authority.

Simulation observations progress applying → verifying → succeeded, or to
needs_intervention. Each append-only observation binds the exact requested package
set and expected versions. Success requires every observed version to equal the
approved target and the synthetic dpkg state to be clean. A simulated mismatch,
missing runner or unverified outcome blocks a new job. Reopening a manager never
automatically starts an approved or claimed job; if its in-process runner was
lost, status becomes needs_intervention rather than fabricated completion/retry.

Expiry limits claim/start, not an already-claimed operation's lifetime. Revocation
blocks future starts and never kills a claimed operation or fabricates canceled
status. There is no cancel, rollback, repair, automatic retry or reboot endpoint.
Reboot evidence is required/not_reported/unknown with source and original time;
not_reported is not a claim that no reboot is needed.

## API and UI boundaries

All routes retain the authenticated operator/Origin/CSRF/session boundaries:

- GET `/api/devices/{id}/package-updates`: latest saved workflow view
- GET `.../jobs/{requestId}`: exact saved request recovery/history
- POST `.../prepare`: current named `plan_updates` grant; typed selection only
- POST `.../approve`: current named `execute_updates` grant; ID/digest only

The two grants are independent. The authenticated actor comes from server state,
not the body. Request body/device reads happen outside the session mutation lease;
capability is rechecked at the final short transaction boundary. Logout can finish
while a client body is stalled. Shared sessions cannot mutate.

The production operator handler has no public constructor/configuration field for
a simulation manager. Private fixture injection exercises the complete API with
real SQLite. Valid production mutation requests remain unavailable. The private
fixture dispatcher is never started by an API request or production process.

The client strictly validates device, schema, mode, state, timing, immutable
preview and exact result rows. Selection changes are scoped to device/source/access.
Approval requires the original actor, execute permission, unexpired evidence and
risk acknowledgment. Lost responses retain the original request ID and recover its
exact saved status; no automatic POST replay or replacement operation occurs.
Bounded session intent contains ID/selection or approval digest, never full preview,
provenance or authentication secrets; it is cleared on access/context changes.

Package scripts and triggers can restart services or change broad system state.
The conffile policy concerns modified dpkg conffiles, not ucf/custom scripts. Native
repository authentication will establish provenance, not harmless behavior. The
future package guard is not a sandbox; no rollback guarantee is made.

## Next implementation stages and native gate

1. Implement protected native preparation: explicitly approved sources/trust,
   complete authenticated refresh, exact solver result, verified archive staging,
   clean/hold checks and mandatory guard configuration. Start the short preview
   lifetime after this preparation. No cached-report conversion is sufficient.
2. Implement signed package-specific dispatch/status transport, identity/setup
   fences, an externally retained replay floor and a shared durable endpoint
   mutation fence used by service and package actions. Define safe reconciliation
   for the conservative SQLite crash fence before enabling live use.
3. Implement a fixed independently surviving runner with durable admission and
   launch records, actual native locks, current-policy checks, archive/path/FD
   TOCTOU protection, mandatory v3 guard and post-install/dpkg verification. HTTP,
   agent or broker cancellation must not terminate applying dpkg.
4. Obtain separate approval for a disposable Debian 13 native gate, then an
   independent Ubuntu 24.04 gate. Cover exact versions/origins, malformed/stale/
   replayed authority, drift/holds/dirty dpkg, unknown hooks, archive replacement,
   locks, storage faults, script failures, lost responses/restarts, and observed
   service/conffile/reboot effects. Source fixtures do not grant that approval.
5. Only after those gates wire a reviewed native constructor into the manager and
   version the UI contract to accept real execution evidence. No flag flip may
   relabel simulation as native readiness.

Tests use temporary SQLite files, synthetic plans and the test process itself for
crash checks. They perform no APT/dpkg/systemd operation, repository access,
privilege grant, hook installation or user-host mutation.
