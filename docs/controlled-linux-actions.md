# Controlled Linux actions

Status: reviewed architecture with a default-off service-only source integration
candidate. The [root-helper runtime](controlled-action-helper.md) and
[durable manager/agent/UI workflow](service-action-workflow.md) are now connected.
No real deployment, host provisioning or native service execution is claimed.
Original design baseline: `4def163cf9d879f3b91360de41754d8aa299b639` (2026-10-05).

## Current source foundation and remaining acceptance

The inert `internal/actionpermit` / `internal/actionstate` foundation is
[documented here](controlled-action-core.md). Optional
[named-operator authentication](named-operator-auth.md) supplies protected static
actor/capability configuration and a current-session admission lease. The narrow
workflow connects that lease to an immutable service preview, explicit approval,
separately provisioned command signer, durable history, first-claim-only agent
delivery and independent helper dispatch/result state. The UI reports unavailable
until the required separately configured local helper/client grants and existing
state are present. HTTP test authority is bound transitively by the signed root
policy digest; there is no separate replay domain or production TLS fallback.

Host key/state/policy/socket/unit provisioning, actual Unix writer-credential
acceptance and a disposable real systemd service test remain separate gates.
Package actions, reconciliation and fleet scheduling below remain design work;
this service-only implementation does not claim those capabilities.

## Decision and first deliverable

Add a default-off, authenticated Linux action path. The first usable action is
an explicit restart of one running, locally allowlisted systemd service. Selected APT
package updates follow through the same approval and result flow. Test doubles
are test fixtures only; they are not a user-facing installation feature.

The existing agent remains unprivileged. Its journal reader remains a separate,
non-root, read-only helper. A new local action helper owns privileged execution.
There is no arbitrary remote command, shell, script, path, or APT-option API.
This does not claim that package maintainer scripts are sandboxed or shell-free.

Scope excludes unattended updates, fleet rollout scheduling, generic IAM,
automatic reboot, release upgrades, package removal, remote unit editing and
automatic repair of a broken package database. No certification is claimed.

## Existing implementation seams

- `internal/api/operator.go` and `internal/operatorauth/auth.go`: sessions,
  origin/CSRF checks, expiry and short mutation admission. Current auth has one
  password verifier and session IDs in legacy mode. Optional static v2 configuration
  adds named actors and explicit maintenance grants; the service workflow uses only
  its exact typed preview/approval routes.
- `internal/journalrequest`, `internal/enrollmentstore/journal_storage.go`,
  `internal/journalstate`, `internal/lanclient/journal.go`: bounded typed work,
  endpoint binding, CAS/sequence floors and consumption before execution.
  Reuse patterns; do not repurpose their log schema or memory-only results.
- `internal/journalhelper`: fixed Unix IPC, peer credentials and protected local
  policy patterns. Do not elevate this existing helper or give the agent its
  journal group or unrestricted sudo.
- `internal/lanclient/transport.go`: verified TLS transport. HTTP-test agent
  signatures do not authenticate manager replies or provide confidentiality.
- `internal/cachedupdates` and `internal/linuxcve`: candidate observations and
  advisory comparison, not an update installer or authoritative execution plan.

Keep new action contract, durable store, transport adapter and Linux helper
small and separate. Preserve existing read-only profiles and compatibility.

## Authorization and local opt-in

### Named operator, narrow capabilities

Use a protected local operator configuration with stable operator ID, username,
password verifier and explicit capabilities: read, package planning, package
execution and service restart. Reuse the existing password/session protections.
No enterprise identity system is required for this first version.

Derive actor and capabilities from authenticated server-side state. A supplied
actor name, role, request digest or UI checkbox is never identity proof. Existing
shared-login configuration receives no new action permission automatically.
Provisioning new credentials and migration remain explicit administration steps.
The implemented static v2 mode applies account removal or grant changes only after
a manager restart, invalidating all in-memory sessions. Existing v1 administration
remains unchanged; named read/query access is documented separately and does not
implicitly grant legacy administration.

Every mutation requires a current authorized operator and explicit approval of
one immutable, expiring plan. Approval binds endpoint, action, exact parameters,
plan digest and current local policy revision. A changed plan needs new approval.
The current actor and permission must be rechecked before execution dispatch.

### Production transport and the disposable test exception

Production actions remain default-off and require authenticated encrypted
browser-to-manager and agent-to-manager transport. There is no silent fallback
from production to HTTP-test.

For the explicitly requested disposable test, plain HTTP is permitted without
mandatory certificate setup or a second local confirmation for each job. A
fixture end-to-end test uses an injected fake executor and grants no privileges.
A later real disposable-machine test requires one explicit local-machine opt-in
pinning manager, endpoint, the HTTP-test transport profile and a narrow fixed
service/package scope. Prefer one harmless locally reviewed test service first.

Show the limitation plainly: anyone who steals the unencrypted HTTP operator
session may authorize actions within that enabled test scope. Manager-signed
jobs prevent forgery without the signing authority but do not repair browser
transport security or make HTTP production-safe. Bind transport profile through the complete signed RootPolicyDigest and
root policy; production must reject test-policy permits and grants while retaining the
shared consumption history. Permission to test over HTTP does not authorize installation
of a helper, signing keys or privileges on any host.

Recommended execution boundary: a manager-signed, domain-separated permit
checked by the helper against a root-pinned public command key. It contains the
schema/domain, manager key ID, immutable endpoint incarnation,
job/execution ID, dedicated action sequence, canonical plan bytes/hash, authenticated approval
actor, root-policy digest, issued-at/not-before and start deadline. The transport
profile is committed transitively through that signed root-policy digest. The helper
enforces a local maximum validity and rejects clock reversal or future validity
beyond its allowed skew. Production requires TLS. Do not reuse the
enrollment issuer CA as a command-signing key.

This makes access to the agent's local socket insufficient to manufacture an
operator-approved root action. The manager signer is still trusted to enforce
operator authorization; this is not protection against a compromised manager.
The command key is preprovided through separately approved setup. Tests use
isolated fixture keys, never production enrollment or signing material.

The root-owned local policy opts this machine into the exact manager, endpoint,
actions and service allowlist. The helper independently checks policy, Unix peer
credentials and permit, then durably consumes the dedicated sequence before an
execution attempt. Unknown fields, schema versions, changed binding, expired or
replayed permits fail closed. Retain the sequence floor across restarts and
terminal jobs; resetting a database must not silently reset endpoint authority.

Installing the helper or creating credentials, trust, accounts, groups, sockets
or persistent privileges requires a separate administrator decision. A manager
upgrade or UI approval alone cannot enable the machine.

## Durable job lifecycle

User flow: request plan, review exact effects, approve, observe status/result.
An approved job is immutable. Use one active mutation per endpoint for the MVP.
The guarantee is at-most-once admission, not exactly-once execution or effects.
An admitted job may never start if a crash loses the in-memory execution permit.

Persist job, approval, dispatch, execution admission and result metadata on the
manager and in root-protected helper storage. APT runs in a separate fixed,
root-owned job-runner unit outside the agent/helper lifetimes and cgroups. The
broker can start only that reviewed runner with an internally derived job ID;
the runner reads and validates its root-owned persisted admission. This is not a
remote transient-unit or arbitrary command API. Do not automatically restart an
interrupted runner process. A browser disconnect, logout, agent/manager restart
or helper restart must not terminate dpkg. Do not copy the current agent unit's
control-group lifetime or use generic Go CommandContext cancellation for APT.
Runner stop/recovery and its systemd timeout behavior need explicit native tests.
An administrator deliberately stopping the runner or powering off the host
remains an interruption, not a guaranteed recoverable successful transaction.

- A duplicate job ID with the same digest returns status, never another launch.
  Reusing an ID with changed bytes fails.
- Commit execution admission before spawn. A crash between those operations is
  ambiguous and must not automatically execute the job again.
- An uncertain durable write blocks further admission until reviewed/reconciled;
  it must not be reported as a committed execution or repaired by resetting the
  sequence floor. Admission alone is never proof of running or success.
- Undispatched jobs can be canceled immediately. Dispatched cancellation is a
  request until the helper confirms a stop before mutation. Once mutation starts,
  cancellation must not kill dpkg. Never display canceled merely because the
  browser stopped waiting.
- Expiry limits admission/start; it is not a timer that kills an admitted dpkg
  process. Recheck live local policy before starting and after waiting for locks.
- On helper crash or machine reboot, reconcile durable metadata and actual
  package/service state. Uncertain outcomes remain interrupted or
  needs-intervention; no automatic retry, repair, rollback or fabricated success.
- Policy disable/revocation blocks future starts. It does not forcibly terminate
  an already-mutating package operation.

Show structured phases and original timestamps: preparing, waiting for lock,
downloading, applying, verifying and terminal result. A missing connection is
unknown communication state, not proof that execution stopped. Preserve partial
package results and a distinct needs-intervention result.

## First real action: service restart

Allow one canonical, locally allowlisted `.service` unit per job. The first
operation is explicitly "restart running service", implemented with
TryRestartUnit/try-restart rather than restart's implicit start of an inactive
service. Inactive/failed targets are ineligible or become a reported no-op if
state changed; starting them is a separate future action.

Verify loaded unit identity, configuration and relevant execution inputs are
not writable by the agent. Reject aliases, arbitrary paths/options and
unsupported transient units. Root policy must pin a reviewed effective unit
and relevant dependency graph, and runtime must reject changed or unknown
transitive stop/restart effects. A name denylist alone cannot establish that
Tracebolt or connectivity-critical services will remain unaffected. Initially
admit only units whose supported systemd dependency semantics demonstrate that
the restart has no such propagation; test this on the supported systemd versions.

Use one fixed systemd operation with typed arguments and no request-controlled
command construction. Do not permit unit editing, enable/disable, daemon-reload,
arbitrary process termination or changes to service credentials. Preview the
exact machine/unit and interruption before approval.

Record the operation result and subsequent observed unit state separately.
Active is not a general application-health test. Restart is not naturally
idempotent: retries must query the same job, never restart again after uncertainty.

Ordinary service diagnostics continue through read-only collectors and the
separately authorized journal reader. Do not introduce a root shell to improve
diagnostic coverage.

## APT execution contract

Initial support is intentionally conservative: selected already-installed
packages on Debian 13 and Ubuntu 24.04, subject to native acceptance. Reject new
dependencies, removals, downgrades, held-package changes and release upgrades.
Kernel updates requiring new ABI packages can therefore be unsupported in this
slice; never present those packages as fully updated.

1. An explicitly requested planning job may refresh metadata from existing
   approved repositories. Disclose network use and local cache writes; this is
   not the existing cached-only observation. Fail planning on partial refresh
   failure rather than silently using a mixed-age successful-looking result.
2. Validate supported distro/tool versions, dpkg consistency, holds, installed
   versions, repository/pinning policy, disk space and helper capability.
3. Produce a complete bounded manifest of exact package, architecture, installed
   and target versions, authenticated target archive SHA-256, source/index
   identity, related package actions and expiry. Version strings alone do not
   pin the approved bytes or repository. Preserve repository signature/hash
   verification; do not treat a matching version as authenticated origin.
   Show known restart/configuration-file risks. Unsupported or incomplete plans
   cannot be approved.
4. Bind explicit operator approval to that canonical manifest and policy.
5. Use a fixed apt-get invocation with exact versions and defensive options such
   as no removals. Preserve native package authentication. No caller-selected
   APT options, environment, repository URL, local archive or force flags.
6. Fence the actual package transaction against the approved manifest immediately
   before dpkg. A candidate implementation uses a fixed root-owned
   `DPkg::Pre-Install-Pkgs` v3 guard. It validates the protocol and actual
   package/architecture/old/new/action tuples and actual archive digests against
   the manifest, failing closed on unexpected work or replaced bytes. It must
   be mandatory, not replaceable through inherited configuration. Native
   acceptance must establish archive-path/ownership and no untrusted replacement
   between digest validation and dpkg consumption.
7. Verify installed versions and dpkg consistency afterward; refresh inventory
   and retain per-package results, failures and reboot evidence separately.

### The guard's limits are part of the design

A separate apt-get simulation disables locking. It can inform a preview but
cannot establish that a later invocation executes the same plan. Never pair a
simulation with a blind later `-y` execution and call this an exact approval gate.

The pre-dpkg guard is an explicit package-action fence, not a sandbox or a proof
that nothing happened before it. APT 3.0.3 runs pre-invoke hooks before it, omits
anonymous pending operations from its package-info stream, and can append
generic configure-pending work afterward. Therefore the native implementation
must verify a clean dpkg state under the execution lock, account for trusted
local hook configuration, and explicitly include normal maintainer-script and
trigger side effects in the approved update semantics. Changed or unsupported
state/configuration fails closed. Do not disable normal required triggers merely
to claim that the action list bounds all effects.

Prove the complete invocation and guard behavior on each supported APT version,
including configure/trigger operations, multiarch, no-op plans and repeated
invocations, before enabling writes. If a mandatory fail-closed fence cannot be
established with the supported CLI, use a native APT transaction adapter or keep
APT execution unavailable; do not weaken approval matching.

Set and disclose a fixed noninteractive configuration-file policy, initially
preserving modified local files. Unexpected interactive/manual requirements
become needs-intervention. Package scripts can restart services and make broad
system changes. Tracebolt itself does not schedule an automatic reboot and does
not promise downtime-free updates or general package rollback.

Use native APT/dpkg locks. Report bounded waiting/busy and honor the original
start deadline. Never delete lock files, kill competing package managers, or
disable the host's unattended-upgrade timers. Do not copy read-only helper
sandbox settings and claim they permit arbitrary package installation safely.

## Audit and evidence

Record stable actor and approval identity, timestamps, target binding, action,
plan digest, policy revision, lifecycle transitions, structured result and
verification evidence. Use application-append-only events with no ordinary
edit/delete endpoint, protected helper storage and manager-side copies. Deny
new execution if durable admission/audit recording fails.

Keep credentials and arbitrary process output out of routine audit events.
Use bounded structured diagnostics; package-script output is potentially
sensitive. Retention and access must be documented. Local root/manager admins
can still modify local storage: this is not immutable storage or certification.

Cached APT candidates do not prove recent successful metadata refresh or
installability. CVE matches compare distribution source-package versions; they
are not executable plans or evidence of active kernel/service remediation.
Reassess after fresh inventory while retaining independent feed age, provenance
and coverage gaps. Missing reboot evidence is not universal proof that no reboot
is needed.

## Implementation and acceptance phases

1. The optional static named operator/capability slice is implemented separately;
   complete production action TLS admission and
   profile-separated disposable HTTP-test admission, immutable approved-job
   contract, durable storage and replay/restart rejection tests.
2. Implement the real fixed service-restart backend, local policy/permit checks
   and UI preview/approve/status. Test doubles stay in test code. Host deployment
   remains a separately authorized operation.
3. Implement APT planning, transaction fence, durable execution, partial results
   and post-update verification with the conservative scope above.
4. Perform independently reviewed disposable Debian/Ubuntu VM acceptance:
   unauthenticated/read-only denial, production HTTP denial, cross-profile permit
   denial, explicitly opted-in HTTP test, forged/wrong-target/replayed permit,
   changed policy/plan, double click, lost result, concurrent package lock,
   disk-full/admission failure, agent/manager/helper restart, machine reboot,
   held/dependency change, configuration conflict, failed script and stale data.

Report separately: source implementation, fixture tests, native VM acceptance,
installation and real-machine behavior. No earlier gate proves the later one.

## Primary references

- [APT scripting guidance](https://manpages.debian.org/trixie/apt/apt.8.en.html)
- [apt-get semantics and simulation](https://manpages.debian.org/trixie/apt/apt-get.8.en.html)
- [APT package-info hook protocol](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)
- [APT 3.0.3 dpkg execution source](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/deb/dpkgpm.cc)
- [APT 3.0.3 install source](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-private/private-install.cc)
- [Debian dpkg lock guidance](https://wiki.debian.org/Teams/Dpkg/FAQ)
- [dpkg configuration-file behavior](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html)
- [Ubuntu update and service-restart behavior](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)

## UI-approved service-action candidate

The narrow service-only vertical slice now has source integration for durable
preview/approval, first-claim-only delivery, independent root-helper execution
and agent-reported result status. See [service-action-workflow.md](service-action-workflow.md).
It remains default-off and requires separately authorized existing local trust,
policy, state and socket/service provisioning plus native disposable-host
acceptance. No APT action, shell, automatic retry or operational deployment is
implied.
