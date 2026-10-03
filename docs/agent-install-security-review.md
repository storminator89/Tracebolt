# Linux installer: targeted security review

Review date: 2026-10-03. Scope: `internal/agentinstall`, `cmd/agent-service`,
the additive sender service-identity/local-validation flags and public bootstrap
parser extraction. This is source and inert-fixture evidence. **Actual systemd,
account creation and privilege-drop runtime acceptance remain pending.** No host
account, service, trust store or security setting was changed during this review.

The 20 held runtime files and their hashes are listed in
[`agent-install-review.sha256`](agent-install-review.sha256). That manifest's
SHA-256 is `9970f6a89ffb3e448ecc9aa1b61983695edcd601a6076157ff9be52264bde8a1`.
Its contents remained unchanged through the final independent focused checks.

## Implemented boundaries reviewed

- Dry-run performs read-only preflight. Application requires the explicit apply
  flag, root/systemd preconditions and the fixed local adapter; neither a plan
  nor repository instructions provide deployment authorization.
- Destinations, account, unit and executable arguments are fixed. No shell,
  network download, source-archive extraction or invitation argument is offered.
  Operator-supplied hashes establish artifact integrity, not publisher identity
  or a reproducible relationship between an archive and its binaries.
- Artifact opening is no-follow and nonblocking. Staging re-hashes the retained
  source descriptor; protected staged bytes then receive another hash and native
  ELF/build-info role check before execution/publication.
- Preflight rejects foreign unit resolution, aliases, drop-ins, incompatible
  accounts/groups and unowned destination files. Account IDs are bounded before
  credential conversion. The generated unit uses numeric IDs; the sender checks
  real/effective/saved IDs and additional groups before private-state access.
- Enrollment runs as the dedicated account with supplementary groups cleared.
  Terminal readiness is checked before changes. Parent-side terminal restoration
  and cooperative cancellation with bounded kill protect interrupted prompts.
  The installer does not read the invitation or endpoint private key as root.
- The unit restricts privileges and writable paths and bounds restart attempts.
  `ConditionPathExists` is only a hint. Local guided-handoff validation checks
  protected configuration, ready-marker hashes, current credentials and the
  existing bound sender ledger without collecting, resolving DNS or sending data.
- Upgrades/restarts stop the owned unit and require a drained service cgroup
  before private-state validation. Identity, sequence and pending observations
  are retained. Failed state validation does not trigger initialization.
- Durable intent precedes each operation. Rollback touches only journal-owned
  changes, restores prior enablement and cannot report success for uncertain
  account creation or a reconciled commit. Failed operations intentionally do
  not automatically restart a service whose state failed validation.
- Retained preparation requires explicit resume and exact ownership/state-domain
  evidence. Repeated uninstall retains the account, bootstrap and private data;
  missing/recreated state is not adopted as a new sequence domain.

## Corrections made during review

1. Cancellation during preflight or durable intent recording could still
   dispatch Begin or a new start/remove action. Deterministic fake-only tests
   reproduced this; cancellation is now checked before the next dispatch.
2. Blocking source-file open after a separate path check could hang before
   validation on a raced special file. No-follow/nonblocking open closes that
   gap, and staged-snapshot checks bind native role to the final verified bytes.
3. Terminal checks originally happened after preparation, and immediate child
   killing could prevent terminal restoration. Preflight and parent-owned
   restoration now cover cancellation and forced child termination.
4. A failed account-creation command could leave an unmarked retained account.
   Intent/ownership evidence and explicit recovery states now prevent treating
   this uncertain result as a completed rollback or adopting an account by name.
5. Filename-only unit checks and MainPID-only stop checks were insufficient.
   Exact loaded-unit resolution and hierarchical cgroup population checks now
   reject foreign ownership and undrained descendants.
6. Oversized numeric IDs could be accepted before a later uint32 conversion.
   A pure regression reproduced the bound gap. Reserved and truncating values
   now fail closed; no hostile privilege escalation was demonstrated.
7. Rollback could leave changed enablement behind. Enablement is now recorded
   and restored separately, while the service remains stopped for inspection.

## Independent verification

On Linux amd64 with Go 1.27.1:

- Adapter and CLI package tests: normal and race checks pass.
- Independent planner/transaction/retained-state/identity regressions: normal
  and race checks pass. Relevant `go vet` checks pass.
- Inert fixtures cover lifecycle ordering, each journal failure boundary,
  cancellation, exclusive fresh preflight, retained preparation, repeated
  uninstall, ownership/permission rejection, account/cgroup parsers and terminal
  restoration after an inert PTY child's forced termination.
- The updated enrollment client, sender and complete independent security suite
  pass with the race detector. These tests do not install a service.
- The actual three-binary guided enrollment/foreground regression passes again
  in TLS and explicit HTTP-test profiles after the additive CLI changes. The
  test harness is race-instrumented; its three subprocess binaries are normal
  builds. This regression also does not install a service. Module verification
  passes.

Independent test file hashes:

- `tests/security/agentinstall_boundary_test.go`:
  `507d49de9108dcbaa0932802696787f4e441ef9e21ecf1e6b47922075b7c1ddd`
- `tests/security/agentinstall_host_boundary_test.go`:
  `e70bd226c96c0c555315fe0e25585f35868310fedc1e867d137c88e027ecd098`

A fresh pinned `govulncheck` v1.8.0 scan of the held Linux/amd64 source covered
40 root packages and 11 modules, with source/module hashes unchanged. It found
zero reachable-symbol or imported-package findings. The required `x/crypto`
module retains [GO-2026-5932 in unused OpenPGP](https://pkg.go.dev/vuln/GO-2026-5932),
with no fixed version listed. This is not an assurance that all vulnerabilities
are absent.

The separate opt-in hosted-VM harness was source-reviewed after these checks.
Its final SHA-256 is
`205b328fc4aee0f6e5732c20b264b8fa9fcb550ca74108411f262354dffe67be`.
Independent ordinary invocation compiles and skips at the first gate before
effects. Enabled execution requires a fresh hosted root Linux/systemd/cgroup-v2
target, absent owned paths/account/group, exact prebuilt artifacts and explicit
opt-in. Upgrade artifacts must have different bytes. Only a sanitized result
file may be uploaded. The documented invocation uses a clean root environment
and one exact precompiled test. Workflow wiring and actual execution remain
separate gates; this harness review is not a runtime pass.

## Explicit remaining gates

The injected command fixtures cannot validate real systemd behavior, effective
credential dropping, account database changes, boot persistence or a deployed
endpoint. Those require separately authorized disposable-host acceptance. No
service installation or reboot success is claimed here.

Exhaustive crash/fsync/host-path race fault injection has not been performed.
Same-UID/root compromise and valid-backup rollback remain outside this boundary.
Abrupt death of the installer itself can prevent terminal restoration; its
cooperative cancellation and killed-child recovery are the tested cases.
Signing/publisher authenticity, source-to-binary reproducibility and production
deployment assurance are also outside this targeted review.
