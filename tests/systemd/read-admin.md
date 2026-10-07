# Fresh read-admin V2 disposable-systemd acceptance candidate

This source-only gate targets the fresh one-command
[read-admin onboarding candidate](../../docs/read-admin-onboarding.md), with read
profile `tracebolt.linux-read-admin.v2` and collection profile
`managed-operations-v3`. It adds no ordinary user setup steps. This gate does not
preserve an older read-admin test path or migrate unrelated installations. The
separate explicit `approved_read_admin_upgrade` option adds one same-profile
rc.2-to-reviewed-source update inside the complete scenario; see
[the exact update contract](../../docs/read-admin-upgrade.md). Without that
additional approval this remains the fresh-install gate. The separate basic TLS and managed-v2 gates are unchanged.

Preparation, compilation, default-skipped tests and synthetic wrapper checks are
**not native acceptance**. No workflow dispatch, account/service/capability change,
release publication or dashboard-pin activation follows from source checks.
Read [the installation runbook](../../docs/installation.md) first. The currently
pinned rc.1 release does not contain this candidate; do not add these source flags
to its public command or substitute an unverified moving download.

## Explicit manual contract

[read-admin-systemd-acceptance.yml](../../.github/workflows/read-admin-systemd-acceptance.yml)
has only `workflow_dispatch`. All of the following must match before build or
privileged invocation:

- `read_profile`: defaults to `unapproved`; its only approved choice is exactly
  `tracebolt.linux-read-admin.v2`.
- `reviewed_source_commit`: the independently reviewed lowercase 40-hex source
  commit, exactly equal to the dispatched `GITHUB_SHA` and checked-out HEAD.
- `approved_fresh_v2_read_admin_systemd`: defaults to false. Its approval covers
  tightening only the root-owned hosted `/opt` directory inode from mode `0777`
  to `0755` (no recursive change), then the fresh dedicated account, persistent
  endpoint identity, owned main service,
  inventory/network grants, journal/socket-owner helper accounts/units/grants,
  bounded root-owned loopback TCP/UDP fixtures, a deliberately created bounded
  fixture log service and its exact-service content query, owned-main-service
  restart, cancellation, the retained journal phase, explicit revocation,
  owned-helper stop/drain and owned-main-service cleanup on each disposable VM.
  It does not authorize purging retained records.
- `approved_cap_sys_ptrace_process_memory`: defaults to false. The isolated
  socket-owner helper receives unit-scoped `CAP_SYS_PTRACE`, which grants broad
  process-memory authority. **Metadata-only collection is code policy, not an OS
  confidentiality boundary.** Approval must acknowledge this risk explicitly.
- `transport`: defaults to `tls`. Selecting `http-test` explicitly accepts
  plaintext passwords, sessions, telemetry and journal content, plus server/UI
  impersonation risk, within the isolated loopback fixture. There is no TLS
  downgrade, external exposure or global CA grant.

A separate ordinary-runner input-validation job reads the existing GitHub event
payload without checkout, credentials or raw input logging. Fixed error codes
identify a profile mismatch, exact source mismatch or either missing approval;
source spelling and whitespace are never normalized. The native job requires
successful validation as well as its existing job condition and early
authorization step. These checks bind the selections above.
A failed early gate prevents both build and privileged execution, including the
otherwise-always-run sanitized evidence reader. The old read-admin opt-in does
not select this gate. Editing this workflow does not provide approval to run it.

The matrix allocates a separate fresh GitHub-hosted `ubuntu-24.04` VM to each of
`complete`, `cancel-enrollment` and `retained-journal`.
A second transport requires a separately reviewed manual
run with new VMs. Never run scenarios on the same host, use an existing
installation, or delete retained state to make a target fresh. Discard the whole
VM on success, failure or interruption.

## Build and native invocation

The wrapper checks out the exact selected `GITHUB_SHA` without retained Git
credentials and uses the pinned Go toolchain. As the ordinary runner user it
verifies modules, builds `agent-service`, `lan-manager`, `enroll-agent`,
`lan-agent`, `socket-owner-reader` and the `cmd/lan-manager` test binary, and
archives that exact SHA. There are no changed-byte `*-upgrade` roles in this
workflow or read-admin V2 acceptance contract.

Only the anchored test
`^TestApprovedReadAdminDisposableSystemdInstallation$` is invoked, once per VM,
with a ten-minute test timeout. Its minimal privileged environment includes:

- `TRACEBOLT_APPROVED_SYSTEMD_TEST=1`: the internal base harness opt-in, enabled
  only behind the explicit fresh V2 and process-memory risk approvals
- `TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST=1`
- `TRACEBOLT_READ_ADMIN_PROFILE=tracebolt.linux-read-admin.v2`
- `TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE`: exactly `GITHUB_SHA`
- `TRACEBOLT_APPROVED_READ_ADMIN_PTRACE=true`
- `TRACEBOLT_READ_ADMIN_TRANSPORT`: the selected `tls` or `http-test`
- `TRACEBOLT_READ_ADMIN_SCENARIO`: the one selected matrix scenario
- `TRACEBOLT_SYSTEMD_BINARY_DIRECTORY`, `TRACEBOLT_SYSTEMD_SOURCE_ARCHIVE` and
  `TRACEBOLT_SYSTEMD_RESULT_FILE`: the fixed private build inputs/output
- `GITHUB_SHA`, plus minimal system path, locale/home and the three
  GitHub-hosted-runner metadata values

No invitation, password, cookie, CI credential, proxy or loader variable is
inherited. Invitation entry stays inside the hidden local PTY path. The native
harness must refuse missing/wrong explicit approvals, mismatched read profile or
reviewed source, non-hosted/nonroot targets, unsupported kernel/systemd/cgroup
conditions, unsafe fixed parents, and existing account, installer, journal or
socket-helper domains before installation effects. Ordinary invocation skips before effects;
a selected but unsupported host fails rather than silently skipping. The only
explicit test-fixture preparation is the bounded `/opt` change described below;
no general permission repair is performed. The native release staging directory must satisfy the production
contract `/tmp/tracebolt-release-[a-z0-9_]{8}`; the runner's private build/output
directory is a separate input.

## Explicit hosted-image prerequisite

The GitHub Ubuntu image's [official configuration script](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/configure-system.sh)
makes `/opt` world-writable. The production installer correctly refuses that
writable parent for root-owned installed binaries. The source-bound fresh native
approval now explicitly includes tightening **only the existing `/opt` directory
inode** from root:root `0777` to `0755` on each disposable hosted VM. It is not
permission to change a user VM, recurse into children, change ownership, or
weaken the production installer check. An older dispatch does not approve this
new preparation; review the updated source and checkbox before running it.

The test accepts exactly root:root directory mode `0777`, or already `0755`.
It opens the fixed path with no symlink following, changes permissions through
that descriptor only when needed, and verifies the same inode/path, owner and
exact final mode. Any other shape or failed readback reports
`read_admin_fixture_opt` and stops. It never restores world-write access; the
entire disposable VM is discarded after the run. Production code is unchanged.

## Scenario boundaries and proof limits

- `complete`: one combined fresh V2 approval, installation/registration and public
  device comparison approval; inventory/network observations, real journal
  content from the deliberately created bounded fixture log service, and actual
  fixture socket owners captured by the ordinary installed main service with
  incoming v4 source/provenance. Then restart the owned installed main service
  and verify it reports online. Finally perform explicit production socket-owner
  revocation/drain and require a newer ordinary report without socket-owner
  authority or a new v4 generation after revocation.
- `cancel-enrollment`: interrupt after hidden invitation entry and a confirmed
  ClaimedPending claim while waiting for device approval. Verify retained
  account, identity and claim. This is not permission to erase installer state
  or retry as a fresh installation.
- `retained-journal`: inject a test-only exception immediately before journal
  configuration after its immutable started receipt. Verify earlier inventory
  grants and main identity remain, and rerun refuses the uncertain phase.

The socket fixtures are bounded root-owned TCP/UDP loopback sockets. Owner capture
must come through the ordinary installed service and exact native helper path,
with native helper/main-agent identity, capability and unit checks. The main
agent remains nonroot with its original unit and groups; it receives no
`CAP_SYS_PTRACE`, broad supplementary groups, sudoers or polkit access. Controlled
service actions are separate permissions.

A successful helper path exercises some kernel checks transitively. It does not
independently prove native syscall-denial behavior, races, LSM enforcement,
adversarial namespace behavior, reboot persistence, or rate/size enforcement.
Fixture ownership is not a claim of complete host/process attribution.

Journal readiness checks cover bounded helper creation, committed
activation/private floors, protected socket, production nonroot amendment
preview and current manager generation metadata. The complete scenario also
requires a real exact-service journal-content query that returns the deliberately
created bounded fixture service's marker through the installed helper/agent path.
Its `journalContent` check cannot pass on readiness alone. This bounded fixture
does not establish completeness for other journal sources or services. The
`serviceRestartOnline` check requires an actual owned installed-main-service
restart and verified subsequent online reporting; it is not a reboot claim.

Cleanup may stop/drain only newly created participants whose ownership is proved.
It retains identity, phase, grant and revocation records; it never purges a
directory or deletes evidence to make a scenario pass. Discarding the disposable
VM remains mandatory even if cleanup is blocked or ownership cannot be proved.

### Required reviewed production composition

This harness depends on composing the separately reviewed mode-contract fix:
the native installer's `lan-agent` remains `0555`
([host transaction](../../internal/agentinstall/host_transaction_linux.go)),
and [socket-owner setup](../../deploy/socket-owner/setup.py) must accept that exact
agent mode while requiring `0755` for the separate helper. The validation base
includes that independently reviewed fix. The harness must never `chmod` the
installed agent or relax production validation to manufacture acceptance.
Production source changes and their review remain outside this harness-only
change; source checks alone still do not establish native acceptance.

## Fixed evidence and privacy

Only `read-admin-systemd-result.json` may be uploaded, under an artifact name
bound to V2, selected transport, scenario and SHA. The wrapper reads the root
result without following symlinks or blocking on special files; it requires a
regular nonempty file of at most 4096 bytes, rejects duplicate JSON keys at every
depth and unknown fields. The bounded diagnostic projection emits normalized JSON
of at most 16 KiB through the ordinary runner; the native source result remains
limited to 4096 bytes and private test output to 1 MiB.
Invalid or missing evidence fails and removes only the invalid export. A
well-formed failure result may be exported for diagnosis but cannot pass the job.

The source fields and bounded projected diagnostic fields are:

- `schemaVersion`: `tracebolt.read-admin-systemd-acceptance.v2`
- `status`: `pass` or `fail`; `pass` requires `stage: complete`
- `stage`: `preflight`, `manager_start`, `operator_login`, `install_enroll`,
  `approval`, `initial_reports`, `read_admin_cancel`, `read_admin_inventory`,
  `read_admin_journal`, `read_admin_repeat`, `read_admin_retained`,
  `read_admin_readiness`, `read_admin_socket`, `read_admin_socket_owners`,
  `read_admin_revoke`, `read_admin_post_revoke`,
  `read_admin_journal_content`, `read_admin_restart`,
  `complete`, or the fixed `installer_preflight`, `installer_prepare`,
  `installer_stage`, `installer_enroll`, `installer_validate`,
  `installer_publish`, `installer_start`, `installer_commit`
- `profile`: exactly the selected transport
- `collectionProfile`: `managed-operations-v3`
- `scenario`: exactly the selected scenario
- `osRebootTested`: false
- `telemetryExported`: false
- `readProfile`: exactly `tracebolt.linux-read-admin.v2`
- `sourceCommit`: exactly the approved `GITHUB_SHA`
- `setupFailure`: exact frozen source-literal coordinator/helper reason, `none`,
  or `not_attempted`; arbitrary strings map to one fixed unknown-stage value.
  Main outcome, interrupted enrollment, resumed setup and helper maintenance
  retain the latest reason before their assertions. Passing complete setup must
  report `none`; expected cancel/retained refusals keep their existing assertions.
  Upgrade restoration failures additionally retain one of eight fixed substeps:
  restart-state reset, enablement, helpers, socket proof, journal proof, agent
  validation, agent start or final enablement. Child reason/recovery text remains
  excluded; older phase-only upgrade failures are still accepted.
- `nativeAssertion`: on failure, the first exact allowlisted static native-test
  assertion found in at most 1 MiB of private test output, or a fixed unavailable/
  unknown label. Its file path, line number and all unmatched text are discarded.
  This covers socket, journal content, service restart and cleanup assertions.
  Successful runs report `none` without reading private output. No diagnostic
  relaxes a scenario or acceptance check.
- `operatorFailures`: up to eight deduplicated closed method/resource/HTTP-status/
  failure/API-code records. Paths, identifiers and response/error bodies are omitted.
- `lifecycleFailures`: up to eight deduplicated closed operation/failure-stage
  records with the existing CLI's committed/rolledBack/identityRetained booleans
  (null when unavailable) and fixed-unit ActiveState/SubState/Result labels.
  This preserves restart, revoke and cleanup failures, including start-limit-hit
  only when actually sampled. Unit state is sampled after command failure and
  rollback, so it may differ from the original failure instant. Successful runs
  export empty diagnostic lists without reading private output.
- `initialProbe`: closed failure/childExit/scopePromptSeen cancellation evidence.
- `ptraceRiskAcknowledged`: true
- `socketNativeChecks`: exactly six strict JSON booleans, with keys
  `installedServiceOwners`, `v4Provenance`, `revocationCompleted`,
  `revokedNoAuthority`, `journalContent`,
  `serviceRestartOnline`. The existing object name now also contains the journal
  content and installed-service restart checks.

For a passing `complete` result all six booleans must be true. For passing
`cancel-enrollment` and `retained-journal` all six must be false.
A failure may record completed partial checks using the same
strict boolean fields but can never be interpreted as success. Relabeling an old
schema or changing a scenario while retaining its check vector is rejected.

Raw runtime output stays in the private VM. The bounded reader projects only
preselected static assertion labels, never arbitrary log text or errors. No wildcard upload, raw terminal or
journal content, manager log, endpoint/socket/process metadata, key, config,
consent, ledger, activation receipt, screenshot or crash dump is exported.
Inspect sensitive diagnostics only within the separately authorized disposable
target. Sanitized evidence is not a release artifact or proof of broad fleet
suitability.

## Safe source checks and remaining gates

The wrapper-contract tests inspect source text and execute only the embedded
input validator and two JSON readers with in-memory fake inputs/files and mocked
file operations. They cover
gate ordering, exact source/profile binding, every scenario check vector, strict
schema/boolean validation, nested duplicate rejection, bounded file reads and
failure-versus-success handling. They never execute workflow shell, a native
harness, a collector/helper or privileged setup:

```sh
python3 -B -m unittest discover -s tests/security -p test_read_admin_systemd_gate.py -v
python3 -O -B -m unittest discover -s tests/security -p test_read_admin_systemd_gate.py -v
```

Separately authorized native runs must establish their exact reviewed revision,
transport, scenario and observed result. Default skips, fixture passes and
compilation remain labeled as such. Native acceptance is still pending and must
use the reviewed production composition above. Independent adversarial/kernel
checks, reboot, production deployment and release activation are separate work;
this wrapper does not prove or perform them.

Pending-state verification observes the actual stopped sender state around revocation.
If no body is pending, that case does not establish forced queued-v4 discard or
ordinary-pending retention acceptance; those native cases remain untested.
