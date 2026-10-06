# Read-admin disposable-systemd acceptance candidate

This source-only gate targets the fresh one-command
[read-admin onboarding candidate](../../docs/read-admin-onboarding.md) with
`managed-operations-v3`. It is separate from the existing basic TLS and managed-v2
systemd gates. Preparation, compilation, default-skipped tests and synthetic
wrapper checks are **not native acceptance**. No workflow dispatch, host setup,
release publication or dashboard-pin activation follows from these checks.

Read [the installation runbook](../../docs/installation.md) first. The currently
pinned rc.1 release does not contain read-admin; do not add these source flags to
its public command or use an unverified moving download as a substitute.

## Explicit manual contract

[read-admin-systemd-acceptance.yml](../../.github/workflows/read-admin-systemd-acceptance.yml)
has only `workflow_dispatch`. Its required boolean
`approved_disposable_read_admin_systemd` defaults to false. Selecting it authorizes
only the reviewed disposable target and described fixture operations; this source
change does not select it. The separate `transport` choice defaults to `tls`.
Selecting `http-test` explicitly accepts plaintext passwords, sessions, telemetry
and journal content, plus server/UI impersonation risk, within the isolated
loopback fixture. There is no TLS downgrade, external exposure or global CA grant.

The scenario matrix allocates a separate fresh GitHub-hosted `ubuntu-24.04` VM for
each of `complete`, `cancel-enrollment` and `retained-journal`. A second transport
requires a separately reviewed manual run with new VMs. Never run scenarios on
the same host, use a user's existing installation, or delete retained state to
make a target fresh. Discard the whole VM on success, failure or interruption.

The wrapper checks out the exact selected `GITHUB_SHA` without retained Git
credentials and uses the pinned Go toolchain. As the ordinary runner user it
verifies modules, builds `agent-service`, `lan-manager`, `enroll-agent`,
`lan-agent`, the two changed-byte `*-upgrade` artifacts required by the shared
preflight, and the `cmd/lan-manager` test binary. It archives that exact SHA.
Building the upgrade artifacts is not evidence of a read-admin upgrade test.

Only the anchored test
`^TestApprovedReadAdminDisposableSystemdInstallation$` is invoked, once per VM,
with a ten-minute test timeout. Its minimal privileged environment includes:

- `TRACEBOLT_APPROVED_SYSTEMD_TEST=1`
- `TRACEBOLT_APPROVED_READ_ADMIN_SYSTEMD_TEST=1`
- `TRACEBOLT_READ_ADMIN_TRANSPORT`: the selected `tls` or `http-test`
- `TRACEBOLT_READ_ADMIN_SCENARIO`: the one selected matrix scenario
- `TRACEBOLT_SYSTEMD_BINARY_DIRECTORY`, `TRACEBOLT_SYSTEMD_SOURCE_ARCHIVE` and
  `TRACEBOLT_SYSTEMD_RESULT_FILE`: the fixed private staging inputs/output
- `GITHUB_SHA`: the exact selected 40-hex commit binding the launcher's
  `sourceCommit` to the checkout and archive
- Minimal system path, locale/home and the three hosted-runner metadata values

No invitation, password, cookie, CI credential, proxy or loader variable is
inherited. Invitation entry stays inside the hidden local PTY path. The real
harness must refuse wrong or missing explicit opt-ins, non-hosted/nonroot targets,
missing systemd PID 1/cgroup v2, unsafe fixed parents and existing account,
installer or journal domains before effects. Ordinary invocation skips before
effects. A selected but unsupported host must fail rather than skip or repair
permissions to pass its preflight.

## Scenario boundaries

- `complete`: fresh v3 installation/enrollment, public comparison approval and
  received package/system/full-overview/identity inventory; the combined
  inventory/network grants and separate journal helper; completed-path rerun and
  current readiness checks.
- `cancel-enrollment`: interrupt after hidden invitation entry and a confirmed
  ClaimedPending claim, while waiting for device approval; verify the retained
  account, key and claim.
  Cancellation is not permission to erase identity/installer state or retry as a
  fresh installation.
- `retained-journal`: inject a test-only exception immediately before journal
  configuration, after its immutable started receipt. Verify that the earlier
  inventory grants and main identity remain and a rerun refuses the uncertain
  phase. Never delete the marker or silently create a replacement helper.

The main agent must stay nonroot without broad supplementary groups, sudoers,
polkit, root execution or additional process-attribution capabilities. The
separate helper's scope is the existing bounded exact-system-service journal
contract. Controlled service actions remain a separate capability.

Journal checks are readiness-only: actual broad-scope helper creation, committed
activation and private floors, an active protected socket, the real nonroot
amendment preview through production read-admin verification, and current manager
generation metadata as a required condition. This slice sends no log-content query and
creates no fixture service to produce log lines. It does not establish effective
journal-source completeness or actual log-read acceptance.

## Fixed evidence and privacy

Only `read-admin-systemd-result.json` may be uploaded, under an artifact name
bound to the selected transport, scenario and SHA. The wrapper reads the root
result without following symlinks or blocking on special files; it requires a
regular nonempty file of at most 4096 bytes, rejects duplicate JSON keys and
unknown fields, and emits normalized JSON through the ordinary runner. Invalid
or missing evidence fails and removes only the invalid export. A well-formed
failure result may be exported for diagnosis but cannot pass the job.

The exact eight-field schema is:

- `schemaVersion`: `tracebolt.read-admin-systemd-acceptance.v1`
- `status`: `pass` or `fail`; `pass` requires `stage: complete`
- `stage`: `preflight`, `manager_start`, `operator_login`, `install_enroll`,
  `approval`, `initial_reports`, `read_admin_cancel`, `read_admin_inventory`,
  `read_admin_journal`, `read_admin_repeat`, `read_admin_retained`,
  `read_admin_readiness`, `complete`, or the existing fixed `installer_preflight`,
  `installer_prepare`, `installer_stage`, `installer_enroll`,
  `installer_validate`, `installer_publish`, `installer_start`, `installer_commit`
- `profile`: exactly the selected transport
- `collectionProfile`: `managed-operations-v3`
- `scenario`: exactly the selected scenario
- `osRebootTested`: false
- `telemetryExported`: false

All runtime output stays in the private VM. No wildcard upload, raw terminal or
journal content, manager log, endpoint metadata, key, config, consent, ledger,
activation receipt, screenshot or crash dump is exported. Inspect sensitive
diagnostics only within the separately authorized disposable target. A sanitized
result is not a release artifact or proof of broad fleet suitability.

## Safe source checks and remaining gates

The wrapper-contract tests inspect source text and run only the isolated embedded
JSON readers with in-memory fake files and mocked file operations. They never
execute workflow shell blocks, a native harness, a collector or privileged setup:

```sh
python3 -B -m unittest discover -s tests/security -p test_read_admin_systemd_gate.py -v
python3 -O -B -m unittest discover -s tests/security -p test_read_admin_systemd_gate.py -v
```

Separately authorized native runs must establish their exact revision, transport,
scenario and observed result. Default skips, fixture passes and compilation must
remain labeled as such. Reboot persistence, read-admin upgrade compatibility,
real source-content coverage, production deployment and release activation are
separate acceptance work; this wrapper does not prove or perform them.
