# Source-bound native ARM64 read-admin acceptance

Status: **manual harness prepared; not executed by this change**. This extends the
existing `read-admin-systemd-acceptance.yml` workflow; it adds no new trigger,
production bypass flag or automatic privileged job. Public ARM64 release
admission remains closed. Historical bootstrap/assets and the dashboard pin are
unchanged.

## What this gate proves

Selecting `architecture=arm64` uses native `ubuntu-24.04-arm` hosted VMs and four
independent cases:

1. **Fresh candidate:** successful fresh install of the exact dispatched candidate
   source components, reporting, journal/socket-owner checks, restart, revocation
   and owned cleanup.
2. **Same-identity upgrade:** fresh install of the fixed reviewed
   `7b20a93e481feb1f7433ee0ef6c912a35f68ce6d` source components, followed by the real
   coordinator replacing them with the distinct dispatched candidate's ARM64
   artifacts. Identity, scopes, original receipts and durable floors remain bound;
   the same journal/socket/restart/revoke/cleanup checks follow the upgrade.
3. **Cancel enrollment:** retain the existing cancellation-before-trust assertions.
4. **Retained journal:** retain the existing interrupted/incomplete-phase guards.

Every case gets a fresh disposable VM. No reboot is performed. The three original
scope approvals are all required on ARM64, including when a particular case only
builds and verifies the two source generations without executing the upgrade.
A separate fixed matrix value selects actual upgrade execution only in case 2.
No missing approval is inferred from the architecture choice.

This is **source-component acceptance**, not a published ARM release install or
old-rc.2-to-ARM upgrade. The rc.2 contract remains the amd64-only baseline for the
existing amd64 lane. The ARM64 prior is not labeled rc.2 or rc.3. An Ubuntu ARM VM
is not Raspberry Pi hardware or Raspberry Pi OS runtime evidence. These success
cases do not establish interrupted-upgrade recovery.

## Source and artifact binding

The ordinary runner checks out the dispatched reviewed commit. A detached
worktree selects the full fixed 7b20 revision; neither a branch name nor a
caller-selected prior SHA is accepted. Both trees must remain clean, including
untracked files, and use their exact declared native ARM64 Go toolchain.

The fixture builder compiles agent-service, enroll-agent, lan-agent and
socket-owner-reader for both generations using CGO disabled, baseline ARMv8.0,
trimmed paths and `-buildvcs=true`. It does not execute any artifact. It verifies
ELF64 little-endian AArch64, Go module/role, architecture, exact `vcs.revision` and
`vcs.modified=false`, and records complete source archives plus every file's size
and SHA-256 in one canonical bounded proof. Different embedded source metadata
can produce different executable bytes even when runtime behavior is unchanged;
this verifies artifact replacement, not a claimed behavioral migration.

The root test independently checks the proof's exact schema, source revisions,
file hashes, native ELF/build information and candidate/prior distinction before
changing `/opt`, creating identities or starting fixture services. Copies into
root-private installer staging must still match the same recorded hashes. Missing or mismatched source evidence cannot produce a successful overall result
or upgrade claim.

The candidate-owned `inspect_platform()` contains the shared read-only OS,
architecture, 64-bit userspace, systemd, cgroup and prerequisite checks. The
source-only launcher loads its hash-bound bytes from the candidate archive for
both source generations. Each generation still supplies its own archived runtime
modules. It never replaces an old bootstrap's function, modifies runtimeTargets,
sets a release pin or calls release download/provenance code. The test-only checker
accepts only the known amd64-only or amd64+ARM64 source contracts so a later
separately reviewed activation can reuse the gate. Current production admission
is still amd64-only. Public
`inspect_host()` still wraps platform validation with mandatory release admission.
Thus the precise prior claim is “7b20 source components installed by the reviewed
candidate acceptance harness,” not “the 7b20 public bootstrap installed ARM64.”

## Smallest manual run

Only an authorized operator should take these steps after this exact source has
been reviewed and published and ordinary CI is green:

1. Open the existing **Approved disposable fresh read-admin V2 systemd acceptance**
   workflow. Select the branch/reference whose full commit is the reviewed
   candidate, and enter that same full SHA as `reviewed_source_commit`.
2. Select `tracebolt.linux-read-admin.v2`, `architecture=arm64`, and normally `tls`.
   `http-test` remains a separate explicit plaintext-risk selection for isolated
   loopback fixtures.
3. Deliberately approve all three existing checkboxes: fresh identities/accounts,
   services and read scopes with owned cleanup; the broad process-memory risk of
   CAP_SYS_PTRACE; and the disclosed same-identity source-artifact upgrade. These
   authorize the listed disposable hosted tests only. They do not approve work on
   a user's Pi/server, persistent production trust changes or reboot.
4. Run once. Require all four architecture-labeled case jobs to pass. Inspect only
   their normalized bounded results: exact candidate/source proof, ARM64
   architecture, all six functional checks on complete cases, and all four native
   upgrade checks on the upgrade case. `status=fail`, incomplete output or a
   missing result is not acceptance. Never upload private fixture logs/state.
5. For public ARM64 activation, separately review the exact runtime-target change,
   rebuild/reverify the new release and public provenance, then change the
   dashboard pin. Do not rewrite historical artifacts. Actual download-based
   install/update and actual Raspberry Pi OS 64-bit/Trixie behavior remain separate
   observations; this source-built gate cannot establish them.

The existing kernel 6.5+, cgroup v2, systemd PID1, namespace, dedicated nonroot
main agent, helper capability, consent and fail-stop boundaries are unchanged.
No privilege or deadline is weakened to make an ARM run pass.
