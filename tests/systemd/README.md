# Explicit disposable-systemd acceptance gate

This gate is being prepared and is **not executed by ordinary tests**. It requires
separate action-time approval for a fresh standard Ubuntu GitHub-hosted VM.
No user host, existing environment, private fleet or production credential is a
test target. The repository publisher owns workflow activation after approval.

Planned real operations in that VM:

1. Verify Linux/systemd PID 1/cgroup v2 and absence of all fixed Tracebolt paths,
   account, group, units, aliases, drop-ins and installer state.
2. Build the four native binaries and verify a selected local source archive.
3. Start one actual manager on literal loopback with ephemeral protected test
   TLS/issuer/auth material. No global CA installation or firewall change.
4. Execute the actual root installer through a disposable PTY. The invitation
   travels only through private process input and hidden terminal input. Approve
   the matching full fingerprint via the real authenticated operator API.
5. Require the real service UID, exact unit, successful enrollment and at least
   two distinct real Linux observations. Export only pass/fail/count evidence.
6. Restart, then upgrade verified artifact bytes; require new reports and
   unchanged identity/certificate/config plus nondecreasing durable sequence.
7. Uninstall; prove stopped/disabled service and absent owned binaries/unit while
   private identity/counter and account remain. Repeat uninstall without effects.
8. Discard the entire hosted VM at job end. Do not upload raw logs, private state,
   invitation/password, key material, cookies or runtime telemetry.

The opt-in test must fail rather than skip when explicitly enabled but required
root/systemd/clean-target conditions are absent. It must remain skipped by default.
Tests of TLS/HTTP policy and read-only collectors remain separate required gates.

A service restart does not prove boot persistence. True reboot acceptance needs
its own reviewed disposable guest VM and before/after proof; it is not claimed by
this hosted-runner gate. No reboot or host privilege action has been performed
by the local preparation work.

## Exact manual-dispatch contract

The publisher may add a **manual-dispatch-only** job after the harness review and
explicit approval. Do not attach this privileged gate to every push. Use a fresh
standard `ubuntu-24.04` GitHub-hosted runner, normal checkout at the exact selected
commit, and the repository's pinned Go toolchain. Normal jobs remain unprivileged.
The harness itself verifies opt-in, hosted-runner metadata, UID 0, running systemd,
cgroup v2 and a fresh installation target before creating fixture material.

Build as the normal runner user (no installation happens in these commands):

```sh
STAGE="$RUNNER_TEMP/tracebolt-systemd-acceptance"
mkdir -m 0700 "$STAGE"
go build -buildvcs=false -o "$STAGE/agent-service" ./cmd/agent-service
go build -buildvcs=false -o "$STAGE/lan-manager" ./cmd/lan-manager
go build -buildvcs=false -o "$STAGE/enroll-agent" ./cmd/enroll-agent
go build -buildvcs=false -o "$STAGE/lan-agent" ./cmd/lan-agent
go build -buildvcs=false -trimpath -ldflags=-buildid=tracebolt-disposable-upgrade -o "$STAGE/enroll-agent-upgrade" ./cmd/enroll-agent
go build -buildvcs=false -trimpath -ldflags=-buildid=tracebolt-disposable-upgrade -o "$STAGE/lan-agent-upgrade" ./cmd/lan-agent
go test -c -o "$STAGE/systemd.test" ./cmd/lan-manager
git archive --format=tar --output="$STAGE/source.tar" "$GITHUB_SHA"
```

Only on the explicitly approved fresh hosted VM, invoke the compiled test once:

```sh
sudo env -i \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  LANG=C LC_ALL=C HOME=/ \
  GITHUB_ACTIONS="$GITHUB_ACTIONS" \
  RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT" \
  RUNNER_OS="$RUNNER_OS" \
  TRACEBOLT_APPROVED_SYSTEMD_TEST=1 \
  TRACEBOLT_SYSTEMD_BINARY_DIRECTORY="$STAGE" \
  TRACEBOLT_SYSTEMD_SOURCE_ARCHIVE="$STAGE/source.tar" \
  TRACEBOLT_SYSTEMD_RESULT_FILE="$STAGE/systemd-result.json" \
  "$STAGE/systemd.test" \
  -test.run '^TestApprovedDisposableSystemdInstallation$' \
  -test.v -test.timeout 8m
```

An explicitly enabled unsupported host fails; it does not silently skip. Without
the opt-in, the test skips before effects. The upgrade artifacts are the same
selected source built with different path-stripping/build-ID metadata, so this gate checks
real verified artifact replacement, not an unimplemented semantic-version update
service or remote updater.

Allowlisted artifact: **only `systemd-result.json`**, a fixed schema containing
pass/fail, safe stage, TLS profile, `osRebootTested:false` and no telemetry. Do not
upload the staging directory, private files, terminal transcript, journal, process
logs, screenshots or core dumps. Missing/failing cleanup or result generation is
a test failure. Discard the VM regardless of result; no retained test identity may
be adopted for another job or deployment.
