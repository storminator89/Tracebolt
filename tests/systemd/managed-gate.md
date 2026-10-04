# Managed Linux service acceptance preparation

This adds a separate, default-disabled acceptance target for
`managed-operations-v2` over explicit HTTP-test transport. It preserves the
original basic TLS target and its result schema. No enabled run has occurred as
part of this source change. The normal test invocation skips before effects.

Run only on a separately authorized fresh hosted Ubuntu24.04 VM with systemd
PID1, cgroupv2 and the installer's trusted fixed parent paths. A hosted image with
writable `/opt` is unsupported by the current installer: fail preflight, do not
chmod that directory or bypass its guard. Do not run this fixture on a user's
host, reuse a prior gate's account/state, or run both installation targets on the
same machine. A manually operated Debian pilot is distinct evidence.

The compiled test target is exactly:
`TestApprovedManagedDisposableSystemdInstallation`.
It requires both `TRACEBOLT_APPROVED_SYSTEMD_TEST=1` and
`TRACEBOLT_APPROVED_MANAGED_SYSTEMD_TEST=1`, plus the original hosted-runner,
prebuilt-binary, selected-source-archive and fresh result-file inputs described in
README.md. The clean privileged environment needs the additional managed opt-in;
no invitation, password, proxy, CI token or loader variables are inherited.
Compiling/skipping this target does not authorize enabling it. The manual workflow
needs a separate reviewed target selection and result validator before dispatch.

The manager runs only on loopback with generated fixture material. The actual
installer creates its dedicated account and unit, enrolls through the hidden PTY,
starts the sandboxed service, then checks repeated real observations, a service
restart, changed-byte upgrade, uninstall and retained identity/sequence. The
managed invitation includes the required metadata acknowledgement. Every HTTP
installer lifecycle command includes the explicit HTTP-test acknowledgement.

After each of the first two reports, restart and upgrade, the gate reads the
actual manager's package and operational APIs. It requires matching advancing
sequence, distinct generation and strictly advancing original collection time,
with collection later than the recorded completion of install/restart/upgrade,
plus fresh views and the existing bounded positive Ubuntu24.04
package/operational evidence checks. It allows the unchanged30-second service interval within a bounded75-second
readback window. It does not replace collection with a test
snapshot. Denied/partial journal or service coverage remains permissible and
visible; the sandbox is unchanged. No raw metadata is included in result output.

The result has exactly seven fields:

- schemaVersion: `tracebolt.managed-systemd-acceptance.v1`
- status: pass or fail
- stage: the existing fixed systemd stage allowlist
- osRebootTested: false
- profile: `http-test`
- collectionProfile: `managed-operations-v2`
- telemetryExported: false

Result handling must use the same bounded no-follow/nonblocking fixed-schema
reader as the original gate; root umask077 may make the raw result0600. Upload
only normalized fixed-schema output. No raw journal, terminal, config, key,
ledger, package, process or device data may be exported.

An actual successful run proves service install/start/restart/upgrade/uninstall
only on that exact host and revision. It does not prove a full OS reboot,
production fleet behavior or complete host visibility. Boot persistence requires
a separately authorized and observed reboot with a later advancing report.
