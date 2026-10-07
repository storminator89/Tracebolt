# One-command existing test-VM update

This is a **bounded candidate for one existing Debian 13 amd64 VM**, not a fresh
installer or universal reset tool. The script is `deploy/update/test-vm.py`.
Local fixtures are not native Debian/HTTP acceptance. Do not present it as a
completed user-host update or use it with an unaccepted manager revision.

The publisher renders one shell line using the offline helper:

```sh
python3 -B deploy/update/prepare-test-vm-command.py --updater-commit FULL_PUBLISHED_UPDATER_COMMIT --manager-commit FULL_ACCEPTED_MANAGER_COMMIT --manager-tree FULL_ACCEPTED_MANAGER_TREE
```

Use the exact resulting line in the VM's existing root terminal. The separate
updater commit pins the script URL and SHA-256; the explicit manager commit and
tree pin the build. This avoids a circular self-commit dependency. The rendered
command clears ambient environment, requires root and a real terminal, downloads
only over strict HTTPS without a proxy or redirect, checks SHA-256, unlinks its
private staging file and executes the open descriptor with isolated Python.
No dependency is installed. The script's rc.3 download independently repeats that
contract and executes its verified open descriptor (whose number may differ from
3 because the updater lock and source descriptor are open).

The bootstrap stays in the same controlling-terminal session and gets its own
foreground process group. It inherits ignored SIGHUP; the shell-tracked wrapper
forwards a hangup as the coordinator's handled SIGTERM. A real terminal Ctrl+C
reaches the foreground child once instead of being forwarded twice. The wrapper
restores foreground ownership when the child finishes. Closing the terminal still
means the final terminal/check status is unconfirmed; it is never reported as a
success. Fixtures cover an interactive bash job with actual PTY closure, not just
a signal sent directly to a parent handler.

## Supported starting state

- Debian **13**, Linux **amd64**, Python 3.11+, systemd PID 1 and cgroup v2.
  Git, curl, system CA certificates, Docker Engine and Compose **v2** must exist.
  `/tmp` must permit the published bootstrap's native verified executables.
- Existing clean repository `/root/tracebolt-rc2-test` with exact official HTTPS
  origin. No tracked or untracked edits may be present; normal ignored build
  outputs stay. Git includes, filters, fsmonitor and custom HTTP/URL rewriting
  settings, remote-specific proxies/custom transport helpers and worktree config
  are rejected. Nothing is reset or force-overwritten.
- Existing project `tracebolt-rc2-test`, exactly one manager service container,
  config `/etc/tracebolt-http-complete-test`, named volume
  `tracebolt-rc2-test_http-complete-state`, UID/GID 65532, read-only root filesystem,
  and the existing fixed bindings **192.168.0.221:8787/8788**. Docker is explicitly
  addressed through the local Unix socket, not an ambient remote context.
- Existing manager HTTP config and full `managed-operations-v3` enrollment
  profile for that address. Compose loads no ambient `.env` file.
- An already completed `tracebolt.linux-read-admin.v2` installation with exact
  published **rc.2 or rc.3** agent, enrollment and socket-helper bytes, active
  agent plus journal/socket-owner sockets, all original phase receipts, and no
  unresolved native/read-admin transaction. The unchanged rc.3 coordinator does
  the authoritative detailed scope, ownership, lifecycle and private-state checks.
  Revoked, disabled, incomplete, foreign, changed-address, source-built or basic
  installations are not repaired or upgraded through a fallback.

## What happens

1. Validate the fixed starting state without exposing private state or passwords.
2. Fetch only the explicit manager commit, verify commit and tree, detach the clean
   checkout, validate Compose and build the manager/UI. The old container remains
   until the build succeeds. Docker base image tags retain the repository's
   existing nondeterministic build limitation; the resulting image ID is recorded.
3. Replace only the existing manager service with `up -d --no-build --no-deps`.
   Verify its actual image ID, mount/bind contract, running state and unauthenticated
   LAN/HTTP login endpoint. This establishes startup, not accepted agent reports.
4. Download and SHA-256-check the unchanged rc.3 bootstrap from publication
   `bba617e459bb072d4506fe6cacecaa97388ea93c`. It verifies release provenance and
   artifacts and asks for **UPGRADE READ ADMIN OVER HTTP** in the local terminal.
   Keep the terminal open. No invitation or new device approval is involved.
5. Require the same original intent, rc.3 source/binary hashes, active services,
   absent unresolved transaction, and a newly advanced immutable rc.3 coordinator
   binding chained to its predecessor. The bootstrap's exit zero on cancellation
   is explicitly **not** sufficient for success. Finally recheck manager startup.

The manager checkout, image and container change. The coordinator replaces only
its existing approved agent/enrollment/socket-helper executables and their
same-scope bindings, preserving identity, private state, original receipts and
startup enablement. Its owned systemd failure/start-limit counters reset. Original
HTTP exposure, passwords, trust, approved scopes and data volume stay. No package
installation, journal-content read, scope grant, credential creation, reset,
recursive delete, automatic renewal, firewall change, action helper or AI-provider
configuration is added. A repeated rc.3-to-rc.3 invocation is still an explicit
coordinated upgrade with a new history entry; it is not a repair or silent no-op.

## Stops and recovery boundaries

This is **not an atomic manager-plus-agent transaction**. A normal VM snapshot is
the reliable rollback of the whole VM. The manager may migrate its SQLite store,
so merely starting an older image is not a safe database rollback. No snapshot,
manager-state backup or cross-component rollback is implemented here.

- Before checkout, rejection leaves manager/agent programs unchanged, apart from
  fetching source into Git after preflight. The dedicated updater lock is a small
  root-owned file in `/run` and is advisory for copies of this wrapper only.
- A checkout/build failure can leave the working tree at the new revision with the
  old manager container still running. No agent upgrade has happened.
- Replacement/startup failure may leave a changed or unavailable manager. No
  agent upgrade is attempted after that failed startup check.
- Canceling or failing the agent upgrade leaves the already-updated manager.
  Follow the coordinator's exact result. An uncertain transaction can leave owned
  participants stopped with retained evidence; preserve every receipt, transaction,
  public backup and private state. Do not reinstall, delete evidence or blindly
  retry. The script never claims a manager rollback from agent rollback.
- Any later failed postcheck reports incomplete even if some changes succeeded.
  Process/HTTP startup does not prove telemetry, journal content, socket ownership,
  feature behavior or an OS reboot. Check fresh accepted reports for the same
  device and the documented function checks in the dashboard afterward.

Only the original twelve-command guide's existing functionality is composed.
That delivered guide remains unchanged. No Docker daemon, systemd unit, installer,
CI dispatch or user host was exercised by the local script fixtures.
