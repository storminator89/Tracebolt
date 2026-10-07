#!/usr/bin/env python3
"""Bounded update of one existing Debian 13 amd64 HTTP test VM. Inert on import.

No reset, installation, enrollment, grant, dependency install or automatic repair.
The published rc.3 bootstrap remains the sole authority for the agent update.
"""
import argparse
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

REPOSITORY = "https://github.com/storminator89/Tracebolt.git"
CHECKOUT = "/root/tracebolt-rc2-test"
CONFIG = "/etc/tracebolt-http-complete-test"
PROJECT = "tracebolt-rc2-test"
VOLUME = PROJECT + "_http-complete-state"
SERVICE = "manager-http-complete-test"
COMPOSE = "deploy/compose.http-complete-test.yaml"
IMAGE = "tracebolt-manager:http-complete-test"
IP = "192.168.0.221"
ORIGIN = "http://" + IP
CONTROL = "/var/lib/tracebolt-agent-installer"
INTENT = CONTROL + "/read-admin-intent.json"
CURRENT = CONTROL + "/read-admin-upgrade-current.json"
BOOTSTRAP_URL = "https://raw.githubusercontent.com/storminator89/Tracebolt/bba617e459bb072d4506fe6cacecaa97388ea93c/deploy/release/published/v0.1.0-rc.3.py"
BOOTSTRAP_SHA256 = "5071d6ecb5933c70c9ee9be8a2ff0b4c0b48fbd6084ea83065b8c5cf634cc231"
RC3_MANIFEST_SHA256 = "93db5f49635fd40e9ac81c5434aa0c7f1500b7920d2063d84eac621cd71f5c07"
# Public bytes from the independently verified rc.2/rc.3 manifests. The
# bootstrap still verifies rc.3's manifest, Sigstore provenance and every asset.
RELEASES = {
    "rc.2": ("3813b61b0565e9becd8c6921769b8448437d5c0adca4348ba4cbff8510356856", "6e1ac6ca7b50ae11141b1d345dc69cd59e0ff97583aa3cefd52152b209509bb5", "44a2235072459cc73fc918c9596e51fe441407b721f3d7cfc2b796fc1bbe645c", "5e360633dbc1acda24acd5b24317f3ce7619af7598dd7ed6119f5d5c4e5585f8"),
    "rc.3": ("6e8dee99b99d77ef61bf16fe4920beb105040b8b89400468dcfc4cfa8a427a98", "0f70903e349276abaee123be2e1939e81331757753ac70ac50f2452f1a54c91e", "6dcf5b8108958b4c2a638fb3d7a02fa2723099bee4a46fc981cea782a7d346b5", "21ea4df0a99f1f57e18ae4daea37d88aa34c5f3f7a538dbda70e6a5206e0de49"),
}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
       "TRACEBOLT_HTTP_TEST_BIND_IP": IP, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.proxy=", "-c", "http.followRedirects=false", "-c", "http.sslVerify=true", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never"]
DOCKER = ["docker", "--host=unix:///var/run/docker.sock"]
STACK = DOCKER + ["compose", "--env-file", "/dev/null", "-p", PROJECT, "-f", COMPOSE]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Rejected(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Rejected(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, "duplicate-json-field")
            obj[key] = value
        return obj
    return json.loads(raw, object_pairs_hook=unique)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def stamp(entry):
    return tuple(getattr(entry, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def parent_paths(*paths):
    checked, blocked, rejected = set(), set(), []
    for path in paths:
        for part in reversed(Path(path).parents):
            if part in checked or any(parent in blocked for parent in part.parents):
                continue
            checked.add(part)
            try:
                entry = part.lstat()
            except FileNotFoundError:
                reasons = ["missing-parent-directory"]
                blocked.add(part)
            except OSError:
                reasons = ["parent-metadata-unavailable"]
                blocked.add(part)
            else:
                if not stat.S_ISDIR(entry.st_mode):
                    reasons = ["symlink" if stat.S_ISLNK(entry.st_mode) else "not-directory"]
                    blocked.add(part)
                else:
                    reasons = []
                    if entry.st_uid not in (0, 65532):
                        reasons.append("untrusted-owner")
                    if entry.st_mode & 0o022:
                        reasons.append("group-or-other-writable")
            if reasons:
                rejected.append(str(part) + " (" + ", ".join(reasons) + ")")
    # Only fixed parent paths and reason categories are reported, never file
    # contents or symlink targets. Do not inspect below a missing/non-directory
    # parent or follow a symlink while collecting the other parent families.
    require(not rejected, "unprotected-parent-directory: " + "; ".join(rejected))


class Host:
    def say(self, message):
        print(message, flush=True)

    def read(self, path, limit=16384, optional=False):
        parent_paths(path)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except FileNotFoundError:
            if optional:
                return None
            raise
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, 65532)
                    and not before.st_mode & 0o022 and 0 < before.st_size <= limit, "protected-file-required")
            raw = stream.read(limit + 1)
            require(len(raw) == before.st_size and stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(os.lstat(path)),
                    "file-changed-during-read")
            return raw

    def absent(self, path):
        parent_paths(path)
        require(not os.path.lexists(path), "unresolved-agent-state")

    def command(self, argv, *, capture=True, timeout=60):
        # Never print private command output on a failure. Fixed public build
        # output and the verified bootstrap's own disclosures stay on the TTY.
        result = subprocess.run(argv, cwd=CHECKOUT, env=ENV, check=False,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.PIPE if capture else None, timeout=timeout)
        require(result.returncode == 0, "fixed-command-failed")
        require(not capture or len(result.stdout) <= 1048576, "command-output-too-large")
        return result.stdout.strip() if capture else b""

    def prerequisites(self):
        require(os.getuid() == os.geteuid() == 0, "run-explicitly-as-root")
        require(sys.version_info >= (3, 11) and platform.system() == "Linux" and platform.machine() == "x86_64",
                "debian-13-amd64-required")
        distro = platform.freedesktop_os_release()
        require(distro.get("ID") == "debian" and distro.get("VERSION_ID") == "13", "debian-13-required")
        require(sys.stdin.isatty() and os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp(), "foreground-local-terminal-required")
        with open("/dev/tty", "rb", buffering=0) as tty:
            require(tty.isatty(), "controlling-terminal-required")
        for path in ("/usr/bin/git", "/usr/bin/docker", "/usr/bin/curl", "/usr/bin/python3", "/usr/bin/systemctl"):
            require(os.path.isfile(path) and os.access(path, os.X_OK), "missing-prerequisite-no-tools-installed")
        require(Path("/proc/1/comm").read_text().strip() == "systemd" and Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
                "systemd-and-cgroup-v2-required")
        require(not os.statvfs("/tmp").f_flag & os.ST_NOEXEC, "tmp-noexec-not-supported")
        parent_paths(CHECKOUT + "/.git/config", CONFIG + "/http-test.json", INTENT,
                     "/opt/tracebolt-agent/installation.json")
        self.command(DOCKER + ["info", "--format", "{{.OSType}} {{.Architecture}}"])
        require(self.command(DOCKER + ["compose", "version", "--short"]).startswith(b"2."), "compose-v2-required")

    def session_probe(self):
        connection = http.client.HTTPConnection(IP, 8787, timeout=3)
        try:
            connection.request("GET", "/api/auth/session", headers={"Accept": "application/json", "Connection": "close"})
            response = connection.getresponse()
            raw = response.read(8193)
            require(response.status == 200 and len(raw) <= 8192, "manager-session-unavailable")
            value = strict_json(raw)
            return all(value.get(k) == v for k, v in {"mode": "lan", "transport": "http", "insecureTestMode": True,
                       "authenticationRequired": True, "authenticated": False}.items())
        finally:
            connection.close()

    def pause(self):
        time.sleep(2)

    def bootstrap(self):
        directory = Path(tempfile.mkdtemp(prefix="tracebolt-test-update-", dir="/tmp"))
        path = directory / "bootstrap.py"
        try:
            status = self.command(["curl", "-q", "--fail", "--silent", "--show-error", "--proto", "=https", "--proto-redir", "=https",
                "--proxy", "", "--noproxy", "*", "--max-redirs", "0", "--connect-timeout", "10", "--max-time", "60",
                "--max-filesize", "131072", "--output", str(path), "--write-out", "%{http_code}", BOOTSTRAP_URL], timeout=70)
            require(status == b"200", "bootstrap-http-200-required")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                        stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 131072, "bootstrap-file-rejected")
                raw = os.read(fd, 131073)
                require(digest(raw) == BOOTSTRAP_SHA256, "bootstrap-sha256-mismatch")
                os.lseek(fd, 0, os.SEEK_SET)
                path.unlink()
                directory.rmdir()
                # The verified descriptor survives exec; no pathname is reopened.
                # Input stays attached to the real foreground terminal.
                command = ["/usr/bin/python3", "-I", "-B", "/proc/self/fd/" + str(fd), "--action", "upgrade",
                           "--upgrade-read-admin", "--apply", "--insecure-http-test"]
                code = run_foreground(command, {k: ENV[k] for k in ("PATH", "LANG", "LC_ALL")}, (fd,))
                require(code == 0, "agent-upgrade-incomplete")
            finally:
                os.close(fd)
        finally:
            # Exact files only; never recurse or clear installer evidence.
            if os.path.lexists(path):
                path.unlink()
            if directory.exists():
                directory.rmdir()


def foreground_child():
    """Same session/TTY, distinct foreground group; called only before exec.

    This single-threaded wrapper never starts threads before Popen. Ignoring HUP
    survives exec; the immutable bootstrap replaces INT/TERM handlers itself.
    A separate group keeps terminal Ctrl+C from also reaching the parent and
    being forwarded a second time during the coordinator's containment.
    """
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    os.setpgid(0, 0)
    os.tcsetpgrp(0, os.getpgrp())
    signal.signal(signal.SIGTTOU, signal.SIG_DFL)


def run_foreground(command, environment, descriptors):
    terminal = sys.stdin.fileno()
    previous_group = os.tcgetpgrp(terminal)
    require(previous_group == os.getpgrp(), "bootstrap-requires-foreground-terminal")
    child = None
    pending, forwarded = set(), set()
    def forward(signum, _frame):
        requested = signal.SIGTERM if signum == signal.SIGHUP else signum
        if child is None:
            pending.add(requested)
        elif requested not in forwarded:
            forwarded.add(requested)
            try:
                child.send_signal(requested)
            except ProcessLookupError:
                pass
    previous_handlers = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    restored = False
    try:
        # Do not create a new session: bootstrap inspect_terminal and local
        # confirmation must retain their original controlling /dev/tty.
        child = subprocess.Popen(command, env=environment, pass_fds=descriptors, preexec_fn=foreground_child)
        for signum in pending:
            forward(signum, None)
        code = child.wait()
    finally:
        # We are now in a background group. Temporarily ignore TTOU only for
        # restoration; preserve its original disposition afterward.
        old_ttou = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        try:
            os.tcsetpgrp(terminal, previous_group)
            restored = True
        except OSError:
            # A closed terminal cannot be restored. Never turn that uncertainty
            # into a success report or kill an active coordinator as cleanup.
            pass
        finally:
            signal.signal(signal.SIGTTOU, old_ttou)
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
    require(restored, "foreground-terminal-unavailable-after-upgrade")
    return code


def inspect_repository(host):
    names = host.command(GIT + ["config", "--local", "--name-only", "--list"]).decode("ascii").lower().splitlines()
    require(not any(name.startswith(("include.", "includeif.", "filter.", "http.", "url.")) or
                    name in ("core.fsmonitor", "core.gitproxy", "core.sshcommand", "extensions.worktreeconfig") or
                    (name.startswith("remote.") and name.endswith((".proxy", ".vcs", ".uploadpack"))) for name in names), "custom-git-execution-or-network-config-rejected")
    require(host.command(GIT + ["rev-parse", "--show-toplevel"]) == CHECKOUT.encode(), "wrong-checkout")
    require(host.command(GIT + ["remote", "get-url", "origin"]) == REPOSITORY.encode(), "wrong-origin")
    require(host.command(GIT + ["status", "--porcelain", "--untracked-files=all"]) == b"", "local-edits-stop-without-overwriting")
    return host.command(GIT + ["rev-parse", "HEAD"]).decode("ascii")


def inspect_agent(host):
    for leaf in ("transaction.json", "read-admin-upgrade-transaction.json"):
        host.absent(CONTROL + "/" + leaf)
    raw = host.read(INTENT)
    intent = strict_json(raw)
    require(intent.get("schemaVersion") == "tracebolt.read-admin-intent.v2" and
            intent.get("readProfile") == "tracebolt.linux-read-admin.v2" and intent.get("managerOrigin") == ORIGIN + ":8788"
            and raw == canonical(intent), "completed-http-read-admin-v2-required")
    for phase in ("inventory", "journal", "socket"):
        for state in ("started", "complete"):
            expected = dict(schemaVersion="tracebolt.read-admin-phase.v2", intentSHA256=digest(raw), phase=phase, state=state)
            require(host.read(CONTROL + "/read-admin-" + phase + "." + state + ".json") == canonical(expected), "incomplete-agent-profile")
    manifest = strict_json(host.read("/opt/tracebolt-agent/installation.json"))
    actual = (manifest.get("sourceHash"), digest(host.read("/opt/tracebolt-agent/lan-agent", 128 << 20)),
              digest(host.read("/opt/tracebolt-agent/enroll-agent", 128 << 20)), digest(host.read("/opt/tracebolt-agent/socket-owner-reader", 128 << 20)))
    require(manifest.get("profile") == "http-test" and manifest.get("agentHash") == actual[1] and manifest.get("enrollHash") == actual[2], "agent-installation-mismatch")
    versions = [version for version, expected in RELEASES.items() if actual == expected]
    require(len(versions) == 1, "only-published-rc2-or-rc3-supported")
    for unit in ("tracebolt-agent.service", "tracebolt-journal-reader.socket", "tracebolt-socket-owner-reader.socket"):
        require(host.command(["systemctl", "is-active", unit]) == b"active", "existing-agent-and-sockets-must-be-active")
    return raw, host.read(CURRENT, optional=True), versions[0]


def inspect_config(host):
    raw = host.read(CONFIG + "/http-test.json")
    value = strict_json(raw)
    require(all(value.get(k) == v for k, v in {"profile": "http-test", "operatorOrigin": ORIGIN + ":8787",
            "agentOrigin": ORIGIN + ":8788", "insecureHTTPAcknowledged": True, "stateDirectory": "/data/state"}.items()), "manager-origin-or-profile-changed")
    enrolled = strict_json(host.read(CONFIG + "/enrollment.json"))
    require(enrolled.get("collectionProfile") == "managed-operations-v3" and enrolled.get("profile") == "http-test", "complete-manager-profile-required")
    require(host.command(DOCKER + ["volume", "inspect", VOLUME, "--format", "{{.Name}}"]) == VOLUME.encode(), "existing-volume-required")
    return digest(raw)


def inspect_container(host, expected_image=None):
    ids = host.command(DOCKER + ["ps", "-aq", "--filter", "label=com.docker.compose.project=" + PROJECT,
                               "--filter", "label=com.docker.compose.service=" + SERVICE]).splitlines()
    require(len(ids) == 1 and re.fullmatch(rb"[0-9a-f]{12,64}", ids[0]), "one-existing-manager-container-required")
    value = strict_json(host.command(DOCKER + ["inspect", ids[0].decode("ascii")]))[0]
    config = value["HostConfig"]
    require(value["Config"]["Labels"].get("com.docker.compose.project") == PROJECT and
            value["Config"]["Labels"].get("com.docker.compose.service") == SERVICE, "manager-container-label-mismatch")
    require(config["PortBindings"] == {"8787/tcp": [{"HostIp": IP, "HostPort": "8787"}],
                                      "8788/tcp": [{"HostIp": IP, "HostPort": "8788"}]}, "manager-bindings-changed")
    mounts = value["Mounts"]
    require(len(mounts) == 2 and any(m.get("Type") == "volume" and m.get("Name") == VOLUME and m.get("Destination") == "/data" for m in mounts)
            and any(m.get("Type") == "bind" and m.get("Source") == CONFIG and m.get("Destination") == "/run/tracebolt" and m.get("RW") is False for m in mounts), "manager-mounts-changed")
    require(not config.get("Privileged") and config.get("ReadonlyRootfs") is True and value["Config"].get("User") == "65532:65532",
            "manager-isolation-changed")
    if expected_image:
        require(value["Image"] == expected_image and value["State"]["Running"] is True and not value["State"].get("Restarting"), "new-manager-not-running")
    return value["Image"]


def wait_manager(host, image):
    for attempt in range(30):
        try:
            inspect_container(host, image)
            if host.session_probe():
                return
        except (Rejected, OSError, ValueError, http.client.HTTPException):
            pass
        if attempt != 29:
            host.pause()
    raise Rejected("manager-startup-unconfirmed")


def perform(host, commit, tree):
    phase = "preflight"
    try:
        require(HEX40.fullmatch(commit) and HEX40.fullmatch(tree), "full-reviewed-commit-and-tree-required")
        host.prerequisites()
        previous = inspect_repository(host)
        config = inspect_config(host)
        old_image = inspect_container(host)
        intent, before_binding, version = inspect_agent(host)
        host.say("Update only " + CHECKOUT + " on " + IP + ": manager " + previous + " -> " + commit + "; agent " + version + " -> rc.3.")
        host.say("Existing identity, scopes, passwords, configuration and volume stay. Manager and agent updates are separate; there is no combined rollback. A VM snapshot is the reliable whole-VM rollback. Keep this terminal open.")
        phase = "fetch"
        host.command(GIT + ["fetch", "--no-tags", "--no-recurse-submodules", "origin", commit], timeout=300)
        require(host.command(GIT + ["rev-parse", "FETCH_HEAD"]) == commit.encode() and
                host.command(GIT + ["rev-parse", commit + "^{tree}"]) == tree.encode(), "reviewed-source-mismatch")
        require(inspect_repository(host) == previous, "checkout-changed-after-preflight")
        phase = "checkout"
        host.command(GIT + ["checkout", "--detach", commit])
        require(inspect_repository(host) == commit, "checkout-verification-failed")
        host.command(STACK + ["config", "--quiet"])
        phase = "build"
        host.say("Building the pinned manager/UI; the existing container keeps running until the build succeeds.")
        host.command(DOCKER + ["build", "-t", IMAGE, "."], capture=False, timeout=1800)
        image = host.command(DOCKER + ["image", "inspect", IMAGE, "--format", "{{.Id}}"] ).decode("ascii")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "built-image-id-required")
        require(inspect_repository(host) == commit and inspect_config(host) == config and inspect_container(host) == old_image,
                "manager-changed-before-replacement")
        phase = "manager-replacement"
        host.command(STACK + ["up", "-d", "--no-build", "--no-deps", SERVICE], capture=False, timeout=180)
        phase = "manager-startup"
        wait_manager(host, image)
        host.say("Pinned manager container and unauthenticated login endpoint are responding. This is startup evidence; device reporting is checked separately in the dashboard.")
        require(inspect_agent(host) == (intent, before_binding, version), "agent-changed-before-upgrade")
        phase = "agent-upgrade"
        host.bootstrap()
        phase = "agent-postcheck"
        after_intent, after_binding, after_version = inspect_agent(host)
        require(after_intent == intent and after_version == "rc.3" and after_binding and after_binding != before_binding,
                "agent-upgrade-canceled-or-completion-unconfirmed")
        binding = strict_json(after_binding)
        require(binding.get("schemaVersion") == "tracebolt.read-admin-upgrade-binding.v1" and
                binding.get("releaseManifestSHA256") == RC3_MANIFEST_SHA256 and binding.get("originalParentSHA256") == digest(intent)
                and binding.get("previousBindingSHA256") == (digest(before_binding) if before_binding else ""), "rc3-completion-binding-mismatch")
        require(host.read(CONTROL + "/read-admin-upgrade-" + digest(after_binding) + ".complete.json") == after_binding,
                "immutable-upgrade-completion-required")
        phase = "final-manager-check"
        require(inspect_config(host) == config, "manager-config-changed")
        wait_manager(host, image)
        host.say("Update completed: manager " + commit + "; image " + image + "; verified agent rc.3; existing identity and scopes retained by its coordinator. Open " + ORIGIN + ":8787 and check fresh accepted reports for the same device, journals and socket owners. Debian/HTTP functional and OS reboot acceptance remain local checks.")
        return 0
    except (Rejected, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError, KeyboardInterrupt):
        if phase == "preflight":
            host.say("STOP at preflight. No manager or agent update occurred. The download wrapper may have created its temporary file and this updater may have created its advisory lock. No automatic repair was attempted. Inspect the reported preflight failure locally.")
        else:
            host.say("STOP at " + phase + ". No automatic rollback or repair was attempted. Manager source/image/state may already be newer; the agent may be unchanged or contained/stopped by its coordinator. Preserve its reported failure, receipts, backups and private state. Do not erase evidence, reinstall or blindly rerun. Inspect the named phase locally.")
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument("--manager-commit", required=True)
    parser.add_argument("--manager-tree", required=True)
    parser.add_argument("--apply", action="store_true", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        # A dedicated advisory lock only coordinates copies of this wrapper.
        # The existing agent installer retains its independent protected lock.
        require(os.getuid() == os.geteuid() == 0, "run-explicitly-as-root")
        parent_paths("/run/tracebolt-test-vm-update.lock")
        fd = os.open("/run/tracebolt-test-vm-update.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            entry = os.fstat(fd)
            require(stat.S_ISREG(entry.st_mode) and entry.st_uid == 0 and entry.st_nlink == 1 and stat.S_IMODE(entry.st_mode) == 0o600,
                    "update-lock-rejected")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return perform(Host(), args.manager_commit, args.manager_tree)
        finally:
            os.close(fd)
    except (Rejected, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print("Tracebolt test update: " + (str(error) if isinstance(error, Rejected) else "operation-unconfirmed"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
