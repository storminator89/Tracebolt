#!/usr/bin/env python3
"""Inert updater fixtures. No real Docker, systemd, installer or network calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("test_vm_update", Path(__file__).with_name("test-vm.py"))
u = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(u)
COMMIT, TREE, OLD = "a" * 40, "b" * 40, "c" * 40
OLD_IMAGE, NEW_IMAGE = "sha256:" + "d" * 64, "sha256:" + "e" * 64
BINARIES = {v: [f"{v}-{role}".encode() for role in ("agent", "enroll", "helper")] for v in ("rc.2", "rc.3")}
RELEASES = {v: (u.digest((v + "-source").encode()), *(u.digest(raw) for raw in values)) for v, values in BINARIES.items()}


class Fixture:
    def __init__(self, version="rc.2"):
        self.files = {}
        self.commands, self.messages = [], []
        self.head, self.image = OLD, OLD_IMAGE
        self.remote, self.status, self.fetched, self.tree = u.REPOSITORY, b"", COMMIT, TREE
        self.running, self.responding, self.cancel, self.fail = True, True, False, None
        self.upgraded, self.bootstrap_called, self.waits = False, False, 0
        self.bootstrap_corrupt = False
        self.files[u.CONFIG + "/http-test.json"] = u.canonical(dict(profile="http-test", operatorOrigin=u.ORIGIN + ":8787", agentOrigin=u.ORIGIN + ":8788", insecureHTTPAcknowledged=True, stateDirectory="/data/state"))
        self.files[u.CONFIG + "/enrollment.json"] = u.canonical(dict(profile="http-test", collectionProfile="managed-operations-v3"))
        self.intent = u.canonical(dict(schemaVersion="tracebolt.read-admin-intent.v2", readProfile="tracebolt.linux-read-admin.v2", managerOrigin=u.ORIGIN + ":8788", deviceId="agent_" + "f" * 32))
        self.files[u.INTENT] = self.intent
        for phase in ("inventory", "journal", "socket"):
            for state in ("started", "complete"):
                self.files[u.CONTROL + "/read-admin-" + phase + "." + state + ".json"] = u.canonical(dict(schemaVersion="tracebolt.read-admin-phase.v2", intentSHA256=u.digest(self.intent), phase=phase, state=state))
        self.set_version(version)
        self.value = dict(Config={"Labels": {"com.docker.compose.project": u.PROJECT, "com.docker.compose.service": u.SERVICE}, "User": "65532:65532"},
                          HostConfig={"PortBindings": {"8787/tcp": [{"HostIp": u.IP, "HostPort": "8787"}], "8788/tcp": [{"HostIp": u.IP, "HostPort": "8788"}]}, "Privileged": False, "ReadonlyRootfs": True},
                          Mounts=[{"Type": "volume", "Name": u.VOLUME, "Destination": "/data"}, {"Type": "bind", "Source": u.CONFIG, "Destination": "/run/tracebolt", "RW": False}])

    def set_version(self, version):
        for name, raw in zip(("lan-agent", "enroll-agent", "socket-owner-reader"), BINARIES[version]):
            self.files["/opt/tracebolt-agent/" + name] = raw
        self.files["/opt/tracebolt-agent/installation.json"] = u.canonical(dict(profile="http-test", sourceHash=RELEASES[version][0], agentHash=RELEASES[version][1], enrollHash=RELEASES[version][2]))

    def say(self, value):
        self.messages.append(value)

    def prerequisites(self):
        if self.fail == "prerequisites":
            raise u.Rejected("unsupported-host")

    def read(self, path, limit=16384, optional=False):
        if optional:
            return self.files.get(path)
        return self.files[path]

    def absent(self, path):
        u.require(path not in self.files, "unresolved-agent-state")

    def command(self, argv, *, capture=True, timeout=60):
        self.commands.append(argv)
        if argv[:len(u.GIT)] == u.GIT:
            action = argv[len(u.GIT):]
            if action == ["config", "--local", "--name-only", "--list"]: return getattr(self, "git_config_names", b"core.repositoryformatversion\nremote.origin.url")
            if action == ["rev-parse", "--show-toplevel"]: return u.CHECKOUT.encode()
            if action == ["remote", "get-url", "origin"]: return self.remote.encode()
            if action == ["status", "--porcelain", "--untracked-files=all"]: return self.status
            if action == ["rev-parse", "HEAD"]: return self.head.encode()
            if action[0] == "fetch":
                if self.fail == "fetch": raise u.Rejected("fetch-failed")
                return b""
            if action == ["rev-parse", "FETCH_HEAD"]: return self.fetched.encode()
            if action == ["rev-parse", COMMIT + "^{tree}"]: return self.tree.encode()
            if action == ["checkout", "--detach", COMMIT]: self.head = COMMIT; return b""
        if argv[:len(u.STACK)] == u.STACK:
            action = argv[len(u.STACK):]
            if action == ["config", "--quiet"]: return b""
            if action == ["up", "-d", "--no-build", "--no-deps", u.SERVICE]:
                if self.fail == "up": raise u.Rejected("replace-uncertain")
                self.image = NEW_IMAGE
                return b""
        if argv[:len(u.DOCKER)] == u.DOCKER:
            action = argv[len(u.DOCKER):]
            if action == ["volume", "inspect", u.VOLUME, "--format", "{{.Name}}"]: return u.VOLUME.encode()
            if action[:2] == ["ps", "-aq"]: return b"0123456789ab"
            if action == ["inspect", "0123456789ab"]:
                value = copy.deepcopy(self.value)
                value.update(Image=self.image, State={"Running": self.running, "Restarting": False})
                return u.canonical([value])
            if action == ["build", "-t", u.IMAGE, "."]:
                if self.fail == "build": raise u.Rejected("build-failed")
                return b""
            if action == ["image", "inspect", u.IMAGE, "--format", "{{.Id}}"]: return NEW_IMAGE.encode()
        if argv[:2] == ["systemctl", "is-active"]:
            if self.fail == "agent-inactive": raise u.Rejected("inactive")
            return b"active"
        raise AssertionError("Unexpected command: " + repr(argv))

    def session_probe(self):
        return self.responding

    def pause(self):
        self.waits += 1

    def bootstrap(self):
        self.bootstrap_called = True
        if self.fail == "bootstrap": raise u.Rejected("bootstrap-sha256-mismatch")
        if self.cancel: return
        before = self.files.get(u.CURRENT)
        self.set_version("rc.3")
        binding = u.canonical(dict(schemaVersion="tracebolt.read-admin-upgrade-binding.v1", releaseManifestSHA256=u.RC3_MANIFEST_SHA256,
                     originalParentSHA256=u.digest(self.intent), previousBindingSHA256=u.digest(before) if before else ""))
        self.files[u.CURRENT] = binding
        if not self.bootstrap_corrupt:
            self.files[u.CONTROL + "/read-admin-upgrade-" + u.digest(binding) + ".complete.json"] = binding
        self.upgraded = True


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.releases = patch.object(u, "RELEASES", RELEASES)
        self.releases.start()
        self.addCleanup(self.releases.stop)
        # If a fixture accidentally calls a real process or network it fails.
        for target in ("subprocess.run", "subprocess.Popen", "http.client.HTTPConnection"):
            item = patch(target, side_effect=AssertionError("real effects forbidden"))
            item.start()
            self.addCleanup(item.stop)

    def fails(self, fixture, reason=None):
        with self.assertRaises((u.Rejected, KeyError)) as ctx:
            u.perform(fixture, COMMIT, TREE)
        if reason:
            self.assertEqual(str(ctx.exception), reason)
        return fixture

    def test_rc2_full_update(self):
        f = Fixture()
        self.assertEqual(u.perform(f, COMMIT, TREE), 0)
        self.assertTrue(f.upgraded)
        self.assertEqual(f.image, NEW_IMAGE)
        self.assertIn("Update completed:", f.messages[-1])
        self.assertEqual(f.files[u.INTENT], f.intent)
        self.assertEqual(f.commands.count(u.STACK + ["up", "-d", "--no-build", "--no-deps", u.SERVICE]), 1)

    def test_rc3_existing_can_complete_an_explicit_repeat(self):
        f = Fixture("rc.3")
        self.assertEqual(u.perform(f, COMMIT, TREE), 0)

    def test_malformed_pin_has_no_effects(self):
        f = Fixture()
        with self.assertRaises(u.Rejected): u.perform(f, "main", TREE)
        self.assertEqual(f.commands, [])

    def test_dirty_checkout_no_overwrite(self):
        f = Fixture(); f.status = b" M web/src/app.tsx"
        self.fails(f, "local-edits-stop-without-overwriting")
        self.assertEqual(f.head, OLD)
        self.assertFalse(f.bootstrap_called)
        self.assertFalse(any("fetch" in command for command in f.commands))

    def test_wrong_origin(self):
        f = Fixture(); f.remote = "https://example.com/fork.git"
        self.fails(f, "wrong-origin")
        self.assertEqual(f.image, OLD_IMAGE)

    def test_foreign_bindings(self):
        f = Fixture(); f.value["HostConfig"]["PortBindings"]["8787/tcp"][0]["HostIp"] = "0.0.0.0"
        self.fails(f, "manager-bindings-changed")
        self.assertEqual(f.head, OLD)

    def test_foreign_volume(self):
        f = Fixture(); f.value["Mounts"][0]["Name"] = "other-volume"
        self.fails(f, "manager-mounts-changed")

    def test_changed_ip_rejected(self):
        f = Fixture(); value = json.loads(f.files[u.CONFIG + "/http-test.json"]); value["agentOrigin"] = "http://192.168.0.222:8788"
        f.files[u.CONFIG + "/http-test.json"] = u.canonical(value)
        self.fails(f, "manager-origin-or-profile-changed")

    def test_basic_profile_rejected(self):
        f = Fixture(); f.files[u.CONFIG + "/enrollment.json"] = b'{}'
        self.fails(f, "complete-manager-profile-required")

    def test_incomplete_agent_phase_rejected(self):
        f = Fixture(); f.files[u.CONTROL + "/read-admin-socket.complete.json"] = b'{}'
        self.fails(f, "incomplete-agent-profile")

    def test_unresolved_upgrade_rejected(self):
        f = Fixture(); f.files[u.CONTROL + "/read-admin-upgrade-transaction.json"] = b'{}'
        self.fails(f, "unresolved-agent-state")

    def test_unpublished_binary_rejected(self):
        f = Fixture(); f.files["/opt/tracebolt-agent/socket-owner-reader"] = b"source-built-helper"
        self.fails(f, "only-published-rc2-or-rc3-supported")

    def test_inactive_agent_rejected_before_manager(self):
        f = Fixture(); f.fail = "agent-inactive"
        self.fails(f)
        self.assertEqual(f.head, OLD)

    def test_fetch_tree_mismatch_no_checkout(self):
        f = Fixture(); f.tree = "0" * 40
        self.fails(f, "reviewed-source-mismatch")
        self.assertEqual(f.head, OLD)

    def test_fetch_commit_mismatch_no_checkout(self):
        f = Fixture(); f.fetched = "0" * 40
        self.fails(f, "reviewed-source-mismatch")
        self.assertEqual(f.head, OLD)

    def test_build_failure_old_container_stays(self):
        f = Fixture(); f.fail = "build"
        self.fails(f)
        self.assertEqual(f.head, COMMIT)
        self.assertEqual(f.image, OLD_IMAGE)
        self.assertFalse(f.bootstrap_called)

    def test_uncertain_manager_replacement_never_upgrades_agent(self):
        f = Fixture(); f.fail = "up"
        self.fails(f)
        self.assertFalse(f.bootstrap_called)

    def test_manager_startup_failure_is_bounded(self):
        f = Fixture(); f.responding = False
        self.fails(f, "manager-startup-unconfirmed")
        self.assertEqual(f.waits, 29)
        self.assertFalse(f.bootstrap_called)

    def test_bootstrap_failure_does_not_claim_rollback(self):
        f = Fixture(); f.fail = "bootstrap"
        self.fails(f)
        self.assertEqual(f.image, NEW_IMAGE)
        self.assertIn("No automatic rollback", f.messages[-1])

    def test_exit_zero_cancellation_rc2_is_not_success(self):
        f = Fixture(); f.cancel = True
        self.fails(f, "agent-upgrade-canceled-or-completion-unconfirmed")
        self.assertFalse(any(m.startswith("Update completed:") for m in f.messages))

    def test_exit_zero_cancellation_rc3_is_not_success(self):
        f = Fixture("rc.3"); f.cancel = True
        f.files[u.CURRENT] = u.canonical(dict(prior="binding"))
        self.fails(f, "agent-upgrade-canceled-or-completion-unconfirmed")

    def test_new_binding_requires_immutable_completion(self):
        f = Fixture(); f.bootstrap_corrupt = True
        self.fails(f)
        self.assertFalse(any(m.startswith("Update completed:") for m in f.messages))

    def test_prior_binding_chain_is_preserved(self):
        f = Fixture("rc.3"); prior = u.canonical(dict(prior="binding")); f.files[u.CURRENT] = prior
        self.assertEqual(u.perform(f, COMMIT, TREE), 0)
        self.assertEqual(json.loads(f.files[u.CURRENT])["previousBindingSHA256"], u.digest(prior))

    def test_local_git_execution_configuration_rejected_before_status(self):
        for name in (b"core.fsmonitor", b"filter.custom.smudge", b"http.sslverify", b"include.path", b"url.file:///tmp/.insteadof", b"remote.origin.proxy", b"remote.origin.vcs", b"remote.origin.uploadpack", b"extensions.worktreeconfig"):
            f = Fixture(); f.git_config_names = name
            self.fails(f, "custom-git-execution-or-network-config-rejected")
            self.assertFalse(any("status" in c for c in f.commands))

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(u.Rejected): u.strict_json(b'{"profile":"http-test","profile":"tls"}')

    def test_no_shell_reset_or_installer_shortcut(self):
        f = Fixture(); u.perform(f, COMMIT, TREE)
        for command in f.commands:
            self.assertIsInstance(command, list)
            self.assertFalse(any(word in command for word in ("reset", "clean", "down", "rm", "prune", "restart", "sudo", "install")))
        self.assertIn("--env-file", u.STACK)
        self.assertIn("/dev/null", u.STACK)
        self.assertIn("--host=unix:///var/run/docker.sock", u.DOCKER)

    def test_download_contract_is_still_the_published_pin(self):
        path = Path(__file__).resolve().parents[1] / "release/published/v0.1.0-rc.3.py"
        self.assertEqual(u.digest(path.read_bytes()), u.BOOTSTRAP_SHA256)
        self.assertIn("/bba617e459bb072d4506fe6cacecaa97388ea93c/", u.BOOTSTRAP_URL)


class BootstrapTests(unittest.TestCase):
    def exercise(self, status=b"200", valid=True, exitcode=0, interrupt=False):
        import types
        import stat
        import signal
        payload = b"# inert verified fixture\n"
        host = u.Host()
        executed, downloads, signals = [], [], []
        original_mkdtemp = u.tempfile.mkdtemp
        original_fstat = u.os.fstat
        with tempfile.TemporaryDirectory() as root:
            def stage(*args, **kwargs):
                return original_mkdtemp(prefix="fixture-", dir=root)
            def fetch(argv, **kwargs):
                downloads.append(argv)
                destination = Path(argv[argv.index("--output") + 1])
                destination.write_bytes(payload if valid else b"corrupt")
                destination.chmod(0o600)
                return status
            def metadata(fd):
                value = original_fstat(fd)
                return types.SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_nlink=value.st_nlink, st_size=value.st_size)
            class Child:
                def send_signal(self, sig): signals.append(sig)
                def wait(self):
                    if interrupt: signal.getsignal(signal.SIGHUP)(signal.SIGHUP, None)
                    return exitcode
            def spawn(argv, **kwargs):
                executed.append((argv, kwargs))
                fd = kwargs["pass_fds"][0]
                self.assertEqual(os.read(fd, 131073), payload)
                self.assertFalse(list(Path(root).iterdir()))
                return Child()
            with patch.object(host, "command", side_effect=fetch), patch.object(u.tempfile, "mkdtemp", side_effect=stage), \
                 patch.object(u.os, "fstat", side_effect=metadata), patch.object(u, "BOOTSTRAP_SHA256", u.digest(payload)), \
                 patch.object(u.subprocess, "Popen", side_effect=spawn), patch.object(u.os, "tcgetpgrp", return_value=os.getpgrp()), \
                 patch.object(u.os, "tcsetpgrp"):

                error = None
                try: host.bootstrap()
                except u.Rejected as exc: error = str(exc)
            self.assertFalse(list(Path(root).iterdir()))
        return error, executed, downloads, signals

    def test_verified_descriptor_only_execution(self):
        error, executed, downloads, _ = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(len(executed), 1)
        argv, kwargs = executed[0]
        self.assertEqual(argv[:3], ["/usr/bin/python3", "-I", "-B"])
        self.assertTrue(argv[3].startswith("/proc/self/fd/"))
        self.assertEqual(argv[4:], ["--action", "upgrade", "--upgrade-read-admin", "--apply", "--insecure-http-test"])
        self.assertEqual(set(kwargs), {"env", "pass_fds", "preexec_fn"})
        self.assertIs(kwargs["preexec_fn"], u.foreground_child)
        self.assertEqual(set(kwargs["env"]), {"PATH", "LANG", "LC_ALL"})
        self.assertEqual(downloads[0][-1], u.BOOTSTRAP_URL)
        for flag, value in (("--proto", "=https"), ("--proxy", ""), ("--noproxy", "*"), ("--max-redirs", "0")):
            self.assertEqual(downloads[0][downloads[0].index(flag)+1], value)

    def test_redirect_never_executes(self):
        error, executed, _, _ = self.exercise(status=b"302")
        self.assertEqual(error, "bootstrap-http-200-required")
        self.assertEqual(executed, [])

    def test_hash_mismatch_never_executes(self):
        error, executed, _, _ = self.exercise(valid=False)
        self.assertEqual(error, "bootstrap-sha256-mismatch")
        self.assertEqual(executed, [])

    def test_installer_failure_preserved(self):
        error, _, _, _ = self.exercise(exitcode=1)
        self.assertEqual(error, "agent-upgrade-incomplete")

    def test_hangup_requests_coordinator_term_containment(self):
        import signal
        error, _, _, signals = self.exercise(exitcode=1, interrupt=True)
        self.assertEqual(error, "agent-upgrade-incomplete")
        self.assertEqual(signals, [signal.SIGTERM])


class CommandRendererTests(unittest.TestCase):
    def test_one_line_exact_pins_and_shell_syntax(self):
        import subprocess
        spec = importlib.util.spec_from_file_location("prepare_command", Path(__file__).with_name("prepare-test-vm-command.py"))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        value = module.command("1" * 40, COMMIT, TREE)
        self.assertNotIn("\n", value)
        parsed = shlex.split(value)
        self.assertEqual(parsed[:2], ["/usr/bin/env", "-i"])
        shell = parsed[-1]
        self.assertIn("/" + "1" * 40 + "/deploy/update/test-vm.py", shell)
        self.assertIn(u.digest(Path(__file__).with_name("test-vm.py").read_bytes()), shell)
        self.assertIn("--manager-commit " + COMMIT, shell)
        self.assertIn("--manager-tree " + TREE, shell)
        self.assertIn("exec python3 -I -B /proc/self/fd/3", shell)
        # Syntax-only shell parsing: no line is executed.
        subprocess.run(["/bin/sh", "-n", "-c", shell], check=True)
        with self.assertRaises(ValueError): module.command("main", COMMIT, TREE)


if __name__ == "__main__":
    unittest.main()
