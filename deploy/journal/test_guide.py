"""Inert guide fixtures. No systemd, journal, root paths or network is used."""
import copy
import importlib.util
import io
import json
import os
import pty
import select
import signal
import sys
import time
from pathlib import Path
import shlex
import stat
import types
import unittest
from unittest import mock

import test_amend as amendment


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


g = load("journal_guide_test", "guide.py")
c = load("journal_guide_command_test", "prepare-guide-command.py")
a, s = amendment.a, amendment.s
REVISION = "a" * 40


class Sources:
    def __init__(self):
        self.files = {g.GUIDE_FILE: b"inert reviewed guide"}
        self.remote = {name: ("synthetic source " + name).encode() for name in g.CORE_FILES}
        self.manifest = dict(schemaVersion=g.MANIFEST_VERSION, files={name: dict(sha256=g.sha256(raw), size=len(raw)) for name, raw in self.remote.items()})
        self.files[g.MANIFEST_FILE] = g.canonical(self.manifest)
        self.created = []
        self.state = "initial"
        self.downloads = []

    def path(self, relative):
        return "/synthetic-protected/" + relative

    def read(self, relative, limit):
        raw = self.files[relative]
        g.require(len(raw) <= limit, "fixture-source-limit")
        return raw

    def cache_state(self):
        if self.state == "partial":
            raise g.Rejected("partial-or-foreign-source-cache")
        return self.state

    def mkdir(self):
        g.require(self.state == "initial", "fixture-create-only")
        self.state = "partial"
        self.created.append("systemd/")

    def create(self, name, raw):
        g.require(name not in self.files, "fixture-create-only")
        self.files[name] = raw
        self.created.append(name)
        if set(g.CORE_FILES) <= set(self.files):
            self.state = "complete"

    def fetch(self, url, limit):
        self.downloads.append(url)
        prefix = g.REPOSITORY + REVISION + "/"
        g.require(url.startswith(prefix), "fixture-immutable-origin")
        return self.remote[url[len(prefix):]]

    def stage(self):
        return g.stage_sources(self, REVISION, self.files[g.MANIFEST_FILE],
                               g.sha256(self.files[g.GUIDE_FILE]), g.sha256(self.files[g.MANIFEST_FILE]), self.fetch)


class SourceTests(unittest.TestCase):
    def test_exact_sources_verified_before_load_and_complete_cache_reusable(self):
        f = Sources()
        expected = f.stage()
        self.assertEqual(len(expected), 7)
        self.assertEqual(f.created, ["systemd/", *g.CORE_FILES])
        self.assertEqual(len(f.downloads), 5)
        self.assertEqual(f.stage(), expected)
        self.assertEqual(len(f.downloads), 5)

    def test_bad_download_retains_partial_and_cannot_retry(self):
        f = Sources()
        f.remote[g.CORE_FILES[1]] += b"tamper"
        with self.assertRaisesRegex(g.Rejected, "source-download-verification"):
            f.stage()
        before = copy.deepcopy(f.files)
        self.assertEqual(f.created, ["systemd/", g.CORE_FILES[0]])
        with self.assertRaisesRegex(g.Rejected, "partial-or-foreign"):
            f.stage()
        self.assertEqual(f.files, before)

    def test_complete_cache_with_changed_bytes_denied(self):
        f = Sources()
        f.stage()
        f.files[g.CORE_FILES[0]] = b"x" * len(f.files[g.CORE_FILES[0]])
        with self.assertRaisesRegex(g.Rejected, "source-staging-changed"):
            f.stage()

    def test_manifest_rejects_unknown_path_duplicates_and_unbounded_sizes(self):
        f = Sources()
        cases = []
        for mutation in (lambda x: x["files"].update({"../../foreign.py": x["files"][g.CORE_FILES[0]]}),
                         lambda x: x["files"][g.CORE_FILES[0]].update(size=True),
                         lambda x: x["files"][g.CORE_FILES[0]].update(size=g.MAX_SOURCE_BYTES + 1),
                         lambda x: x["files"][g.CORE_FILES[0]].update(sha256="A" * 64)):
            value = copy.deepcopy(f.manifest)
            mutation(value)
            cases.append(g.canonical(value))
        cases.append(b'{"schemaVersion":"x",' + f.files[g.MANIFEST_FILE][1:])
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises(g.Rejected):
                g.source_manifest(raw)

    def test_untrusted_guide_hash_fails_before_source_creation(self):
        f = Sources()
        with self.assertRaisesRegex(g.Rejected, "reviewed-launcher-hashes"):
            g.stage_sources(f, REVISION, f.files[g.MANIFEST_FILE], "0" * 64,
                            g.sha256(f.files[g.MANIFEST_FILE]), f.fetch)
        self.assertEqual(f.created, [])
        self.assertEqual(f.downloads, [])


class Fixture(amendment.Fixture):
    def __init__(self, profile="tls", **kwargs):
        super().__init__(profile, **kwargs)
        bootstrap = json.loads(self.files[s.BOOTSTRAP])
        bootstrap.update(enrollmentOrigin="https://manager.example:8443" if profile == "tls" else "http://192.168.10.2:8787",
                         serverCaPem="PUBLIC TEST CA" if profile == "tls" else "")
        self.files[s.BOOTSTRAP] = s.canonical(bootstrap)
        self.manifest["bootstrapHash"] = s.digest(self.files[s.BOOTSTRAP])
        self.files[s.MANIFEST] = s.canonical(self.manifest) + b"\n"
        self.files[s.INSTALLER_DIR + "/installation-owner.json"] = s.canonical(self.owner) + b"\n"
        for name in (s.BOOTSTRAP, s.MANIFEST, s.INSTALLER_DIR + "/installation-owner.json"):
            self.meta[name].st_size = len(self.files[name])
        self.probes = []
        self.downloads = []
        self.prompts = []
        self.output = []
        self.probe_raw = g.canonical(g.AGENT_CAPABILITIES) + b"\n"
        self.manager = dict(schemaVersion="tracebolt.journal-manager-capabilities.v1", agentOrigin=bootstrap["agentOrigin"],
                            generationReport="tracebolt.journal-generation-report.v2", request="tracebolt.journal-request.v2",
                            serviceAuthorization=["exact-units", "all-system-services"])

    def probe(self, uid, gid):
        self.probes.append((uid, gid))
        return self.probe_raw

    def fetch(self, url, limit, **kwargs):
        self.downloads.append((url, limit, kwargs))
        return g.canonical(self.manager)

    def run(self, approved=True, before_confirm=None):
        def confirm(phrase):
            # No host mutation, nonroot consent CLI or private read before this.
            self.prompts.append(phrase)
            if before_confirm:
                before_confirm(self)
            return approved
        return g.run(a, s, self, self.templates, REVISION, self.probe, confirm, self.output.append, self.fetch)


class GuideTests(unittest.TestCase):
    def test_one_confirmation_then_existing_apply_and_no_private_root_reads(self):
        for profile in ("tls", "http-test"):
            with self.subTest(profile=profile):
                f = Fixture(profile)
                before = copy.deepcopy((f.files, f.meta, f.units))
                def untouched(current):
                    self.assertEqual(current.actions, [])
                    self.assertEqual((current.files, current.meta, current.units), before)
                result = f.run(before_confirm=untouched)
                self.assertTrue(result["committed"], result)
                self.assertEqual(f.prompts, ["GRANT ALL SYSTEM SERVICES" + (" OVER HTTP" if profile == "http-test" else "")])
                self.assertEqual(f.probes, [(200, 201), (200, 201)])
                self.assertFalse(any(path.startswith(s.STATE_DIR + "/") for path in f.reads))
                self.assertEqual(json.loads(f.files[a.POLICY])["serviceAuthorization"], "all-system-services")
                self.assertIn("future", f.output[0])
                self.assertIn("Bound plan:", f.output[0])
                self.assertEqual(f.downloads[0][2], {"ca_pem": None if profile == "http-test" else "PUBLIC TEST CA", "plaintext": profile == "http-test"})
                if profile == "http-test":
                    self.assertIn("can be impersonated", f.output[0])

    def test_cancel_and_nontrue_answer_never_apply(self):
        for answer in (False, None, "yes", 1):
            with self.subTest(answer=answer):
                f = Fixture()
                before = copy.deepcopy((f.files, f.meta, f.units))
                self.assertTrue(f.run(approved=answer)["canceled"])
                self.assertEqual(f.actions, [])
                self.assertEqual((f.files, f.meta, f.units), before)

    def test_unsupported_agent_or_manager_stops_before_prompt(self):
        for side in ("agent", "manager"):
            f = Fixture()
            if side == "agent":
                f.probe_raw = b"{}"
            else:
                f.manager["generationReport"] = "tracebolt.journal-generation-report.v1"
            with self.subTest(side=side), self.assertRaisesRegex(g.Rejected, side + "-upgrade-required"):
                f.run()
            self.assertEqual(f.prompts, [])
            self.assertEqual(f.actions, [])

    def test_old_binary_exit_maps_actionable_upgrade_without_prompt(self):
        f = Fixture()
        f.probe = mock.Mock(side_effect=s.Rejected("journal-preview-command-failed"))
        with self.assertRaisesRegex(g.Rejected, "agent-upgrade-required"):
            f.run()
        self.assertEqual(f.prompts, [])
        self.assertEqual(f.actions, [])

    def test_manager_wrong_origin_duplicate_keys_and_network_failure_stop(self):
        for cause in ("origin", "duplicate", "network"):
            f = Fixture()
            if cause == "origin":
                f.manager["agentOrigin"] = "https://other.example:8444"
            elif cause == "duplicate":
                f.fetch = lambda *_, **kw: b'{"request":"foreign",' + g.canonical(f.manager)[1:]
            else:
                f.fetch = mock.Mock(side_effect=OSError("private irrelevant exception detail"))
            with self.subTest(cause=cause), self.assertRaises(g.Rejected):
                f.run()
            self.assertEqual(f.prompts, [])
            self.assertEqual(f.actions, [])

    def test_installed_or_compatibility_drift_before_apply_has_no_mutation(self):
        for cause in ("binary", "manager", "plan"):
            f = Fixture()
            def mutate(current):
                if cause == "binary":
                    current.files[s.BINARY] += b"changed"
                elif cause == "manager":
                    current.manager["request"] = "old"
                else:
                    current.units[s.AGENT_UNIT]["ActiveState"] = "inactive"
                    current.units[s.AGENT_UNIT]["MainPID"] = "0"
            with self.subTest(cause=cause), self.assertRaises((g.Rejected, a.Rejected, s.Rejected)):
                f.run(before_confirm=mutate)
            self.assertFalse(any(action[0].startswith("command.stop.") or action[0].startswith("evidence.") or
                                 action[0] == "command" and len(action) > 1 and action[1][:2] == ["/usr/bin/systemctl", "stop"]
                                 for action in f.actions), f.actions)

    def test_disabled_policy_blocks_without_prompt(self):
        f = Fixture(policy_enabled=False)
        with self.assertRaisesRegex(g.Rejected, "existing-policy-disabled"):
            f.run()
        self.assertEqual(f.prompts, [])
        self.assertEqual(f.probes, [])
        self.assertEqual(f.actions, [])

    def test_already_broad_returns_readonly_status(self):
        for active in (True, False):
            with self.subTest(active=active):
                f = Fixture(active=active)
                self.assertTrue(f.run()["committed"])
                before = copy.deepcopy((f.files, f.meta, f.units))
                f.actions.clear()
                f.prompts.clear()
                result = f.run()
                self.assertTrue(result["alreadyAuthorized"])
                self.assertEqual(result["originalActivity"][s.AGENT_UNIT], active)
                self.assertEqual("previously stopped agent remains stopped" in g.outcome_text(result), not active)
                self.assertEqual("after the next agent report" in g.outcome_text(result), active)
                self.assertEqual(f.prompts, [])
                self.assertEqual(f.actions, [])
                self.assertEqual((f.files, f.meta, f.units), before)

    def test_source_drift_after_confirmation_prevents_apply(self):
        f = Fixture()
        original = f.source_hashes
        def mutate(current):
            current.source_hashes = mock.Mock(side_effect=a.Rejected("reviewed-source-changed"))
        with self.assertRaisesRegex(a.Rejected, "reviewed-source-changed"):
            f.run(before_confirm=mutate)
        self.assertEqual(f.actions, [])
        f.source_hashes = original

    def test_terminal_answer_is_exact_once_and_descriptor_closed(self):
        for text, expected in ((b"GRANT ALL SYSTEM SERVICES\n", True), (b"yes\n", False), (b"GRANT ALL SYSTEM SERVICES", False), (b"x" * 128, False)):
            data = io.BytesIO(text)
            with self.subTest(text=text), mock.patch.object(g.os, "open", return_value=99) as opened, \
                 mock.patch.object(g.os, "isatty", return_value=True), \
                 mock.patch.object(g.os, "write", side_effect=lambda fd, value: min(3, len(value))), \
                 mock.patch.object(g.os, "read", side_effect=lambda fd, size: data.read(size)), \
                 mock.patch.object(g.os, "close") as closed:
                self.assertEqual(g.terminal_confirm("GRANT ALL SYSTEM SERVICES"), expected)
                opened.assert_called_once_with("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
                closed.assert_called_once_with(99)

    def test_non_terminal_descriptor_rejected_and_closed(self):
        with mock.patch.object(g.os, "open", return_value=99), \
             mock.patch.object(g.os, "isatty", return_value=False), mock.patch.object(g.os, "close") as closed:
            with self.assertRaisesRegex(g.Rejected, "local-terminal-required"):
                g.require_terminal()
            closed.assert_called_once_with(99)


    def test_main_output_failure_retains_returned_commit(self):
        sources = Sources()
        sources.files.update(sources.remote)
        sources.files[g.CORE_FILES[0]] = b"# inert, already supplied module\n"
        fixture = Fixture()
        module = types.ModuleType("inert_amendment")
        module.Rejected = a.Rejected
        module.load_setup = lambda: (s, {})
        module.real_effects = lambda *_: fixture
        captured = []
        def output(text, **kwargs):
            if kwargs.get("file") is g.sys.stderr:
                captured.append(json.loads(text))
            else:
                raise BrokenPipeError("synthetic display failure")
        with mock.patch.object(g, "SourceStore", return_value=sources), \
             mock.patch.object(g, "__file__", sources.path(g.GUIDE_FILE)), \
             mock.patch.object(g, "stage_sources", return_value={}), \
             mock.patch.object(g, "require_terminal"), \
             mock.patch.object(g.types, "ModuleType", return_value=module), \
             mock.patch.object(g, "run", return_value={"committed": True, "commitState": "committed"}), \
             mock.patch.object(g.os, "getuid", return_value=0), mock.patch.object(g.os, "geteuid", return_value=0), \
             mock.patch.object(g.signal, "signal"), mock.patch("builtins.print", side_effect=output):
            self.assertEqual(g.main(["--revision", REVISION, "--guide-sha256", "a" * 64, "--manifest-sha256", "b" * 64]), 1)
        self.assertEqual(captured, [{"committed": True, "commitState": "committed", "reportingFailure": "result-output-failed"}])

    def test_outcome_distinguishes_commit_restart_and_previously_stopped_agent(self):
        active = {"committed": True, "originalActivity": {s.AGENT_UNIT: True}}
        self.assertIn("after the next agent report", g.outcome_text(active))
        inactive = {"committed": True, "originalActivity": {s.AGENT_UNIT: False}}
        self.assertIn("previously stopped agent remains stopped", g.outcome_text(inactive))
        self.assertNotIn("make bounded requests", g.outcome_text(inactive))
        restart_failed = dict(active, restartFailureStage="owned-activity-restore-failed")
        self.assertIn("Grant committed, but", g.outcome_text(restart_failed))
        self.assertIn("before using Logs", g.outcome_text(restart_failed))
        self.assertIn("commit state is uncertain", g.outcome_text({"committed": False, "commitState": "commit-uncertain"}))
        self.assertIn("unchanged", g.outcome_text({"committed": False, "canceled": True}))


class BootstrapFixture:
    """Execute the exact privileged bootstrap against an entirely virtual OS."""
    def __init__(self):
        self.nodes = {}
        self.handles = {}
        self.next_fd = 20
        self.downloads = []
        self.executions = []
        self.sources = Sources()
        self.remote = dict(self.sources.remote, **self.sources.files)
        self.put("/", stat.S_IFDIR | 0o755)
        self.put("/root", stat.S_IFDIR | 0o700)
        self.put("/dev/tty", stat.S_IFCHR | 0o600)
        self.os = types.SimpleNamespace(**{key: getattr(os, key) for key in
            ("O_RDONLY", "O_RDWR", "O_NOCTTY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_WRONLY", "O_CREAT", "O_EXCL")})
        for method in ("open", "mkdir", "fstat", "stat", "lstat", "fchown", "fchmod", "fsync", "listdir", "read", "write", "close", "execv"):
            setattr(self.os, method, getattr(self, method))
        self.os.getuid = self.os.geteuid = lambda: 0
        self.os.isatty = lambda fd: self.handles[fd][0] == "/dev/tty"
        request = types.SimpleNamespace(HTTPRedirectHandler=object, ProxyHandler=lambda *args: None,
            HTTPSHandler=lambda **kwargs: None, build_opener=lambda *args: types.SimpleNamespace(open=self.download),
            Request=lambda url, **kwargs: url)
        self.urllib = types.SimpleNamespace(request=request)
        self.ssl = types.SimpleNamespace(create_default_context=lambda: None)

    def put(self, path, mode, raw=b""):
        self.nodes[path] = dict(mode=mode, uid=0, gid=0, inode=len(self.nodes) + 1, raw=bytearray(raw))

    def resolve(self, name, dir_fd=None):
        return name if name.startswith("/") else str(Path(self.handles[dir_fd][0]) / name)

    def open(self, name, flags, mode=0o777, dir_fd=None):
        path = self.resolve(name, dir_fd)
        if flags & os.O_CREAT:
            if path in self.nodes and flags & os.O_EXCL:
                raise FileExistsError(path)
            self.put(path, stat.S_IFREG | mode)
        if path not in self.nodes:
            raise FileNotFoundError(path)
        node = self.nodes[path]
        if flags & os.O_DIRECTORY and not stat.S_ISDIR(node["mode"]):
            raise NotADirectoryError(path)
        if flags & os.O_NOFOLLOW and stat.S_ISLNK(node["mode"]):
            raise OSError("virtual symlink blocked")
        self.next_fd += 1
        self.handles[self.next_fd] = [path, 0]
        return self.next_fd

    def mkdir(self, name, mode, dir_fd=None):
        path = self.resolve(name, dir_fd)
        if path in self.nodes:
            raise FileExistsError(path)
        self.put(path, stat.S_IFDIR | mode)

    def lstat(self, path):
        n = self.nodes[path]
        return types.SimpleNamespace(st_dev=1, st_ino=n["inode"], st_uid=n["uid"], st_gid=n["gid"],
            st_mode=n["mode"], st_nlink=1, st_size=len(n["raw"]), st_mtime_ns=1, st_ctime_ns=1)

    def stat(self, name, dir_fd=None, follow_symlinks=False):
        return self.lstat(self.resolve(name, dir_fd))

    def fstat(self, fd):
        return self.lstat(self.handles[fd][0])

    def fchown(self, fd, uid, gid):
        self.nodes[self.handles[fd][0]].update(uid=uid, gid=gid)

    def fchmod(self, fd, mode):
        node = self.nodes[self.handles[fd][0]]
        node["mode"] = stat.S_IFMT(node["mode"]) | mode

    def fsync(self, fd):
        assert fd in self.handles

    def listdir(self, fd):
        return [Path(path).name for path in self.nodes if path != "/" and str(Path(path).parent) == self.handles[fd][0]]

    def read(self, fd, limit):
        path, offset = self.handles[fd]
        raw = bytes(self.nodes[path]["raw"][offset:offset + limit])
        self.handles[fd][1] += len(raw)
        return raw

    def write(self, fd, raw):
        # Exercise the real bootstrap's partial-write loop.
        count = min(len(raw), 7)
        self.nodes[self.handles[fd][0]]["raw"].extend(raw[:count])
        return count

    def close(self, fd):
        del self.handles[fd]

    def execv(self, binary, args):
        self.executions.append((binary, args))

    def download(self, url, timeout):
        self.downloads.append(url)
        prefix = g.REPOSITORY + REVISION + "/"
        assert url.startswith(prefix)
        data = io.BytesIO(self.remote[url[len(prefix):]])
        data.status = 200
        data.headers = {}
        data.geturl = lambda: url
        data.read1 = data.read
        return data

    def complete(self):
        base = "/root/tracebolt-journal-guide-" + REVISION
        self.put(base + "/deploy/systemd", stat.S_IFDIR | 0o700)
        for path, raw in self.sources.remote.items():
            self.put(base + "/" + path, stat.S_IFREG | 0o600, raw)

    def run(self):
        actual_import = __import__
        def imported(name, *args, **kwargs):
            if name == "os":
                return self.os
            if name == "urllib.request":
                return self.urllib
            if name == "ssl":
                return self.ssl
            return actual_import(name, *args, **kwargs)
        class TTY(io.StringIO):
            def isatty(self):
                return True
        guide, manifest = self.sources.files[g.GUIDE_FILE], self.sources.files[g.MANIFEST_FILE]
        with mock.patch("builtins.__import__", side_effect=imported), mock.patch("builtins.open", return_value=TTY()), \
             mock.patch("sys.argv", ["bootstrap", REVISION, g.sha256(guide), str(len(guide)), g.sha256(manifest), str(len(manifest))]):
            exec(compile(c.BOOTSTRAP, "virtual-bootstrap", "exec"), {})


class BootstrapExecutionTests(unittest.TestCase):
    def test_verified_fresh_download_executes_only_pinned_guide(self):
        f = BootstrapFixture()
        f.run()
        self.assertEqual(len(f.downloads), 2)
        self.assertEqual(len(f.executions), 1)
        binary, args = f.executions[0]
        self.assertEqual(binary, "/usr/bin/python3")
        self.assertEqual(args[:3], [binary, "-I", "/root/tracebolt-journal-guide-" + REVISION + "/deploy/journal/guide.py"])
        self.assertEqual(args[3:5], ["--revision", REVISION])
        self.assertTrue(all(node["uid"] == node["gid"] == 0 for node in f.nodes.values()))

    def test_hash_mismatch_preserves_staging_and_never_executes(self):
        f = BootstrapFixture()
        f.remote[g.GUIDE_FILE] = b"x" * len(f.remote[g.GUIDE_FILE])
        with self.assertRaises(SystemExit):
            f.run()
        self.assertEqual(f.executions, [])
        self.assertIn("/root/tracebolt-journal-guide-" + REVISION, f.nodes)

    def test_complete_verified_cache_reexecutes_without_network(self):
        f = BootstrapFixture()
        f.run()
        f.complete()
        before = copy.deepcopy(f.nodes)
        f.run()
        self.assertEqual(len(f.downloads), 2)
        self.assertEqual(len(f.executions), 2)
        self.assertEqual(f.nodes, before)

    def test_partial_or_changed_cache_never_executes_or_downloads(self):
        for cause in ("partial", "hash", "foreign"):
            f = BootstrapFixture()
            f.run()
            if cause != "partial":
                f.complete()
                path = "/root/tracebolt-journal-guide-" + REVISION + "/" + g.CORE_FILES[0]
                if cause == "hash":
                    f.nodes[path]["raw"][0] ^= 1
                else:
                    f.put("/root/tracebolt-journal-guide-" + REVISION + "/foreign", stat.S_IFREG | 0o600, b"keep")
            before = copy.deepcopy(f.nodes)
            with self.subTest(cause=cause), self.assertRaises(SystemExit):
                f.run()
            self.assertEqual(len(f.downloads), 2)
            self.assertEqual(len(f.executions), 1)
            self.assertEqual(f.nodes, before)


class GeneratorTests(unittest.TestCase):
    def fixture(self):
        f = Sources()
        files = dict(f.remote, **f.files)
        return files, lambda name: files[name]

    def test_one_command_exact_revision_hashes_and_no_privilege_escalation(self):
        files, read = self.fixture()
        seen = []
        def download(url, limit):
            seen.append(url)
            return files[url.split(REVISION + "/", 1)[1]]
        command = c.command(REVISION, read, download)
        self.assertNotIn("\n", command)
        args = shlex.split(command)
        self.assertEqual(args[:9], ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
                                   "/usr/bin/python3", "-I", "-c", "exec(" + repr(c.BOOTSTRAP) + ")"])
        self.assertEqual(args[9:], [REVISION, g.sha256(files[g.GUIDE_FILE]), str(len(files[g.GUIDE_FILE])),
                                   g.sha256(files[g.MANIFEST_FILE]), str(len(files[g.MANIFEST_FILE]))])
        self.assertEqual(len(seen), 7)
        compile(c.BOOTSTRAP, "reviewed-bootstrap", "exec")

    def test_unpublished_or_changed_bytes_never_generate_command(self):
        files, read = self.fixture()
        with self.assertRaisesRegex(c.g.Rejected, "publication-bytes"):
            c.command(REVISION, read, lambda *_: b"foreign")
        files[g.CORE_FILES[0]] += b"changed"
        with self.assertRaisesRegex(c.g.Rejected, "refresh-reviewed-source-manifest"):
            c.command(REVISION, read, mock.Mock(side_effect=AssertionError("must not fetch")))

    def test_branch_and_shell_metacharacters_rejected_before_network(self):
        _, read = self.fixture()
        for revision in ("main", "a" * 39, "A" * 40, "$(id)", "a" * 40 + "/x"):
            with self.subTest(revision=revision), self.assertRaises(c.g.Rejected):
                c.command(revision, read, mock.Mock(side_effect=AssertionError("must not fetch")))

    def test_bootstrap_no_tty_stops_before_filesystem_and_network(self):
        with mock.patch("sys.argv", ["bootstrap", REVISION, "b" * 64, "20", "c" * 64, "30"]), \
             mock.patch("os.getuid", return_value=0), mock.patch("os.geteuid", return_value=0), \
             mock.patch("os.open", side_effect=OSError("no local terminal")) as opened, \
             mock.patch("urllib.request.build_opener", side_effect=AssertionError("must not contact network")):
            with self.assertRaisesRegex(SystemExit, "local interactive root terminal"):
                exec(compile(c.BOOTSTRAP, "inert-bootstrap-test", "exec"), {})
            opened.assert_called_once_with("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)


@unittest.skipUnless(sys.platform == "linux", "Linux controlling terminal regression")
class RealTerminalTests(unittest.TestCase):
    def test_real_controlling_pty_bootstrap_guard_and_exact_confirmation(self):
        # Only terminal helpers execute. The full bootstrap is stopped at its
        # first filesystem access after the terminal check, before any staging
        # or network. No UID change or actual root privilege is required.
        for phrase, answer, expected in (("GRANT ALL SYSTEM SERVICES", b"GRANT ALL SYSTEM SERVICES\n", True),
                                         ("GRANT ALL SYSTEM SERVICES OVER HTTP", b"GRANT ALL SYSTEM SERVICES OVER HTTP\n", True),
                                         ("GRANT ALL SYSTEM SERVICES", b"\n", False),
                                         ("GRANT ALL SYSTEM SERVICES", b"yes\n", False)):
            with self.subTest(answer=answer):
                pid, master = pty.fork()
                if pid == 0:
                    try:
                        self.assertTrue(os.isatty(0))
                        # This is the real failure mode that StringIO missed.
                        with self.assertRaises(io.UnsupportedOperation):
                            with open("/dev/tty", "r+"):
                                pass
                        g.require_terminal()
                        original_open = os.open
                        class GuardPassed(Exception):
                            pass
                        def stop_before_files(path, *args, **kwargs):
                            if path == "/dev/tty":
                                return original_open(path, *args, **kwargs)
                            if path == "/":
                                raise GuardPassed()
                            raise AssertionError("unexpected filesystem access")
                        with mock.patch("sys.argv", ["bootstrap", REVISION, "b" * 64, "20", "c" * 64, "30"]), \
                             mock.patch("os.getuid", return_value=0), mock.patch("os.geteuid", return_value=0), \
                             mock.patch("os.open", side_effect=stop_before_files), \
                             mock.patch("urllib.request.build_opener", side_effect=AssertionError("network forbidden")):
                            with self.assertRaises(GuardPassed):
                                exec(compile(c.BOOTSTRAP, "real-pty-bootstrap", "exec"), {})
                        print("GUARDS_PASSED", flush=True)
                        actual = g.terminal_confirm(phrase)
                        print("RESULT=" + str(actual), flush=True)
                        os._exit(0 if actual is expected else 2)
                    except BaseException as exc:
                        print("CHILD_ERROR=" + repr(exc), flush=True)
                        os._exit(3)
                output = bytearray()
                status = None
                try:
                    deadline = time.monotonic() + 5
                    sent = False
                    while time.monotonic() < deadline:
                        if select.select([master], [], [], 0.05)[0]:
                            try:
                                chunk = os.read(master, 8192)
                            except OSError:
                                chunk = b""
                            output.extend(chunk)
                            if not sent and b"to approve, or press Enter to cancel: " in output:
                                os.write(master, answer)
                                sent = True
                        done, value = os.waitpid(pid, os.WNOHANG)
                        if done:
                            status = value
                            break
                    self.assertIsNotNone(status, output.decode(errors="replace"))
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors="replace"))
                    self.assertIn(b"GUARDS_PASSED", output)
                    self.assertTrue(sent)
                finally:
                    if status is None:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                    os.close(master)


if __name__ == "__main__":
    unittest.main()
