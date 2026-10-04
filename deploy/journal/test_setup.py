"""Inert fixtures only: no account/systemd/source commands or host configuration reads."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("journal_setup", Path(__file__).with_name("setup.py"))
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)


def meta(mode, uid=0, gid=0, ino=1):
    return types.SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid,
                                 st_ino=ino, st_dev=1, st_nlink=1)


def status(name, loaded=False, active="inactive", enabled=False):
    out = dict(LoadState="loaded" if loaded else "not-found", ActiveState=active,
                FragmentPath=s.UNIT_DIR + "/" + name if loaded else "", DropInPaths="",
                Transient="no", Names=name,
                UnitFileState=("enabled" if enabled else "disabled") if loaded else "not-found")
    if name != s.SOCKET:
        out["MainPID"] = "123" if active == "active" and name == s.AGENT_UNIT else "0"
    return out


def status_output(name, loaded=False, active="inactive"):
    # Synthetic equivalents of systemd's selected-property output. Absent unit
    # files may have an empty UnitFileState; sockets never have a MainPID.
    raw = ("MainPID=123\n" if loaded and active == "active" else "MainPID=0\n") if name != s.SOCKET else ""
    return (raw + "Names=" + name + "\nLoadState=" + ("loaded" if loaded else "not-found") +
            "\nActiveState=" + active + "\nFragmentPath=" +
            (s.UNIT_DIR + "/" + name if loaded else "") +
            "\nDropInPaths=\nUnitFileState=" + ("enabled" if loaded else "") +
            "\nTransient=no\n").encode("ascii")


class Fixture:
    # Deliberately does not derive from the real Effects adapter.
    def __init__(self, profile="tls", active=True):
        self.files = {}
        self.meta = {s.INSTALLER_DIR: meta(stat.S_IFDIR | 0o700),
                     s.STATE_DIR: meta(stat.S_IFDIR | 0o700, 200, 201, 44)}
        self.templates = {name: (s.TEMPLATES / name).read_bytes() for name in
                          (s.AGENT_UNIT + ".in", s.SERVICE + ".in", s.SOCKET + ".in")}
        self.actions = []
        self.fail = None
        self.init = False
        self.locked = False
        self.units = {s.AGENT_UNIT: status(s.AGENT_UNIT, True, "active" if active else "inactive", True),
                      s.SERVICE: status(s.SERVICE), s.SOCKET: status(s.SOCKET)}
        self.files["/etc/passwd"] = b"root:x:0:0:root:/root:/bin/bash\ntracebolt-agent:x:200:201::/var/lib/tracebolt-agent:/usr/sbin/nologin\n"
        self.files["/etc/group"] = b"root:x:0:\nsystemd-journal:x:190:\ntracebolt-agent:x:201:\n"
        self.files["/etc/nsswitch.conf"] = b"passwd: files systemd\ngroup: files systemd\n"
        self.files[s.BINARY] = b"inert sender binary"
        self.files["/opt/tracebolt-agent/enroll-agent"] = b"inert enrollment binary"
        self.files[s.BOOTSTRAP] = s.canonical(dict(profile=profile, collectionProfile=s.PROFILE,
            agentOrigin="https://manager.example:8444" if profile == "tls" else "http://192.168.10.2:8788"))
        self.manifest = dict(version="tracebolt.agent-installation.v2", profile=profile, uid=200, gid=201,
            agentHash=s.digest(self.files[s.BINARY]), enrollHash=s.digest(self.files["/opt/tracebolt-agent/enroll-agent"]),
            sourceHash="a" * 64, bootstrapHash=s.digest(self.files[s.BOOTSTRAP]), unitHash="b" * 64)
        self.files[s.UNIT_DIR + "/" + s.AGENT_UNIT] = s.agent_unit(self.templates[s.AGENT_UNIT + ".in"], self.manifest)
        self.manifest["unitHash"] = s.digest(self.files[s.UNIT_DIR + "/" + s.AGENT_UNIT])
        self.files[s.MANIFEST] = s.canonical(self.manifest) + b"\n"
        self.owner = dict(version="tracebolt.agent-install-owner.v2", status="installed",
                          installation=self.manifest, stateDevice=1, stateInode=44)
        self.files[s.INSTALLER_DIR + "/installation-owner.json"] = s.canonical(self.owner) + b"\n"
        self.files[s.INSTALLER_DIR + "/ownership"] = b"tracebolt.agent-installer-owned.v1\n"
        self.files[s.INSTALLER_DIR + "/install.lock"] = b""
        for p in ("/usr/bin/systemctl", "/usr/sbin/useradd", "/usr/sbin/nologin"):
            self.files[p] = b"inert command"
        self.preview = dict(schemaVersion="tracebolt.journal-consent-result.v1", mode="preview", scope=s.SCOPE,
            senderBinding="c" * 64, managerOrigin=json.loads(self.files[s.BOOTSTRAP])["agentOrigin"],
            transportProfile=profile, collectionProfile=s.PROFILE, deviceId="agent_" + "d" * 32,
            certificateHash="e" * 64, agentUid=200, agentGid=201, initialized=False, existingStatePreserved=True)

    def protected_dir(self, path):
        if path in self.meta:
            st = self.meta[path]
            s.require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o6022 == 0, "protected-directory")

    def read(self, path, limit=65536, mode=None):
        s.require(path in self.files, "missing-fixture-file")
        raw = self.files[path]
        s.require(len(raw) <= limit, "fixture-file-limit")
        return raw

    def absent(self, path):
        return path not in self.files and path not in self.meta

    def metadata(self, path):
        return self.meta[path]

    def status(self, name):
        return copy.deepcopy(self.units[name])

    @contextlib.contextmanager
    def lock(self):
        self.actions.append(("lock",))
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def mkdir(self, path):
        self.effect("mkdir", path)
        s.require(path in s.CREATE_DIRS and self.absent(path), "fixture-create-directory")
        self.meta[path] = meta(stat.S_IFDIR | 0o755)

    def create(self, path, raw, gid, mode):
        self.effect("create", path)
        s.require(path in s.CREATED_FILES and self.absent(path), "fixture-create-file")
        self.files[path] = raw
        self.meta[path] = meta(stat.S_IFREG | mode, gid=gid)

    def effect(self, kind, target):
        s.require(self.locked, "mutation-without-installer-lock")
        self.actions.append((kind, target))
        if self.fail == (kind, target):
            raise s.Rejected("injected-failure")

    def command(self, args, uid=None, gid=None, limit=16384, timeout=45):
        args = tuple(args)
        self.effect("command", args)
        if args[0] == "/usr/sbin/useradd":
            self.files["/etc/passwd"] += b"tracebolt-journal-reader:x:300:301::/nonexistent:/usr/sbin/nologin\n"
            self.files["/etc/group"] += b"tracebolt-journal-reader:x:301:\n"
        elif args[0] == s.BINARY:
            s.require(uid == 200 and gid == 201 and self.units[s.AGENT_UNIT]["ActiveState"] == "inactive", "nonroot-stopped-cli")
            mode = args[-1] if args[-2] == "--journal-content-consent" else "initialize"
            p = copy.deepcopy(self.preview)
            p["mode"] = mode
            p["initialized"] = mode == "initialize"
            if mode == "initialize":
                s.require(not self.init, "create-only-consent-marker")
                self.init = True
            return s.canonical(p) + b"\n"
        elif args == ("/usr/bin/systemctl", "stop", s.AGENT_UNIT):
            self.units[s.AGENT_UNIT]["ActiveState"] = "inactive"
            self.units[s.AGENT_UNIT]["MainPID"] = "0"
        elif args == ("/usr/bin/systemctl", "start", s.AGENT_UNIT):
            self.units[s.AGENT_UNIT]["ActiveState"] = "active"
            self.units[s.AGENT_UNIT]["MainPID"] = "124"
        elif args == ("/usr/bin/systemctl", "daemon-reload"):
            self.units[s.SERVICE] = status(s.SERVICE, True)
            self.units[s.SOCKET] = status(s.SOCKET, True)
        elif args == ("/usr/bin/systemctl", "enable", "--now", s.SOCKET):
            self.units[s.SOCKET] = status(s.SOCKET, True, "active", True)
            self.meta[s.RUNTIME_DIR] = meta(stat.S_IFDIR | 0o755)
            self.meta[s.SOCKET_PATH] = meta(stat.S_IFSOCK | 0o660, gid=201)
        else:
            raise AssertionError("Unreviewed fixture command: " + repr(args))
        return b""

    def plan(self, units=("demo.service",)):
        return s.preflight(self, list(units), self.templates)[1]

    def apply(self, units=("demo.service",), content=True, plaintext=None):
        if plaintext is None:
            plaintext = self.manifest["profile"] == "http-test"
        plan_hash = s.digest(s.canonical(self.plan(units)))
        return s.apply(self, list(units), self.templates, plan_hash, content, plaintext)


class SetupTests(unittest.TestCase):
    def test_status_parses_installed_and_absent_fixed_unit_types(self):
        for name in (s.AGENT_UNIT, s.SERVICE, s.SOCKET):
            for loaded, active in ((False, "inactive"), (True, "inactive"), (True, "active")):
                with self.subTest(name=name, loaded=loaded, active=active):
                    result = s.unit_state(status_output(name, loaded, active), name)
                    self.assertEqual(len(result), 7 if name == s.SOCKET else 8)
                    self.assertEqual("MainPID" in result, name != s.SOCKET)
                    if loaded:
                        self.assertTrue(s.owned_unit(result, name, active))
                        self.assertFalse(s.absent_unit(result, name))
                    else:
                        self.assertEqual(result["UnitFileState"], "")
                        self.assertTrue(s.absent_unit(result, name))
                        result["UnitFileState"] = "not-found"
                        self.assertTrue(s.absent_unit(result, name))

    def test_status_rejects_missing_duplicate_unknown_and_invalid_pid(self):
        for name in (s.AGENT_UNIT, s.SERVICE, s.SOCKET):
            raw = status_output(name)
            lines = raw.splitlines(keepends=True)
            for line in lines:
                for bad in (raw.replace(line, b"", 1), raw + line):
                    with self.subTest(name=name, bad=bad), self.assertRaisesRegex(s.Rejected, "^systemd-unit-status$"):
                        s.unit_state(bad, name)
            for extra in (b"Unknown=0\n", b"ControlPID=0\n", b"malformed\n"):
                with self.subTest(name=name, extra=extra), self.assertRaises(s.Rejected):
                    s.unit_state(raw + extra, name)
            if name == s.SOCKET:
                with self.assertRaises(s.Rejected):
                    s.unit_state(raw + b"MainPID=0\n", name)
            else:
                for pid in (b"", b"-1", b"abc", b"1 2"):
                    with self.subTest(name=name, pid=pid), self.assertRaises(s.Rejected):
                        s.unit_state(raw.replace(b"MainPID=0", b"MainPID=" + pid), name)
                result = s.unit_state(raw.replace(b"MainPID=0", b"MainPID=123"), name)
                self.assertFalse(s.absent_unit(result, name))

    def test_status_command_has_fixed_type_specific_property_allowlist(self):
        common = "LoadState,ActiveState,FragmentPath,DropInPaths,Transient,Names,"
        for name in (s.AGENT_UNIT, s.SERVICE, s.SOCKET):
            e = s.Effects()
            properties = common + ("" if name == s.SOCKET else "MainPID,") + "UnitFileState"
            with mock.patch.object(e, "command", return_value=status_output(name)) as command:
                self.assertTrue(s.absent_unit(e.status(name), name))
            command.assert_called_once_with(["/usr/bin/systemctl", "show", name,
                "--property=" + properties, "--all", "--no-pager"], timeout=5)
        for name in ("other.service", "other.socket", "*.service", "--all"):
            e = s.Effects()
            with mock.patch.object(e, "command") as command, self.assertRaisesRegex(s.Rejected, "^fixed-unit$"):
                e.status(name)
            command.assert_not_called()

    def test_stopped_service_pid_check_remains_required(self):
        f = Fixture()
        original = f.command
        def command(args, **kwargs):
            result = original(args, **kwargs)
            if args == ["/usr/bin/systemctl", "stop", s.AGENT_UNIT]:
                f.units[s.AGENT_UNIT]["MainPID"] = "123"
            return result
        f.command = command
        result = f.apply()
        self.assertFalse(result["configured"])
        self.assertEqual(result["failureStage"], "stopped-agent")
        self.assertTrue(result["agentRestarted"])
        self.assertFalse(any(x[0] in ("mkdir", "create") for x in f.actions))

    def test_plan_is_read_only_and_binds_explicit_risks(self):
        f = Fixture()
        before = copy.deepcopy(f.files)
        p = f.plan(("z.service", "demo.service"))
        self.assertEqual(f.actions, [])
        self.assertEqual(before, f.files)
        self.assertEqual(p["allowUnits"], ["demo.service", "z.service"])
        self.assertEqual((p["maxWindowSeconds"], p["maxLookbackSeconds"]), (3600, 86400))
        self.assertIn("best effort", p["warning"])
        self.assertIn("during-apply", p["senderBinding"])
        self.assertEqual(p["managerOrigin"], "https://manager.example:8444")

    def test_allowlist_is_exact_and_required(self):
        for units in ([], ["*.service"], ["demo.service", "demo.service"], ["x@.service"],
                      ["../x.service"], ["a.service\n"], ["-x.service"], ["x.socket"],
                      ["a" * 248 + ".service"], [f"x{i}.service" for i in range(33)]):
            with self.subTest(units=units), self.assertRaises(s.Rejected):
                s.selected_units(units)
        self.assertEqual(s.selected_units(["worker@one.service"]), ["worker@one.service"])

    def test_success_uses_exact_paired_canonical_bytes_and_numeric_units(self):
        f = Fixture()
        result = f.apply()
        self.assertTrue(result["configured"])
        self.assertTrue(result["agentRestarted"])
        self.assertFalse(result["sourceVerified"])
        self.assertFalse(result["contentRead"])
        self.assertEqual(f.files[s.POLICY], f.files[s.CLIENT_POLICY])
        self.assertEqual(f.files[s.DEPLOYMENT], f.files[s.CLIENT_DEPLOYMENT])
        self.assertEqual(f.files[s.DEPLOYMENT], b'{"schemaVersion":"tracebolt.journal-helper-deployment.v1","helperUid":300,"helperGid":301,"journalGid":190,"agentUid":200,"agentGid":201}')
        self.assertEqual(result["policySHA256"], s.digest(f.files[s.CLIENT_POLICY]))
        for path, gid in ((s.POLICY, 301), (s.DEPLOYMENT, 301), (s.CLIENT_POLICY, 201), (s.CLIENT_DEPLOYMENT, 201)):
            self.assertEqual((stat.S_IMODE(f.meta[path].st_mode), f.meta[path].st_uid, f.meta[path].st_gid), (0o640, 0, gid))
        service = f.files[s.UNIT_DIR + "/" + s.SERVICE]
        self.assertIn(b"User=300\nGroup=301\nSupplementaryGroups=190\n", service)
        self.assertIn(b"ExecStart=/opt/tracebolt-agent/lan-agent --journal-reader\n", service)
        self.assertIn(b"PrivateNetwork=yes", service)
        self.assertIn(b"InaccessiblePaths=-/var/lib/tracebolt-agent", service)
        self.assertIn(b"SocketGroup=201\nSocketMode=0660", f.files[s.UNIT_DIR + "/" + s.SOCKET])
        self.assertEqual(set(x[1] for x in f.actions if x[0] == "create"), s.CREATED_FILES)
        self.assertNotIn("tracebolt-journal-reader", f.files["/etc/group"].decode().split("systemd-journal:")[1].splitlines()[0])

    def test_http_requires_separate_plaintext_ack(self):
        f = Fixture("http-test")
        with self.assertRaises(s.Rejected):
            f.apply(plaintext=False)
        self.assertEqual(f.actions, [("lock",)])
        f.actions.clear()
        result = f.apply()
        self.assertTrue(result["configured"])
        self.assertTrue(json.loads(f.files[s.POLICY])["plaintextAcknowledged"])
        calls = [x[1] for x in f.actions if x[0] == "command" and x[1][0] == s.BINARY]
        self.assertNotIn("--ack-journal-http-plaintext", calls[0])
        self.assertIn("--ack-journal-http-plaintext", calls[1])
        with self.assertRaises(s.Rejected):
            Fixture().apply(plaintext=True)

    def test_missing_content_ack_has_no_effect(self):
        f = Fixture()
        with self.assertRaises(s.Rejected):
            f.apply(content=False)
        self.assertEqual(f.actions, [])

    def test_changed_reviewed_plan_has_no_mutation(self):
        f = Fixture()
        with self.assertRaises(s.Rejected):
            s.apply(f, ["other.service"], f.templates, s.digest(s.canonical(f.plan())), True, False)
        self.assertEqual(f.actions, [("lock",)])

    def test_existing_foreign_or_partial_paths_refused(self):
        for p in (s.CONFIG_DIR, s.RUNTIME_DIR, s.UNIT_DIR + "/" + s.SERVICE,
                  s.UNIT_DIR + "/" + s.SOCKET + ".d", s.UNIT_DIR + "/sockets.target.wants/" + s.SOCKET):
            f = Fixture()
            f.files[p] = b"foreign or uncertain"
            with self.subTest(path=p), self.assertRaises(s.Rejected):
                f.plan()
            self.assertEqual(f.actions, [])

    def test_existing_account_and_nonlocal_nss_refused(self):
        for p, extra in (("/etc/passwd", b"tracebolt-journal-reader:x:300:301::/nonexistent:/usr/sbin/nologin\n"),
                         ("/etc/group", b"tracebolt-journal-reader:x:301:\n"),
                         ("/etc/group", b"unexpected:x:350:tracebolt-agent\n")):
            f = Fixture()
            f.files[p] += extra
            with self.subTest(p=p, extra=extra), self.assertRaises(s.Rejected):
                f.plan()
        f = Fixture()
        f.files["/etc/nsswitch.conf"] = b"passwd: files sss\ngroup: files sss\n"
        with self.assertRaises(s.Rejected):
            f.plan()

    def test_manifest_owner_artifact_and_state_fail_closed(self):
        mutations = [lambda f: f.files.__setitem__(s.BINARY, b"changed binary"),
                     lambda f: f.files.__setitem__(s.INSTALLER_DIR + "/transaction.json", b"{}"),
                     lambda f: f.files.__setitem__(s.INSTALLER_DIR + "/transaction.json.new", b"partial"),
                     lambda f: f.files.__setitem__(s.INSTALLER_DIR + "/ownership", b"wrong\n"),
                     lambda f: setattr(f.meta[s.STATE_DIR], "st_ino", 99),
                     lambda f: setattr(f.meta[s.STATE_DIR], "st_uid", 0),
                     lambda f: f.files.__setitem__(s.INSTALLER_DIR + "/installation-owner.json",
                                                   s.canonical(dict(f.owner, status="prepared"))),
                     lambda f: f.files.__setitem__(s.INSTALLER_DIR + "/installation-owner.json",
                                                   s.canonical(dict(f.owner, version="unknown")))]
        for change in mutations:
            f = Fixture()
            change(f)
            with self.subTest(change=change), self.assertRaises(s.Rejected):
                f.plan()
            self.assertEqual(f.actions, [])

    def test_systemd_aliases_dropins_transient_and_foreign_fragment_refused(self):
        for name, field, value in ((s.AGENT_UNIT, "DropInPaths", "/etc/systemd/system/x.conf"),
                                  (s.AGENT_UNIT, "Names", s.AGENT_UNIT + " alias.service"),
                                  (s.AGENT_UNIT, "Transient", "yes"),
                                  (s.AGENT_UNIT, "FragmentPath", "/run/systemd/foreign.service"),
                                  (s.SERVICE, "LoadState", "loaded"), (s.SOCKET, "UnitFileState", "enabled")):
            f = Fixture()
            f.units[name][field] = value
            with self.subTest(field=field), self.assertRaises(s.Rejected):
                f.plan()

    def test_failed_setup_restarts_prior_agent_retains_partial_and_never_retries(self):
        f = Fixture()
        f.fail = ("create", s.CLIENT_POLICY)
        out = f.apply()
        self.assertFalse(out["configured"])
        self.assertTrue(out["retainedPartialState"])
        self.assertTrue(out["agentRestarted"])
        self.assertIn(s.ATTEMPT, f.files)
        self.assertIn(s.POLICY, f.files)
        self.assertNotIn(s.CLIENT_POLICY, f.files)
        self.assertFalse(f.init)
        with self.assertRaises(s.Rejected):
            f.plan()

    def test_preview_failure_restarts_without_creating_anything(self):
        f = Fixture()
        f.preview["managerOrigin"] = "https://another.example"
        out = f.apply()
        self.assertFalse(out["configured"])
        self.assertTrue(out["agentRestarted"])
        self.assertFalse(out["retainedPartialState"])
        self.assertFalse(any(x[0] in ("mkdir", "create") for x in f.actions))

    def test_inactive_agent_is_left_inactive(self):
        f = Fixture(active=False)
        out = f.apply()
        self.assertTrue(out["configured"])
        self.assertFalse(out["agentRestarted"])
        self.assertEqual(f.units[s.AGENT_UNIT]["ActiveState"], "inactive")

    def test_uncertain_installer_state_blocks_restart_instead_of_override(self):
        f = Fixture()
        original = f.create
        def fail_and_change(path, raw, gid, mode):
            if path == s.CLIENT_POLICY:
                f.files[s.INSTALLER_DIR + "/transaction.json"] = b"foreign uncertain state"
                raise s.Rejected("injected-failure")
            original(path, raw, gid, mode)
        f.create = fail_and_change
        out = f.apply()
        self.assertEqual(out["failureStage"], "agent-restart-blocked-retain-state")
        self.assertFalse(out["agentRestarted"])
        self.assertEqual(f.units[s.AGENT_UNIT]["ActiveState"], "inactive")

    def test_duplicate_and_unknown_preview_members_rejected(self):
        f = Fixture()
        facts = s.inspect_agent(f, f.templates)
        raw = s.canonical(f.preview)
        for bad in (raw[:-1] + b',"agentUid":200}', raw[:-1] + b',"unknown":true}'):
            with self.assertRaises(s.Rejected):
                s.preview(bad, facts)

    def test_noncanonical_owner_and_shared_primary_group_rejected(self):
        f = Fixture()
        owner = {k: f.owner[k] for k in reversed(f.owner)}
        f.files[s.INSTALLER_DIR + "/installation-owner.json"] = s.canonical(owner)
        with self.assertRaises(s.Rejected):
            f.plan()
        f = Fixture()
        f.files["/etc/passwd"] += b"unexpected:x:500:201::/nonexistent:/usr/sbin/nologin\n"
        with self.assertRaises(s.Rejected):
            f.plan()

    def test_initialize_collision_retains_state_and_restores_agent(self):
        f = Fixture()
        f.init = True
        result = f.apply()
        self.assertFalse(result["configured"])
        self.assertTrue(result["retainedPartialState"])
        self.assertTrue(result["agentRestarted"])
        self.assertEqual(f.units[s.SOCKET]["LoadState"], "not-found")

    def test_protected_reader_rejects_symlink_alias_mode_owner_and_changed_metadata(self):
        def st(**updates):
            values = dict(st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=301,
                          st_nlink=1, st_size=7, st_dev=1, st_ino=2,
                          st_mtime_ns=10, st_ctime_ns=10)
            values.update(updates)
            return types.SimpleNamespace(**values)
        for bad in (st(st_mode=stat.S_IFLNK | 0o777), st(st_nlink=2),
                    st(st_uid=200), st(st_mode=stat.S_IFREG | 0o666), st(st_size=100)):
            e = s.Effects()
            with mock.patch.object(e, "protected_dir"), mock.patch.object(s.os, "open", return_value=10), \
                 mock.patch.object(s.os, "close"), mock.patch.object(s.os, "fstat", return_value=bad), \
                 self.assertRaises(s.Rejected):
                e.read("/fixture/owned", 20)
        for after in (st(st_ino=3), st(st_mtime_ns=11), st(st_gid=999)):
            e = s.Effects()
            with mock.patch.object(e, "protected_dir"), mock.patch.object(s.os, "open", return_value=10), \
                 mock.patch.object(s.os, "close"), mock.patch.object(s.os, "fstat", side_effect=[st(), after]), \
                 mock.patch.object(s.os, "read", side_effect=[b"fixture", b""]), self.assertRaises(s.Rejected):
                e.read("/fixture/owned", 20)

    def test_protected_directory_rejects_symlink_ancestor(self):
        def lstat(path):
            return meta(stat.S_IFLNK | 0o777) if str(path) == "/etc" else meta(stat.S_IFDIR | 0o755)
        with mock.patch.object(s.os, "lstat", side_effect=lstat), self.assertRaises(s.Rejected):
            s.Effects().protected_dir("/etc/tracebolt")

    def test_nonroot_cli_clears_groups_environment_and_inherited_descriptors(self):
        e = s.Effects()
        with mock.patch.object(e, "read", return_value=b"inert binary"), \
             mock.patch.object(s.subprocess, "Popen", side_effect=s.Rejected("inert-process-boundary")) as popen, \
             self.assertRaises(s.Rejected):
            e.command([s.BINARY, "--journal-content-consent", "preview"], uid=200, gid=201)
        kw = popen.call_args.kwargs
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (200, 201, []))
        self.assertEqual(kw["env"], s.ENV)
        self.assertTrue(kw["close_fds"])
        self.assertEqual(kw["stdin"], s.subprocess.DEVNULL)
        self.assertNotIn("preexec_fn", kw)
        self.assertNotIn("shell", kw)

    def test_real_adapter_has_frozen_destinations(self):
        with self.assertRaises(s.Rejected):
            s.Effects().mkdir("/tmp/not-approved")
        with self.assertRaises(s.Rejected):
            s.Effects().create("/tmp/not-approved", b"fixture", 0, 0o600)
        with self.assertRaises(s.Rejected):
            s.Effects().command(["/bin/sh", "-c", "true"])


if __name__ == "__main__":
    unittest.main()
