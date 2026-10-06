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
                                 st_ino=ino, st_dev=1, st_nlink=1,
                                 st_size=0, st_mtime_ns=1, st_ctime_ns=1)


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
        self.private_generation = None
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
        s.require(path in s.BROAD_CREATED_FILES and self.absent(path), "fixture-create-file")
        self.files[path] = raw
        self.meta[path] = meta(stat.S_IFREG | mode, gid=gid)
        self.meta[path].st_size = len(raw)

    def nonce(self):
        return "f" * 64

    def commit_activation(self, pending, committed):
        self.commit_uncertain = False
        s.require(self.files[s.ACTIVATION] == pending, "fixture-pending-activation")
        self.create(s.ACTIVATION_STAGE, committed, 0, 0o644)
        self.effect("activation", "stage-fsync")
        self.commit_uncertain = True
        self.effect("activation", "rename")
        self.files[s.ACTIVATION] = self.files.pop(s.ACTIVATION_STAGE)
        self.meta[s.ACTIVATION] = self.meta.pop(s.ACTIVATION_STAGE)
        self.effect("activation", "directory-fsync")

    def effect(self, kind, target):
        s.require(self.locked, "mutation-without-installer-lock")
        self.actions.append((kind, target))
        if self.fail == (kind, target):
            raise s.Rejected("injected-failure")

    def command(self, args, uid=None, gid=None, limit=16384, timeout=45,
                failure_stage="fixed-command-failed"):
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
                policy = json.loads(self.files[s.CLIENT_POLICY])
                if policy["schemaVersion"] == "tracebolt.journal-content-policy.v3":
                    gate = json.loads(self.files[s.ACTIVATION])
                    g = dict(revision=policy["revision"], generation=policy["generation"],
                             policyDigest="sha256:" + s.digest(self.files[s.CLIENT_POLICY]))
                    s.require(gate["phase"] == "pending" and gate["policyGeneration"] == g and
                              self.absent(s.ACTIVATION_STAGE) and self.private_generation is None, "fixture-initial-generation")
                    self.private_generation = g
                    p.update(scope=s.SCOPE_V3, policyGeneration=g)
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

    def plan(self, units=("demo.service",), *, all_system_services=False):
        return s.preflight(self, list(units), self.templates, all_system_services=all_system_services)[1]

    def apply(self, units=("demo.service",), content=True, plaintext=None, *, all_system_services=False):
        if plaintext is None:
            plaintext = self.manifest["profile"] == "http-test"
        plan_hash = s.digest(s.canonical(self.plan(units, all_system_services=all_system_services)))
        return s.apply(self, list(units), self.templates, plan_hash, content, plaintext,
                       all_system_services=all_system_services)


class SetupTests(unittest.TestCase):
    def test_broad_plan_is_explicit_read_only_and_separate_from_legacy(self):
        f = Fixture()
        before = copy.deepcopy(f.files)
        plan = f.plan([], all_system_services=True)
        self.assertEqual(f.files, before)
        self.assertEqual(f.actions, [])
        self.assertEqual(plan["schemaVersion"], "tracebolt.journal-helper-plan.v2")
        self.assertEqual(plan["serviceAuthorization"], "all-system-services")
        self.assertEqual(plan["allowUnits"], [])
        self.assertTrue(plan["currentAndFutureSystemServices"])
        self.assertTrue(plan["generationMetadataReported"])
        self.assertIn("system-wide-authentication", plan["excludedSources"])
        self.assertIn("credentials", plan["warning"])
        self.assertEqual(set(plan["createFiles"]), s.BROAD_CREATED_FILES)
        self.assertEqual(set(f.plan()["createFiles"]), s.CREATED_FILES)
        for units, broad in (([], False), (["a.service"], True), ([], 1), ([], "true")):
            with self.subTest(units=units, broad=broad), self.assertRaises(s.Rejected):
                f.plan(units, all_system_services=broad)

    def test_broad_success_initializes_pending_then_commits_before_socket(self):
        for profile in ("tls", "http-test"):
            f = Fixture(profile)
            out = f.apply([], all_system_services=True)
            with self.subTest(profile=profile):
                self.assertTrue(out["configured"], out)
                self.assertTrue(out["activationCommitted"])
                self.assertEqual(out["commitState"], "committed")
                self.assertTrue(out["agentRestarted"])
                self.assertFalse(out["sourceVerified"])
                self.assertFalse(out["contentRead"])
                self.assertEqual(f.files[s.POLICY], f.files[s.CLIENT_POLICY])
                self.assertEqual(f.files[s.DEPLOYMENT], f.files[s.CLIENT_DEPLOYMENT])
                p = json.loads(f.files[s.POLICY])
                self.assertEqual(p["schemaVersion"], "tracebolt.journal-content-policy.v3")
                self.assertEqual(p["scope"], s.SCOPE_V3)
                self.assertEqual(p["serviceAuthorization"], s.ALL_SERVICES)
                self.assertEqual(p["allowedUnits"], [])
                self.assertEqual(p["revision"], "1")
                self.assertEqual(p["plaintextAcknowledged"], profile == "http-test")
                d = json.loads(f.files[s.DEPLOYMENT])
                self.assertEqual(d["schemaVersion"], "tracebolt.journal-helper-deployment.v2")
                self.assertTrue(d["policyGenerationRequired"])
                gate = json.loads(f.files[s.ACTIVATION])
                self.assertEqual(gate["policyGeneration"], f.private_generation)
                self.assertEqual(gate["policyGeneration"], out["policyGeneration"])
                self.assertEqual(gate["phase"], "committed")
                self.assertTrue(f.absent(s.ACTIVATION_STAGE))
                self.assertLess(f.actions.index(("create", s.ACTIVATION)), f.actions.index(("create", s.POLICY)))
                initialize = next(i for i, x in enumerate(f.actions) if x[0] == "command" and "initialize" in x[1])
                committed = f.actions.index(("activation", "directory-fsync"))
                enabled = f.actions.index(("command", ("/usr/bin/systemctl", "enable", "--now", s.SOCKET)))
                self.assertLess(initialize, committed)
                self.assertLess(committed, enabled)
                with self.assertRaises(s.Rejected):
                    f.plan([], all_system_services=True)

    def test_broad_content_and_transport_acks_required_before_mutation(self):
        for profile, content, plaintext in (("tls", False, False), ("tls", True, True),
                                            ("http-test", False, True), ("http-test", True, False)):
            f = Fixture(profile)
            with self.subTest(profile=profile, content=content, plaintext=plaintext), self.assertRaises(s.Rejected):
                f.apply([], content=content, plaintext=plaintext, all_system_services=True)
            self.assertFalse(any(x[0] in ("command", "create", "mkdir", "activation") for x in f.actions))

    def test_broad_initialization_requires_matching_generation_readback(self):
        for corruption in ("missing-generation", "different-generation", "wrong-scope"):
            f = Fixture()
            original = f.command
            def command(args, **kwargs):
                raw = original(args, **kwargs)
                if args[0] == s.BINARY and "initialize" in args:
                    p = json.loads(raw)
                    if corruption == "missing-generation":
                        p.pop("policyGeneration")
                    elif corruption == "different-generation":
                        p["policyGeneration"]["generation"] = "a" * 64
                    else:
                        p["scope"] = s.SCOPE
                    return s.canonical(p)
                return raw
            f.command = command
            out = f.apply([], all_system_services=True)
            with self.subTest(corruption=corruption):
                self.assertFalse(out["configured"])
                self.assertFalse(out["activationCommitted"])
                self.assertTrue(out["retainedPartialState"])
                self.assertFalse(out["agentRestarted"])
                self.assertEqual(json.loads(f.files[s.ACTIVATION])["phase"], "pending")
                self.assertNotIn(("command", ("/usr/bin/systemctl", "enable", "--now", s.SOCKET)), f.actions)

    def test_broad_partial_creation_and_commit_uncertainty_retain_evidence(self):
        for fault in (("create", s.ACTIVATION), ("create", s.CLIENT_POLICY),
                      ("create", s.ACTIVATION_STAGE), ("activation", "stage-fsync"),
                      ("activation", "rename"), ("activation", "directory-fsync")):
            f = Fixture()
            f.fail = fault
            out = f.apply([], all_system_services=True)
            with self.subTest(fault=fault):
                self.assertFalse(out["configured"])
                self.assertFalse(out["activationCommitted"])
                self.assertTrue(out["retainedPartialState"])
                self.assertFalse(out["agentRestarted"])
                self.assertIn(s.ATTEMPT, f.files)
                self.assertEqual(f.units[s.AGENT_UNIT]["ActiveState"], "inactive")
                self.assertNotIn(("command", ("/usr/bin/systemctl", "enable", "--now", s.SOCKET)), f.actions)
                if fault in (("activation", "rename"), ("activation", "directory-fsync")):
                    self.assertEqual(out["commitState"], "commit-uncertain")
                if fault == ("activation", "directory-fsync"):
                    self.assertEqual(json.loads(f.files[s.ACTIVATION])["phase"], "committed")
                with self.assertRaises(s.Rejected):
                    f.plan([], all_system_services=True)

    def test_broad_post_commit_failure_keeps_commit_distinct_from_configuration(self):
        f = Fixture()
        f.fail = ("command", ("/usr/bin/systemctl", "daemon-reload"))
        out = f.apply([], all_system_services=True)
        self.assertFalse(out["configured"])
        self.assertTrue(out["activationCommitted"])
        self.assertEqual(out["commitState"], "committed")
        self.assertTrue(out["retainedPartialState"])
        self.assertFalse(out["agentRestarted"])

    def test_broad_created_files_are_rechecked_before_commit(self):
        for path in (s.POLICY, s.CLIENT_POLICY, s.DEPLOYMENT, s.ACTIVATION):
            f = Fixture()
            original = f.command
            def command(args, **kwargs):
                raw = original(args, **kwargs)
                if args[0] == s.BINARY and "initialize" in args:
                    f.files[path] += b" "
                return raw
            f.command = command
            out = f.apply([], all_system_services=True)
            with self.subTest(path=path):
                self.assertFalse(out["activationCommitted"])
                self.assertFalse(out["agentRestarted"])
                self.assertNotIn(("activation", "rename"), f.actions)

    def test_broad_account_or_activity_drift_blocks_activation(self):
        for kind in ("helper-membership", "agent-active", "helper-active", "socket-active"):
            f = Fixture()
            original = f.command
            def command(args, **kwargs):
                raw = original(args, **kwargs)
                if args[0] == s.BINARY and "initialize" in args:
                    if kind == "helper-membership":
                        f.files["/etc/group"] += b"unexpected:x:399:tracebolt-journal-reader\n"
                    else:
                        unit = {"agent-active": s.AGENT_UNIT, "helper-active": s.SERVICE, "socket-active": s.SOCKET}[kind]
                        f.units[unit] = status(unit, loaded=True, active="active")
                return raw
            f.command = command
            out = f.apply([], all_system_services=True)
            with self.subTest(kind=kind):
                self.assertFalse(out["configured"])
                self.assertFalse(out["activationCommitted"])
                self.assertTrue(out["retainedPartialState"])
                self.assertFalse(out["agentRestarted"])
                self.assertNotIn(("activation", "rename"), f.actions)

    def test_broad_creation_compatible_with_existing_amendment_readiness(self):
        import test_amend
        f = Fixture(active=False)
        self.assertTrue(f.apply([], all_system_services=True)["configured"])
        # Reuse the established strict ownership/readback fixture against exactly
        # the bytes created above, with no prior amendment transaction or archive.
        ready = test_amend.Fixture(active=False)
        ready.files = copy.deepcopy(f.files)
        ready.meta = copy.deepcopy(f.meta)
        ready.units = copy.deepcopy(f.units)
        ready.units[s.SERVICE]["UnitFileState"] = "static"
        for path, raw in ready.files.items():
            if path not in ready.meta:
                mode = 0o600 if path in (s.INSTALLER_DIR + "/ownership", s.INSTALLER_DIR + "/install.lock", s.INSTALLER_DIR + "/installation-owner.json") else 0o644
                ready.setmeta(path, stat.S_IFREG | mode, size=len(raw))
        link = s.UNIT_DIR + "/sockets.target.wants/" + s.SOCKET
        ready.links = {link: s.UNIT_DIR + "/" + s.SOCKET}
        ready.setmeta(link, stat.S_IFLNK | 0o777)
        ready.private_generation = f.private_generation
        a = test_amend.a
        facts = a.inspect(s, ready, ready.templates)
        self.assertEqual(facts["policy"]["serviceAuthorization"], s.ALL_SERVICES)
        # The established inert amendment command fixture conservatively asks
        # for all three units inactive; the production CLI needs only sender lock.
        ready.units[s.SOCKET]["ActiveState"] = "inactive"
        with ready.lock():
            dto = a.command(s, ready, facts, "preview", facts["policy"])
        self.assertEqual(dto["policyGeneration"], f.private_generation)
        self.assertFalse(dto["accepted"])
        self.assertFalse(any("journal-amendment-" in p for p in ready.meta))

    def test_real_fixed_activation_commit_syscalls_and_uncertainty(self):
        for fault in (None, "replace", "fsync", "stage-pin", "old-pin", "parent-pin"):
            f = Fixture(active=False)
            f.commit_activation = types.MethodType(s.Effects.commit_activation, f)
            opened, renames, syncs = [], [], []
            def open_dir(path, flags):
                self.assertEqual(path, s.CONFIG_DIR)
                self.assertEqual(flags, s.os.O_RDONLY | s.os.O_DIRECTORY | s.os.O_NOFOLLOW | s.os.O_CLOEXEC)
                opened.append(path)
                return 42
            def stat_at(name, **kwargs):
                self.assertEqual(kwargs, dict(dir_fd=42, follow_symlinks=False))
                path = s.CONFIG_DIR + "/" + name
                value = copy.deepcopy(f.meta[path])
                if fault == "stage-pin" and path == s.ACTIVATION_STAGE or fault == "old-pin" and path == s.ACTIVATION:
                    value.st_ino += 1
                return value
            def replace(src, dst, **kwargs):
                self.assertEqual((src, dst, kwargs), (Path(s.ACTIVATION_STAGE).name, Path(s.ACTIVATION).name,
                                                     dict(src_dir_fd=42, dst_dir_fd=42)))
                renames.append((src, dst))
                if fault == "replace":
                    raise OSError("synthetic rename failure")
                f.files[s.ACTIVATION] = f.files.pop(s.ACTIVATION_STAGE)
                f.meta[s.ACTIVATION] = f.meta.pop(s.ACTIVATION_STAGE)
                # Real rename changes ctime; it must not invalidate an otherwise
                # identical newly published inode.
                f.meta[s.ACTIVATION].st_ctime_ns += 1
            def fsync(fd):
                self.assertEqual(fd, 42)
                syncs.append(fd)
                if fault == "fsync":
                    raise OSError("synthetic directory fsync failure")
            def lstat(path):
                self.assertEqual(path, s.CONFIG_DIR)
                result = copy.deepcopy(f.meta[path])
                if fault == "parent-pin":
                    result.st_ino += 1
                return result
            with mock.patch.object(s.os, "open", side_effect=open_dir), \
                 mock.patch.object(s.os, "fstat", side_effect=lambda fd: copy.deepcopy(f.meta[s.CONFIG_DIR])), \
                 mock.patch.object(s.os, "lstat", side_effect=lstat), \
                 mock.patch.object(s.os, "stat", side_effect=stat_at), \
                 mock.patch.object(s.os, "replace", side_effect=replace), \
                 mock.patch.object(s.os, "fsync", side_effect=fsync), \
                 mock.patch.object(s.os, "close") as close:
                result = f.apply([], all_system_services=True)
            with self.subTest(fault=fault):
                self.assertEqual(opened, [s.CONFIG_DIR])
                close.assert_called_once_with(42)
                self.assertEqual(result["configured"], fault is None, result)
                self.assertEqual(result["activationCommitted"], fault is None)
                self.assertEqual(len(renames), int(fault in (None, "replace", "fsync")))
                self.assertEqual(len(syncs), int(fault in (None, "fsync")))
                if fault is not None:
                    self.assertTrue(result["retainedPartialState"])
                    self.assertEqual(result["commitState"], "commit-uncertain" if fault in ("replace", "fsync") else "pending")
                if fault == "fsync":
                    self.assertEqual(json.loads(f.files[s.ACTIVATION])["phase"], "committed")

    def test_real_activation_commit_rejects_non_phase_changes_without_writes(self):
        f = Fixture()
        pending = s.activation_record(f.preview, dict(revision="1", generation="f" * 64,
                                                     policyDigest="sha256:" + "d" * 64), "pending")
        for changed in (dict(pending, phase="pending"), dict(pending, phase="committed", deviceId="agent_" + "a" * 32)):
            with self.subTest(changed=changed), self.assertRaises(s.Rejected):
                s.Effects.commit_activation(f, s.canonical(pending), s.canonical(changed))
        self.assertEqual(f.actions, [])

    def test_cli_requires_exclusive_explicit_service_selection(self):
        for argv in ([], ["--all-system-services", "--allow-unit", "demo.service"]):
            with self.subTest(argv=argv), mock.patch.object(s.sys, "stderr"), self.assertRaises(SystemExit):
                s.main(argv)

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
                "--property=" + properties, "--all", "--no-pager"], timeout=5,
                failure_stage="systemd-unit-inspection-command-failed")
        for name in ("other.service", "other.socket", "*.service", "--all"):
            e = s.Effects()
            with mock.patch.object(e, "command") as command, self.assertRaisesRegex(s.Rejected, "^fixed-unit$"):
                e.status(name)
            command.assert_not_called()

    def test_command_failure_reports_only_allowlisted_stage(self):
        for stage in s.COMMAND_FAILURE_STAGES:
            e = s.Effects()
            child = mock.Mock()
            child.wait.return_value = child.poll.return_value = 3
            with mock.patch.object(e, "read", return_value=b"inert executable"), \
                 mock.patch.object(s.subprocess, "Popen", return_value=child) as popen, \
                 mock.patch.object(s.selectors, "DefaultSelector") as selectors:
                selectors.return_value.__enter__.return_value.get_map.return_value = {}
                with self.subTest(stage=stage), self.assertRaisesRegex(s.Rejected, "^" + stage + "$"):
                    e.command(["/usr/bin/systemctl", "daemon-reload"], failure_stage=stage)
                self.assertEqual(popen.call_args.kwargs["stderr"], s.subprocess.DEVNULL)
        e = s.Effects()
        with mock.patch.object(e, "read") as read, \
             mock.patch.object(s.subprocess, "Popen") as popen, \
             self.assertRaisesRegex(s.Rejected, "^fixed-command-stage$"):
            e.command(["/usr/bin/systemctl", "daemon-reload"], failure_stage="untrusted error /path")
        read.assert_not_called()
        popen.assert_not_called()

    def test_post_attempt_command_failures_retain_state_and_restore_agent(self):
        for stage in ("helper-account-command-failed", "journal-initialize-command-failed",
                      "systemd-reload-command-failed", "helper-socket-start-command-failed"):
            f = Fixture()
            before = set(f.files)
            original = f.command
            def command(args, **kwargs):
                if kwargs.get("failure_stage") == stage:
                    f.effect("command", tuple(args))
                    raise s.Rejected(stage)
                return original(args, **kwargs)
            f.command = command
            result = f.apply()
            with self.subTest(stage=stage):
                self.assertEqual(result["failureStage"], stage)
                self.assertFalse(result["configured"])
                self.assertTrue(result["retainedPartialState"])
                self.assertTrue(result["agentRestarted"])
                self.assertFalse(result["sourceVerified"])
                self.assertFalse(result["contentRead"])
                if stage == "helper-account-command-failed":
                    self.assertEqual(set(f.files) - before, {s.ATTEMPT})
                    self.assertNotIn(s.HELPER.encode(), f.files["/etc/passwd"])
                    self.assertNotIn(s.HELPER.encode(), f.files["/etc/group"])
                with self.assertRaises(s.Rejected):
                    f.plan()

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
        self.assertEqual([x[1] for x in f.actions if x[0] == "command" and x[1][0] == "/usr/sbin/useradd"],
            [("/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--no-log-init",
              "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", s.HELPER)])

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
