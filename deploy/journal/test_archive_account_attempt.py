"""Inert archive tests: synthetic state and mocked OS/process boundaries only."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

import test_setup

SPEC = importlib.util.spec_from_file_location(
    "journal_archive_account_attempt", Path(__file__).with_name("archive_account_attempt.py"))
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)
# The fixtures and archive checks must raise the identical Rejected class.
a.s = s = test_setup.s


def metadata(mode, uid=0, gid=0, ino=100, size=0, nlink=1, **changes):
    values = dict(st_dev=1, st_ino=ino, st_uid=uid, st_gid=gid,
                  st_mode=mode, st_nlink=nlink, st_size=size,
                  st_mtime_ns=10, st_ctime_ns=11)
    values.update(changes)
    return types.SimpleNamespace(**values)


class Fixture(test_setup.Fixture):
    """Never inherits or calls the host Effects implementation."""
    def __init__(self, active=True, units=("demo.service",)):
        super().__init__(active=active)
        self.read_requests = []
        self.allowed_units = list(units)
        self.original_plan = super().plan(units)
        self.original_hash = s.digest(s.canonical(self.original_plan))
        self.attempt = dict(schemaVersion="tracebolt.journal-setup-attempt.v1",
                           planSHA256=self.original_hash,
                           senderBinding=self.preview["senderBinding"],
                           deviceId=self.preview["deviceId"],
                           certificateHash=self.preview["certificateHash"])
        self.files[s.ATTEMPT] = s.canonical(self.attempt)
        self.meta[s.CONFIG_DIR] = metadata(stat.S_IFDIR | 0o755, ino=100, size=4096, nlink=2)
        self.meta[s.ATTEMPT] = metadata(stat.S_IFREG | 0o600, ino=101,
                                      size=len(self.files[s.ATTEMPT]))
        self.absence_ok = True
        self.marker_calls = 0
        self.read_requests.clear()

    def read(self, path, limit=65536, mode=None):
        self.read_requests.append((path, limit, mode))
        return super().read(path, limit, mode)

    def marker(self):
        self.marker_calls += 1
        s.require(s.CONFIG_DIR in self.meta and s.ATTEMPT in self.files,
                  "missing-fixture-marker")
        directory, marker = self.meta[s.CONFIG_DIR], self.meta[s.ATTEMPT]
        s.require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == directory.st_gid == 0 and
                  stat.S_IMODE(directory.st_mode) == 0o755, "marker-directory-ownership")
        prefix = s.CONFIG_DIR + "/"
        names = {path[len(prefix):].split("/", 1)[0] for path in set(self.files) | set(self.meta)
                 if path.startswith(prefix)}
        s.require(names == {Path(s.ATTEMPT).name}, "marker-directory-not-singleton")
        raw = self.files[s.ATTEMPT]
        s.require(stat.S_ISREG(marker.st_mode) and marker.st_uid == marker.st_gid == 0 and
                  stat.S_IMODE(marker.st_mode) == 0o600 and marker.st_nlink == 1 and
                  marker.st_size == len(raw) <= 4096, "protected-file")
        return raw, copy.deepcopy(directory), copy.deepcopy(marker)

    def journal_absent(self, facts):
        self.effect("journal_absent", (facts["uid"], facts["gid"]))
        s.require(self.units[s.AGENT_UNIT]["ActiveState"] == "inactive", "probe-requires-stopped-agent")
        s.require(self.absence_ok, "journal-state-absence-not-confirmed")

    def archive(self, snapshot):
        self.effect("archive", a.ARCHIVE)
        raw, directory, marker = self.marker()
        s.require(snapshot == dict(sha256=s.digest(raw), directory=a.identity(directory),
                                   marker=a.identity(marker)), "marker-identity-changed")
        s.require(self.absent(a.BACKUP), "archive-destination-exists")
        self.meta[a.BACKUP] = metadata(stat.S_IFDIR | 0o700, ino=102, nlink=2)
        self.meta[a.ARCHIVE] = self.meta.pop(s.CONFIG_DIR)
        archived_marker = a.ARCHIVE + "/" + Path(s.ATTEMPT).name
        self.meta[archived_marker] = self.meta.pop(s.ATTEMPT)
        self.files[archived_marker] = self.files.pop(s.ATTEMPT)

    def review(self, units=None):
        return a.plan(self, self.allowed_units if units is None else units,
                      self.templates, self.original_hash)[3]

    def recover(self, expected_original=None, expected_archive=None, units=None):
        if expected_archive is None:
            expected_archive = s.digest(s.canonical(self.review()))
        return a.archive(self, self.allowed_units if units is None else units, self.templates,
                         self.original_hash if expected_original is None else expected_original,
                         expected_archive)


class ArchiveTests(unittest.TestCase):
    def assert_no_setup_effects(self, f):
        self.assertFalse(f.init)
        self.assertFalse(any(action[0] in ("mkdir", "create") for action in f.actions))
        for action in f.actions:
            if action[0] == "command":
                self.assertNotEqual(action[1][0], "/usr/sbin/useradd")
                if action[1][0] == s.BINARY:
                    self.assertEqual(action[1][-2:], ("--journal-content-consent", "preview"))
                else:
                    self.assertIn(action[1], (("/usr/bin/systemctl", "stop", s.AGENT_UNIT),
                                               ("/usr/bin/systemctl", "start", s.AGENT_UNIT)))

    def test_default_plan_is_read_only_and_binds_full_marker_identity(self):
        f = Fixture(units=("z.service", "demo.service"))
        before_files, before_meta = copy.deepcopy(f.files), copy.deepcopy(f.meta)
        plan = f.review()
        self.assertEqual(f.actions, [])
        self.assertEqual(f.files, before_files)
        self.assertEqual(f.meta, before_meta)
        self.assertEqual(plan["originalPlan"], f.original_plan)
        self.assertEqual(plan["originalPlanSHA256"], f.original_hash)
        self.assertEqual(plan["attempt"]["sha256"], s.digest(f.files[s.ATTEMPT]))
        self.assertEqual(plan["attempt"]["directory"], a.identity(f.meta[s.CONFIG_DIR]))
        self.assertEqual(plan["attempt"]["marker"], a.identity(f.meta[s.ATTEMPT]))
        self.assertEqual(plan["archiveDirectory"], a.ARCHIVE)
        self.assertEqual(plan["backupParentMode"], "0700")
        for key in ("stoppedIdentityAndStateAbsenceRequired", "restorePreviouslyActiveAgent",
                    "archiveOnly", "setupApplySeparate"):
            self.assertIs(plan[key], True)
        self.assertNotIn(s.CONFIG, [p for p, _, _ in f.read_requests])

    def test_cli_defaults_to_read_only_plan(self):
        f = Fixture()
        f.files[str(Path(a.__file__).resolve())] = b"inert archive source"
        f.files[str(Path(a.__file__).with_name("setup.py").resolve())] = b"inert setup source"
        for name, raw in f.templates.items():
            f.files[str(s.TEMPLATES / name)] = raw
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(a, "Effects", return_value=f), \
             mock.patch.object(a.os, "geteuid", return_value=0), \
             mock.patch.object(a.sys, "platform", "linux"), \
             mock.patch.object(a.signal, "signal"), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = a.main(["--allow-unit", "demo.service", "--original-plan-sha256", f.original_hash])
        result = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(result["archivePlanSHA256"], s.digest(s.canonical(result["plan"])))
        self.assertEqual(f.actions, [])
        self.assertIn(s.ATTEMPT, f.files)
        self.assertTrue(f.absent(a.BACKUP))

    def test_success_archives_only_config_marker_and_restores_active_agent(self):
        f = Fixture()
        before_files, before_meta = copy.deepcopy(f.files), copy.deepcopy(f.meta)
        result = f.recover()
        self.assertTrue(result["archived"])
        self.assertTrue(result["agentRestarted"])
        self.assertTrue(result["retainedPartialState"])
        self.assertTrue(result["setupApplySeparate"])
        self.assertFalse(result["sourceVerified"])
        self.assertFalse(result["contentRead"])
        self.assertNotIn("failureStage", result)
        destination = a.ARCHIVE + "/" + Path(s.ATTEMPT).name
        expected_files = dict(before_files)
        expected_files[destination] = expected_files.pop(s.ATTEMPT)
        self.assertEqual(f.files, expected_files)
        self.assertEqual(f.meta[destination], before_meta[s.ATTEMPT])
        self.assertEqual(f.meta[a.ARCHIVE], before_meta[s.CONFIG_DIR])
        self.assertEqual((f.meta[a.BACKUP].st_uid, f.meta[a.BACKUP].st_gid,
                          stat.S_IMODE(f.meta[a.BACKUP].st_mode)), (0, 0, 0o700))
        self.assertTrue(f.absent(s.CONFIG_DIR))
        self.assertEqual(f.units[s.AGENT_UNIT]["ActiveState"], "active")
        self.assertEqual([x[0] for x in f.actions],
                         ["lock", "command", "command", "journal_absent", "archive", "command"])
        self.assert_no_setup_effects(f)

    def test_inactive_agent_remains_inactive_after_success_or_failure(self):
        for absent in (True, False):
            f = Fixture(active=False)
            f.absence_ok = absent
            result = f.recover()
            with self.subTest(absent=absent):
                self.assertEqual(result["archived"], absent)
                self.assertFalse(result["agentRestarted"])
                self.assertEqual(f.units[s.AGENT_UNIT]["ActiveState"], "inactive")
                self.assertFalse(any(x == ("command", ("/usr/bin/systemctl", "start", s.AGENT_UNIT))
                                     for x in f.actions))
                self.assert_no_setup_effects(f)

    def test_exact_original_and_archive_plan_hashes_required_before_stop(self):
        for original, archive in (("f" * 64, None), ("", None), (None, "f" * 64), (None, "")):
            f = Fixture()
            reviewed_hash = s.digest(s.canonical(f.review()))
            with self.subTest(original=original, archive=archive), self.assertRaises(s.Rejected):
                a.archive(f, f.allowed_units, f.templates,
                          f.original_hash if original is None else original,
                          reviewed_hash if archive is None else archive)
            self.assertEqual(f.actions, [("lock",)])
            self.assertIn(s.ATTEMPT, f.files)

    def test_changed_original_plan_and_reviewed_marker_identity_are_refused(self):
        for change in (lambda f: f.allowed_units.append("other.service"),
                       lambda f: setattr(f.meta[s.ATTEMPT], "st_ino", 888),
                       lambda f: setattr(f.meta[s.CONFIG_DIR], "st_ctime_ns", 999)):
            f = Fixture()
            reviewed_hash = s.digest(s.canonical(f.review()))
            change(f)
            with self.subTest(change=change), self.assertRaises(s.Rejected):
                f.recover(expected_archive=reviewed_hash)
            self.assertEqual(f.actions, [("lock",)])

    def test_helper_user_or_group_presence_refused_without_mutation(self):
        for path, data in (("/etc/passwd", b"tracebolt-journal-reader:x:300:301::/nonexistent:/usr/sbin/nologin\n"),
                           ("/etc/group", b"tracebolt-journal-reader:x:301:\n")):
            f = Fixture()
            f.files[path] += data
            with self.subTest(path=path), self.assertRaisesRegex(s.Rejected, "^existing-helper-account$"):
                f.review()
            self.assertEqual(f.actions, [])

    def test_existing_helper_paths_and_loaded_units_refused(self):
        for path in (s.RUNTIME_DIR, s.UNIT_DIR + "/" + s.SERVICE, s.UNIT_DIR + "/" + s.SOCKET,
                     s.UNIT_DIR + "/" + s.SERVICE + ".d", s.UNIT_DIR + "/" + s.SOCKET + ".d",
                     s.UNIT_DIR + "/sockets.target.wants/" + s.SOCKET):
            f = Fixture()
            f.files[path] = b"inert pre-existing file"
            with self.subTest(path=path), self.assertRaisesRegex(s.Rejected, "^existing-helper-path$"):
                f.review()
            self.assertEqual(f.actions, [])
        for unit in (s.SERVICE, s.SOCKET):
            f = Fixture()
            f.units[unit] = test_setup.status(unit, loaded=True)
            with self.subTest(unit=unit), self.assertRaisesRegex(s.Rejected, "^foreign-helper-systemd-unit$"):
                f.review()
            self.assertEqual(f.actions, [])

    def test_extra_config_entries_and_metadata_faults_refused_at_marker_seam(self):
        changes = [lambda f: f.files.__setitem__(s.POLICY, b"inert existing policy"),
                   lambda f: f.meta.__setitem__(s.CONFIG_DIR + "/extra", metadata(stat.S_IFDIR | 0o700))]
        for path, field, value in ((s.CONFIG_DIR, "st_uid", 200), (s.CONFIG_DIR, "st_gid", 201),
                                   (s.CONFIG_DIR, "st_mode", stat.S_IFDIR | 0o700),
                                   (s.CONFIG_DIR, "st_mode", stat.S_IFLNK | 0o755),
                                   (s.ATTEMPT, "st_uid", 200), (s.ATTEMPT, "st_gid", 201),
                                   (s.ATTEMPT, "st_mode", stat.S_IFREG | 0o640),
                                   (s.ATTEMPT, "st_mode", stat.S_IFLNK | 0o600),
                                   (s.ATTEMPT, "st_nlink", 2), (s.ATTEMPT, "st_size", 5000)):
            changes.append(lambda f, p=path, k=field, v=value: setattr(f.meta[p], k, v))
        for change in changes:
            f = Fixture()
            change(f)
            with self.subTest(change=change), self.assertRaises(s.Rejected):
                f.review()
            self.assertEqual(f.actions, [])

    def test_malformed_noncanonical_or_wrong_attempt_identity_is_refused(self):
        f = Fixture()
        raw = f.files[s.ATTEMPT]
        cases = [b"{}", raw + b"\n", raw[:-1] + b',"unknown":true}',
                 raw[:-1] + b',"schemaVersion":"duplicate"}',
                 s.canonical(dict(f.attempt, schemaVersion="unknown")),
                 s.canonical(dict(f.attempt, senderBinding="0" * 64)),
                 s.canonical(dict(f.attempt, certificateHash="not-a-hash")),
                 s.canonical(dict(f.attempt, deviceId="foreign-device")),
                 s.canonical(dict(f.attempt, planSHA256="f" * 64))]
        for bad in cases:
            f = Fixture()
            f.files[s.ATTEMPT] = bad
            f.meta[s.ATTEMPT].st_size = len(bad)
            with self.subTest(raw=bad), self.assertRaises(s.Rejected):
                f.review()
            self.assertEqual(f.actions, [])

    def test_changed_stopped_attempt_identity_retains_marker_and_restores_agent(self):
        for key, value in (("senderBinding", "f" * 64), ("deviceId", "agent_" + "f" * 32),
                           ("certificateHash", "f" * 64)):
            f = Fixture()
            f.preview[key] = value
            before = copy.deepcopy(f.files)
            result = f.recover()
            with self.subTest(key=key):
                self.assertEqual(result["failureStage"], "attempt-identity-changed")
                self.assertFalse(result["archived"])
                self.assertTrue(result["agentRestarted"])
                self.assertEqual(f.files, before)
                self.assertFalse(any(x[0] in ("archive", "journal_absent") for x in f.actions))
                self.assert_no_setup_effects(f)

    def test_marker_changed_after_stop_fails_review_and_restores_agent(self):
        f = Fixture()
        original = f.command
        def command(args, **kwargs):
            result = original(args, **kwargs)
            if args[0] == s.BINARY:
                f.meta[s.ATTEMPT].st_ctime_ns += 1
            return result
        f.command = command
        result = f.recover()
        self.assertEqual(result["failureStage"], "archive-reviewed-plan-changed")
        self.assertFalse(result["archived"])
        self.assertTrue(result["agentRestarted"])
        self.assertIn(s.ATTEMPT, f.files)
        self.assertFalse(any(x[0] in ("archive", "journal_absent") for x in f.actions))

    def test_journal_absence_failure_preserves_state_and_restores_agent(self):
        f = Fixture()
        f.absence_ok = False
        before = copy.deepcopy(f.files)
        result = f.recover()
        self.assertEqual(result["failureStage"], "journal-state-absence-not-confirmed")
        self.assertFalse(result["archived"])
        self.assertTrue(result["agentRestarted"])
        self.assertTrue(result["retainedPartialState"])
        self.assertEqual(f.files, before)
        self.assertTrue(f.absent(a.BACKUP))
        self.assertFalse(any(x[0] == "archive" for x in f.actions))
        self.assert_no_setup_effects(f)

    def test_archive_failure_retains_state_and_restores_agent(self):
        f = Fixture()
        f.fail = ("archive", a.ARCHIVE)
        before = copy.deepcopy(f.files)
        result = f.recover()
        self.assertEqual(result["failureStage"], "injected-failure")
        self.assertFalse(result["archived"])
        self.assertTrue(result["agentRestarted"])
        self.assertTrue(result["retainedPartialState"])
        self.assertEqual(f.files, before)
        self.assert_no_setup_effects(f)

    def test_partial_backup_is_retained_and_refuses_automatic_retry(self):
        f = Fixture()
        reviewed_hash = s.digest(s.canonical(f.review()))
        def archive(snapshot):
            f.effect("archive", a.ARCHIVE)
            f.meta[a.BACKUP] = metadata(stat.S_IFDIR | 0o700, ino=102, nlink=2)
            raise OSError("private raw path and error must not escape")
        f.archive = archive
        result = f.recover(expected_archive=reviewed_hash)
        self.assertEqual(result["failureStage"], "archive-operation-failed-retain-state")
        self.assertFalse(result["archived"])
        self.assertTrue(result["agentRestarted"])
        self.assertIn(s.ATTEMPT, f.files)
        self.assertIn(a.BACKUP, f.meta)
        f.actions.clear()
        with self.assertRaisesRegex(s.Rejected, "^archive-destination-exists$"):
            f.recover(expected_archive=reviewed_hash)
        self.assertEqual(f.actions, [("lock",)])

    def test_existing_backup_refused_even_when_original_marker_remains(self):
        for kind in ("file", "directory"):
            f = Fixture()
            if kind == "file":
                f.files[a.BACKUP] = b"inert existing archive"
            else:
                f.meta[a.BACKUP] = metadata(stat.S_IFDIR | 0o700)
            with self.subTest(kind=kind), self.assertRaisesRegex(s.Rejected, "^archive-destination-exists$"):
                f.review()
            self.assertEqual(f.actions, [])

    def test_successful_archive_cannot_be_retried(self):
        f = Fixture()
        reviewed_hash = s.digest(s.canonical(f.review()))
        self.assertTrue(f.recover(expected_archive=reviewed_hash)["archived"])
        before = copy.deepcopy(f.files)
        f.actions.clear()
        with self.assertRaises(s.Rejected):
            f.recover(expected_archive=reviewed_hash)
        self.assertEqual(f.actions, [("lock",)])
        self.assertEqual(f.files, before)

    def test_changed_installer_ownership_blocks_restart_without_override(self):
        for after_archive in (False, True):
            f = Fixture()
            original = f.archive
            def archive(snapshot):
                if after_archive:
                    original(snapshot)
                f.files[s.INSTALLER_DIR + "/transaction.json"] = b"inert uncertain transaction"
                if not after_archive:
                    raise s.Rejected("injected-failure")
            f.archive = archive
            result = f.recover()
            with self.subTest(after_archive=after_archive):
                self.assertEqual(result["archived"], after_archive)
                self.assertEqual(result["failureStage"], "agent-restart-blocked-retain-state")
                self.assertFalse(result["agentRestarted"])
                self.assertEqual(f.units[s.AGENT_UNIT]["ActiveState"], "inactive")
                self.assertFalse(any(x == ("command", ("/usr/bin/systemctl", "start", s.AGENT_UNIT))
                                     for x in f.actions))
                self.assert_no_setup_effects(f)

    def test_stop_failure_or_nonzero_stopped_pid_never_reaches_archive(self):
        for fault in ("command", "pid"):
            f = Fixture()
            if fault == "command":
                f.fail = ("command", ("/usr/bin/systemctl", "stop", s.AGENT_UNIT))
            else:
                original = f.command
                def command(args, **kwargs):
                    result = original(args, **kwargs)
                    if args == ["/usr/bin/systemctl", "stop", s.AGENT_UNIT]:
                        f.units[s.AGENT_UNIT]["MainPID"] = "123"
                    return result
                f.command = command
            result = f.recover()
            with self.subTest(fault=fault):
                self.assertFalse(result["archived"])
                self.assertTrue(result["agentRestarted"])
                self.assertIn(s.ATTEMPT, f.files)
                self.assertFalse(any(x[0] in ("archive", "journal_absent") for x in f.actions))


class EffectsMarkerTests(unittest.TestCase):
    @contextlib.contextmanager
    def boundary(self, names=None, directory=None, marker=None):
        directory = directory or metadata(stat.S_IFDIR | 0o755, size=4096, nlink=2)
        marker = marker or metadata(stat.S_IFREG | 0o600, ino=101, size=7)
        entries = [types.SimpleNamespace(name=name) for name in
                   ([Path(s.ATTEMPT).name] if names is None else names)]
        scan = mock.MagicMock()
        scan.__enter__.return_value = iter(entries)
        e = a.Effects()
        with contextlib.ExitStack() as stack:
            patches = {"open": mock.Mock(return_value=10), "close": mock.Mock(),
                       "fstat": mock.Mock(return_value=directory),
                       "scandir": mock.Mock(return_value=scan), "stat": mock.Mock(return_value=marker),
                       "lstat": mock.Mock(side_effect=lambda p: marker if p == s.ATTEMPT else directory)}
            for name, replacement in patches.items():
                stack.enter_context(mock.patch.object(a.os, name, replacement))
            stack.enter_context(mock.patch.object(e, "protected_dir"))
            read = stack.enter_context(mock.patch.object(e, "read", return_value=b"fixture"))
            yield e, patches, read

    def test_real_marker_adapter_uses_singleton_nofollow_boundary(self):
        with self.boundary() as (e, calls, read):
            raw, directory, marker = e.marker()
        self.assertEqual(raw, b"fixture")
        self.assertEqual(directory.st_uid, 0)
        self.assertEqual(marker.st_gid, 0)
        calls["open"].assert_called_once_with(s.CONFIG_DIR,
            a.os.O_RDONLY | a.os.O_DIRECTORY | a.os.O_NOFOLLOW | a.os.O_CLOEXEC)
        read.assert_called_once_with(s.ATTEMPT, 4096, 0o600)
        self.assertEqual(calls["stat"].call_args_list, [
            mock.call(Path(s.ATTEMPT).name, dir_fd=10, follow_symlinks=False),
            mock.call(Path(s.ATTEMPT).name, dir_fd=10, follow_symlinks=False)])
        calls["close"].assert_called_once_with(10)

    def test_real_marker_adapter_refuses_extra_entries_and_root_group_faults(self):
        for names, directory, marker in (([], None, None), ([Path(s.ATTEMPT).name, "extra"], None, None),
                (None, metadata(stat.S_IFDIR | 0o755, gid=201), None),
                (None, metadata(stat.S_IFDIR | 0o700), None),
                (None, None, metadata(stat.S_IFREG | 0o600, gid=201))):
            with self.subTest(names=names, directory=directory, marker=marker):
                with self.boundary(names, directory, marker) as (e, calls, _), self.assertRaises(s.Rejected):
                    e.marker()
                calls["close"].assert_called_once_with(10)


class EffectsArchiveTests(unittest.TestCase):
    @contextlib.contextmanager
    def boundary(self, rename_result=0):
        parent = metadata(stat.S_IFDIR | 0o755, ino=10, nlink=2)
        source = metadata(stat.S_IFDIR | 0o755, ino=20, nlink=2)
        backup = metadata(stat.S_IFDIR | 0o700, ino=30, nlink=2)
        marker = metadata(stat.S_IFREG | 0o600, ino=40, size=7)
        snapshot = dict(sha256=s.digest(b"fixture"), directory=a.identity(source), marker=a.identity(marker))
        rename = mock.Mock(return_value=rename_result)
        libc = types.SimpleNamespace(renameat2=rename)
        def st(path, **kwargs):
            if path == Path(a.BACKUP).name:
                return backup
            if path == "tracebolt":
                return source
            if path == Path(s.ATTEMPT).name:
                return marker
            raise AssertionError("Unexpected mocked stat: " + str(path))
        e = a.Effects()
        with contextlib.ExitStack() as stack:
            calls = {"open": mock.Mock(side_effect=[10, 20, 30, 40]), "close": mock.Mock(),
                     "fstat": mock.Mock(side_effect=lambda fd: {10: parent, 20: source, 30: backup, 40: marker}[fd]),
                     "lstat": mock.Mock(return_value=parent), "stat": mock.Mock(side_effect=st),
                     "read": mock.Mock(return_value=b"fixture")}
            calls.update({name: mock.Mock() for name in ("mkdir", "fchown", "fchmod", "fsync")})
            calls.update({name: mock.Mock(side_effect=AssertionError("Forbidden archive mutation: " + name))
                          for name in ("unlink", "rmdir", "rename", "replace")})
            for name, replacement in calls.items():
                stack.enter_context(mock.patch.object(a.os, name, replacement))
            stack.enter_context(mock.patch.object(a.ctypes, "CDLL", return_value=libc))
            stack.enter_context(mock.patch.object(e, "protected_dir"))
            stack.enter_context(mock.patch.object(e, "marker_snapshot", return_value=snapshot))
            stack.enter_context(mock.patch.object(e, "absent", return_value=True))
            yield e, snapshot, rename, calls

    def test_real_archive_adapter_uses_fixed_no_clobber_rename_and_syncs(self):
        with self.boundary() as (e, snapshot, rename, calls):
            e.archive(snapshot)
        rename.assert_called_once_with(10, b"tracebolt", 30, b"tracebolt", 1)
        calls["mkdir"].assert_called_once_with(Path(a.BACKUP).name, 0o700, dir_fd=10)
        calls["fchown"].assert_called_once_with(30, 0, 0)
        calls["fchmod"].assert_called_once_with(30, 0o700)
        calls["read"].assert_called_once_with(40, 4097)
        self.assertEqual(calls["close"].call_args_list, [mock.call(40), mock.call(20), mock.call(30), mock.call(10)])
        self.assertEqual(calls["fsync"].call_args_list,
                         [mock.call(30), mock.call(10), mock.call(20), mock.call(30), mock.call(10)])

    def test_real_archive_adapter_refuses_failed_rename_without_retry(self):
        with self.boundary(rename_result=-1) as (e, snapshot, rename, calls):
            with self.assertRaisesRegex(s.Rejected, "^archive-no-clobber-rename-failed$"):
                e.archive(snapshot)
        self.assertEqual(rename.call_count, 1)
        calls["read"].assert_not_called()
        self.assertEqual(calls["close"].call_args_list, [mock.call(20), mock.call(30), mock.call(10)])


class EffectsJournalAbsenceTests(unittest.TestCase):
    @contextlib.contextmanager
    def boundary(self, chunks=None, returncode=0, running=False, times=None):
        """Every process, descriptor, executable lookup, and clock is synthetic."""
        chunks = [b'{"journalStateAbsent":true}\n', b""] if chunks is None else chunks
        e = a.Effects()
        child = mock.Mock(pid=777)
        child.stdout.fileno.return_value = 91
        child.wait.return_value = returncode
        child.poll.return_value = None if running else returncode
        selected = mock.MagicMock()
        selector = selected.__enter__.return_value
        selector.get_map.side_effect = [True] * len(chunks) + [False]
        selector.select.return_value = [(types.SimpleNamespace(fileobj=child.stdout), s.selectors.EVENT_READ)]
        with contextlib.ExitStack() as stack:
            calls = {}
            calls["resolve"] = stack.enter_context(mock.patch.object(a.Path, "resolve", return_value=Path("/usr/bin/python3.12")))
            calls["read_executable"] = stack.enter_context(mock.patch.object(e, "read", return_value=b"inert interpreter"))
            calls["popen"] = stack.enter_context(mock.patch.object(a.subprocess, "Popen", return_value=child))
            calls["run"] = stack.enter_context(mock.patch.object(a.subprocess, "run", side_effect=AssertionError("No unbounded subprocess.run")))
            calls["selectors"] = stack.enter_context(mock.patch.object(s.selectors, "DefaultSelector", return_value=selected))
            calls["read"] = stack.enter_context(mock.patch.object(a.os, "read", side_effect=chunks))
            calls["killpg"] = stack.enter_context(mock.patch.object(a.os, "killpg"))
            calls["time"] = stack.enter_context(mock.patch.object(s.time, "monotonic", return_value=0,
                                                                  side_effect=times))
            yield e, child, selector, calls

    def test_nonroot_probe_uses_exact_fixed_argv_ids_groups_and_environment(self):
        with self.boundary() as (e, child, selector, calls):
            self.assertIsNone(e.journal_absent(dict(uid=200, gid=201)))
        args, kw = calls["popen"].call_args
        self.assertEqual(args, (["/usr/bin/python3.12", "-I", "-S", "-c", a.ABSENCE_PROBE, "200", "201"],))
        self.assertTrue(a.ABSENCE_PROBE)
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (200, 201, []))
        self.assertIs(type(kw["user"]), int)
        self.assertIs(type(kw["group"]), int)
        self.assertEqual(kw["env"], s.ENV)
        self.assertEqual(kw["cwd"], "/")
        self.assertTrue(kw["close_fds"])
        self.assertTrue(kw["start_new_session"])
        self.assertEqual(kw["stdin"], a.subprocess.DEVNULL)
        self.assertEqual(kw["stdout"], a.subprocess.PIPE)
        self.assertEqual(kw["stderr"], a.subprocess.DEVNULL)
        self.assertNotIn("shell", kw)
        self.assertNotIn("preexec_fn", kw)
        calls["read_executable"].assert_called_once_with("/usr/bin/python3.12", 256 << 20)
        self.assertEqual(calls["read"].call_args_list, [mock.call(91, 65), mock.call(91, 65)])
        selector.unregister.assert_called_once_with(child.stdout)
        child.wait.assert_called_once_with(timeout=5)
        child.stdout.close.assert_called_once_with()
        calls["killpg"].assert_not_called()
        calls["run"].assert_not_called()

    def test_probe_accepts_only_exact_true_boolean_and_zero_exit(self):
        values = [b"", b'{"journalStateAbsent":false}\n', b'{"journalStateAbsent":1}\n',
                  b'{"journalStateAbsent":"true"}\n', b'{"journalStateAbsent":true}',
                  b'{"journalStateAbsent":true,"extra":true}\n',
                  b'{"journalStateAbsent":true}\nprivate-output', b"private raw diagnostic"]
        for raw, returncode in [(value, 0) for value in values] + [(b'{"journalStateAbsent":true}\n', 1)]:
            with self.subTest(raw=raw, returncode=returncode):
                with self.boundary(chunks=[raw, b""], returncode=returncode) as (e, child, _, _):
                    with self.assertRaisesRegex(s.Rejected, "^journal-state-absence-not-confirmed$"):
                        e.journal_absent(dict(uid=200, gid=201))
                child.stdout.close.assert_called_once_with()

    def test_probe_output_and_runtime_are_bounded_and_live_child_is_killed(self):
        for chunks, times, stage in (([b"x" * 65], None, "journal-state-probe-output-limit"),
                                    ([b"x"], [0, 6], "journal-state-probe-timeout")):
            with self.subTest(stage=stage):
                with self.boundary(chunks=chunks, running=True, times=times) as (e, child, _, calls):
                    with self.assertRaisesRegex(s.Rejected, "^" + stage + "$"):
                        e.journal_absent(dict(uid=200, gid=201))
                calls["killpg"].assert_called_once_with(777, a.signal.SIGKILL)
                child.wait.assert_called_once_with()
                child.stdout.close.assert_called_once_with()
                calls["run"].assert_not_called()

    def test_untrusted_interpreter_and_missing_probe_fail_before_process(self):
        for path in ("/usr/local/bin/python3", "/usr/bin/python3-malicious", "/usr/bin/python3.12/child"):
            with self.subTest(path=path), self.boundary() as (e, _, _, calls):
                calls["resolve"].return_value = Path(path)
                with self.assertRaisesRegex(s.Rejected, "^fixed-recovery-interpreter$"):
                    e.journal_absent(dict(uid=200, gid=201))
                calls["popen"].assert_not_called()
                calls["read_executable"].assert_not_called()
        with self.boundary() as (e, _, _, calls), mock.patch.object(a, "ABSENCE_PROBE", ""):
            with self.assertRaisesRegex(s.Rejected, "^missing-recovery-probe$"):
                e.journal_absent(dict(uid=200, gid=201))
            calls["popen"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
