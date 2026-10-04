"""Inert tests: every filesystem/identity/write call goes to FakeProbeOS.

To embed these tests in an archive test module, import its probe constant as
JOURNAL_ABSENCE_PROBE instead. Compilation executes definitions only, never the
production __main__ entry point. No live fixed path is accessed.
"""
import copy
import errno
import json
import os
import stat
import types
import unittest

from archive_account_attempt import ABSENCE_PROBE as JOURNAL_ABSENCE_PROBE


def load_probe():
    scope = {"__name__": "inert_probe_definitions"}
    exec(compile(JOURNAL_ABSENCE_PROBE, "<trusted-journal-absence-probe>", "exec"), scope)
    return scope


PROBE = load_probe()
BASE = ("var", "lib", "tracebolt-agent", "enrollment")
CONFIG = BASE + ("agent.json",)
TELEMETRY = BASE + ("telemetry",)
JOURNAL = TELEMETRY + ("journal",)
UID, GID = 1101, 1102


def valid_config(profile="tls"):
    base = "/var/lib/tracebolt-agent/enrollment"
    return {
        "schemaVersion": "tracebolt.lan-agent.v5", "profile": profile,
        "managerOrigin": "https://manager.example:8443" if profile == "tls" else "http://127.0.0.1:8080",
        "agentId": "agent_" + "a" * 32,
        "certificateFile": base + "/agent-cert.pem", "privateKeyFile": base + "/agent-key.pem",
        "serverCAFile": base + "/server-ca.pem" if profile == "tls" else "",
        "stateDirectory": base + "/telemetry", "insecureHTTPAcknowledged": profile == "http-test",
        "collectionProfile": "managed-operations-v3",
    }


class FakeProbeOS:
    # Constants are inert values. No os filesystem or process operation is called.
    O_RDONLY, O_DIRECTORY = os.O_RDONLY, os.O_DIRECTORY
    O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK = os.O_NOFOLLOW, os.O_CLOEXEC, os.O_NONBLOCK

    def __init__(self, config=None):
        self.nodes = {}
        for index, path in enumerate([(), ("var",), ("var", "lib"), BASE[:3], BASE, TELEMETRY]):
            private = len(path) >= 3
            self.nodes[path] = types.SimpleNamespace(
                st_dev=5, st_ino=index + 1, st_mode=stat.S_IFDIR | (0o700 if private else 0o755),
                st_uid=UID if private else 0, st_gid=GID if private else 0,
                st_nlink=2, st_size=4096, st_mtime_ns=100, st_ctime_ns=100)
        self.nodes[CONFIG] = types.SimpleNamespace(
            st_dev=5, st_ino=99, st_mode=stat.S_IFREG | 0o600, st_uid=UID, st_gid=GID,
            st_nlink=1, st_size=0, st_mtime_ns=100, st_ctime_ns=100)
        self.set_raw(json.dumps(valid_config() if config is None else config).encode())
        self.fds, self.offsets = {}, {}
        self.next_fd = 10
        self.calls, self.opened_paths, self.read_paths, self.output = [], [], [], bytearray()
        self.uids, self.gids, self.groups = (UID,) * 3, (GID,) * 3, []
        self.hook = None
        self.max_chunk = None

    def set_raw(self, raw):
        self.raw = raw
        self.nodes[CONFIG].st_size = len(raw)

    def getresuid(self):
        return self.uids

    def getresgid(self):
        return self.gids

    def getgroups(self):
        return self.groups

    def event(self, method, path):
        self.calls.append((method, path))
        if self.hook:
            self.hook(method, path, self)

    def resolve(self, name, dir_fd):
        if dir_fd is None:
            assert name == "/", "Only a fixed root open is allowed"
            return ()
        assert "/" not in name and name not in (".", "..", "")
        return self.fds[dir_fd][0] + (name,)

    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        assert follow_symlinks is False
        path = self.resolve(name, dir_fd)
        self.event("stat", path)
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "inert fixture missing")
        return copy.copy(self.nodes[path])

    def open(self, name, flags, *, dir_fd=None):
        path = self.resolve(name, dir_fd)
        self.event("open", path)
        assert flags & self.O_NOFOLLOW and flags & self.O_CLOEXEC
        assert path in [(), ("var",), ("var", "lib"), BASE[:3], BASE, CONFIG, TELEMETRY]
        node = self.nodes[path]
        if stat.S_ISLNK(node.st_mode):
            raise OSError(errno.ELOOP, "inert nofollow rejection")
        if path == CONFIG:
            assert flags == (self.O_RDONLY | self.O_NOFOLLOW | self.O_CLOEXEC | self.O_NONBLOCK)
        else:
            assert flags == (self.O_RDONLY | self.O_NOFOLLOW | self.O_CLOEXEC | self.O_DIRECTORY)
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = (path, copy.copy(node))
        self.offsets[fd] = 0
        self.opened_paths.append(path)
        return fd

    def fstat(self, fd):
        path, opened = self.fds[fd]
        self.event("fstat", path)
        current = self.nodes.get(path)
        return copy.copy(current if current and current.st_ino == opened.st_ino else opened)

    def read(self, fd, size):
        path = self.fds[fd][0]
        assert path == CONFIG, "No credential, ledger or journal contents may be read"
        self.event("read", path)
        self.read_paths.append(path)
        assert 0 < size <= 16385
        if self.max_chunk is not None:
            size = min(size, self.max_chunk)
        pos = self.offsets[fd]
        result = self.raw[pos:pos + size]
        self.offsets[fd] += len(result)
        return result

    def close(self, fd):
        self.event("close", self.fds[fd][0])
        del self.fds[fd]
        del self.offsets[fd]

    def write(self, fd, raw):
        assert fd == 1
        self.event("write", None)
        self.output.extend(raw)
        return len(raw)


class JournalAbsenceProbeTests(unittest.TestCase):
    def run_probe(self, fs=None, argv=None):
        fs = fs or FakeProbeOS()
        result = PROBE["_main"](fs, argv or ["-c", str(UID), str(GID)])
        self.assertFalse(fs.fds, "All mock descriptors must close")
        self.assertTrue(all(path == CONFIG for path in fs.read_paths))
        return result, bytes(fs.output)

    def assert_rejected(self, fs, argv=None):
        self.assertEqual((1, b""), self.run_probe(fs, argv))

    def test_success_is_exact_and_reads_only_public_config(self):
        for profile in ("tls", "http-test"):
            fs = FakeProbeOS(valid_config(profile))
            self.assertEqual((0, b'{"journalStateAbsent":true}\n'), self.run_probe(fs))
            self.assertEqual(2, fs.calls.count(("stat", JOURNAL)))
            self.assertEqual([CONFIG], sorted(set(fs.read_paths)))
            self.assertNotIn(JOURNAL, fs.opened_paths)

    def test_short_reads_are_bounded_and_supported(self):
        fs = FakeProbeOS()
        fs.max_chunk = 7
        self.assertEqual(0, self.run_probe(fs)[0])

    def test_identity_and_arguments_are_strict_before_any_path_access(self):
        variants = [((0, 0, 0), (GID,) * 3, []), ((UID, UID, 0), (GID,) * 3, []),
                    ((UID,) * 3, (GID, GID, 0), []), ((UID,) * 3, (0, 0, 0), []),
                    ((UID,) * 3, (GID,) * 3, [GID]), ((UID + 1,) * 3, (GID,) * 3, [])]
        for uids, gids, groups in variants:
            fs = FakeProbeOS()
            fs.uids, fs.gids, fs.groups = uids, gids, groups
            self.assert_rejected(fs)
            self.assertFalse(fs.calls)
        for args in (["-c"], ["-c", "0", str(GID)], ["-c", "01101", str(GID)],
                     ["-c", "+1101", str(GID)], ["-c", str(UID), "0"],
                     ["-c", "4294967295", str(GID)], ["-c", str(UID), str(GID), "/tmp"]):
            fs = FakeProbeOS()
            self.assert_rejected(fs, args)
            self.assertFalse(fs.calls)

    def test_all_missing_ancestors_and_config_fail(self):
        for path in [(), ("var",), ("var", "lib"), BASE[:3], BASE, CONFIG, TELEMETRY]:
            fs = FakeProbeOS()
            del fs.nodes[path]
            self.assert_rejected(fs)

    def test_all_symlink_and_nondirectory_ancestors_fail(self):
        for path in [(), ("var",), ("var", "lib"), BASE[:3], BASE, TELEMETRY]:
            for mode in (stat.S_IFLNK | 0o777, stat.S_IFREG | 0o700, stat.S_IFIFO | 0o700):
                fs = FakeProbeOS()
                fs.nodes[path].st_mode = mode
                self.assert_rejected(fs)

    def test_private_directories_require_exact_identity_and_mode(self):
        for path in (BASE[:3], BASE, TELEMETRY):
            for attr, value in (("st_uid", 0), ("st_gid", 0), ("st_mode", stat.S_IFDIR | 0o750),
                                ("st_mode", stat.S_IFDIR | 0o1700)):
                fs = FakeProbeOS()
                setattr(fs.nodes[path], attr, value)
                self.assert_rejected(fs)

    def test_public_ancestors_require_root_and_no_writable_or_special_bits(self):
        for path in [(), ("var",), ("var", "lib")]:
            for attr, value in (("st_uid", UID), ("st_gid", GID),
                                ("st_mode", stat.S_IFDIR | 0o775), ("st_mode", stat.S_IFDIR | 0o1777)):
                fs = FakeProbeOS()
                setattr(fs.nodes[path], attr, value)
                self.assert_rejected(fs)

    def test_config_file_owner_mode_hardlinks_types_and_size(self):
        for attr, value in (("st_uid", 0), ("st_gid", 0), ("st_nlink", 2), ("st_nlink", 0),
                            ("st_mode", stat.S_IFREG | 0o640), ("st_mode", stat.S_IFREG | 0o4600),
                            ("st_mode", stat.S_IFLNK | 0o600), ("st_mode", stat.S_IFDIR | 0o600),
                            ("st_mode", stat.S_IFIFO | 0o600), ("st_size", 0), ("st_size", 16385)):
            fs = FakeProbeOS()
            setattr(fs.nodes[CONFIG], attr, value)
            self.assert_rejected(fs)
            self.assertFalse(fs.read_paths)

    def test_journal_any_existing_entry_fails_without_open(self):
        for mode in (stat.S_IFDIR | 0o700, stat.S_IFREG | 0o600, stat.S_IFLNK | 0o777,
                     stat.S_IFIFO | 0o600, stat.S_IFSOCK | 0o600):
            fs = FakeProbeOS()
            fs.nodes[JOURNAL] = copy.copy(fs.nodes[TELEMETRY])
            fs.nodes[JOURNAL].st_mode = mode
            self.assert_rejected(fs)
            self.assertNotIn(JOURNAL, fs.opened_paths)

    def test_journal_permission_and_io_error_are_not_absence(self):
        for error in (PermissionError(errno.EACCES, "inert"), OSError(errno.EIO, "inert"),
                      NotADirectoryError(errno.ENOTDIR, "inert")):
            fs = FakeProbeOS()
            def fail(method, path, fixture):
                if method == "stat" and path == JOURNAL:
                    raise error
            fs.hook = fail
            self.assert_rejected(fs)

    def test_strict_full_known_config_shape(self):
        for key in valid_config():
            for mutation in ("missing", "null", "wrong-type"):
                c = valid_config()
                if mutation == "missing":
                    del c[key]
                else:
                    c[key] = None if mutation == "null" else (0 if key == "insecureHTTPAcknowledged" else [])
                self.assert_rejected(FakeProbeOS(c))
        c = valid_config()
        c["extra"] = "ignored?"
        self.assert_rejected(FakeProbeOS(c))
        for raw in (b"[]", b"null", b"{}", b"NaN", b"{", b"\xff", b"\xef\xbb\xbf{}",
                    json.dumps(valid_config()).encode() + b"{}",
                    json.dumps(valid_config()).encode()[:-1] + b',"profile":"tls"}',
                    json.dumps(valid_config()).replace("manager.example", "manager\\ufffdexample").encode()):
            fs = FakeProbeOS()
            fs.set_raw(raw)
            self.assert_rejected(fs)

    def test_schema_profile_id_paths_and_ack_are_exact(self):
        changes = {"schemaVersion": ["tracebolt.lan-agent.v4", "tracebolt.lan-agent.v6"],
                   "collectionProfile": ["managed-operations-v2", ""],
                   "profile": ["", "TLS", "http-test"], "insecureHTTPAcknowledged": [True, "false", 0],
                   "agentId": ["agent_" + "A" * 32, "agent_" + "a" * 31, "agent_" + "a" * 32 + "\n"],
                   "certificateFile": ["/tmp/cert", "/var/lib/tracebolt-agent/enrollment/./agent-cert.pem"],
                   "privateKeyFile": ["/tmp/key"], "serverCAFile": ["", "/tmp/ca"],
                   "stateDirectory": ["/tmp/telemetry", "/var/lib/tracebolt-agent/enrollment/telemetry/",
                                      "/var/lib/tracebolt-agent/enrollment/./telemetry"]}
        for key, values in changes.items():
            for value in values:
                c = valid_config()
                c[key] = value
                self.assert_rejected(FakeProbeOS(c))

    def test_origin_is_bounded_ascii_metadata_only(self):
        for origin in ("", "a" * 513, "https://m\u00e4nager.example", None, 12, [], {}):
            c = valid_config()
            c["managerOrigin"] = origin
            self.assert_rejected(FakeProbeOS(c))
        # Identity/origin/handoff validity belongs to the fresh consent preview.
        # Recovery must not grow a divergent copy of the Go routing policy.
        for origin in ("a", "a" * 512, "https://manager.example:443", "https://192.0.2.1"):
            c = valid_config()
            c["managerOrigin"] = origin
            self.assertEqual(0, self.run_probe(FakeProbeOS(c))[0])

    def test_config_size_growth_truncation_and_read_error_fail_silently(self):
        for raw in (b"x" * 16385, b"x"):
            fs = FakeProbeOS()
            fs.raw = raw
            self.assert_rejected(fs)
        fs = FakeProbeOS()
        def fail(method, path, fixture):
            if method == "read":
                raise OSError(errno.EIO, "inert private data must never be echoed")
        fs.hook = fail
        self.assert_rejected(fs)

    def test_all_open_races_are_detected_before_use(self):
        for target in [(), ("var",), ("var", "lib"), BASE[:3], BASE, CONFIG, TELEMETRY]:
            fs = FakeProbeOS()
            def replace(method, path, fixture):
                if method == "open" and path == target:
                    fixture.nodes[path].st_ino += 100
            fs.hook = replace
            self.assert_rejected(fs)

    def test_final_metadata_and_link_replacement_are_detected(self):
        for target in [(), ("var",), ("var", "lib"), BASE[:3], BASE, CONFIG, TELEMETRY]:
            for attribute in ("st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size",
                              "st_mtime_ns", "st_ctime_ns", "st_dev"):
                fs = FakeProbeOS()
                def replace(method, path, fixture):
                    if method == "stat" and path == JOURNAL and fixture.calls.count((method, path)) == 1:
                        setattr(fixture.nodes[target], attribute, getattr(fixture.nodes[target], attribute) + 100)
                fs.hook = replace
                self.assert_rejected(fs)

    def test_journal_appearing_between_absence_checks_fails(self):
        fs = FakeProbeOS()
        def appear(method, path, fixture):
            if method == "stat" and path == JOURNAL and fixture.calls.count((method, path)) == 2:
                fixture.nodes[JOURNAL] = copy.copy(fixture.nodes[TELEMETRY])
        fs.hook = appear
        self.assert_rejected(fs)

    def test_late_parent_metadata_change_is_checked_after_second_absence(self):
        fs = FakeProbeOS()
        def change(method, path, fixture):
            if method == "stat" and path == JOURNAL and fixture.calls.count((method, path)) == 2:
                fixture.nodes[TELEMETRY].st_ctime_ns += 1
        fs.hook = change
        self.assert_rejected(fs)

    def test_import_and_compile_do_not_run_probe(self):
        self.assertTrue(callable(load_probe()["_probe"]))
        self.assertNotIn("subprocess", JOURNAL_ABSENCE_PROBE)
        self.assertNotIn("socket", JOURNAL_ABSENCE_PROBE)
        self.assertNotIn("ledger", JOURNAL_ABSENCE_PROBE)


if __name__ == "__main__":
    unittest.main()
