"""Inert SBOM fixtures: no release, native program, credential or network action."""
import copy
from contextlib import contextmanager
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("candidate_evidence", ROOT / "deploy/release/build-candidate-evidence.py")
e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e)
VERSION = "v0.1.0-evidence.1"
COMMIT = "a" * 40
CHECKSUM = "h1:" + "A" * 43 + "="


class CandidateEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tracebolt-inert-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir(mode=0o700)
        self.output = self.root / "evidence"
        self.go_mod = b"module localrmm\n\ngo 1.27.1\n"
        self.go_sum = ("example.org/dependency v1.2.3 " + CHECKSUM + "\n").encode()
        self.assets = {}
        for name in sorted(e.b.asset_names(VERSION)):
            if name.endswith("-source.tar"):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as archive:
                    for lock_name, raw in (("go.mod", self.go_mod), ("go.sum", self.go_sum)):
                        member = tarfile.TarInfo(lock_name)
                        member.size = len(raw)
                        archive.addfile(member, io.BytesIO(raw))
                raw = stream.getvalue()
            else:
                raw = ("inert never-executed binary " + name).encode()
            path = self.candidate / name
            path.write_bytes(raw)
            path.chmod(0o600)
            self.assets[name] = {"size": len(raw), "sha256": e.b.digest(raw)}
        self.manifest = {"schema": e.b.SCHEMA, "repository": e.b.REPOSITORY, "version": VERSION, "sourceCommit": COMMIT,
                         "runtimeTargets": list(e.b.RUNTIME_TARGETS), "assets": self.assets}
        self.write_manifest()
        self.binary = next(name for name in self.assets if "-linux-amd64-" in name)

    def write_manifest(self):
        path = self.candidate / "manifest.json"
        path.write_bytes(e.canonical(self.manifest))
        path.chmod(0o600)

    def info(self, path):
        arch, role = path.name.split("-linux-", 1)[1].split("-", 1)
        settings = {"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0", "-trimpath": "true", "vcs": "git",
                    "vcs.revision": COMMIT, "vcs.modified": "false",
                    "GOAMD64" if arch == "amd64" else "GOARM64": "v1" if arch == "amd64" else "v8.0"}
        return {"GoVersion": "go1.27.1", "Path": "localrmm/cmd/" + role,
                "Main": {"Path": "localrmm", "Version": "(devel)"},
                "Settings": [{"Key": key, "Value": value} for key, value in settings.items()],
                "Deps": [{"Path": "example.org/dependency", "Version": "v1.2.3", "Sum": CHECKSUM}]}

    def generate(self, inspector=None, output=None):
        e.generate(self.candidate, output or self.output, VERSION, COMMIT, inspector or self.info)

    def test_repeat_generation_is_byte_identical_and_binds_all_candidate_and_sbom_bytes(self):
        self.generate()
        other = self.root / "second"
        self.generate(output=other)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()},
                         {p.name: p.read_bytes() for p in other.iterdir()})
        self.assertEqual(len(list(self.output.iterdir())), 9)
        report = json.loads((self.output / "candidate-evidence.json").read_bytes())
        self.assertEqual(report["sourceCommit"], COMMIT)
        self.assertEqual(report["manifestSHA256"], e.b.digest((self.candidate / "manifest.json").read_bytes()))
        self.assertEqual(report["dependencyLocks"]["go.sum"]["sha256"], e.b.digest(self.go_sum))
        self.assertIn("unsigned", report["trust"])
        for name, row in report["assets"].items():
            self.assertEqual({k: row[k] for k in ("size", "sha256")}, self.assets[name])
            if name.endswith("-source.tar"):
                self.assertNotIn("sbom", row)
                continue
            raw = (self.output / row["sbom"]["name"]).read_bytes()
            self.assertEqual(row["sbom"]["sha256"], e.b.digest(raw))
            self.assertEqual(row["sbom"]["size"], len(raw))
            bom = json.loads(raw)
            self.assertEqual(bom["specVersion"], "1.6")
            self.assertEqual(bom["metadata"]["component"]["hashes"][0]["content"], row["sha256"])
            self.assertEqual(bom["components"][0]["purl"], "pkg:golang/example.org/dependency@v1.2.3")
            self.assertNotIn("hashes", bom["components"][0])  # Go h1 is not an archive SHA256.
            self.assertNotIn("dependencies", bom)  # BuildInfo does not establish edges.
            self.assertEqual(bom["compositions"][0]["aggregate"], "incomplete")
            self.assertNotIn("timestamp", bom["metadata"])
            self.assertEqual(os.stat(self.output / row["sbom"]["name"]).st_mode & 0o777, 0o600)

    def test_dependency_order_is_canonical_and_no_dependencies_is_supported(self):
        base = self.info(self.candidate / self.binary)
        # Modern Go can derive the clean main-module version from VCS. The
        # independent exact source/settings checks, not '(devel)', bind identity.
        base["Main"]["Version"] = "v0.0.0-20261101063636-aaaaaaaaaaaa"
        base["Deps"] = []
        bom = e.sbom(base, self.binary, self.assets[self.binary], VERSION, COMMIT, "go1.27.1", {})
        self.assertEqual(bom["components"], [])
        sums = {("example.org/dependency", "v1.2.3"): CHECKSUM, ("example.org/another", "v2.0.0"): CHECKSUM}
        base["Deps"] = [{"Path": path, "Version": version, "Sum": checksum} for (path, version), checksum in sums.items()]
        one = e.canonical(e.sbom(base, self.binary, self.assets[self.binary], VERSION, COMMIT, "go1.27.1", sums))
        base["Deps"].reverse()
        self.assertEqual(one, e.canonical(e.sbom(base, self.binary, self.assets[self.binary], VERSION, COMMIT, "go1.27.1", sums)))

    def test_release_prerelease_labels_cannot_be_confused_with_target_or_role(self):
        version = "v0.1.0-linux-arm64-agent-service"
        info = self.info(self.candidate / self.binary)
        name = self.binary.replace(VERSION, version)
        bom = e.sbom(info, name, self.assets[self.binary], version, COMMIT, "go1.27.1",
                     {("example.org/dependency", "v1.2.3"): CHECKSUM})
        properties = {row["name"]: row["value"] for row in bom["metadata"]["component"]["properties"]}
        self.assertEqual(properties["tracebolt:target"], "linux-amd64")

    def test_wrong_metadata_or_unpinned_dependency_fails_before_output_creation(self):
        changes = [
            lambda i: i.update(GoVersion="go1.27.2"),
            lambda i: i.update(Path="localrmm/cmd/different-command"),
            lambda i: i["Main"].update(Replace={"Path": "/private/local"}),
            lambda i: i["Settings"].append({"Key": "GOOS", "Value": "linux"}),
            lambda i: i["Settings"].append({"Key": "invalid", "Value": False}),
            lambda i: i["Settings"].__setitem__(0, {"Key": "GOOS", "Value": "windows"}),
            lambda i: i["Deps"][0].update(Sum="h1:" + "B" * 43 + "="),
            lambda i: i["Deps"][0].update(Version="(devel)"),
            lambda i: i["Deps"][0].update(Replace={"Path": "/private/local"}),
            lambda i: i["Deps"].append(copy.deepcopy(i["Deps"][0])),
            lambda i: i["Deps"][0].update(Path="example.org/../private"),
        ]
        for change in changes:
            with self.subTest(change=change):
                def invalid(path):
                    info = self.info(path)
                    change(info)
                    return info
                with self.assertRaises(e.b.Rejected):
                    self.generate(inspector=invalid)
                self.assertFalse(self.output.exists())

    def test_modified_source_architecture_or_trimpath_is_rejected(self):
        for key, wrong in (("vcs.revision", "b" * 40), ("vcs.modified", "true"), ("GOARCH", "arm64"),
                           ("CGO_ENABLED", "1"), ("-trimpath", "false"), ("GOAMD64", "v3")):
            with self.subTest(key=key):
                info = self.info(self.candidate / self.binary)
                next(row for row in info["Settings"] if row["Key"] == key)["Value"] = wrong
                with self.assertRaises(e.b.Rejected):
                    e.sbom(info, self.binary, self.assets[self.binary], VERSION, COMMIT, "go1.27.1",
                           {("example.org/dependency", "v1.2.3"): CHECKSUM})

    def test_tampered_binary_symlink_or_unprotected_file_is_rejected(self):
        path = self.candidate / self.binary
        original = path.read_bytes()
        path.write_bytes(b"tampered")
        with self.assertRaises(e.b.Rejected):
            self.generate()
        path.write_bytes(original)
        path.chmod(0o666)
        with self.assertRaises(e.b.Rejected):
            self.generate()
        path.unlink()
        path.symlink_to(self.candidate / next(name for name in self.assets if name != self.binary))
        with self.assertRaises(e.b.Rejected):
            self.generate()
        self.assertFalse(self.output.exists())

    def test_changes_during_inspection_and_existing_output_are_rejected(self):
        def mutate(path):
            path.write_bytes(b"changed during inspection")
            return self.info(path)
        with self.assertRaises(e.b.Rejected):
            self.generate(inspector=mutate)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        with self.assertRaises(e.b.Rejected):
            self.generate()

    def test_source_archive_does_not_extract_paths_and_rejects_duplicate_or_link_locks(self):
        for unsafe in ("duplicate", "link", "missing"):
            with self.subTest(unsafe=unsafe):
                path = self.root / (unsafe + ".tar")
                with tarfile.open(path, mode="w") as archive:
                    for name, raw in (("go.mod", self.go_mod), ("go.sum", self.go_sum)):
                        if unsafe == "missing" and name == "go.sum":
                            continue
                        member = tarfile.TarInfo(name)
                        member.size = len(raw)
                        if unsafe == "link" and name == "go.sum":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "/private/state"
                        archive.addfile(member, io.BytesIO(raw))
                        if unsafe == "duplicate":
                            archive.addfile(member, io.BytesIO(raw))
                with self.assertRaises(e.b.Rejected):
                    e.archived_locks(path)

    def test_inspector_only_uses_read_only_go_version_with_no_network_selection(self):
        raw = e.canonical(self.info(self.candidate / self.binary))
        with InspectorPipes.fixture(self, "import sys; sys.stdout.buffer.write(" + repr(raw) + ")") as (launch, _):
            e.inspect(self.candidate / self.binary)
        args, kwargs = launch.call_args
        self.assertEqual(args[0], ["go", "version", "-m", "-json", str(self.candidate / self.binary)])
        self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
        self.assertEqual(kwargs["env"]["GOPROXY"], "off")
        self.assertEqual(kwargs["env"]["GOWORK"], "off")
        self.assertEqual(kwargs["env"]["GOENV"], "off")
        self.assertEqual(kwargs["env"]["GOFLAGS"], "")
        self.assertEqual(kwargs["env"]["GOSUMDB"], "off")
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["bufsize"], 0)
        self.assertEqual(e.INSPECT_TIMEOUT, 30)

    def test_wrong_manifest_source_or_version_is_rejected_before_binary_inspection(self):
        for key, wrong in (("sourceCommit", "b" * 40), ("version", "v0.1.0-other.1")):
            with self.subTest(key=key):
                original = self.manifest[key]
                self.manifest[key] = wrong
                self.write_manifest()
                with mock.patch.object(e, "inspect") as inspect:
                    with self.assertRaises(e.b.Rejected):
                        self.generate(inspector=inspect)
                    inspect.assert_not_called()
                self.assertFalse(self.output.exists())
                self.manifest[key] = original
                self.write_manifest()


class AtomicOutput(unittest.TestCase):
    """Only private temporary fixture files; no candidates, tools or host changes."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tracebolt-atomic-evidence-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "evidence"
        self.documents = {"candidate-evidence.json": b'{"inert":true}\n',
                          **{f"asset-{i}.cdx.json": (f"inert {i}\n").encode() for i in range(8)}}

    def stages(self, parent=None):
        return list((parent or self.root).glob(".tracebolt-evidence-*"))

    def assert_complete(self, output=None):
        output = output or self.output
        self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, self.documents)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        for path in output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_all_files_sync_before_atomic_visibility_and_parent_sync_after(self):
        original_sync, original_rename = os.fsync, e.atomic_rename()
        operations = []

        def sync(fd):
            metadata = os.fstat(fd)
            operations.append("directory" if stat.S_ISDIR(metadata.st_mode) else "file")
            if not self.output.exists():
                self.assertLessEqual(len(operations), 10)
            original_sync(fd)

        def rename(*args):
            self.assertFalse(self.output.exists())
            self.assertEqual(args[0], args[2])
            self.assertEqual(args[4], 1)
            self.assert_complete(self.stages()[0])
            operations.append("rename")
            result = original_rename(*args)
            self.assertEqual(result, 0)
            self.assert_complete()
            return result

        with mock.patch.object(e.os, "fsync", side_effect=sync), \
                mock.patch.object(e, "atomic_rename", return_value=rename), \
                mock.patch.object(e.os, "unlink", side_effect=AssertionError("No deletion allowed")), \
                mock.patch.object(e.os, "rmdir", side_effect=AssertionError("No deletion allowed")):
            e.publish_documents(self.output, self.documents)
        self.assertEqual(operations, ["file"] * 9 + ["directory", "rename", "directory"])
        self.assert_complete()
        self.assertEqual(self.stages(), [])

    def test_failure_writing_each_file_retains_private_staging_without_partial_output(self):
        original = os.fdopen
        for failed_index in range(9):
            with self.subTest(failed_index=failed_index):
                writes = 0

                @contextmanager
                def failing_file(fd, mode):
                    nonlocal writes
                    with original(fd, mode) as stream:
                        wrapped = mock.Mock(wraps=stream)
                        if writes == failed_index:
                            wrapped.write.side_effect = OSError(errno.ENOSPC, "inert disk full")
                        writes += 1
                        yield wrapped

                before = set(self.stages())
                with mock.patch.object(e.os, "fdopen", side_effect=failing_file):
                    with self.assertRaisesRegex(e.b.Rejected, "Inspect the output"):
                        e.publish_documents(self.output, self.documents)
                self.assertFalse(self.output.exists())
                stage, = set(self.stages()) - before
                self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
                self.assertEqual(len(list(stage.iterdir())), failed_index + 1)
                for path in stage.iterdir():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        # An explicit retry uses a fresh directory, never adopts/deletes old staging.
        retained = {p: p.stat().st_ino for p in self.stages()}
        e.publish_documents(self.output, self.documents)
        self.assert_complete()
        self.assertEqual({p: p.stat().st_ino for p in self.stages()}, retained)

    def test_file_and_stage_sync_failures_never_publish(self):
        original = os.fsync
        for failed_sync in range(10):
            with self.subTest(failed_sync=failed_sync):
                calls = 0

                def sync(fd):
                    nonlocal calls
                    current = calls
                    calls += 1
                    if current == failed_sync:
                        raise OSError(errno.EIO, "inert sync failure")
                    original(fd)

                with mock.patch.object(e.os, "fsync", side_effect=sync):
                    with self.assertRaisesRegex(e.b.Rejected, "Inspect the output"):
                        e.publish_documents(self.output, self.documents)
                self.assertFalse(self.output.exists())
        self.assertEqual(len(self.stages()), 10)

    def test_parent_sync_failure_retains_complete_published_output(self):
        original = os.fsync

        def sync(fd):
            if self.output.exists():
                raise OSError(errno.EIO, "inert parent sync failure")
            original(fd)

        with mock.patch.object(e.os, "fsync", side_effect=sync):
            with self.assertRaisesRegex(e.b.Rejected, "published.*durability is unconfirmed"):
                e.publish_documents(self.output, self.documents)
        self.assert_complete()
        self.assertEqual(self.stages(), [])

    def test_existing_and_raced_targets_are_never_replaced(self):
        original_rename = e.atomic_rename()
        for race in (False, True):
            for kind in ("file", "empty", "nonempty", "symlink", "dangling"):
                with self.subTest(race=race, kind=kind):
                    parent = self.root / f"{race}-{kind}"
                    parent.mkdir(mode=0o700)
                    output, sentinel = parent / "evidence", parent / "sentinel"
                    sentinel.write_bytes(b"existing user bytes")
                    before = None

                    def create_target():
                        nonlocal before
                        if kind == "file":
                            output.write_bytes(b"existing output")
                        elif kind in ("empty", "nonempty"):
                            output.mkdir()
                            if kind == "nonempty":
                                (output / "user").write_bytes(b"existing content")
                        else:
                            output.symlink_to(sentinel if kind == "symlink" else parent / "absent")
                        before = output.lstat()

                    def rename(*args):
                        create_target()
                        return original_rename(*args)

                    if not race:
                        create_target()
                    with mock.patch.object(e, "atomic_rename", return_value=rename if race else original_rename):
                        with self.assertRaises(e.b.Rejected):
                            e.publish_documents(output, self.documents)
                    self.assertEqual(output.lstat(), before)
                    self.assertEqual(sentinel.read_bytes(), b"existing user bytes")
                    if kind == "file":
                        self.assertEqual(output.read_bytes(), b"existing output")
                    if kind == "nonempty":
                        self.assertEqual((output / "user").read_bytes(), b"existing content")
                    self.assertEqual(len(self.stages(parent)), int(race))

    def test_missing_symbol_and_unsupported_filesystem_have_no_rename_fallback(self):
        with mock.patch.object(e.ctypes, "CDLL", return_value=object()), \
                mock.patch.object(e.os, "rename", side_effect=AssertionError("No replacing fallback")):
            with self.assertRaisesRegex(e.b.Rejected, "unavailable"):
                e.publish_documents(self.output, self.documents)
        self.assertEqual(self.stages(), [])
        for code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            with self.subTest(code=code):
                def unavailable(*args):
                    e.ctypes.set_errno(code)
                    return -1
                with mock.patch.object(e, "atomic_rename", return_value=unavailable), \
                        mock.patch.object(e.os, "rename", side_effect=AssertionError("No replacing fallback")):
                    with self.assertRaises(e.b.Rejected):
                        e.publish_documents(self.output, self.documents)
                self.assertFalse(self.output.exists())
        self.assertEqual(len(self.stages()), 3)

    def test_uncertain_rename_result_never_deletes_completed_output(self):
        original = e.atomic_rename()

        def uncertain(*args):
            self.assertEqual(original(*args), 0)
            raise OSError(errno.EIO, "inert uncertain response")

        with mock.patch.object(e, "atomic_rename", return_value=uncertain):
            with self.assertRaisesRegex(e.b.Rejected, "did not finish with confirmation"):
                e.publish_documents(self.output, self.documents)
        self.assert_complete()
        self.assertEqual(self.stages(), [])

    def test_foreign_writable_parent_rejected_but_owned_sticky_parent_supported(self):
        parent = self.root / "writable"
        parent.mkdir()
        parent.chmod(0o777)
        with self.assertRaisesRegex(e.b.Rejected, "protected from foreign renames"):
            e.publish_documents(parent / "evidence", self.documents)
        self.assertEqual(list(parent.iterdir()), [])
        parent.chmod(0o1777)
        e.publish_documents(parent / "evidence", self.documents)
        self.assert_complete(parent / "evidence")

    def test_short_write_and_flush_failure_retain_staging(self):
        original = os.fdopen
        for failure in ("short", "flush"):
            with self.subTest(failure=failure):
                @contextmanager
                def failed_file(fd, mode):
                    with original(fd, mode) as stream:
                        wrapped = mock.Mock(wraps=stream)
                        if failure == "short":
                            wrapped.write.side_effect = lambda data: stream.write(data[:1])
                        else:
                            wrapped.flush.side_effect = OSError(errno.EIO, "inert flush error")
                        yield wrapped
                with mock.patch.object(e.os, "fdopen", side_effect=failed_file):
                    with self.assertRaises(e.b.Rejected):
                        e.publish_documents(self.output, self.documents)
                self.assertFalse(self.output.exists())
        self.assertEqual(len(self.stages()), 2)

    def test_staging_identity_substitution_is_rejected_without_deleting_either_directory(self):
        original_sync = os.fsync
        moved = self.root / "retained-original"
        replacement = None

        def sync(fd):
            nonlocal replacement
            original_sync(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                replacement, = self.stages()
                replacement.rename(moved)
                replacement.mkdir()
                (replacement / "user").write_bytes(b"do not delete")

        rename = mock.Mock(wraps=e.atomic_rename())
        with mock.patch.object(e.os, "fsync", side_effect=sync), \
                mock.patch.object(e, "atomic_rename", return_value=rename):
            with self.assertRaisesRegex(e.b.Rejected, "binding changed"):
                e.publish_documents(self.output, self.documents)
        rename.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assert_complete(moved)
        self.assertEqual((replacement / "user").read_bytes(), b"do not delete")

    def test_parent_path_substitution_is_reported_before_or_after_commit(self):
        original_sync, original_rename = os.fsync, e.atomic_rename()
        for after_check in (False, True):
            with self.subTest(after_check=after_check):
                parent = self.root / f"parent-{after_check}"
                moved = self.root / f"moved-{after_check}"
                parent.mkdir(mode=0o700)
                output = parent / "evidence"
                moved_once = False

                def move_parent():
                    nonlocal moved_once
                    if not moved_once:
                        moved_once = True
                        parent.rename(moved)
                        parent.mkdir(mode=0o700)
                        (parent / "user").write_bytes(b"untouched replacement parent")

                def sync(fd):
                    original_sync(fd)
                    if not after_check and stat.S_ISDIR(os.fstat(fd).st_mode):
                        move_parent()

                def rename(*args):
                    if after_check:
                        move_parent()
                    return original_rename(*args)

                with mock.patch.object(e.os, "fsync", side_effect=sync), \
                        mock.patch.object(e, "atomic_rename", return_value=rename):
                    with self.assertRaisesRegex(e.b.Rejected, "binding changed"):
                        e.publish_documents(output, self.documents)
                self.assertFalse(output.exists())
                self.assertEqual((parent / "user").read_bytes(), b"untouched replacement parent")
                if after_check:
                    self.assert_complete(moved / "evidence")
                else:
                    self.assertFalse((moved / "evidence").exists())
                    stage, = self.stages(moved)
                    self.assert_complete(stage)


class InspectorPipes(unittest.TestCase):
    """Real pipes from inert code under this test's existing Python interpreter.

    Never run Go or a candidate. Substitute only process creation so the actual
    selector, bounded reads, deadline, kill/reap and descriptor cleanup are tested.
    """

    @contextmanager
    def fixture(self, source):
        processes = []
        original = subprocess.Popen

        def launch(command, **kwargs):
            process = original([sys.executable, "-I", "-c", source], **kwargs)
            processes.append(process)
            return process

        try:
            with mock.patch.object(e.subprocess, "Popen", side_effect=launch) as create:
                yield create, processes
            for process in processes:
                self.assertIsNotNone(process.returncode)
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(process.pid, os.WNOHANG)
        finally:
            # Keep a broken implementation from leaking the inert test child.
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdout.close()
                process.stderr.close()

    def test_exact_stdout_and_stderr_limits_with_interleaved_writes_are_supported(self):
        source = f"""
import sys
out, err = sys.stdout.buffer, sys.stderr.buffer
out.write(b'{{'); out.flush()
for _ in range(15):
    err.write(b'e' * 65536); err.flush()
    out.write(b' ' * 65536); out.flush()
err.write(b'e' * 65536); err.flush()
out.write(b' ' * (65536 - 2) + b'}}'); out.flush()
"""
        with self.fixture(source):
            self.assertEqual(e.inspect(Path("inert-candidate")), {})

    def test_stderr_before_stdout_does_not_deadlock(self):
        with self.fixture("import sys; sys.stderr.buffer.write(b'e' * 200000); sys.stderr.flush(); print('{}')"):
            self.assertEqual(e.inspect(Path("inert-candidate")), {})

    def test_overflow_on_either_pipe_stops_after_one_excess_byte_and_reaps(self):
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor):
                source = f"import os, time; os.write({descriptor}, b'x' * {e.MAX_METADATA + 100000}); time.sleep(60)"
                with self.fixture(source) as (_, processes):
                    read = os.read
                    received, requested = [], []

                    def bounded_read(fd, size):
                        chunk = read(fd, size)
                        if processes and fd in (processes[0].stdout.fileno(), processes[0].stderr.fileno()):
                            received.append(len(chunk))
                            requested.append(size)
                        return chunk

                    with mock.patch.object(e.os, "read", side_effect=bounded_read), \
                            mock.patch.object(e, "parse") as parse:
                        with self.assertRaisesRegex(e.b.Rejected, "Inspector output size rejected"):
                            e.inspect(Path("inert-candidate"))
                    parse.assert_not_called()
                    self.assertEqual(sum(received), e.MAX_METADATA + 1)
                    self.assertLessEqual(max(requested), e.INSPECT_READ_SIZE)
                    self.assertLess(processes[0].returncode, 0)

    def test_silent_child_times_out_and_is_reaped(self):
        with self.fixture("import time; time.sleep(60)") as (_, processes), \
                mock.patch.object(e, "INSPECT_TIMEOUT", 0.2):
            with self.assertRaises(subprocess.TimeoutExpired):
                e.inspect(Path("inert-candidate"))
            self.assertLess(processes[0].returncode, 0)

    def test_closed_pipes_do_not_remove_process_exit_deadline(self):
        with self.fixture("import os, time; os.close(1); os.close(2); time.sleep(60)") as (_, processes), \
                mock.patch.object(e, "INSPECT_TIMEOUT", 0.2):
            with self.assertRaises(subprocess.TimeoutExpired):
                e.inspect(Path("inert-candidate"))
            self.assertLess(processes[0].returncode, 0)

    def test_dripping_output_does_not_reset_total_deadline(self):
        source = "import os, time\nwhile True:\n os.write(1, b' '); time.sleep(0.02)"
        with self.fixture(source), mock.patch.object(e, "INSPECT_TIMEOUT", 0.2):
            with self.assertRaises(subprocess.TimeoutExpired):
                e.inspect(Path("inert-candidate"))

    def test_read_failure_and_interruption_reap_child(self):
        for error in (OSError("inert read failure"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with self.fixture("import time; print('{}', flush=True); time.sleep(60)") as (_, processes):
                    original = os.read

                    def failed_read(fd, size):
                        if processes and fd == processes[0].stdout.fileno():
                            raise error
                        return original(fd, size)

                    with mock.patch.object(e.os, "read", side_effect=failed_read):
                        with self.assertRaises(type(error)):
                            e.inspect(Path("inert-candidate"))
                    self.assertLess(processes[0].returncode, 0)

    def test_nonblocking_read_race_does_not_fail_valid_metadata(self):
        with self.fixture("print('{}')") as (_, processes):
            original = os.read
            raced = False

            def raced_read(fd, size):
                nonlocal raced
                if processes and fd == processes[0].stdout.fileno() and not raced:
                    raced = True
                    raise BlockingIOError()
                return original(fd, size)

            with mock.patch.object(e.os, "read", side_effect=raced_read):
                self.assertEqual(e.inspect(Path("inert-candidate")), {})
            self.assertTrue(raced)

    def test_nonzero_exit_keeps_diagnostics_out_of_exception(self):
        with self.fixture("import sys; print('{}'); print('private inspector error', file=sys.stderr); sys.exit(7)"):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                e.inspect(Path("inert-candidate"))
            self.assertEqual(caught.exception.returncode, 7)
            self.assertIsNone(caught.exception.output)
            self.assertIsNone(caught.exception.stderr)
            self.assertNotIn("private inspector error", str(caught.exception))

    def test_empty_or_invalid_json_remains_rejected_after_clean_exit(self):
        for source, error in (("pass", e.b.Rejected), ("print('not json')", ValueError),
                              ("print('{\"duplicate\": 1, \"duplicate\": 2}')", e.b.Rejected)):
            with self.subTest(source=source), self.fixture(source):
                with self.assertRaises(error):
                    e.inspect(Path("inert-candidate"))


if __name__ == "__main__":
    unittest.main()
