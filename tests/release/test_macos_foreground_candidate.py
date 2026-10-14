"""Inert macOS candidate-builder contracts; the compiler and Git are fakes."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import tarfile
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[2] / "deploy/macos-release/build-foreground-candidate.py"
spec = importlib.util.spec_from_file_location("macos_foreground_builder", SOURCE)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
COMMIT = "a" * 40
TREE = "b" * 40
VERSION = "v0.0.0-macos-candidate.1"


def macho(arch: str, label: bytes = b"fixture") -> bytes:
    return (builder.MACHO_MAGIC + builder.MACHO_CPU[arch].to_bytes(4, "little")
            + bytes(4) + (2).to_bytes(4, "little") + label)


class FakeRun:
    def __init__(self, root: Path):
        self.root = root
        self.commit = COMMIT
        self.tree = TREE
        self.status = b""
        self.go_version = b"go1.27.1\n"
        self.tracked = b"100644 " + b"0" * 40 + b" 0\tgo.mod\0"
        self.flags = b"H go.mod\0"
        self.builds = []
        self.after_build = None
        self.bad_arch = False
        self.bad_role = False
        self.drift = False
        self.after_archive = None
        self.archive_extra = []
        self.archive_omit = set()

    def archive_bytes(self):
        stream = io.BytesIO()
        entries = [("go.mod", b"module localrmm\n\ngo 1.27.1\n"), ("go.sum", b""),
                   ("cmd/enroll-agent/main.go", b"package main\nfunc main() {}\n"),
                   ("cmd/macos-agent/main.go", b"package main\nfunc main() {}\n")]
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, data in [entry for entry in entries if entry[0] not in self.archive_omit] + self.archive_extra:
                info = tarfile.TarInfo(name)
                if isinstance(data, tuple) and data[0] in ("symlink", "hardlink"):
                    info.type = tarfile.SYMTYPE if data[0] == "symlink" else tarfile.LNKTYPE
                    info.linkname = data[1]
                else:
                    info.size = len(data)
                archive.addfile(info, None if info.islnk() or info.issym() else io.BytesIO(data))
        return stream.getvalue()

    def run(self, argv, root, *, env=None, stdout=None, timeout=300, limit_stdout=builder.MAX_CAPTURE):
        if argv[:2] in (["go", "build"], ["go", "mod"], ["go", "version"]):
            assert root != self.root and (root / "go.mod").is_file(), "Compiler must use extracted exact Git bytes"
        else:
            assert root == self.root, (root, self.root)
        if argv == ["git", "rev-parse", "--show-toplevel"]:
            return SimpleNamespace(stdout=(str(root) + "\n").encode())
        if argv == ["git", "rev-parse", "HEAD"]:
            return SimpleNamespace(stdout=(self.commit + "\n").encode())
        if argv == ["git", "rev-parse", "HEAD^{tree}"]:
            return SimpleNamespace(stdout=(self.tree + "\n").encode())
        if argv == ["git", "status", "--porcelain=v1", "--untracked-files=all"]:
            return SimpleNamespace(stdout=self.status)
        if argv == ["git", "ls-files", "--stage", "-z"]:
            return SimpleNamespace(stdout=self.tracked)
        if argv == ["git", "ls-files", "-v", "-z"]:
            return SimpleNamespace(stdout=self.flags)
        if argv == ["go", "env", "GOVERSION"]:
            assert env["GOTOOLCHAIN"] == "local" and env["GOENV"] == "off"
            return SimpleNamespace(stdout=self.go_version)
        if argv == ["go", "mod", "verify"]:
            assert env["GOPROXY"] == "off" and env["GOSUMDB"] == "off"
            return SimpleNamespace(stdout=b"")
        if argv[:2] == ["go", "build"]:
            assert argv[2:5] == list(builder.BUILD_FLAGS)
            assert env["GOOS"] == "darwin" and env["CGO_ENABLED"] == "0"
            assert env["GOFLAGS"] == "-mod=readonly"
            role = argv[-1].removeprefix("./cmd/")
            arch = env["GOARCH"]
            assert role in builder.ROLES and arch in builder.ARCHES
            assert env["GOAMD64"] == "v1" and env["GOARM64"] == "v8.0"
            target = Path(argv[argv.index("-o") + 1])
            number = int(target.name.rsplit("-", 1)[1])
            label = f"{arch}/{role}".encode() + (b"drift" if self.drift and number == 2 else b"")
            target.write_bytes(macho("arm64" if self.bad_arch and arch == "amd64" else arch, label))
            self.builds.append((arch, role, number))
            if self.after_build:
                self.after_build(self)
            return SimpleNamespace(stdout=b"")
        if argv[:3] == ["go", "version", "-m"]:
            path = Path(argv[3])
            arch = env["GOARCH"]
            role = "enroll-agent" if "enroll-agent" in path.name else "macos-agent"
            if self.bad_role:
                role = "agent-service"
            report = (f"{path}: go1.27.1\n"
                      f"\tpath\tlocalrmm/cmd/{role}\n"
                      f"\tbuild\tGOOS=darwin\n\tbuild\tGOARCH={arch}\n"
                      "\tbuild\tCGO_ENABLED=0\n")
            return SimpleNamespace(stdout=report.encode())
        if argv == ["git", "archive", "--format=tar", COMMIT]:
            assert stdout is not None
            stdout.write(self.archive_bytes())
            if self.after_archive:
                self.after_archive(self)
            return SimpleNamespace(stdout=None)
        raise AssertionError(f"Unexpected external action: {argv}")


class MacOSForegroundBuilder(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracebolt-macos-candidate-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        (self.root / "go.mod").write_text("module localrmm\n\ngo 1.27.1\n")
        self.output = self.base / "candidate"
        self.fake = FakeRun(self.root)

    def build(self):
        with mock.patch.object(builder, "run", side_effect=self.fake.run):
            return builder.build_candidate(self.root, VERSION, COMMIT, self.output)

    def test_exact_foreground_roles_manifest_and_source_only_build(self):
        manifest = self.build()
        self.assertEqual(len(self.fake.builds), 8)
        self.assertEqual(set((arch, role) for arch, role, _ in self.fake.builds),
                         {(arch, role) for arch in builder.ARCHES for role in builder.ROLES})
        self.assertEqual(set(self.output.iterdir()),
                         {self.output / name for name in manifest["assets"]} |
                         {self.output / "build-manifest.json"})
        self.assertNotIn("macos-agent-service", str(manifest))
        self.assertEqual(manifest["sourceCommit"], COMMIT)
        self.assertEqual(manifest["sourceTree"], TREE)
        self.assertEqual(manifest["goVersion"], "go1.27.1")
        self.assertEqual(manifest["buildFlags"], ["-buildvcs=false", "-trimpath", "-mod=readonly"])
        for key in ("nativeAccepted", "installable", "publisherSigned", "published"):
            self.assertIs(manifest[key], False)
        self.assertEqual((self.output / "build-manifest.json").read_bytes(), builder.canonical_json(manifest))
        builder.validate_manifest(manifest, self.output, VERSION, COMMIT, TREE, "1.27.1")

    def test_dirty_index_worktree_and_untracked_source_are_rejected_before_output(self):
        for status in (b"M  cmd/macos-agent/main.go\n", b" M cmd/macos-agent/main.go\n",
                       b"?? surprise.txt\n"):
            with self.subTest(status=status):
                self.fake.status = status
                with self.assertRaises(builder.Rejected):
                    self.build()
                self.assertFalse(self.output.exists())

    def test_exact_commit_tree_and_toolchain_are_required(self):
        for field, value in (("commit", "c" * 40), ("tree", "invalid"),
                             ("go_version", b"go1.26.0\n")):
            with self.subTest(field=field):
                setattr(self.fake, field, value)
                with self.assertRaises(builder.Rejected):
                    self.build()
                self.assertFalse(self.output.exists())
                setattr(self.fake, field, {"commit": COMMIT, "tree": TREE,
                                           "go_version": b"go1.27.1\n"}[field])

    def test_linked_source_or_output_and_existing_output_fail_closed(self):
        self.fake.tracked = b"120000 " + b"0" * 40 + b" 0\tlinked.go\0"
        with self.assertRaises(builder.Rejected):
            self.build()
        self.assertFalse(self.output.exists())
        self.fake.tracked = b"100644 " + b"0" * 40 + b" 0\tgo.mod\0"
        self.output.mkdir()
        with self.assertRaises(builder.Rejected):
            self.build()
        self.output.rmdir()
        self.output.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(builder.Rejected):
            self.build()
        self.output.unlink()
        linked_parent = self.base / "linked-parent"
        linked_parent.symlink_to(self.base, target_is_directory=True)
        self.output = linked_parent / "candidate"
        with self.assertRaises(builder.Rejected):
            self.build()

    def test_output_parent_inode_alias_to_checkout_is_rejected(self):
        actual_samefile = builder.os.path.samefile
        def case_insensitive_alias(left, right):
            if left == self.output.parent and right == self.root:
                return True
            return actual_samefile(left, right)
        with mock.patch.object(builder.os.path, "samefile", side_effect=case_insensitive_alias):
            with self.assertRaises(builder.Rejected):
                self.build()
        self.assertFalse(self.output.exists())

    def test_unusual_index_flags_rejected_and_ignored_worktree_go_cannot_enter_compile_root(self):
        for flag in (b"h go.mod\0", b"S go.mod\0"):
            with self.subTest(flag=flag):
                self.fake.flags = flag
                with self.assertRaises(builder.Rejected):
                    self.build()
                self.assertFalse(self.output.exists())
        self.fake.flags = b"H go.mod\0"
        ignored = self.root / "cmd/macos-agent/ignored-extra.go"
        ignored.parent.mkdir(parents=True)
        ignored.write_text("package main\n")
        original = self.fake.run
        def bounded_run(argv, root, **kwargs):
            if argv[:2] == ["go", "build"]:
                self.assertNotEqual(root, self.root)
                self.assertFalse((root / "cmd/macos-agent/ignored-extra.go").exists())
            return original(argv, root, **kwargs)
        with mock.patch.object(builder, "run", side_effect=bounded_run):
            builder.build_candidate(self.root, VERSION, COMMIT, self.output)
        self.assertEqual(len(self.fake.builds), 8)

    def test_source_lease_change_after_first_build_retains_unpublished_partial_output(self):
        def mutate(fake):
            fake.commit = "c" * 40
        self.fake.after_build = mutate
        with self.assertRaises(builder.Rejected):
            self.build()
        self.assertTrue(self.output.is_dir())
        self.assertFalse((self.output / "build-manifest.json").exists())

    def test_double_build_drift_wrong_macho_and_wrong_role_fail(self):
        for field in ("drift", "bad_arch", "bad_role"):
            with self.subTest(field=field):
                setattr(self.fake, field, True)
                with self.assertRaises(builder.Rejected):
                    self.build()
                self.assertFalse((self.output / "build-manifest.json").exists())
                setattr(self.fake, field, False)
                if self.output.exists():
                    import shutil
                    shutil.rmtree(self.output)

    def test_closed_manifest_rejects_extra_fields_assets_and_output(self):
        manifest = self.build()
        for changed in (dict(manifest, unexpected=True),
                        dict(manifest, assets={}),
                        dict(manifest, published=True)):
            with self.assertRaises(builder.Rejected):
                builder.validate_manifest(changed, self.output, VERSION, COMMIT, TREE, "1.27.1")
        (self.output / "unexpected").write_bytes(b"x")
        with self.assertRaises(builder.Rejected):
            builder.validate_manifest(manifest, self.output, VERSION, COMMIT, TREE, "1.27.1")

    def test_archive_source_lease_and_binary_size_bounds(self):
        self.fake.after_archive = lambda fake: setattr(fake, "status", b"?? changed-after-archive\n")
        with self.assertRaises(builder.Rejected):
            self.build()
        self.assertFalse((self.output / "build-manifest.json").exists())
        import shutil
        shutil.rmtree(self.output)
        self.fake.after_archive = None
        self.fake.status = b""
        with mock.patch.object(builder, "MAX_BINARY", 8):
            with self.assertRaises(builder.Rejected):
                self.build()

    def test_archive_traversal_duplicate_link_and_member_bounds(self):
        for extra in ([ ("../escape.go", b"x") ],
                      [ ("/absolute.go", b"x") ],
                      [ ("cmd//weird.go", b"x") ],
                      [ ("go.mod", b"duplicate") ],
                      [ ("linked.go", ("symlink", "go.mod")) ],
                      [ ("linked.go", ("hardlink", "go.mod")) ]):
            with self.subTest(extra=extra):
                self.fake.archive_extra = extra
                with self.assertRaises(builder.Rejected):
                    self.build()
                self.assertFalse((self.output / "build-manifest.json").exists())
                import shutil
                shutil.rmtree(self.output)
        self.fake.archive_extra = [("too-large.go", b"0123456789")]
        with mock.patch.object(builder, "MAX_EXTRACTED", 30):
            with self.assertRaises(builder.Rejected):
                self.build()
        import shutil
        shutil.rmtree(self.output)
        self.fake.archive_extra = []
        with mock.patch.object(builder, "MAX_ARCHIVE_MEMBERS", 3):
            with self.assertRaises(builder.Rejected):
                self.build()
        shutil.rmtree(self.output)
        for missing in ("go.mod", "go.sum"):
            with self.subTest(missing=missing):
                self.fake.archive_omit = {missing}
                with self.assertRaises(builder.Rejected):
                    self.build()
                shutil.rmtree(self.output)

    def test_subprocess_stdout_and_stderr_are_bounded_while_running(self):
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel):
                code = ("import sys; " + ("sys.stdout" if channel == "stdout" else "sys.stderr")
                        + ".write('x' * 100000)")
                with mock.patch.object(builder, "MAX_STDERR", 1024):
                    with self.assertRaises(builder.Rejected):
                        builder.run([sys.executable, "-I", "-B", "-c", code], self.root,
                                    timeout=10, limit_stdout=1024)


if __name__ == "__main__":
    unittest.main()
