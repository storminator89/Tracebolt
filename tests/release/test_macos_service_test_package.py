"""Inert exact-source macOS service package builder fixtures."""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
builder_path = ROOT / "deploy/macos-release/build-service-test-package.py"
spec = importlib.util.spec_from_file_location("macos_service_test_builder", builder_path)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

old_spec = importlib.util.spec_from_file_location("macos_foreground_test", Path(__file__).with_name("test_macos_foreground_candidate.py"))
old_test = importlib.util.module_from_spec(old_spec)
old_spec.loader.exec_module(old_test)
COMMIT = old_test.COMMIT
TREE = old_test.TREE
VERSION = old_test.VERSION


class FakeRun(old_test.FakeRun):
    def archive_bytes(self):
        stream = io.BytesIO()
        entries = [("go.mod", b"module localrmm\n\ngo 1.27.1\n"), ("go.sum", b""),
                   ("cmd/enroll-agent/main.go", b"package main\nfunc main() {}\n"),
                   ("cmd/macos-agent/main.go", b"package main\nfunc main() {}\n"),
                   ("cmd/macos-agent-service/main.go", b"package main\nfunc main() {}\n"),
                   ("deploy/macos-release/prepare/main.go", b"package main\nfunc main() {}\n"),
                   ("docs/macos-test-package.md", b"# Synthetic test package\n")]
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, data in entries + self.archive_extra:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return stream.getvalue()

    def run(self, argv, root, *, env=None, stdout=None, timeout=300, limit_stdout=builder.base.MAX_CAPTURE):
        if argv == ["git", "show", "-s", "--format=%ct", COMMIT]:
            return SimpleNamespace(stdout=b"1791999999\n")
        if argv[:2] == ["go", "build"]:
            assert root != self.root and (root / "go.mod").is_file(), "Compile only extracted Git bytes"
            assert argv[2:5] == list(builder.base.BUILD_FLAGS)
            role = "macos-package-prepare" if argv[-1] == "./deploy/macos-release/prepare" else Path(argv[-1]).name
            assert role in builder.ROLES
            arch = env["GOARCH"]
            target = Path(argv[argv.index("-o") + 1])
            number = int(target.name.rsplit("-", 1)[1])
            content = old_test.macho(arch, f"{arch}/{role}".encode() +
                                     (b"drift" if self.drift and number == 2 else b""))
            target.write_bytes(content)
            self.builds.append((arch, role, number))
            if self.after_build:
                self.after_build(self)
            return SimpleNamespace(stdout=b"")
        if argv[:3] == ["go", "version", "-m"]:
            path = Path(argv[3])
            arch = env["GOARCH"]
            role = next((name for name in sorted(builder.ROLES, key=len, reverse=True) if name in path.name), None)
            assert role is not None
            if self.bad_role:
                role = "other"
            go_version = "go1.26.0" if getattr(self, "bad_go_buildinfo", False) else "go1.27.1"
            module = "other" if getattr(self, "bad_module", False) else "localrmm"
            return SimpleNamespace(stdout=(f"{path}: {go_version}\n\tpath\t{builder.role_path(role) if role in builder.ROLES else 'localrmm/cmd/other'}\n"
                                           f"\tmod\t{module}\t(devel)\t\n"
                                           f"\tbuild\tGOOS=darwin\n\tbuild\tGOARCH={arch}\n"
                                           "\tbuild\tCGO_ENABLED=0\n").encode())
        return super().run(argv, root, env=env, stdout=stdout, timeout=timeout, limit_stdout=limit_stdout)


class MacOSServiceTestBuilder(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="macos-service-package-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        (self.root / "go.mod").write_text("module localrmm\n\ngo 1.27.1\n")
        self.output = self.base / "output"
        self.fake = FakeRun(self.root)

    def build(self):
        with mock.patch.object(builder.base, "run", side_effect=self.fake.run):
            return builder.build_candidate(self.root, VERSION, COMMIT, self.output)

    def test_exact_roles_targets_and_deterministic_closed_archives(self):
        manifest = self.build()
        self.assertEqual(len(self.fake.builds), 16)
        self.assertEqual({(a, r) for a, r, _ in self.fake.builds},
                         {(a, r) for a in builder.base.ARCHES for r in builder.ROLES})
        self.assertEqual(len(manifest["assets"]), 4)
        self.assertEqual(set(self.output.iterdir()),
                         {self.output / name for name in manifest["assets"]} |
                         {self.output / "build-manifest.json"})
        self.assertEqual(manifest["sourceCommit"], COMMIT)
        self.assertEqual(manifest["sourceTree"], TREE)
        builder.validate_output(manifest,self.output,VERSION,COMMIT,TREE,"1.27.1")
        for flag in ("nativeAccepted", "publisherSigned", "notarized", "published", "productionReady"):
            self.assertIs(manifest[flag], False)
        for arch in builder.base.ARCHES:
            name = f"tracebolt-{VERSION}-darwin-{arch}-service-test-package.tar.gz"
            with tarfile.open(self.output / name, "r:gz") as archive:
                payload = {member.name: archive.extractfile(member).read() for member in archive}
            self.assertEqual(set(payload), {"payload-manifest.json", "source/source.tar", "TESTING.md"} |
                             {"bin/" + role for role in builder.ROLES})
            self.assertIn(b"sourceCommit", payload["payload-manifest.json"])
            self.assertIn(b"Synthetic test package", payload["TESTING.md"])

    def test_final_manifest_or_asset_drift_is_rejected(self):
        manifest=self.build()
        wrong=dict(manifest, nativeAccepted=True)
        with self.assertRaises(builder.base.Rejected):
            builder.validate_output(wrong,self.output,VERSION,COMMIT,TREE,"1.27.1")
        name=next(iter(manifest["assets"]))
        (self.output / name).write_bytes(b"changed")
        with self.assertRaises(builder.base.Rejected):
            builder.validate_output(manifest,self.output,VERSION,COMMIT,TREE,"1.27.1")

    def test_bad_source_or_toolchain_stops_before_output(self):
        for field, value in (("status", b"?? unexpected.txt\n"), ("commit", "c" * 40),
                             ("go_version", b"go1.26.0\n")):
            with self.subTest(field=field):
                setattr(self.fake, field, value)
                with self.assertRaises(builder.base.Rejected):
                    self.build()
                self.assertFalse(self.output.exists())
                setattr(self.fake, field, {"status": b"", "commit": COMMIT,
                                           "go_version": b"go1.27.1\n"}[field])

    def test_build_drift_and_role_substitution_fail_closed(self):
        for field in ("drift", "bad_role", "bad_go_buildinfo", "bad_module"):
            with self.subTest(field=field):
                setattr(self.fake, field, True)
                with self.assertRaises(builder.base.Rejected):
                    self.build()
                self.assertTrue(self.output.exists())
                self.output.rename(self.base / field)
                setattr(self.fake, field, False)

    def test_archive_member_duplication_and_source_change_rejected(self):
        self.fake.archive_extra = [("go.mod", b"duplicate")]
        with self.assertRaises(builder.base.Rejected):
            self.build()
        self.output.rename(self.base / "duplicate-output")
        self.fake.archive_extra = []
        self.fake.after_build = lambda fake: setattr(fake, "commit", "c" * 40)
        with self.assertRaises(builder.base.Rejected):
            self.build()


if __name__ == "__main__":
    unittest.main()
