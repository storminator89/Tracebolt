"""Inert read-admin release fixtures; no download, real installer or host effects."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("read_admin_bootstrap", ROOT / "deploy/release/linux-bootstrap.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
VERSION = "v0.1.0-inert.1"

def args(*flags):
    return b.parse_args(["--action", "install", "--apply", "--read-admin", "--manager-origin", "https://manager.example:8443",
        "--invitation-id", "invite_" + "a" * 32, "--bootstrap-sha256", "b" * 64, "--server-ca-base64", "PUBLIC-CA-FIXTURE", "--read-admin-agent-origin", "https://telemetry.example:8444", *flags])

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracebolt-inert-onboarding-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / f"tracebolt-{VERSION}-source.tar"
        self.manifest = dict(version=VERSION, assets={})
        for role in b.ROLES:
            self.manifest["assets"][f"tracebolt-{VERSION}-linux-amd64-{role}"] = dict(sha256="c" * 64, size=1)

    def package(self, mutation=None):
        with tarfile.open(self.archive, "w:") as archive:
            for path in b.READ_ADMIN_SOURCES:
                raw = (ROOT / path).read_bytes()
                info = tarfile.TarInfo(path); info.size = len(raw)
                if mutation:
                    info, raw = mutation(path, info, raw)
                if info is not None:
                    archive.addfile(info, io.BytesIO(raw) if info.isreg() else None)
        self.archive.chmod(0o600)
        self.manifest["assets"][self.archive.name] = dict(sha256=b.digest(self.archive.read_bytes()), size=self.archive.stat().st_size)

    def test_complete_regular_verified_archive_loads_inert_modules_only(self):
        self.package()
        with mock.patch.object(b.subprocess, "Popen", side_effect=AssertionError("unexpected child")), \
             mock.patch.object(b, "download", side_effect=AssertionError("unexpected download")), \
             mock.patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("unexpected extraction")):
            workflow, inventory, setup, amend, guide, templates = b.read_admin_sources(self.root, self.manifest)
        self.assertEqual(workflow.PROFILE, "tracebolt.linux-read-admin.v1")
        self.assertEqual(set(templates), {Path(p).name for p in b.READ_ADMIN_SOURCES[5:]})
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [self.archive.name])

    def test_missing_source_or_link_never_compiles_or_extracts(self):
        path = b.READ_ADMIN_SOURCES[0]
        def missing(name, info, raw):
            return (None, raw) if name == path else (info, raw)
        self.package(missing)
        with self.assertRaisesRegex(b.Rejected, "does not contain"):
            b.read_admin_sources(self.root, self.manifest)
        def symlink(name, info, raw):
            if name == path:
                info.type = tarfile.SYMTYPE; info.linkname = "/unrelated/source"; info.size = 0
            return info, raw
        self.package(symlink)
        with self.assertRaisesRegex(b.Rejected, "member rejected"):
            b.read_admin_sources(self.root, self.manifest)

    def test_source_hash_mode_symlink_and_duplicate_rejected(self):
        self.package()
        self.manifest["assets"][self.archive.name]["sha256"] = "f" * 64
        with self.assertRaisesRegex(b.Rejected, "integrity"):
            b.read_admin_sources(self.root, self.manifest)
        self.package(); self.archive.chmod(0o644)
        with self.assertRaisesRegex(b.Rejected, "integrity"):
            b.read_admin_sources(self.root, self.manifest)
        self.package()
        with tarfile.open(self.archive, "a:") as archive:
            raw = b"inert duplicate"
            info = tarfile.TarInfo(b.READ_ADMIN_SOURCES[0]); info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
        self.manifest["assets"][self.archive.name] = dict(sha256=b.digest(self.archive.read_bytes()), size=self.archive.stat().st_size)
        with self.assertRaisesRegex(b.Rejected, "Repeated"):
            b.read_admin_sources(self.root, self.manifest)

    def test_new_profile_waits_for_device_approval_and_requires_complete_bootstrap(self):
        self.package()
        command = b.installer_command(args("--pending-service"), self.root, self.manifest, "amd64")
        self.assertIn("--require-complete-profile", command)
        self.assertEqual(command[command.index("--require-agent-origin") + 1], "https://telemetry.example:8444")
        self.assertNotIn("--pending-service", command)
        self.assertNotIn("--resume", command)
        self.assertNotIn("--read-admin", command)
        self.assertNotIn("--insecure-http-test", command)

    def test_upgrade_cannot_silently_enable_profile_or_reinterpret_native_resume(self):
        for extra in (["--resume"], ["--action", "upgrade"]):
            with self.assertRaises(b.Rejected):
                args(*extra)
        with self.assertRaises(b.Rejected):
            b.parse_args(["--action", "upgrade", "--resume-read-admin"])
        self.assertTrue(args("--resume-read-admin").resume_read_admin)

    def test_ingress_must_be_explicit_valid_and_transport_matched(self):
        for origin in ("", "http://manager.example:8444", "https://user@manager.example", "https://manager.example/path", "https://manager.example:65536", "https://manager.example\x1b", "https://MANAGER.example:8444"):
            with self.subTest(origin=origin), self.assertRaises((b.Rejected, ValueError)):
                args("--read-admin-agent-origin", origin)
        public = args()
        self.assertEqual(public.read_admin_agent_origin, "https://telemetry.example:8444")

    def test_source_existing_public_pin_is_not_rewritten_or_misrepresented(self):
        self.assertIsNone(b.RELEASE_PIN)
        published = (ROOT / "deploy/release/published/v0.1.0-rc.1.py").read_text()
        self.assertNotIn("--read-admin", published)
        self.assertNotIn("read_admin_sources", published)

if __name__ == "__main__":
    unittest.main()
