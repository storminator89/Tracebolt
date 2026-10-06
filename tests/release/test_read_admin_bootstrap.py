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
            workflow, inventory, setup, amend, guide, socket_setup, templates = b.read_admin_sources(self.root, self.manifest)
        self.assertEqual(workflow.PROFILE, "tracebolt.linux-read-admin.v2")
        self.assertEqual(set(templates), {Path(p).name for p in b.READ_ADMIN_SOURCES[6:]})
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

    def test_each_fixed_socket_source_member_is_required_and_never_a_link(self):
        paths = ("deploy/socket-owner/setup.py", "deploy/systemd/tracebolt-socket-owner-reader.service.in",
                 "deploy/systemd/tracebolt-socket-owner-reader.socket.in")
        for selected in paths:
            def missing(path, info, raw): return (None, raw) if path == selected else (info, raw)
            self.package(missing)
            with self.subTest(member=selected, mutation="missing"), self.assertRaisesRegex(b.Rejected, "does not contain"):
                b.read_admin_sources(self.root, self.manifest)
            def link(path, info, raw):
                if path == selected:
                    info.type = tarfile.LNKTYPE; info.linkname = "deploy/onboarding/read_admin.py"; info.size = 0
                return info, raw
            self.package(link)
            with self.subTest(member=selected, mutation="link"), self.assertRaisesRegex(b.Rejected, "member rejected"):
                b.read_admin_sources(self.root, self.manifest)

    def test_read_admin_dispatch_passes_only_exact_manifest_helper_spec(self):
        workflow, inventory, setup, amendment, journal, socket_setup = (mock.Mock() for _ in range(6))
        workflow.run.return_value = dict(canceled=False, configurationComplete=True)
        templates = {"fixed": b"fixture"}
        public = args()
        self.manifest["assets"][f"tracebolt-{VERSION}-source.tar"] = dict(size=1, sha256="d" * 64)
        with mock.patch.object(b, "read_admin_sources", return_value=(workflow, inventory, setup, amendment, journal, socket_setup, templates)), \
             mock.patch.object(b, "run_installer", side_effect=AssertionError("native installer forbidden")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.run_read_admin(public, self.root, self.manifest, "amd64"), 0)
        helper = self.root / f"tracebolt-{VERSION}-linux-amd64-socket-owner-reader"
        expected = dict(self.manifest["assets"][helper.name], path=str(helper))
        workflow.real_adapter.assert_called_once_with(setup, inventory, amendment, journal, socket_setup, templates,
                                                      workflow.make_plan.return_value, expected)
        call = workflow.run.call_args
        self.assertEqual(call.kwargs, dict(resume=False))
        self.assertIs(call.args[3], inventory.confirm_terminal)
        self.assertIs(call.args[4], inventory.emit_terminal)

    def test_ordinary_upgrade_command_keeps_three_role_contract(self):
        public = b.parse_args(["--action", "upgrade"])
        source_name = f"tracebolt-{VERSION}-source.tar"
        self.manifest["assets"][source_name] = dict(size=1, sha256="d" * 64)
        command = b.installer_command(public, self.root, self.manifest, "amd64")
        self.assertFalse(any("socket-owner" in value for value in command))
        self.assertNotIn("--require-complete-profile", command)
        self.assertNotIn("--require-agent-origin", command)

    def test_revoke_rejects_enrollment_and_grant_flags_and_installer_dispatch(self):
        public = b.parse_args(["--action", "revoke-socket-owners", "--apply"])
        self.assertEqual(public.action, "revoke-socket-owners")
        for flags in (["--manager-origin", "https://manager.example"], ["--invitation-id", "invite_" + "a" * 32],
                      ["--read-admin"], ["--read-admin-agent-origin", "https://manager.example"], ["--resume"],
                      ["--resume-read-admin"], ["--pending-service"], ["--insecure-http-test"],
                      ["--bootstrap-sha256", "b" * 64], ["--server-ca-base64", "PUBLIC"]):
            with self.subTest(flags=flags), self.assertRaises(b.Rejected):
                b.parse_args(["--action", "revoke-socket-owners", *flags])
        with self.assertRaisesRegex(b.Rejected, "Maintenance cannot invoke"):
            b.installer_command(public, self.root, self.manifest, "amd64")

    def test_main_revoke_stages_only_source_and_never_dispatches_installer(self):
        pin = dict(version=VERSION, sourceCommit="a" * 40, manifestSHA256="b" * 64, bundleSHA256="c" * 64)
        with contextlib.ExitStack() as stack:
            for owner, name, value in ((b, "RELEASE_PIN", pin), (b, "inspect_host", mock.Mock(return_value="amd64")),
                                     (b.os, "getuid", mock.Mock(return_value=0)), (b.os, "geteuid", mock.Mock(return_value=0)),
                                     (b, "inspect_terminal", mock.Mock()), (b, "inspect_staging", mock.Mock()),
                                     (b.tempfile, "mkdtemp", mock.Mock(return_value=str(self.root))),
                                     (b, "cleanup_release", mock.Mock(return_value=True))):
                stack.enter_context(mock.patch.object(owner, name, value))
            prepare = stack.enter_context(mock.patch.object(b, "prepare_release", return_value=self.manifest))
            revoke = stack.enter_context(mock.patch.object(b, "run_revoke_socket_owners", return_value=0))
            installer = stack.enter_context(mock.patch.object(b, "run_installer", side_effect=AssertionError("installer forbidden")))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(b.main(["--action", "revoke-socket-owners", "--apply"]), 0)
        prepare.assert_called_once_with(self.root, pin, "amd64", maintenance=True)
        revoke.assert_called_once_with(self.root, self.manifest)
        installer.assert_not_called()

    def test_revoke_dispatch_uses_only_verified_source_and_no_artifact_install(self):
        workflow = mock.Mock(); inventory = mock.Mock(); setup = mock.Mock(); socket_setup = mock.Mock()
        workflow.run_revoke.return_value = dict(revoked=True, canceled=False)
        templates = {"fixed": b"fixture"}
        with mock.patch.object(b, "read_admin_sources", return_value=(workflow, inventory, setup, None, None, socket_setup, templates)) as loader, \
             mock.patch.object(b, "installer_command", side_effect=AssertionError("installer forbidden")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.run_revoke_socket_owners(self.root, self.manifest), 0)
        loader.assert_called_once_with(self.root, self.manifest)
        workflow.real_maintenance.assert_called_once_with(setup, inventory, socket_setup, templates, self.manifest)
        workflow.run_revoke.assert_called_once_with(workflow.real_maintenance.return_value, inventory.confirm_terminal, inventory.emit_terminal)

if __name__ == "__main__":
    unittest.main()
