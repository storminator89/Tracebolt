"""Inert release fixtures: no real service/account/install/credential actions.

Fixture runners test the fail-closed keyless verifier boundary and exact policy;
they do not fabricate a GitHub-issued attestation or claim a real release.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import tarfile
from types import SimpleNamespace
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("bootstrap", ROOT / "deploy/release/linux-bootstrap.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
VERSION = "v0.1.0-test.1"


def manifest_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracebolt-inert-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        self.artifacts = {name: ("inert fixture " + name).encode() for name in b.asset_names(VERSION)}
        self.manifest = {"schema": b.SCHEMA, "repository": b.REPOSITORY, "version": VERSION, "sourceCommit": "a" * 40,
                         "runtimeTargets": ["linux-amd64"], "assets": {name: {"size": len(data), "sha256": b.digest(data)} for name, data in self.artifacts.items()}}
        self.raw = manifest_bytes(self.manifest)
        self.pin = {"version": VERSION, "sourceCommit": "a" * 40, "manifestSHA256": b.digest(self.raw), "bundleSHA256": b.digest(b"inert attestation fixture")}
        self.bundle = b"inert attestation fixture"

    def verifier(self, directory, arch, fetch):
        path = directory / "gh-verifier"
        with b.open_private(path) as stream:
            stream.write(b"inert verifier fixture")
        return path

    def verify(self, directory, pin, verifier):
        def policy_runner(args, **kwargs):
            self.assertEqual(args[0], str(verifier))
            self.assertEqual(args[args.index("--repo") + 1], b.REPOSITORY)
            self.assertEqual(args[args.index("--signer-workflow") + 1], b.SIGNER_WORKFLOW)
            self.assertEqual(args[args.index("--source-digest") + 1], pin["sourceCommit"])
            self.assertEqual(args[args.index("--signer-digest") + 1], pin["sourceCommit"])
            self.assertEqual(args[args.index("--source-ref") + 1], "refs/heads/main")
            self.assertEqual(args[args.index("--cert-oidc-issuer") + 1], "https://token.actions.githubusercontent.com")
            self.assertIn("--deny-self-hosted-runners", args)
            self.assertIn("--bundle", args)
            self.assertIn("--custom-trusted-root", args)
            self.assertEqual(kwargs["env"]["GH_CONFIG_DIR"], str(directory))
            self.assertEqual(kwargs["env"]["XDG_STATE_HOME"], str(directory / "verifier-state"))
            self.assertNotIn("GH_TOKEN", kwargs["env"])
            self.assertNotIn("HTTPS_PROXY", kwargs["env"])
            return SimpleNamespace(returncode=getattr(self, "verifier_result", 0))
        return b.verify_attestation(directory, pin, verifier, policy_runner)

    def prepare(self, fetch=None):
        return b.prepare_release(self.stage, self.pin, "amd64", fetch or self.fetch, self.verifier, self.verify)

    def fetch(self, version, name, output, limit, expected_size=None, expected_digest=None):
        self.assertEqual(version, VERSION)
        data = {"manifest.json": self.raw, "manifest.sigstore.json": self.bundle}.get(name, self.artifacts.get(name))
        b.require(data is not None and len(data) <= limit, "fixture bounds")
        b.require(expected_size is None or len(data) == expected_size, "fixture size mismatch")
        b.require(expected_digest is None or b.digest(data) == expected_digest, "fixture hash mismatch")
        with b.open_private(output) as stream:
            stream.write(data)

    def test_production_remains_disabled_without_network_or_temporary_files(self):
        self.assertIsNone(b.RELEASE_PIN)
        with patch.object(b, "inspect_host") as host, patch.object(b.tempfile, "mkdtemp") as temp, patch.object(b, "download") as network, contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(b.main(["--action", "upgrade", "--apply"]), 1)
        host.assert_not_called()
        temp.assert_not_called()
        network.assert_not_called()
        self.assertIn("not activated", stderr.getvalue())

    def test_keyless_policy_pass_precedes_all_program_downloads_and_executable_modes(self):
        result = self.prepare()
        self.assertEqual(result, self.manifest)
        self.assertFalse(any("arm64" in path.name for path in self.stage.iterdir()))
        for role in b.ROLES:
            self.assertEqual(stat.S_IMODE((self.stage / f"tracebolt-{VERSION}-linux-amd64-{role}").stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((self.stage / f"tracebolt-{VERSION}-source.tar").stat().st_mode), 0o600)

    def test_rejected_provenance_prevents_any_tracebolt_program_download(self):
        self.verifier_result = 1
        with self.assertRaises(b.Rejected):
            self.prepare()
        self.assertFalse(any("linux-amd64" in p.name for p in self.stage.iterdir()))

    def test_changed_attestation_bundle_fails_before_verifier_or_program(self):
        self.bundle = b"other bundle"
        with self.assertRaises(b.Rejected):
            self.prepare()
        self.assertFalse(any("linux-amd64" in p.name for p in self.stage.iterdir()))

    def test_tampered_last_asset_never_marks_an_earlier_program_executable(self):
        self.artifacts[f"tracebolt-{VERSION}-source.tar"] = b"changed archive"
        with self.assertRaises(b.Rejected):
            self.prepare()
        self.assertTrue(all(not p.stat().st_mode & 0o111 for p in self.stage.iterdir()))

    def test_source_is_never_extracted_or_executed(self):
        name = f"tracebolt-{VERSION}-source.tar"
        self.artifacts[name] = b"not even a tar; ../../do-not-extract"
        self.manifest["assets"][name] = {"size": len(self.artifacts[name]), "sha256": b.digest(self.artifacts[name])}
        self.raw = manifest_bytes(self.manifest)
        self.pin["manifestSHA256"] = b.digest(self.raw)
        self.bundle = b"inert attestation fixture"
        self.prepare()
        self.assertEqual((self.stage / name).read_bytes(), self.artifacts[name])
        self.assertFalse((self.root / "do-not-extract").exists())

    def test_asset_symlink_and_replacement_are_rejected(self):
        def replaced(*args, **kwargs):
            self.fetch(*args, **kwargs)
            if args[1].endswith("-source.tar"):
                first = self.stage / f"tracebolt-{VERSION}-linux-amd64-agent-service"
                target = self.root / "replacement"
                target.write_bytes(first.read_bytes())
                first.unlink()
                first.symlink_to(target)
        with self.assertRaises(b.Rejected):
            self.prepare(replaced)

    def test_duplicate_json_fields_rejected_even_with_matching_pin(self):
        raw = self.raw.replace(b'"schema":', b'"schema":"duplicate","schema":')
        pin = dict(self.pin, manifestSHA256=b.digest(raw))
        with self.assertRaises(b.Rejected):
            b.parse_manifest(raw, pin)

    def test_unknown_fields_wrong_repository_source_version_and_platform_rejected(self):
        for name, value in (("new", True), ("repository", "other/repo"), ("sourceCommit", "b" * 40), ("version", "v9.0.0"), ("runtimeTargets", ["linux-amd64", "linux-arm64"])):
            with self.subTest(name=name):
                manifest = dict(self.manifest)
                manifest[name] = value
                raw = manifest_bytes(manifest)
                with self.assertRaises(b.Rejected):
                    b.parse_manifest(raw, dict(self.pin, manifestSHA256=b.digest(raw)))

    def test_manifest_asset_contract_rejects_missing_extra_traversal_sizes_and_hashes(self):
        name = next(iter(self.manifest["assets"]))
        mutations = [lambda assets: assets.pop(name), lambda assets: assets.update({"../../agent-service": assets[name]}),
                     lambda assets: assets[name].update(size=True), lambda assets: assets[name].update(size=0),
                     lambda assets: assets[name].update(size=b.MAX_SOURCE + 1), lambda assets: assets[name].update(sha256="A" * 64),
                     lambda assets: assets[name].update(url="https://other.test/program")]
        for mutation in mutations:
            manifest = json.loads(self.raw)
            mutation(manifest["assets"])
            raw = manifest_bytes(manifest)
            with self.assertRaises(b.Rejected):
                b.parse_manifest(raw, dict(self.pin, manifestSHA256=b.digest(raw)))

    def test_exact_manifest_digest_rejects_valid_json_reformatting_and_rollback(self):
        for raw in (self.raw + b"\n", manifest_bytes(dict(self.manifest, version="v0.0.1"))):
            with self.assertRaises(b.Rejected):
                b.parse_manifest(raw, self.pin)

    def test_pin_cannot_inject_a_key_download_url_or_workflow(self):
        for extra in ({"publicKeyBase64": "fake"}, {"url": "https://evil.test"}, {"workflow": "evil.yml"}):
            with self.assertRaises(b.Rejected):
                b.validate_pin(dict(self.pin, **extra))

    def test_existing_installer_arguments_preserve_resume_and_pending_service(self):
        args = b.parse_args(["--apply", "--pending-service", "--resume", "--manager-origin", "http://192.168.1.2:8787", "--invitation-id", "invite_" + "1" * 32, "--bootstrap-sha256", "b" * 64, "--insecure-http-test"])
        command = b.installer_command(args, self.stage, self.manifest, "amd64")
        self.assertIn("--resume", command)
        self.assertIn("--pending-service", command)
        self.assertIn("--insecure-http-test", command)
        self.assertNotIn("sudo", command)
        self.assertFalse(any("secret" in arg for arg in command))
        self.assertEqual(command[0], str(self.stage / f"tracebolt-{VERSION}-linux-amd64-agent-service"))
        self.assertEqual(command[command.index("--agent-sha256") + 1], self.manifest["assets"][f"tracebolt-{VERSION}-linux-amd64-lan-agent"]["sha256"])

    def test_upgrade_cannot_reenroll_or_reset_identity(self):
        for flags in (["--resume"], ["--pending-service"], ["--manager-origin", "https://manager.test"]):
            with self.assertRaises(b.Rejected):
                b.parse_args(["--action", "upgrade", *flags])
        args = b.parse_args(["--action", "upgrade", "--apply", "--insecure-http-test"])
        command = b.installer_command(args, self.stage, self.manifest, "amd64")
        self.assertIn("upgrade", command)
        self.assertNotIn("--manager-origin", command)


class VerifierArchive(unittest.TestCase):
    def make_archive(self, members):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as package:
            for name, kind, data in members:
                info = tarfile.TarInfo(name)
                info.type, info.size = kind, len(data)
                if kind == tarfile.SYMTYPE:
                    info.linkname = "/unrelated/path"
                    info.size = 0
                package.addfile(info, io.BytesIO(data) if info.size else None)
        return out.getvalue()

    def test_exact_regular_member_only_and_no_archive_path_extraction(self):
        exact = f"gh_{b.GH_VERSION}_linux_amd64/bin/gh"
        raw = self.make_archive([("../../do-not-extract", tarfile.REGTYPE, b"not extracted"), (exact, tarfile.REGTYPE, b"inert verifier")])
        with tempfile.TemporaryDirectory() as temp, patch.dict(b.GH_ARCHIVES, {"amd64": {"size": len(raw), "sha256": b.digest(raw)}}):
            directory = Path(temp)
            def fetch(version, name, out, limit, **kwargs):
                self.assertEqual(b.asset_url(version, name), f"https://github.com/cli/cli/releases/download/v{b.GH_VERSION}/gh_{b.GH_VERSION}_linux_amd64.tar.gz")
                self.assertEqual(kwargs["expected_digest"], b.digest(raw))
                with b.open_private(out) as stream:
                    stream.write(raw)
            result = b.prepare_verifier(directory, "amd64", fetch)
            self.assertEqual(result.read_bytes(), b"inert verifier")
            self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o500)
            self.assertEqual({p.name for p in directory.iterdir()}, {"gh-verifier", f"gh_{b.GH_VERSION}_linux_amd64.tar.gz"})

    def test_symlink_missing_duplicate_or_corrupt_member_cannot_execute(self):
        exact = f"gh_{b.GH_VERSION}_linux_amd64/bin/gh"
        variants = [[(exact, tarfile.SYMTYPE, b"")], [("wrong/bin/gh", tarfile.REGTYPE, b"inert")], [(exact, tarfile.REGTYPE, b"one"), (exact, tarfile.REGTYPE, b"two")]]
        for members in variants:
            raw = self.make_archive(members)
            with tempfile.TemporaryDirectory() as temp, patch.dict(b.GH_ARCHIVES, {"amd64": {"size": len(raw), "sha256": b.digest(raw)}}):
                directory = Path(temp)
                def fetch(version, name, out, limit, **kwargs):
                    with b.open_private(out) as stream:
                        stream.write(raw)
                with self.assertRaises(b.Rejected):
                    b.prepare_verifier(directory, "amd64", fetch)
                for path in directory.iterdir():
                    self.assertFalse(path.stat().st_mode & 0o111)

    def test_official_verifier_archives_are_independent_of_tracebolt_manifest(self):
        self.assertEqual(b.GH_ARCHIVES["amd64"]["sha256"], "bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386")
        self.assertIn("certificateAuthorities", json.loads(b.TRUSTED_ROOT_JSON))
        self.assertEqual(b.SIGNER_WORKFLOW, "storminator89/Tracebolt/.github/workflows/linux-release-candidate.yml")



class BootstrapCleanup(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture("test_source_is_never_extracted_or_executed")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def apply(self, exit_code=0, after_prepare=None, prepare_error=None, unlink_error=False):
        f = self.fixture
        prepare = b.prepare_release
        fixture_uid = os.geteuid()
        def verified_with_state(directory, pin, verifier):
            f.verify(directory, pin, verifier)
            state = directory / "verifier-state" / "gh"
            state.mkdir(parents=True, mode=0o700)
            with b.open_private(state / "device-id") as stream:
                stream.write(b"inert verifier state")
        def prepare_fixture(directory, pin, arch):
            if prepare_error:
                raise b.Rejected(prepare_error)
            # Only the CLI root preflight is simulated. Staging ownership is
            # still checked against the real unprivileged fixture owner.
            with patch.object(b.os, "geteuid", return_value=fixture_uid):
                manifest = prepare(directory, pin, arch, f.fetch, f.verifier, verified_with_state)
            if after_prepare:
                after_prepare(directory)
            return manifest
        stdout, stderr = io.StringIO(), io.StringIO()
        old_umask = os.umask(0o077)
        try:
            with contextlib.ExitStack() as stack:
                for owner, name, value in ((b, "RELEASE_PIN", f.pin),):
                    stack.enter_context(patch.object(owner, name, value))
                stack.enter_context(patch.object(b, "inspect_host", return_value="amd64"))
                stack.enter_context(patch.object(b.os, "getuid", return_value=0))
                stack.enter_context(patch.object(b.os, "geteuid", return_value=0))
                stack.enter_context(patch.object(b.sys.stdin, "isatty", return_value=True))
                stack.enter_context(patch.object(b.tempfile, "mkdtemp", return_value=str(f.stage)))
                stack.enter_context(patch.object(b, "prepare_release", side_effect=prepare_fixture))
                installer = stack.enter_context(patch.object(b, "run_installer", return_value=exit_code))
                if unlink_error:
                    stack.enter_context(patch.object(b.os, "unlink", side_effect=PermissionError("inert protected staging")))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                result = b.main(["--action", "upgrade", "--apply", "--insecure-http-test"])
        finally:
            os.umask(old_umask)
        return result, stderr.getvalue(), installer.call_count

    def test_successful_installer_and_verifier_state_are_cleaned(self):
        result, error, calls = self.apply()
        self.assertEqual((result, error, calls), (0, "", 1))
        self.assertFalse(self.fixture.stage.exists())

    def test_nonzero_installer_status_is_preserved(self):
        result, error, calls = self.apply(exit_code=7)
        self.assertEqual((result, error, calls), (7, "", 1))
        self.assertFalse(self.fixture.stage.exists())

    def test_readonly_artifact_modes_do_not_require_permission_changes(self):
        def readonly(directory):
            for path in directory.iterdir():
                if path.is_file():
                    path.chmod(0o400)
        result, error, calls = self.apply(after_prepare=readonly)
        self.assertEqual((result, error, calls), (0, "", 1))
        self.assertFalse(self.fixture.stage.exists())

    def test_protected_staging_does_not_turn_success_into_preparation_failure(self):
        result, error, calls = self.apply(unlink_error=True)
        self.assertEqual((result, calls), (0, 1))
        self.assertIn("Installer exit status is preserved", error)
        self.assertNotIn("Release preparation failed", error)
        self.assertTrue(self.fixture.stage.exists())

    def test_original_preparation_error_is_not_masked_by_cleanup(self):
        (self.fixture.stage / "unknown").write_text("retain me")
        result, error, calls = self.apply(prepare_error="inert original failure")
        self.assertEqual((result, calls), (1, 0))
        self.assertIn("Tracebolt: inert original failure", error)
        self.assertIn("original operation error is preserved", error)
        self.assertEqual((self.fixture.stage / "unknown").read_text(), "retain me")

    def test_unknown_nested_state_is_retained_without_recursive_cleanup(self):
        def extra(directory):
            (directory / "verifier-state" / "gh" / "unknown").write_text("retain me")
        result, error, calls = self.apply(after_prepare=extra)
        self.assertEqual((result, calls), (0, 1))
        self.assertIn("cleanup was incomplete", error)
        self.assertEqual((self.fixture.stage / "verifier-state" / "gh" / "unknown").read_text(), "retain me")

    def test_cleanup_does_not_follow_state_directory_symlink(self):
        outside = self.fixture.root / "outside"
        (outside / "gh").mkdir(parents=True)
        sentinel = outside / "gh" / "device-id"
        sentinel.write_text("outside")
        (self.fixture.stage / "verifier-state").symlink_to(outside, target_is_directory=True)
        self.assertFalse(b.cleanup_release(self.fixture.stage, set()))
        self.assertEqual(sentinel.read_text(), "outside")

    def test_cleanup_rejects_nonleaf_names(self):
        sentinel = self.fixture.root / "outside"
        sentinel.write_text("outside")
        self.assertFalse(b.cleanup_release(self.fixture.stage, {"../outside"}))
        self.assertEqual(sentinel.read_text(), "outside")


class Preflight(unittest.TestCase):
    def test_exact_supported_distribution(self):
        self.assertEqual(b.read_os_release('ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"'), "debian")
        self.assertEqual(b.read_os_release('ID=ubuntu\nVERSION_ID="24.04"'), "ubuntu")
        for text in ('ID=debian\nVERSION_ID="12"', 'ID=ubuntu\nVERSION_ID="22.04"', 'ID=alpine\nVERSION_ID="3.22"', 'ID=debian\nID=ubuntu\nVERSION_ID="13"', 'ID=$(touch /tmp/no)\nVERSION_ID=13'):
            with self.assertRaises(b.Rejected):
                b.read_os_release(text)

    def test_arm64_and_no_systemd_fail_closed(self):
        with patch.object(b.sys, "platform", "linux"), patch.object(b.platform, "machine", return_value="aarch64"), patch.object(b.Path, "read_text", return_value='ID=debian\nVERSION_ID="13"'):
            with self.assertRaisesRegex(b.Rejected, "build-only"):
                b.inspect_host()
        with patch.object(b.sys, "platform", "linux"), patch.object(b.platform, "machine", return_value="x86_64"), patch.object(b.Path, "read_text", side_effect=['ID=debian\nVERSION_ID="13"', 'not-systemd']):
            with self.assertRaisesRegex(b.Rejected, "systemd"):
                b.inspect_host()

    def test_no_apply_is_read_only(self):
        pin = {"version": VERSION, "sourceCommit": "a" * 40, "manifestSHA256": "b" * 64, "bundleSHA256": b.digest(b"inert attestation fixture")}
        with patch.object(b, "RELEASE_PIN", pin), patch.object(b, "inspect_host", return_value="amd64"), patch.object(b.tempfile, "mkdtemp") as temp, patch.object(b, "download") as network, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.main(["--action", "upgrade"]), 0)
        temp.assert_not_called()
        network.assert_not_called()

    def test_apply_never_elevates_and_requires_real_terminal(self):
        pin = {"version": VERSION, "sourceCommit": "a" * 40, "manifestSHA256": "b" * 64, "bundleSHA256": b.digest(b"inert attestation fixture")}
        with patch.object(b, "RELEASE_PIN", pin), patch.object(b, "inspect_host", return_value="amd64"), patch.object(b.os, "getuid", return_value=1000), patch.object(b.subprocess, "run") as run, patch.object(b.tempfile, "mkdtemp") as temp, contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(b.main(["--action", "upgrade", "--apply"]), 1)
            self.assertIn("will not invoke sudo", stderr.getvalue())
            run.assert_not_called()
            temp.assert_not_called()

    def test_untrusted_download_root_secret_and_short_flags_do_not_exist(self):
        for args in (["--url", "https://evil.test"], ["--invitation-secret", "example"], ["--app"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                b.parse_args(args)


class WholeDownloadDeadline(unittest.TestCase):
    def test_stalled_resolution_or_slow_progress_is_terminated(self):
        def stalled(*args):
            time.sleep(10)
        def slow_progress(*args):
            # Continuous sub-inactivity-timeout progress must still be bounded.
            while True:
                time.sleep(0.01)
        for worker in (stalled, slow_progress):
            with tempfile.TemporaryDirectory() as temp, patch.object(b, "_download", side_effect=worker):
                started = time.monotonic()
                with self.assertRaisesRegex(b.Rejected, "whole-operation"):
                    b.download(VERSION, "manifest.json", Path(temp) / "download", 100, deadline_seconds=0.05)
                self.assertLess(time.monotonic() - started, 2)
                self.assertFalse(Path(temp, "download").exists())

    def test_successful_worker_preserves_private_output_and_failure_is_safe(self):
        def success(version, name, output, *args):
            with b.open_private(output) as stream:
                stream.write(b"verified fixture")
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "download"
            with patch.object(b, "_download", side_effect=success):
                b.download(VERSION, "manifest.json", output, 100, deadline_seconds=1)
            self.assertEqual(output.read_bytes(), b"verified fixture")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with patch.object(b, "_download", side_effect=OSError("untrusted transport detail")):
                with self.assertRaisesRegex(b.Rejected, "Official HTTPS download failed") as error:
                    b.download(VERSION, "manifest.json", output, 100, deadline_seconds=1)
                self.assertNotIn("untrusted transport detail", str(error.exception))



class CandidateBuildBoundary(unittest.TestCase):
    def test_invalid_version_never_creates_output_or_runs_a_shell(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "candidate"
            marker = Path(temp) / "marker"
            result = subprocess.run(["/usr/bin/python3", "-I", "-B", str(ROOT / "deploy/release/build-linux-release.py"),
                                     "--version", "v1.0.0; touch " + str(marker), "--output", str(output)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertFalse(marker.exists())

    def test_workflow_separates_approved_keyless_and_explicit_publication_permissions(self):
        workflow = (ROOT / ".github/workflows/linux-release-candidate.yml").read_text()
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        candidate, publish = workflow.split("\n  publish:\n", 1)
        self.assertNotIn("contents: write", candidate)
        self.assertIn("contents: write", publish)
        self.assertNotIn("id-token: write", publish)
        self.assertNotIn("attestations: write", publish)
        self.assertIn("if: inputs.publish &&", publish)
        self.assertIn("default: false", candidate)
        self.assertIn("artifact-ids: ${{ needs.candidate.outputs.artifact-id }}", publish)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("gh release create", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("actions/attest-build-provenance@977bb373ede98d70efdf65b84cb5f73e068dcc2a", workflow)
        self.assertIn("--source-commit", workflow)



class InstallerCancellation(unittest.TestCase):
    def test_interrupt_is_forwarded_and_waits_without_force_kill(self):
        installed = {}
        previous = {b.signal.SIGINT: object(), b.signal.SIGTERM: object()}
        sent = []
        class Child:
            def send_signal(self, signum):
                sent.append(signum)
            def wait(self):
                installed[b.signal.SIGINT](b.signal.SIGINT, None)
                return 7
        def set_handler(signum, handler):
            old = installed.get(signum, previous[signum])
            installed[signum] = handler
            return old
        with patch.object(b.signal, "signal", side_effect=set_handler), patch.object(b.subprocess, "Popen", return_value=Child()) as popen:
            self.assertEqual(b.run_installer(["/inert-fixture/agent-service"]), 7)
        self.assertEqual(sent, [b.signal.SIGINT])
        self.assertEqual(installed, previous)
        popen.assert_called_once_with(["/inert-fixture/agent-service"], env=b.SAFE_ENV)



class Response:
    def __init__(self, status=200, data=b"data", headers=None):
        self.status, self.stream = status, io.BytesIO(data)
        self.headers = headers if headers is not None else [("Content-Length", str(len(data)))]
    def getheaders(self):
        return self.headers
    def read(self, size):
        return self.stream.read(size)


class Network(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "download"
        self.requests = []

    def factory(self, responses):
        outer = self
        class Fake:
            def __init__(self, host, port, **kwargs):
                self.host, self.port = host, port
            def request(self, method, path, headers):
                outer.requests.append((self.host, self.port, method, path, headers))
            def getresponse(self):
                return responses.pop(0)
            def close(self):
                pass
        return Fake

    def fetch(self, responses, **kwargs):
        return b._download(VERSION, "manifest.json", self.output, kwargs.pop("limit", 100), connection=self.factory(responses), **kwargs)

    def test_direct_official_https_no_proxy_auth_or_compression(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://untrusted:9999", "SSL_CERT_FILE": "/missing"}):
            self.fetch([Response()], expected_size=4, expected_digest=b.digest(b"data"))
        self.assertEqual(self.output.read_bytes(), b"data")
        host, port, method, path, headers = self.requests[0]
        self.assertEqual((host, port, method), ("github.com", 443, "GET"))
        self.assertEqual(path, f"/storminator89/Tracebolt/releases/download/{VERSION}/manifest.json")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertNotIn("Authorization", headers)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_single_official_asset_redirect(self):
        url = "https://release-assets.githubusercontent.com/github-production-release-asset/123/abc?signature=public-fixture"
        self.fetch([Response(302, headers=[("Location", url)]), Response()])
        self.assertEqual(self.requests[1][0], "release-assets.githubusercontent.com")

    def test_external_downgraded_credentialed_port_fragment_and_multiple_redirect_rejected(self):
        targets = ["https://evil.test/program", "http://release-assets.githubusercontent.com/github-production-release-asset/1/a",
                   "https://user:pass@release-assets.githubusercontent.com/github-production-release-asset/1/a",
                   "https://release-assets.githubusercontent.com:443/github-production-release-asset/1/a",
                   "https://release-assets.githubusercontent.com/github-production-release-asset/1/a#fragment",
                   "https://github.com/storminator89/Tracebolt/releases/download/other/a"]
        for url in targets:
            with self.subTest(url=url), self.assertRaises(b.Rejected):
                self.fetch([Response(302, headers=[("Location", url)])])
        url = "https://release-assets.githubusercontent.com/github-production-release-asset/1/a"
        with self.assertRaises(b.Rejected):
            self.fetch([Response(302, headers=[("Location", url)]), Response(302, headers=[("Location", url)])])
        self.assertFalse(self.output.exists())

    def test_error_encoding_ambiguous_length_and_oversized_response(self):
        for response in [Response(404), Response(headers=[("Content-Encoding", "gzip")]), Response(headers=[("Content-Length", "4"), ("Content-Length", "4")]), Response(headers=[("Content-Length", "101")])]:
            with self.assertRaises(b.Rejected):
                self.fetch([response])
        self.assertFalse(self.output.exists())
        with self.assertRaises(b.Rejected):
            self.fetch([Response(data=b"x" * 101, headers=[])])
        self.assertLessEqual(self.output.stat().st_size, 100)

    def test_truncated_checksum_mismatch_and_symlink_destination_fail(self):
        with self.assertRaises(b.Rejected):
            self.fetch([Response(data=b"short", headers=[("Content-Length", "10")])])
        self.output.unlink()
        with self.assertRaises(b.Rejected):
            self.fetch([Response()], expected_digest="a" * 64)
        self.output.unlink()
        self.output.symlink_to(Path(self.temp.name) / "untouched")
        with self.assertRaises(FileExistsError):
            self.fetch([Response()])
        self.assertFalse(self.output.resolve().exists())

    def test_private_and_mixed_dns_answers_never_connect(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("140.82.112.3", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        multicast = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("224.0.0.1", 443))
        for answers in ([private], [public, private], [multicast], []):
            with patch.object(b.socket, "getaddrinfo", return_value=answers), patch.object(b.socket, "socket") as sock:
                conn = b.OfficialHTTPSConnection("github.com", 443, timeout=1, context=b.release_context())
                with self.assertRaises(b.Rejected):
                    conn.connect()
                sock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
