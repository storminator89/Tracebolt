"""Inert hosted-publication readback fixtures; no network or binaries run."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("public_readback", ROOT / "deploy/release/verify-published-release.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class PublicReadback(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.output = self.parent / "tracebolt-public-readback"
        self.b, self.real_template = v.load_bootstrap()
        self.template = b"# inert fixture, never executed\nRELEASE_PIN = None\n"
        self.data = {name: ("inert:" + name).encode() for name in self.b.asset_names(v.VERSION)}
        manifest = {"schema": self.b.SCHEMA, "repository": v.REPOSITORY, "version": v.VERSION,
                    "sourceCommit": v.SOURCE, "runtimeTargets": ["linux-amd64"],
                    "assets": {name: {"size": len(data), "sha256": self.b.digest(data)} for name, data in self.data.items()}}
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        bundle = b"inert attestation fixture"
        self.pin = dict(v.PIN, manifestSHA256=self.b.digest(raw), bundleSHA256=self.b.digest(bundle))
        bootstrap = self.template.replace(b"RELEASE_PIN = None", ("RELEASE_PIN = " + repr(self.pin)).encode())
        self.data.update({"manifest.json": raw, "manifest.sigstore.json": bundle, "bootstrap.py": bootstrap})
        self.expected = {name: (len(data), self.b.digest(data)) for name, data in self.data.items()}
        self.calls = []
        self.corrupt = None
        self.reject_provenance = False

    def fetch(self, version, name, output, limit, expected_size=None, expected_digest=None, deadline_seconds=None):
        self.assertEqual(version, v.VERSION)
        self.assertEqual(self.b.asset_url(version, name), f"https://github.com/{v.REPOSITORY}/releases/download/{v.VERSION}/{name}")
        self.assertEqual((limit, expected_size, expected_digest, deadline_seconds),
                         (self.expected[name][0], *self.expected[name], 120))
        self.calls.append(name)
        with self.b.open_private(output) as stream:
            stream.write(b"tampered" if name == self.corrupt else self.data[name])

    def attest(self, work, pin, verifier):
        self.assertEqual(pin, self.pin)
        self.assertEqual(verifier, work / "inert-verifier")
        self.calls.append("PROVENANCE")
        if self.reject_provenance:
            raise RuntimeError("sensitive raw error must not escape")

    def run_fixture(self):
        with patch.object(v, "PIN", self.pin), patch.object(v, "EXPECTED", self.expected), \
             patch.object(self.b, "download", self.fetch), \
             patch.object(self.b, "prepare_verifier", side_effect=lambda work, arch, fetch: work / "inert-verifier"), \
             patch.object(self.b, "verify_attestation", self.attest), \
             patch.object(self.b, "run_installer", side_effect=AssertionError("installer forbidden")):
            return v.verify(self.output, self.b, self.template)

    def test_all_ten_assets_verified_before_only_four_public_files_are_retained(self):
        result = self.run_fixture()
        self.assertEqual(self.calls[:3], ["manifest.json", "manifest.sigstore.json", "PROVENANCE"])
        self.assertEqual(set(self.calls) - {"PROVENANCE"}, set(self.expected))
        self.assertEqual({path.name for path in self.output.iterdir()}, set(v.PUBLIC_FILES) | {v.RESULT_FILE})
        self.assertEqual(set(result), {"schema", "status", "version", "sourceCommit", "assetsVerified", "publicArtifacts", "traceboltProgramsExecuted", "installerExecuted"})
        self.assertEqual((result["status"], result["assetsVerified"]), ("PASS", 10))
        self.assertFalse(result["traceboltProgramsExecuted"])
        self.assertFalse(result["installerExecuted"])
        for name in v.PUBLIC_FILES:
            self.assertEqual((self.output / name).read_bytes(), self.data[name])
            self.assertEqual((self.output / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((self.output / v.RESULT_FILE).read_bytes()), result)
        self.assertEqual({path.name for path in self.parent.iterdir()}, {self.output.name})

    def test_bad_bytes_or_provenance_leave_no_success_artifacts(self):
        for name in ("manifest.json", "manifest.sigstore.json", "bootstrap.py", *sorted(self.b.asset_names(v.VERSION))):
            with self.subTest(name=name):
                self.corrupt = name
                with self.assertRaisesRegex(v.Failed, "^FAIL_ARTIFACT$"):
                    self.run_fixture()
                self.assertEqual(list(self.parent.iterdir()), [])
        self.corrupt = None
        self.reject_provenance = True
        self.calls = []
        with self.assertRaisesRegex(v.Failed, "^FAIL_PROVENANCE$"):
            self.run_fixture()
        self.assertEqual(self.calls, ["manifest.json", "manifest.sigstore.json", "PROVENANCE"])
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_bootstrap_must_be_exact_template_even_if_its_hash_pin_matches(self):
        self.data["bootstrap.py"] += b"\n# changed\n"
        self.expected["bootstrap.py"] = (len(self.data["bootstrap.py"]), self.b.digest(self.data["bootstrap.py"]))
        with self.assertRaisesRegex(v.Failed, "^FAIL_BOOTSTRAP$"):
            self.run_fixture()
        self.assertFalse(self.output.exists())

    def test_manifest_must_match_all_independent_asset_pins(self):
        name = next(iter(self.b.asset_names(v.VERSION)))
        self.expected[name] = (self.expected[name][0] + 1, self.expected[name][1])
        with self.assertRaisesRegex(v.Failed, "^FAIL_MANIFEST$"):
            self.run_fixture()
        self.assertEqual(self.calls, ["manifest.json", "manifest.sigstore.json", "PROVENANCE"])

    def test_source_template_and_network_destinations_are_fixed(self):
        self.assertEqual(self.b.digest(self.real_template), v.TEMPLATE_SHA256)
        self.assertEqual(len(v.EXPECTED), 10)
        for version, name in (("v0.1.0-other", "manifest.json"), (v.VERSION, "other.py"), (v.VERSION, "../bootstrap.py")):
            with self.assertRaises(v.Failed):
                self.b.asset_url(version, name)
        gh_name = f"gh_{self.b.GH_VERSION}_linux_amd64.tar.gz"
        self.assertEqual(self.b.asset_url(self.b.GH_VERSION, gh_name), f"https://github.com/cli/cli/releases/download/v{self.b.GH_VERSION}/{gh_name}")
        with patch.object(v, "TEMPLATE_SHA256", "0" * 64), self.assertRaisesRegex(v.Failed, "^FAIL_TEMPLATE$"):
            v.load_bootstrap()

    def test_old_release_uses_its_immutable_template_with_pin_disabled(self):
        published = (v.HERE / "published" / f"{v.VERSION}.py").read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "published").mkdir()
            selected = root / "published" / f"{v.VERSION}.py"
            selected.write_bytes(published)
            (root / "linux-bootstrap.py").write_text("raise AssertionError('mutable template must not run')\n")
            with patch.object(v, "HERE", root):
                loaded, template = v.load_bootstrap()
                self.assertIsNone(loaded.RELEASE_PIN)
                self.assertEqual(loaded.digest(template), v.TEMPLATE_SHA256)
                selected.write_bytes(published + b"\nraise AssertionError('tampered source must not run')\n")
                with self.assertRaisesRegex(v.Failed, "^FAIL_TEMPLATE$"):
                    v.load_bootstrap()

    def test_wrong_historical_pin_cannot_select_template_code(self):
        for key in ("version", "sourceCommit", "manifestSHA256", "bundleSHA256"):
            with self.subTest(key=key), patch.object(v, "PIN", dict(v.PIN, **{key: "wrong"})), \
                 self.assertRaisesRegex(v.Failed, "^FAIL_TEMPLATE$"):
                v.load_bootstrap()

    def test_default_arguments_wrong_context_and_root_never_load_or_download(self):
        for arguments in ([], ["--output", str(self.output)], ["--output", str(self.output), "--verify-published-pilot2"], ["--secret=do-not-print"]):
            stream = io.StringIO()
            with patch("sys.argv", ["verify-published-release.py", *arguments]), \
                 patch.dict(os.environ, {}, clear=True), patch.object(v, "load_bootstrap") as loader, redirect_stdout(stream):
                self.assertEqual(v.main(), 1)
                loader.assert_not_called()
            self.assertIn(stream.getvalue(), ("FAIL_ARGUMENTS\n", "FAIL_CONTEXT\n"))
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": v.REPOSITORY, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "push", "GITHUB_JOB": "verify-published-release", "TRACEBOLT_VERIFY_PUBLISHED_PILOT2": "1",
               "GITHUB_WORKFLOW_REF": v.REPOSITORY + "/.github/workflows/verify-published-release.yml@refs/heads/main",
               "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "RUNNER_TEMP": str(self.parent)}
        with patch.dict(os.environ, env, clear=True), patch.object(v.os, "getuid", return_value=0), self.assertRaisesRegex(v.Failed, "^FAIL_CONTEXT$"):
            v.check_context(self.output, True)

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_bytes(b"existing")
        with self.assertRaisesRegex(v.Failed, "^FAIL_OUTPUT$"):
            self.run_fixture()
        self.assertEqual(marker.read_bytes(), b"existing")

    def test_only_exact_nonroot_hosted_context_and_output_are_allowed(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": v.REPOSITORY, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "push", "GITHUB_JOB": "verify-published-release", "TRACEBOLT_VERIFY_PUBLISHED_PILOT2": "1",
               "GITHUB_WORKFLOW_REF": v.REPOSITORY + "/.github/workflows/verify-published-release.yml@refs/heads/main",
               "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "RUNNER_TEMP": str(self.parent)}
        original_stat = Path.stat

        def owned_stat(path, **kwargs):
            info = original_stat(path, **kwargs)
            if path == self.parent:
                values = list(info)
                values[4] = 1001
                return os.stat_result(values)
            return info

        with patch.dict(os.environ, env, clear=True), patch.object(v.os, "getuid", return_value=1001), \
             patch.object(v.os, "geteuid", return_value=1001), patch.object(Path, "stat", owned_stat):
            v.check_context(self.output, True)
            for key in env:
                if key == "RUNNER_TEMP":
                    continue
                with self.subTest(key=key), patch.dict(os.environ, {key: "wrong"}), self.assertRaisesRegex(v.Failed, "^FAIL_CONTEXT$"):
                    v.check_context(self.output, True)
            with self.assertRaisesRegex(v.Failed, "^FAIL_CONTEXT$"):
                v.check_context(self.output, False)
            with self.assertRaisesRegex(v.Failed, "^FAIL_OUTPUT$"):
                v.check_context(self.parent / "other", True)


if __name__ == "__main__":
    unittest.main()
