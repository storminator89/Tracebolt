"""Inert builder tests: every Git/Go invocation is mocked; no artifact executes."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("arm64_fixture", ROOT / "deploy/release/prepare-arm64-source-upgrade-fixture.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
CANDIDATE = "a" * 40
GO_VERSION = "go1.27.1"


def approved_env(**changes):
    value = dict(GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux", RUNNER_ARCH="ARM64",
                 TRACEBOLT_APPROVED_SYSTEMD_TEST="1", TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST="1",
                 TRACEBOLT_READ_ADMIN_PROFILE="tracebolt.linux-read-admin.v2", TRACEBOLT_APPROVED_READ_ADMIN_PTRACE="true",
                 TRACEBOLT_APPROVED_READ_ADMIN_UPGRADE="true", TRACEBOLT_READ_ADMIN_SCENARIO="complete",
                 TRACEBOLT_READ_ADMIN_TRANSPORT="tls", GITHUB_SHA=CANDIDATE, TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE=CANDIDATE)
    value.update(changes)
    return value


def metadata(role="lan-agent", revision=CANDIDATE, **changes):
    settings = {"GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0", "CGO_ENABLED": "0", "-trimpath": "true",
                "vcs": "git", "vcs.revision": revision, "vcs.modified": "false"}
    settings.update(changes)
    return "/inert/artifact: " + GO_VERSION + "\n\tpath\tlocalrmm/cmd/" + role + "\n\tmod\tlocalrmm\t(devel)\t\n" + "".join(
        "\tbuild\t" + key + "=" + value + "\n" for key, value in settings.items())


def elf(payload=b"inert"):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 183, 1)
    return bytes(header) + payload


class SourceFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracebolt-inert-arm64-build-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prior, self.candidate, self.output = (self.root / name for name in ("prior-checkout", "candidate-checkout", "output"))
        for path in (self.prior, self.candidate):
            path.mkdir()
            (path / "go.mod").write_text("module localrmm\n\ngo 1.27.1\n")
        self.calls = []
        self.dirty = False
        self.wrong_revision = False
        self.same_bytes = False

    def runner(self, argv, root, env, *, stdout=subprocess.PIPE):
        self.calls.append((list(argv), root, dict(env)))
        revision = b.PRIOR_SOURCE if root == self.prior else CANDIDATE
        if argv[:3] == ["git", "rev-parse", "--show-toplevel"]:
            result = str(root).encode()
        elif argv[:3] == ["git", "rev-parse", "--verify"]:
            result = ("f" * 40 if self.wrong_revision else revision).encode()
        elif argv[:2] == ["git", "status"]:
            result = b"?? untracked" if self.dirty else b""
        elif argv[:2] == ["go", "env"]:
            result = json.dumps(dict(GOHOSTOS="linux", GOHOSTARCH="arm64", GOVERSION=GO_VERSION)).encode()
        elif argv == ["go", "mod", "verify"]:
            result = b"all modules verified"
        elif argv[:2] == ["go", "build"]:
            artifact = Path(argv[argv.index("-o") + 1])
            artifact.write_bytes(elf(("identical" if self.same_bytes else revision).encode() + argv[-1].encode()))
            result = b""
        elif argv[:3] == ["go", "version", "-m"]:
            result = metadata(Path(argv[3]).name, revision).encode()
        elif argv[:2] == ["git", "archive"]:
            self.assertEqual(argv, ["git", "archive", "--format=tar", revision])
            stdout.write(b"inert exact tree " + revision.encode())
            result = b""
        else:
            raise AssertionError("Unexpected command; no real command is permitted")
        return SimpleNamespace(stdout=result, returncode=0)

    def invoke(self, **kwargs):
        # Validate the pure gate with native fixture facts; never pretend the
        # actual test process is privileged or execute a native workflow.
        def gate(env, *_):
            return b.require_gate_original(env, "linux", "aarch64", 2**63-1, 1000, 1000)
        with patch.dict(b.os.environ, approved_env(**kwargs), clear=True), \
                patch.object(b, "run", side_effect=self.runner), \
                patch.object(b, "require_gate_original", b.require_gate, create=True), \
                patch.object(b, "require_gate", side_effect=gate), contextlib.redirect_stdout(io.StringIO()):
            return b.main(["--prior-checkout", str(self.prior), "--candidate-checkout", str(self.candidate), "--directory", str(self.output)])

    def test_pure_gate_requires_every_approval_native_fact_and_exact_distinct_source(self):
        def gate(env, **facts):
            values = dict(system="linux", machine="aarch64", maxsize=2**63-1, uid=1000, euid=1000)
            values.update(facts)
            return b.require_gate(env, **values)
        for scenario in ("complete", "cancel-enrollment", "retained-journal"):
            self.assertEqual(gate(approved_env(TRACEBOLT_READ_ADMIN_SCENARIO=scenario)), CANDIDATE)
        self.assertEqual(gate(approved_env(TRACEBOLT_READ_ADMIN_TRANSPORT="http-test")), CANDIDATE)
        for key in approved_env():
            for invalid in (None, "", "true ", True, False):
                with self.subTest(key=key, invalid=invalid), self.assertRaises(b.Rejected):
                    gate(approved_env(**{key: invalid}))
        for changes in (dict(system="darwin"), dict(machine="x86_64"), dict(machine="armv7l"), dict(maxsize=2**31-1),
                        dict(uid=0, euid=0), dict(euid=0), dict(uid=1001), dict(uid=True)):
            with self.subTest(changes=changes), self.assertRaises(b.Rejected):
                gate(approved_env(), **changes)
        with self.assertRaises(b.Rejected):
            gate(approved_env(GITHUB_SHA=b.PRIOR_SOURCE, TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE=b.PRIOR_SOURCE))
        with self.assertRaises(b.Rejected):
            gate(approved_env(TRACEBOLT_READ_ADMIN_SCENARIO="unsupported"))

    def test_every_supported_scenario_prepares_source_proof_without_running_artifacts(self):
        for scenario in ("complete", "cancel-enrollment", "retained-journal"):
            with self.subTest(scenario=scenario):
                self.output = self.root / ("output-" + scenario)
                self.calls.clear()
                self.assertEqual(self.invoke(TRACEBOLT_READ_ADMIN_SCENARIO=scenario), 0)
                proof = json.loads((self.output / "proof.json").read_bytes())
                self.assertEqual(proof["priorSourceCommit"], b.PRIOR_SOURCE)
                self.assertEqual(proof["candidateSourceCommit"], CANDIDATE)
                self.assertTrue(all(argv[0] in ("git", "go") for argv, _, _ in self.calls))

    def test_rejected_main_does_not_touch_paths_git_or_go(self):
        with patch.dict(b.os.environ, {}, clear=True), patch.object(b, "exact_path") as paths, patch.object(b, "run") as commands:
            with self.assertRaises(b.Rejected):
                b.main([])
        paths.assert_not_called()
        commands.assert_not_called()

    def test_fixture_schema_hashes_clean_source_rechecks_and_command_contract(self):
        self.assertEqual(self.invoke(), 0)
        proof = json.loads((self.output / "proof.json").read_bytes())
        self.assertEqual(set(proof), {"schemaVersion", "architecture", "baselineKind", "priorSourceCommit", "candidateSourceCommit", "prior", "candidate"})
        self.assertEqual(proof["schemaVersion"], b.SCHEMA)
        self.assertEqual(proof["architecture"], "arm64")
        self.assertEqual(proof["baselineKind"], "source-built")
        self.assertEqual(proof["priorSourceCommit"], b.PRIOR_SOURCE)
        self.assertEqual(proof["candidateSourceCommit"], CANDIDATE)
        for generation, revision in (("prior", b.PRIOR_SOURCE), ("candidate", CANDIDATE)):
            item = proof[generation]
            self.assertEqual(set(item), {"sourceCommit", "files"})
            self.assertEqual(item["sourceCommit"], revision)
            self.assertEqual(set(item["files"]), set(b.ROLES) | {"source"})
            self.assertEqual(stat.S_IMODE((self.output / generation).stat().st_mode), 0o700)
            for role, record in item["files"].items():
                path = self.output / generation / ("source.tar" if role == "source" else role)
                raw = path.read_bytes()
                self.assertEqual(record, {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertLessEqual((self.output / "proof.json").stat().st_size, 4096)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.output / "proof.json").stat().st_mode), 0o600)
        builds = [(argv, env) for argv, _, env in self.calls if argv[:2] == ["go", "build"]]
        self.assertEqual(len(builds), 8)
        for argv, env in builds:
            self.assertEqual(argv[2:5], ["-buildvcs=true", "-trimpath", "-mod=readonly"])
            for key, value in {"GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0", "GOARM64": "v8.0", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOWORK": "off"}.items():
                self.assertEqual(env[key], value)
        self.assertTrue(all(argv[0] in ("git", "go") for argv, _, _ in self.calls))
        for root in (self.prior, self.candidate):
            statuses = [argv for argv, cwd, _ in self.calls if cwd == root and argv[:2] == ["git", "status"]]
            self.assertEqual(len(statuses), 4)

    def test_source_mismatch_dirty_checkout_and_identical_bytes_never_emit_proof(self):
        for failure in ("dirty", "wrong_revision", "same_bytes"):
            with self.subTest(failure=failure):
                setattr(self, failure, True)
                with self.assertRaises(b.Rejected):
                    self.invoke()
                self.assertFalse((self.output / "proof.json").exists())
                setattr(self, failure, False)
                # Failed prepared data is deliberately retained. Each next
                # attempt uses a new directory, never erases a failed fixture.
                self.output = self.root / (failure + "-next")

    def test_existing_or_nested_output_and_symlink_paths_fail(self):
        self.output.mkdir()
        with self.assertRaises(b.Rejected):
            self.invoke()
        self.assertFalse(self.calls)
        self.output = self.prior / "nested-output"
        with self.assertRaises(b.Rejected):
            self.invoke()
        self.assertFalse(self.calls)
        link = self.root / "linked-prior"
        link.symlink_to(self.prior, target_is_directory=True)
        with self.assertRaises(b.Rejected):
            b.exact_path(str(link))

    def test_build_metadata_rejects_arch_source_role_and_missing_or_duplicate_settings(self):
        b.verify_build_info(metadata(), "lan-agent", CANDIDATE, GO_VERSION)
        for key, value in {"GOOS": "darwin", "GOARCH": "amd64", "GOARM64": "v8.1", "CGO_ENABLED": "1", "vcs": "hg",
                           "vcs.revision": b.PRIOR_SOURCE, "vcs.modified": "true", "-trimpath": "false"}.items():
            with self.subTest(key=key), self.assertRaises(b.Rejected):
                b.verify_build_info(metadata(**{key: value}), "lan-agent", CANDIDATE, GO_VERSION)
        for raw in (metadata(role="agent-service"), metadata().replace("localrmm\t(devel)", "other\t(devel)"),
                    metadata().replace("\tbuild\tvcs.modified=false\n", ""), metadata() + "\tbuild\tGOARCH=arm64\n",
                    metadata().replace(GO_VERSION, "go1.27.0"), metadata() + "\tpath\tlocalrmm/cmd/lan-agent\n"):
            with self.assertRaises(b.Rejected):
                b.verify_build_info(raw, "lan-agent", CANDIDATE, GO_VERSION)

    def test_elf_evidence_rejects_wrong_machine_endian_class_type_and_mutable_mode(self):
        path = self.root / "artifact"
        path.write_bytes(elf())
        path.chmod(0o600)
        self.assertEqual(b.file_evidence(path, b.MAX_BINARY, executable=True)["size"], 69)
        for index, value in ((4, 1), (5, 2), (16, 1), (18, 62), (20, 0)):
            raw = bytearray(elf())
            raw[index] = value
            path.write_bytes(raw)
            with self.subTest(index=index), self.assertRaises(b.Rejected):
                b.file_evidence(path, b.MAX_BINARY, executable=True)
        path.write_bytes(elf())
        path.chmod(0o666)
        with self.assertRaises(b.Rejected):
            b.file_evidence(path, b.MAX_BINARY, executable=True)

    def test_toolchain_must_be_exact_and_native_for_each_source(self):
        env = b.build_environment({})
        good = dict(GOHOSTOS="linux", GOHOSTARCH="arm64", GOVERSION=GO_VERSION)
        for changes in (dict(GOHOSTOS="darwin"), dict(GOHOSTARCH="amd64"), dict(GOVERSION="go1.27.0"), dict(extra="unexpected")):
            facts = dict(good, **changes)
            with self.subTest(changes=changes), patch.object(b, "text_command", return_value=json.dumps(facts)), self.assertRaises(b.Rejected):
                b.verify_toolchain(self.prior, env)
        with patch.object(b, "text_command", return_value=json.dumps(good)):
            self.assertEqual(b.verify_toolchain(self.prior, env), GO_VERSION)
        (self.prior / "go.mod").write_text("module localrmm\n\ngo 1.27\n")
        with patch.object(b, "run") as commands, self.assertRaises(b.Rejected):
            b.verify_toolchain(self.prior, env)
        commands.assert_not_called()

    def test_prior_checkout_change_during_candidate_build_prevents_proof(self):
        original_runner = self.runner
        candidate_built = False
        def changed_runner(argv, root, env, **kwargs):
            nonlocal candidate_built
            if root == self.candidate and argv[:2] == ["go", "build"]:
                candidate_built = True
            if candidate_built and root == self.prior and argv[:2] == ["git", "status"]:
                return SimpleNamespace(stdout=b" M changed-source", returncode=0)
            return original_runner(argv, root, env, **kwargs)
        self.runner = changed_runner
        with self.assertRaises(b.Rejected):
            self.invoke()
        self.assertTrue(candidate_built)
        self.assertFalse((self.output / "proof.json").exists())

    def test_proof_is_exact_canonical_ascii_json_with_newline(self):
        self.invoke()
        raw = (self.output / "proof.json").read_bytes()
        self.assertEqual(raw, (json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
        self.assertEqual(b.PRIOR_SOURCE, "7b20a93e481feb1f7433ee0ef6c912a35f68ce6d")

    def test_builder_environment_excludes_credentials_and_ambient_overrides(self):
        env = b.build_environment(dict(PATH="/usr/bin", HOME="/inert", GH_TOKEN="secret", GIT_DIR="/elsewhere",
                                      LD_PRELOAD="/evil", GOFLAGS="-ldflags=unreviewed", GOARCH="amd64", CC="other"))
        for key in ("GH_TOKEN", "GIT_DIR", "LD_PRELOAD", "CC"):
            self.assertNotIn(key, env)
        self.assertEqual(env["GOARCH"], "arm64")
        self.assertEqual(env["GOFLAGS"], "")
        self.assertEqual(env["GOENV"], "off")


if __name__ == "__main__":
    unittest.main()
