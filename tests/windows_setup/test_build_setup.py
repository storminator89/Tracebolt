"""Packaging/resource fixtures only. Never execute Setup or native service code."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("setup_builder", ROOT / "deploy/windows-setup/build-setup.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
r = builder.resources
VERSION = "v0.1.0-setup.1"
SOURCE = "a" * 40


def fixture_pe(coff, setup=True, suffix=b""):
    """Minimal PE mapping a COFF resource section, separate from production parser."""
    machine, _, _, _, _, _, _ = struct.unpack_from("<HHIIIHH", coff)
    section = struct.unpack_from("<8sIIIIIIHHI", coff, 20)
    _, _, _, size, pointer, relocation_pointer, _, relocations, _, _ = section
    data = bytearray(coff[pointer:pointer + size])
    for i in range(relocations):
        offset, symbol, kind = struct.unpack_from("<IIH", coff, relocation_pointer + 10 * i)
        assert symbol == 0 and kind in (2, 3)
        struct.pack_into("<I", data, offset, struct.unpack_from("<I", data, offset)[0] + 0x1000)
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x84, machine, 1, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<H", header, optional + 68, 2 if setup else 3)
    struct.pack_into("<I", header, optional + 108, 16)
    struct.pack_into("<II", header, optional + 112 + 16, 0x1000, len(data))
    struct.pack_into("<8sIIIIIIHHI", header, optional + 240, b".rsrc\0\0\0", len(data), 0x1000, len(data), 512, 0, 0, 0, 0, 0x40000040)
    return bytes(header) + data + suffix


class ResourceTests(unittest.TestCase):
    def test_semver_rejects_ambiguous_or_unbounded_values(self):
        for version in ["0.1.0", "v01.0.0", "v1.0.0-01", "v1.0.0/a", "v1.0.0\n", "v65536.0.0", "v1.2.3+" + "x" * 80]:
            with self.subTest(version=version), self.assertRaises(r.Rejected):
                r.version_parts(version)
        self.assertEqual(r.version_parts("v1.2.3-rc.1+abc"), (1, 2, 3, 0))

    def test_version_and_uac_are_deterministic_for_both_architectures(self):
        for arch in r.MACHINES:
            for setup in [False, True]:
                with self.subTest(arch=arch, setup=setup):
                    obj = r.coff_resources(VERSION, SOURCE, arch, setup=setup)
                    self.assertEqual(obj, r.coff_resources(VERSION, SOURCE, arch, setup=setup))
                    image = fixture_pe(obj, setup)
                    metadata = r.verify_pe(image, VERSION, SOURCE, arch, setup=setup)
                    self.assertEqual(metadata["uac"], "requireAdministrator" if setup else "asInvoker")
                    self.assertEqual(metadata["authenticode"], "unsigned")
                    self.assertIn(SOURCE.encode("utf-16le"), image)

    def test_resource_tree_and_coff_relocations(self):
        obj = r.coff_resources(VERSION, SOURCE, "arm64", setup=True)
        header = struct.unpack_from("<HHIIIHH", obj)
        self.assertEqual(header[:3], (0xAA64, 1, 0))
        section = struct.unpack_from("<8sIIIIIIHHI", obj, 20)
        self.assertEqual(section[7], 2)
        self.assertEqual([struct.unpack_from("<IIH", obj, section[5] + 10 * i)[2] for i in range(2)], [2, 2])

    def test_tamper_wrong_machine_and_signed_candidate_fail(self):
        image = fixture_pe(r.coff_resources(VERSION, SOURCE, "amd64", setup=True))
        mutations = [image.replace(b"requireAdministrator", b"requireAdministrat0r"), image[:100]]
        signed = bytearray(image)
        struct.pack_into("<II", signed, 0x98 + 112 + 32, len(image), 8)
        mutations.append(bytes(signed))
        for item in mutations:
            with self.subTest(length=len(item)), self.assertRaises(r.Rejected):
                r.verify_pe(item, VERSION, SOURCE, "amd64", setup=True)
        with self.assertRaises(r.Rejected):
            r.verify_pe(image, VERSION, SOURCE, "arm64", setup=True)

    def test_dangerous_resource_offsets_fail_closed(self):
        original = fixture_pe(r.coff_resources(VERSION, SOURCE, "amd64", setup=True))
        for position, value in [(0x3C, 0xFFFFFFFF), (0x98 + 112 + 16, 0xFFFFFFF0), (512 + 20, 0x8FFFFFFF), (512 + 16, 0x80000010)]:
            image = bytearray(original)
            struct.pack_into("<I", image, position, value)
            with self.subTest(position=position), self.assertRaises(r.Rejected):
                r.inspect_pe(bytes(image))


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "go.mod").write_text("module fixture\ngo 1.27.1\n")
        (self.root / "go.sum").write_text("")
        for relative in ["cmd/windows-service/main.go", "internal/fake/fake.go", "deploy/windows-setup/build-setup.py", "deploy/windows-setup/pe_resources.py", "deploy/windows-setup/verify-package.go"]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture source\n")
        self.calls = []

    def fake_run(self, argv, root, **kwargs):
        self.calls.append((argv, kwargs))
        self.assertEqual(argv[0], "fixture-go")
        env = kwargs["env"]
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["CGO_ENABLED"], "0")
        if argv[1:] == ["env", "GOVERSION"]:
            return subprocess.CompletedProcess(argv, 0, "go1.27.1\n")
        if argv[1:] == ["env", "GOHOSTOS", "GOHOSTARCH"]:
            return subprocess.CompletedProcess(argv, 0, "linux\namd64\n")
        if argv[1:] == ["mod", "verify"]:
            return subprocess.CompletedProcess(argv, 0)
        if argv[1] == "run":
            self.assertEqual(env["GOOS"], "linux")
            self.assertEqual(env["GOARCH"], "amd64")
            manifest, image = map(Path, argv[-2:])
            self.assertEqual(json.loads(manifest.read_bytes())["sha256"], builder.sha256(image.read_bytes()))
            return subprocess.CompletedProcess(argv, 0)
        self.assertEqual(argv[1], "build")
        self.assertIn("-trimpath", argv)
        self.assertIn("-buildvcs=false", argv)
        self.assertIn("-mod=readonly", argv)
        setup = "-tags=tracebolt_setup" in argv
        root = Path(root)
        syso = root / "cmd/windows-service" / f'resource_windows_{env["GOARCH"]}.syso'
        payload = root / "cmd/windows-service/setup_payload"
        suffix = (payload / "service.exe").read_bytes() + (payload / "manifest.json").read_bytes() if setup else b""
        image = fixture_pe(syso.read_bytes(), setup, suffix)
        destination = Path(argv[argv.index("-o") + 1])
        destination.write_bytes(image)
        return subprocess.CompletedProcess(argv, 0)

    def invoke(self, **kwargs):
        with patch.object(builder, "run", self.fake_run):
            return builder.build(self.root, self.base / "output", VERSION, SOURCE,
                                 ["amd64", "arm64"], "fixture-go", snapshot=True, **kwargs)

    def test_complete_artifacts_hashes_rebuild_and_no_source_mutation(self):
        before, _ = builder.source_inputs(self.root)
        result = self.invoke()
        after, _ = builder.source_inputs(self.root)
        self.assertEqual(before, after)
        self.assertEqual(result["sourceKind"], "uncommitted-snapshot")
        self.assertEqual(result["sourceCommitRole"], "base")
        self.assertFalse(result["nativeExecution"])
        self.assertTrue(result["repeatBuildIdentical"])
        self.assertEqual(len([item for item, _ in self.calls if "build" in item]), 8)
        output = self.base / "output"
        self.assertEqual(json.loads((output / "build-manifest.json").read_bytes()), result)
        for line in (output / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(builder.sha256((output / name).read_bytes()), digest)
        for arch in r.MACHINES:
            manifest = json.loads((output / f"setup-package-{arch}.json").read_bytes())
            service = output / f"tracebolt-{VERSION}-windows-{arch}-service.exe"
            self.assertEqual(manifest["sha256"], builder.sha256(service.read_bytes()))
        self.assertFalse(list(self.root.rglob("*.syso")))
        self.assertFalse(list(self.base.glob("tracebolt-windows-build-*")))

    def test_package_manifest_binds_exact_payload(self):
        raw = b"opaque service bytes"
        first = builder.package_manifest(VERSION, SOURCE, "amd64", raw)
        second = builder.package_manifest(VERSION, SOURCE, "amd64", raw + b"x")
        self.assertNotEqual(first["sha256"], second["sha256"])
        self.assertEqual(set(first), {"schemaVersion", "version", "sourceCommit", "architecture", "sha256"})

    def test_repeat_mismatch_never_produces_output(self):
        normal = self.fake_run
        def changed(argv, root, **kwargs):
            value = normal(argv, root, **kwargs)
            if "-o" in argv and Path(argv[argv.index("-o") + 1]).name == "repeat.exe":
                with Path(argv[argv.index("-o") + 1]).open("ab") as stream:
                    stream.write(b"changed")
            return value
        with patch.object(builder, "run", changed), self.assertRaisesRegex(r.Rejected, "Repeated build"):
            builder.build(self.root, self.base / "output", VERSION, SOURCE, ["amd64"], "fixture-go", snapshot=True)
        self.assertFalse((self.base / "output").exists())

    def test_source_drift_never_produces_output(self):
        normal = self.fake_run
        def changed(argv, root, **kwargs):
            value = normal(argv, root, **kwargs)
            if "build" in argv:
                (self.root / "internal/fake/fake.go").write_text("changed source\n")
            return value
        with patch.object(builder, "run", changed), self.assertRaisesRegex(r.Rejected, "Source changed"):
            builder.build(self.root, self.base / "output", VERSION, SOURCE, ["amd64"], "fixture-go", snapshot=True)
        self.assertFalse((self.base / "output").exists())

    def test_existing_or_inside_output_fails_before_compiling(self):
        (self.base / "output").mkdir()
        with patch.object(builder, "run") as call, self.assertRaises(r.Rejected):
            builder.build(self.root, self.base / "output", VERSION, SOURCE, ["amd64"], "fixture-go", snapshot=True)
        call.assert_not_called()
        with self.assertRaises(r.Rejected):
            builder.build(self.root, self.root / "output", VERSION, SOURCE, ["amd64"], "fixture-go", snapshot=True)

    @unittest.skipIf(os.name == "nt", "Windows nonprivileged symlink creation is unavailable")
    def test_source_links_rejected(self):
        (self.root / "internal/link.go").symlink_to(self.root / "go.mod")
        with self.assertRaises(r.Rejected):
            builder.source_inputs(self.root)

    def test_source_resource_objects_rejected(self):
        (self.root / "cmd/windows-service/stale.syso").write_bytes(b"object")
        with self.assertRaises(r.Rejected):
            builder.source_inputs(self.root)

    def test_exact_git_source_requires_matching_clean_root(self):
        def git(argv, root, **kwargs):
            values = {tuple(["git", "rev-parse", "--show-toplevel"]): str(self.root),
                      tuple(["git", "rev-parse", "HEAD"]): SOURCE,
                      tuple(["git", "status", "--porcelain", "--untracked-files=all"]): b""}
            return subprocess.CompletedProcess(argv, 0, values[tuple(argv)])
        with patch.object(builder, "run", git):
            self.assertEqual(builder.git_source(self.root, SOURCE, False), "clean-git-commit")
            with self.assertRaises(r.Rejected):
                builder.git_source(self.root, "b" * 40, False)
        def dirty(argv, root, **kwargs):
            result = git(argv, root, **kwargs)
            if "status" in argv:
                result.stdout = b"?? untracked.go\n"
            return result
        with patch.object(builder, "run", dirty), self.assertRaisesRegex(r.Rejected, "clean checkout"):
            builder.git_source(self.root, SOURCE, False)

    def test_snapshot_mode_never_claims_exact_commit(self):
        with patch.object(builder, "run") as run:
            self.assertEqual(builder.git_source(self.root, SOURCE, True), "uncommitted-snapshot")
        run.assert_not_called()
        with self.assertRaises(r.Rejected):
            builder.git_source(self.root, "a" * 39, True)

    def test_payload_validator_rejection_blocks_package(self):
        normal = self.fake_run
        def rejected(argv, root, **kwargs):
            if argv[1] == "run":
                raise subprocess.CalledProcessError(1, argv)
            return normal(argv, root, **kwargs)
        with patch.object(builder, "run", rejected), self.assertRaises(subprocess.CalledProcessError):
            builder.build(self.root, self.base / "output", VERSION, SOURCE, ["amd64"], "fixture-go", snapshot=True)
        self.assertFalse((self.base / "output").exists())
        self.assertFalse(any("-tags=tracebolt_setup" in argv for argv, _ in self.calls))

    def test_wrong_toolchain_stops_before_compilation(self):
        with patch.object(builder, "run", return_value=subprocess.CompletedProcess([], 0, "go1.26.0\n")) as run, self.assertRaisesRegex(r.Rejected, "exact Go version"):
            builder.build(self.root, self.base / "output", VERSION, SOURCE, ["amd64"], "fixture-go", snapshot=True)
        self.assertEqual(run.call_count, 1)
        self.assertFalse((self.base / "output").exists())

    def test_ci_has_no_signing_publication_or_native_execution(self):
        workflow = (ROOT / ".github/workflows/windows-setup-build.yml").read_text()
        self.assertIn("contents: read", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("id-token:", workflow)
        self.assertNotIn("attestations:", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("gh release", workflow)
        self.assertNotIn("Start-Process", workflow)

    def test_no_ambient_go_build_flags(self):
        with patch.dict(os.environ, {"GOFLAGS": "-toolexec=untrusted", "GOENV": "host-env", "GOEXPERIMENT": "x", "GOWORK": "/arbitrary"}):
            env = builder.isolated_environment("arm64")
        self.assertEqual(env["GOFLAGS"], "")
        self.assertEqual(env["GOENV"], "off")
        self.assertEqual(env["GOWORK"], "off")
        self.assertEqual(env["GOEXPERIMENT"], "")


if __name__ == "__main__":
    unittest.main()
