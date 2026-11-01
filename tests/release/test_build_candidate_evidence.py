"""Inert SBOM fixtures: no release, native program, credential or network action."""
import copy
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
        with mock.patch.object(e.subprocess, "run", return_value=mock.Mock(stdout=e.canonical(self.info(self.candidate / self.binary)))) as run:
            e.inspect(self.candidate / self.binary)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["go", "version", "-m", "-json", str(self.candidate / self.binary)])
        self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
        self.assertEqual(kwargs["env"]["GOPROXY"], "off")
        self.assertEqual(kwargs["env"]["GOWORK"], "off")
        self.assertEqual(kwargs["timeout"], 30)

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


if __name__ == "__main__":
    unittest.main()
