"""Inert release builder fixture; no Git command, Go build or native program runs."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("inert_release_builder", ROOT / "deploy/release/build-linux-release.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildContract(unittest.TestCase):
    def test_exact_attested_asset_set_builds_four_roles_for_both_architectures(self):
        with tempfile.TemporaryDirectory(prefix="tracebolt-inert-release-build-") as temporary:
            output = Path(temporary) / "candidate"
            calls = []
            expected_go = next(line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines() if line.startswith("go "))
            def inert_run(argv, root, **kwargs):
                self.assertEqual(root, ROOT)
                if argv == ["git", "rev-parse", "HEAD"]:
                    return SimpleNamespace(stdout="a" * 40 + "\n")
                if argv == ["git", "status", "--porcelain", "--untracked-files=all"]:
                    return SimpleNamespace(stdout=b"")
                if argv == ["go", "env", "GOVERSION"]:
                    return SimpleNamespace(stdout="go" + expected_go + "\n")
                if argv == ["go", "mod", "verify"]:
                    return SimpleNamespace()
                if argv[:2] == ["go", "build"]:
                    arch = kwargs["env"]["GOARCH"]
                    role = argv[-1].removeprefix("./cmd/")
                    calls.append((arch, role))
                    Path(argv[argv.index("-o") + 1]).write_bytes(("inert binary " + arch + role).encode())
                    return SimpleNamespace()
                if argv == ["git", "archive", "--format=tar", "a" * 40]:
                    kwargs["stdout"].write(b"inert source archive fixture")
                    return SimpleNamespace()
                raise AssertionError("Unexpected external command")
            with mock.patch.object(build, "run", side_effect=inert_run), \
                 mock.patch("sys.argv", ["build-linux-release.py", "--version", "v0.1.0-inert.1", "--output", str(output)]), \
                 contextlib.redirect_stdout(io.StringIO()):
                build.main()
            self.assertEqual(set(calls), {(arch, role) for arch in ("amd64", "arm64")
                                        for role in ("agent-service", "enroll-agent", "lan-agent", "socket-owner-reader")})
            self.assertEqual(len(calls), 8)
            manifest = json.loads((output / "manifest.json").read_bytes())
            self.assertEqual(set(manifest["assets"]), build.bootstrap.asset_names("v0.1.0-inert.1"))
            self.assertEqual(len(manifest["assets"]), 9)
            self.assertEqual(manifest["runtimeTargets"], ["linux-amd64"])
            for name, entry in manifest["assets"].items():
                raw = (output / name).read_bytes()
                self.assertEqual(entry, dict(size=len(raw), sha256=build.bootstrap.digest(raw)))


if __name__ == "__main__":
    unittest.main()
