"""Inert builder fixtures; Go builds and candidate programs never run.

One source-guard fixture uses real Git history in a disposable local repository.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("inert_release_builder", ROOT / "deploy/release/build-linux-release.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildContract(unittest.TestCase):
    def test_real_hidden_tracked_edits_are_rejected_without_changing_the_index(self):
        # Both flags can hide different source bytes from git status while HEAD
        # (and therefore git archive) still describes the original content.
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory(prefix="tracebolt-local-git-hidden-source-") as temporary:
                repo = Path(temporary)
                env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
                env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")

                def git(*args):
                    return subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull,
                                           "-c", "commit.gpgsign=false", "-c", "user.name=Inert source fixture",
                                           "-c", "user.email=fixture@example.invalid", *args],
                                          cwd=repo, env=env, check=True, capture_output=True)

                git("init", "--quiet")
                source = repo / "source.go"
                original = b"package original\n"
                changed = b"package changed\n"
                source.write_bytes(original)
                git("add", "source.go")
                git("commit", "--quiet", "-m", "Inert original source")
                revision = git("rev-parse", "HEAD").stdout.decode().strip()

                def real_git(argv, root, **kwargs):
                    self.assertEqual(root, repo)
                    self.assertEqual(argv[0], "git")
                    return subprocess.run(argv, cwd=root, env=env, check=True, **kwargs)

                with mock.patch.object(build, "run", side_effect=real_git):
                    build.check_source(repo, revision)
                    git("update-index", flag, "source.go")
                    source.write_bytes(changed)
                    self.assertEqual(git("status", "--porcelain", "--untracked-files=all").stdout, b"")
                    self.assertEqual(git("show", "HEAD:source.go").stdout, original)
                    index_before = git("ls-files", "-v", "-z").stdout
                    with self.assertRaisesRegex(build.bootstrap.Rejected, "Source .*discard the candidate"):
                        build.check_source(repo, revision)
                self.assertEqual(git("ls-files", "-v", "-z").stdout, index_before)
                self.assertEqual(source.read_bytes(), changed)

    def test_real_clean_checkout_change_after_first_build_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="tracebolt-local-git-source-drift-") as temporary:
            root = Path(temporary)
            repo = root / "source"
            repo.mkdir()
            output = root / "candidate"
            env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")

            def git(*args):
                return subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull,
                                       "-c", "commit.gpgsign=false", "-c", "user.name=Inert source fixture",
                                       "-c", "user.email=fixture@example.invalid", *args],
                                      cwd=repo, env=env, check=True, capture_output=True)

            git("init", "--quiet")
            (repo / "go.mod").write_bytes((ROOT / "go.mod").read_bytes())
            git("add", "go.mod")
            git("commit", "--quiet", "-m", "First inert source")
            first = git("rev-parse", "HEAD").stdout.decode().strip()
            (repo / "source.txt").write_text("second inert source\n")
            git("add", "source.txt")
            git("commit", "--quiet", "-m", "Second inert source")
            second = git("rev-parse", "HEAD").stdout.decode().strip()
            self.assertNotEqual(first, second)
            git("checkout", "--quiet", first)
            builds = []
            expected_go = next(line.split()[1] for line in (repo / "go.mod").read_text().splitlines() if line.startswith("go "))

            def inert_run(argv, source_root, **kwargs):
                self.assertEqual(source_root, repo)
                if argv[0] == "git":
                    return subprocess.run(argv, cwd=repo, env=env, check=True, **kwargs)
                if argv == ["go", "env", "GOVERSION"]:
                    return SimpleNamespace(stdout="go" + expected_go + "\n")
                if argv == ["go", "mod", "verify"]:
                    return SimpleNamespace()
                if argv[:2] == ["go", "build"]:
                    builds.append(argv[-1])
                    Path(argv[argv.index("-o") + 1]).write_bytes(b"inert binary; never executed")
                    git("checkout", "--quiet", second)
                    self.assertEqual(git("status", "--porcelain", "--untracked-files=all").stdout, b"")
                    return SimpleNamespace()
                raise AssertionError("Unexpected external command")

            stream = io.StringIO()
            with mock.patch.object(build, "HERE", repo / "deploy" / "release"), \
                 mock.patch.object(build, "run", side_effect=inert_run), \
                 mock.patch("sys.argv", ["build-linux-release.py", "--version", "v0.1.0-inert.1", "--output", str(output)]), \
                 contextlib.redirect_stdout(stream):
                with self.assertRaisesRegex(build.bootstrap.Rejected, "Source .*discard the candidate"):
                    build.main()
            self.assertEqual(len(builds), 1)
            self.assertFalse((output / "manifest.json").exists())
            self.assertNotIn("Unsigned candidates prepared", stream.getvalue())

    def run_source_change_fixture(self, output, change_at, *, dirty=False, hidden=False):
        """Change clean HEAD (or dirty files) during one otherwise inert build."""
        initial = "a" * 40
        current = initial
        status = b""
        indexed = b"H source.go\0"
        builds = []
        expected_go = next(line.split()[1] for line in (ROOT / "go.mod").read_text().splitlines() if line.startswith("go "))

        def change(phase):
            nonlocal current, status, indexed
            if change_at == phase:
                if hidden:
                    indexed = b"h source.go\0"
                elif dirty:
                    status = b" M cmd/lan-agent/main.go\n"
                else:
                    current = "b" * 40

        def inert_run(argv, root, **kwargs):
            self.assertEqual(root, ROOT)
            if argv == ["git", "rev-parse", "HEAD"]:
                return SimpleNamespace(stdout=current + "\n")
            if argv == ["git", "status", "--porcelain", "--untracked-files=all"]:
                return SimpleNamespace(stdout=status)
            if argv == ["git", "ls-files", "-v", "-z"]:
                return SimpleNamespace(stdout=indexed)
            if argv == ["go", "env", "GOVERSION"]:
                return SimpleNamespace(stdout="go" + expected_go + "\n")
            if argv == ["go", "mod", "verify"]:
                change("module-verification")
                return SimpleNamespace()
            if argv[:2] == ["go", "build"]:
                builds.append(argv[-1])
                Path(argv[argv.index("-o") + 1]).write_bytes(b"inert binary")
                change("build-" + str(len(builds)))
                return SimpleNamespace()
            if argv == ["git", "archive", "--format=tar", initial]:
                kwargs["stdout"].write(b"inert source archive fixture")
                change("source-archive")
                return SimpleNamespace()
            raise AssertionError("Unexpected external command")

        stream = io.StringIO()
        with mock.patch.object(build, "run", side_effect=inert_run), \
             mock.patch("sys.argv", ["build-linux-release.py", "--version", "v0.1.0-inert.1", "--output", str(output)]), \
             contextlib.redirect_stdout(stream):
            with self.assertRaisesRegex(build.bootstrap.Rejected, "Source .*discard the candidate"):
                build.main()
        self.assertNotIn("Unsigned candidates prepared", stream.getvalue())
        self.assertFalse((output / "manifest.json").exists())
        return builds

    def test_clean_head_change_during_module_verification_stops_before_building(self):
        with tempfile.TemporaryDirectory(prefix="tracebolt-inert-source-drift-") as temporary:
            self.assertEqual(self.run_source_change_fixture(Path(temporary) / "candidate", "module-verification"), [])

    def test_clean_head_change_during_any_binary_build_stops_before_next_build(self):
        with tempfile.TemporaryDirectory(prefix="tracebolt-inert-source-drift-") as temporary:
            for number in range(1, 9):
                with self.subTest(binary=number):
                    builds = self.run_source_change_fixture(Path(temporary) / str(number), "build-" + str(number))
                    self.assertEqual(len(builds), number)

    def test_clean_head_change_during_archive_cannot_leave_a_candidate_manifest(self):
        with tempfile.TemporaryDirectory(prefix="tracebolt-inert-source-drift-") as temporary:
            self.assertEqual(len(self.run_source_change_fixture(Path(temporary) / "candidate", "source-archive")), 8)

    def test_dirty_source_at_build_boundaries_is_also_rejected_before_manifest(self):
        with tempfile.TemporaryDirectory(prefix="tracebolt-inert-source-drift-") as temporary:
            for phase, count in (("module-verification", 0), ("build-1", 1), ("build-8", 8), ("source-archive", 8)):
                with self.subTest(phase=phase):
                    builds = self.run_source_change_fixture(Path(temporary) / phase, phase, dirty=True)
                    self.assertEqual(len(builds), count)

    def test_hidden_index_flags_at_build_boundaries_are_rejected_before_manifest(self):
        with tempfile.TemporaryDirectory(prefix="tracebolt-inert-hidden-source-") as temporary:
            for phase, count in (("module-verification", 0), ("build-1", 1), ("build-8", 8), ("source-archive", 8)):
                with self.subTest(phase=phase):
                    builds = self.run_source_change_fixture(Path(temporary) / phase, phase, hidden=True)
                    self.assertEqual(len(builds), count)

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
                if argv == ["git", "ls-files", "-v", "-z"]:
                    return SimpleNamespace(stdout=b"H source.go\0")
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
