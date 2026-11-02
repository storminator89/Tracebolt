"""Portable CI guard/source/orchestration negatives; no Windows execution."""
import hashlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = Path(__file__).resolve().parent
def source(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
c = source("rust_gui_contract", "contract.py")
p = source("rust_gui_ci_policy", "ci_policy.py")
SOURCE = "a" * 40

def context():
    return {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REF": "refs/pull/201/merge", "GITHUB_JOB": "rust-gui-tls",
        "GITHUB_WORKFLOW": "Build unsigned Windows Setup candidates",
        "GITHUB_WORKFLOW_REF": "storminator89/Tracebolt/.github/workflows/windows-setup-build.yml@refs/pull/201/merge",
        "GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE,
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
        "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "TRACEBOLT_RUST_GUI_CI": p.ACK,
        "TRACEBOLT_RUST_GUI_CI_SOURCE": SOURCE, "TRACEBOLT_RUST_GUI_CI_HEAD": "b" * 40,
        "TRACEBOLT_RUST_GUI_CI_BASE": "c" * 40}

class CIContextTests(unittest.TestCase):
    def test_exact_context_and_each_missing_or_wrong_binding(self):
        self.assertEqual(p.authorization("nt", True, SOURCE, context()), context())
        for key in context():
            with self.subTest(key=key):
                env = context(); del env[key]
                with self.assertRaisesRegex(c.Failure, "ci"): p.authorization("nt", True, SOURCE, env)
                env[key] = "wrong"
                with self.assertRaisesRegex(c.Failure, "ci"): p.authorization("nt", True, SOURCE, env)

    def test_no_approval_non_windows_other_ci_and_case_expansion_are_rejected(self):
        for platform, ack, stage in [("nt", False, "approval"), ("posix", True, "platform")]:
            with self.assertRaisesRegex(c.Failure, stage): p.authorization(platform, ack, SOURCE, context())
        for key in p.OTHER_CI:
            env = context(); env[key.lower()] = ""
            with self.assertRaisesRegex(c.Failure, "ci"): p.authorization("nt", True, SOURCE, env)
        for case in ["http", "renewal", "uninstall", "cancel", "modal-resize", "failure", "close-input"]:
            env = context(); env["TRACEBOLT_RUST_GUI_FIXTURE_CASE"] = case
            with self.assertRaisesRegex(c.Failure, "ci"): p.authorization("nt", True, SOURCE, env)
        env = context(); env["ci"] = "true"
        with self.assertRaisesRegex(c.Failure, "ci"): p.authorization("nt", True, SOURCE, env)

    def test_manual_authorization_still_rejects_the_complete_ci_context(self):
        with self.assertRaisesRegex(c.Failure, "ci"):
            c.authorization("nt", True, "tls", SOURCE, "b" * 64, context())

    def test_source_ack_requires_exact_unique_embedded_source(self):
        row = b"RUST_GUI_FIXTURE_CI_SOURCE " + SOURCE.encode() + b"\n"
        p.parse_source_ack(row, SOURCE)
        for raw in [b"", row[:-1], row * 2, row.replace(SOURCE.encode(), b"b" * 40), row + b"x" * 65536]:
            with self.assertRaises(c.Failure): p.parse_source_ack(raw, SOURCE)

    def test_manifest_is_closed_exact_source_tls_and_repeat_only(self):
        state = {"sourceCommit": SOURCE, "sourceTree": "b" * 40, "sourceInputsSHA256": "c" * 64}
        tags = ["tracebolt_setup_rust", "tracebolt_setup_gui_fixture", "tracebolt_setup_gui_ci_fixture"]
        deps = ("localrmm/internal/windowssetupui", "localrmm/internal/windowssetupui [localrmm/internal/windowssetupui.test]", "localrmm/internal/windowssetupui.test")
        value = {"schema": "tracebolt.rust-gui-ci-build.v1", **state, "case": "tls", "testName": p.TEST_NAME,
            "tags": tags, "image": {"file": p.IMAGE, "sha256": "d" * 64, "size": 512, "repeatBuildIdentical": True},
            "rustArchive": {"sha256": "e" * 64, "size": 512, "repeatBuildIdentical": True},
            "tools": {"goVersion": "go1.27.1", "rustVersion": "1.99.1", "gccTarget": "x86_64-w64-mingw32",
                **{key: "f" * 64 for key in ("goSHA256", "rustcSHA256", "gccSHA256", "rustupSHA256")}},
            "pe": {}, "goBuild": {}, "projectDependencies": list(deps), "nativeExecution": False, "installerHostActionsAttempted": False}
        p.validate_build(value, state, tags, deps)
        for key, replacement in [("extra", True), ("sourceCommit", "b"*40), ("case", "http"), ("nativeExecution", True),
                                  ("installerHostActionsAttempted", 0), ("projectDependencies", ["localrmm/internal/windowsservice"]), ("tags", tags[:-1])]:
            bad = copy.deepcopy(value); bad[key] = replacement
            with self.subTest(key=key), self.assertRaises(c.Failure): p.validate_build(bad, state, tags, deps)
        for key, replacement in [("file", "Setup.exe"), ("size", True), ("sha256", "wrong"), ("repeatBuildIdentical", False)]:
            bad = copy.deepcopy(value); bad["image"][key] = replacement
            with self.subTest(key=key), self.assertRaises(c.Failure): p.validate_build(bad, state, tags, deps)

    def test_source_checks_synthetic_merge_parents_and_complete_clean_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); env = context(); env["GITHUB_WORKSPACE"] = directory
            files = ["go.mod", "go.sum", "internal/windowssetupui/a.go", "rust/windows-setup/Cargo.toml"]
            for name in files:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(name)
            replies = {("rev-parse", "HEAD"): SOURCE.encode() + b"\n",
                ("rev-list", "--parents", "-n", "1", "HEAD"): (SOURCE + " " + "c"*40 + " " + "b"*40).encode() + b"\n",
                ("status", "--porcelain", "--untracked-files=all"): b"",
                ("rev-parse", "HEAD^{tree}"): b"d"*40 + b"\n"}
            def git(_, args):
                return (b"\0".join(item.encode() for item in files) + b"\0") if args[0] == "ls-files" else replies[tuple(args)]
            state = p.source_state(root, SOURCE, env, git)
            self.assertEqual(state["sourceTree"], "d" * 40)
            self.assertEqual(len(state["sourceInputsSHA256"]), 64)
            for key, value in [("status", b" M private-not-exported\n"), ("parents", b"a"*40 + b" " + b"b"*40 + b" " + b"c"*40), ("head", b"b"*40)]:
                def bad(_, args):
                    if key == "status" and args[0] == "status": return value
                    if key == "parents" and args[0] == "rev-list": return value
                    if key == "head" and args == ["rev-parse", "HEAD"]: return value
                    return git(_, args)
                with self.assertRaisesRegex(c.Failure, "source"): p.source_state(root, SOURCE, env, bad)
            missing = dict(env); del missing["GITHUB_WORKSPACE"]
            with self.assertRaisesRegex(c.Failure, "source"): p.source_state(root, SOURCE, missing, git)

    def test_build_output_must_not_overlap_checked_out_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); workspace = root / "checkout"; workspace.mkdir()
            temp = root / "temp"; temp.mkdir()
            env = {"RUNNER_TEMP": str(temp), "GITHUB_WORKSPACE": str(workspace)}
            self.assertEqual(p.output_directory(env), temp / p.DIRECTORY)
            for values in [{"RUNNER_TEMP": str(workspace), "GITHUB_WORKSPACE": str(workspace)},
                           {"RUNNER_TEMP": str(temp)}, {"RUNNER_TEMP": "", "GITHUB_WORKSPACE": str(workspace)}]:
                with self.assertRaisesRegex(c.Failure, "source"): p.output_directory(values)

    def test_original_workflow_build_and_manual_entry_are_not_relaxed(self):
        root = HERE.parents[1]
        text = (root / ".github/workflows/windows-setup-build.yml").read_text()
        build = text.split("\n  build:\n", 1)[1].split("\n  rust-gui-tls:\n", 1)[0].rstrip() + "\n"
        self.assertEqual(hashlib.sha256(build.encode()).hexdigest(), "c80cdaa5ca9a9328f69230e2c74117c294c99001fe4bf089be7b1afa48a8990e")
        job = text.split("\n  rust-gui-tls:\n", 1)[1]
        self.assertIn("github.event.pull_request.number == 201", job)
        self.assertIn("github.event_name == 'pull_request'", job)
        self.assertIn("persist-credentials: false", job)
        self.assertIn("fetch-depth: 2", job)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("secrets.", job)
        self.assertNotIn("matrix", job)
        self.assertEqual(job.count("--execute-github-tls-fixture"), 1)
        manual = (root / "internal/windowssetupui/rust_gui_fixture_windows_test.go").read_text().split("func runRustNativeGUIFixture", 1)[0]
        self.assertIn('[]string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILD_BUILDID", "TF_BUILD"}', manual)
        self.assertIn('t.Fatal("native GUI fixture requires a separately approved interactive session")', manual)
        entry = (root / "internal/windowssetupui/rust_gui_ci_windows_test.go").read_text()
        self.assertTrue(entry.startswith("//go:build windows && cgo && tracebolt_setup_rust && tracebolt_setup_gui_fixture && tracebolt_setup_gui_ci_fixture\n"))
        self.assertIn('runRustNativeGUIFixture(t, "tls")', entry)
        for forbidden in ['"os/exec"', '"net"', '"net/http"', '"localrmm/internal/windowsservice"', '"localrmm/internal/windowspackage"']:
            self.assertNotIn(forbidden, entry + manual)

    def test_ci_selector_and_linker_source_recipe_are_fixed_test_only(self):
        entry = (HERE / "run_ci.py").read_text()
        self.assertIn('"-test.run=^TestRustNativeGUITLSCI$", "-test.count=1", "-test.timeout=80s"', entry)
        self.assertNotIn('add_argument("--case"', entry)
        self.assertNotIn('add_argument("--image"', entry)
        default = (HERE / "windows.py").read_text()
        self.assertIn('"-test.run=^TestRustNativeGUIFixture$", "-test.count=1", "-test.timeout=80s"', default)
        builder = (HERE / "build_ci.py").read_text()
        self.assertIn('-X localrmm/internal/windowssetupui.fixtureCIBuildSource=', builder)
        self.assertIn('"--no-self-update"', builder)
        self.assertNotIn("GITHUB_ENV", builder)
        self.assertNotIn("GITHUB_PATH", builder)

class CIRunnerTests(unittest.TestCase):
    def isolated(self, body):
        setup = f"""import importlib.util,sys,json,os,contextlib,io
from unittest.mock import patch
from pathlib import Path
path=Path({str(HERE / 'run_ci.py')!r})
spec=importlib.util.spec_from_file_location('runner_under_test',path)
r=importlib.util.module_from_spec(spec);sys.modules[spec.name]=r;spec.loader.exec_module(r)
env={context()!r}
env.update(GITHUB_WORKSPACE=str(r.ROOT),RUNNER_TEMP=str(r.ROOT.parent))
"""
        result = subprocess.run([sys.executable, "-I", "-B", "-c", setup + textwrap.dedent(body)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, "isolated mock runner assertion failed")

    def test_non_windows_cli_and_unknown_arguments_never_create_or_echo(self):
        for file, flag in [("run_ci.py", "--execute-github-tls-fixture"), ("build_ci.py", "--build-inert-github-tls-fixture")]:
            with tempfile.TemporaryDirectory() as directory:
                env = dict(os.environ, RUNNER_TEMP=directory)
                result = subprocess.run([sys.executable, "-I", "-B", str(HERE/file), flag, "--source", SOURCE], env=env, capture_output=True, timeout=5)
                if os.name != "nt":
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(json.loads(result.stdout)["stage"], "platform")
                self.assertEqual(list(Path(directory).iterdir()), [])
            marker = "invented-private-cli-value"
            result = subprocess.run([sys.executable, "-I", "-B", str(HERE/file), "--case", marker], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(marker.encode(), result.stdout + result.stderr)

    def test_context_and_dirty_source_refuse_before_provenance_or_launch(self):
        self.isolated('''
        r.PLATFORM='nt'
        with patch.dict(os.environ,env,clear=True),patch.object(r,'read_build',side_effect=AssertionError('must not read image')),patch.object(r,'session',side_effect=AssertionError('must not launch')):
            bad=dict(env);bad['GITHUB_REF']='refs/pull/202/merge'
            with patch.dict(os.environ,bad,clear=True),contextlib.redirect_stdout(io.StringIO()) as output:
                assert r.main(['--execute-github-tls-fixture','--source','a'*40])==2
                assert json.loads(output.getvalue())['stage']=='ci'
            with patch.object(r.policy,'source_state',side_effect=r.contract.Failure('source')),contextlib.redirect_stdout(io.StringIO()) as output:
                assert r.main(['--execute-github-tls-fixture','--source','a'*40])==2
                assert json.loads(output.getvalue())['stage']=='source'
        ''')

    def test_provenance_or_desktop_failure_cannot_launch_or_pass(self):
        self.isolated('''
        r.PLATFORM='nt';state={'sourceCommit':'a'*40,'sourceTree':'d'*40,'sourceInputsSHA256':'e'*64}
        with patch.dict(os.environ,env,clear=True),patch.object(r.policy,'source_state',return_value=state),patch.object(r,'read_build',side_effect=r.contract.Failure('provenance')),patch.object(r,'session',side_effect=AssertionError('must not launch')),contextlib.redirect_stdout(io.StringIO()) as output:
            assert r.main(['--execute-github-tls-fixture','--source','a'*40])==2
            assert json.loads(output.getvalue())['stage']=='provenance'
        class DesktopUnavailable:
            def __enter__(self): raise r.contract.Failure('desktop')
            def __exit__(self,*args): raise AssertionError('not entered')
        with patch.dict(os.environ,env,clear=True),patch.object(r.policy,'source_state',return_value=state),patch.object(r,'read_build',return_value={'image':{'sha256':'b'*64}}),patch.object(r,'session',return_value=DesktopUnavailable()),contextlib.redirect_stdout(io.StringIO()) as output:
            assert r.main(['--execute-github-tls-fixture','--source','a'*40])==2
            assert json.loads(output.getvalue())['stage']=='desktop'
            assert not any(json.loads(output.getvalue())['coverage'].values())
        ''')

    def test_missing_child_source_ack_and_cleanup_uncertainty_never_pass(self):
        self.isolated('''
        r.PLATFORM='nt';state={'sourceCommit':'a'*40,'sourceTree':'d'*40,'sourceInputsSHA256':'e'*64}
        class FakeSession:
            def __init__(self,cleanup=False): self.cleanup=cleanup
            def __enter__(self): return self
            def __exit__(self,*args):
                if self.cleanup: raise r.contract.Failure('cleanup')
            def finish(self): return b'invented no acknowledgement'
        build={'image':{'sha256':'b'*64},'rustArchive':{'sha256':'c'*64}}
        for cleanup,stage in [(False,'fixture-report'),(True,'cleanup')]:
            with patch.dict(os.environ,env,clear=True),patch.object(r.policy,'source_state',return_value=state),patch.object(r,'read_build',return_value=build),patch.object(r,'session',return_value=FakeSession(cleanup)),patch.object(r.contract,'drive',return_value={}),patch.object(r.contract,'parse_fixture'),contextlib.redirect_stdout(io.StringIO()) as output:
                assert r.main(['--execute-github-tls-fixture','--source','a'*40])==2
                assert json.loads(output.getvalue())['stage']==stage
        ''')

    def test_mock_tls_orchestration_has_one_attempt_and_keeps_all_coverage_false(self):
        self.isolated('''
        spec=importlib.util.spec_from_file_location('portable_fake_ui',r.HERE/'test_contract.py')
        f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
        r.PLATFORM='nt';state={'sourceCommit':'a'*40,'sourceTree':'d'*40,'sourceInputsSHA256':'e'*64}
        attempts=[]
        class FakeSession(f.FakeUI):
            def __init__(self): super().__init__('tls')
            def __enter__(self): attempts.append(True);return self
            def __exit__(self,*args): assert not self.alive
            def finish(self): return b'RUST_GUI_FIXTURE_CI_SOURCE '+b'a'*40+b'\\n'+f.fixture_report('tls')
        build={'image':{'sha256':'b'*64},'rustArchive':{'sha256':'c'*64}}
        with patch.dict(os.environ,env,clear=True),patch.object(r.policy,'source_state',return_value=state),patch.object(r,'read_build',return_value=build),patch.object(r,'session',return_value=FakeSession()),contextlib.redirect_stdout(io.StringIO()) as output:
            assert r.main(['--execute-github-tls-fixture','--source','a'*40])==0
        value=json.loads(output.getvalue())
        assert attempts==[True] and value['case']=='tls'
        assert value['checks']['scopeUncheckedAndBack'] and value['checks']['singleAttempt']
        assert not any(value['coverage'].values()) and value['installerHostActionsAttempted'] is False
        ''')

if __name__ == "__main__":
    unittest.main()
