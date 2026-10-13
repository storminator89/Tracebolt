"""Pure/fake manual-gate tests. Never construct a real runtime or native child."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

import gate


def manifest():
    return {"sha256": "a" * 64, "fileCount": 3,
            "files": {gate.HELPER: "b" * 64, gate.FIXTURE: "c" * 64,
                      "tests/macosendpointfixture/gate.py": "d" * 64}}


def environment():
    return {"TRACEBOLT_RUNNER_LABEL": "macos-15", "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "storminator89/Tracebolt",
            "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
            "TRACEBOLT_REPOSITORY_VISIBILITY": "public", "GITHUB_RUN_ATTEMPT": "1",
            "TRACEBOLT_SELECT_ENDPOINT": "true", "TRACEBOLT_REVIEWED_COMMIT": "1" * 40,
            "GITHUB_SHA": "1" * 40, "GITHUB_WORKFLOW_SHA": "1" * 40,
            "TRACEBOLT_REVIEWED_SOURCE_SHA256": "a" * 64, "RUNNER_TEMP": "/fake-temp"}


def public_provenance():
    return {"sourceSHA256": "a" * 64, "sourceFileCount": 10, "commit": "1" * 40, "tree": "2" * 40,
            "runner": "macos-15", "architecture": "arm64", "imageOS": "macos15-arm64",
            "imageVersion": "20261010.1.1", "productVersion": "15.7", "productBuild": "24G222",
            "darwinRelease": "24.6.0", "pythonVersion": "3.12.14", "goVersion": "go1.27.1",
            "hashes": {k: "d" * 64 for k in ("wrapper", "fixture", "helper", "python", "go", "compile", "link", "peer", "enroll", "sender")}}


def fake_result():
    return {"blocked": True, "stage1_passed": False, "custody_case_implemented": False,
            "endpoint_cases_passed": True, "children_reaped": True, "listeners_stopped": True,
            "owned_tree_removed": True, "custody_mismatch": False}


class GateTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("subprocess.Popen", "socket.socket", "pty.openpty", "termios.tcgetattr"):
            self.stack.enter_context(mock.patch(name, side_effect=AssertionError("native edge in fake test")))

    def test_default_is_inert_without_source_or_platform_inspection(self):
        with mock.patch.object(gate, "source_manifest", side_effect=AssertionError), mock.patch.object(gate, "execute", side_effect=AssertionError):
            out = io.StringIO()
            self.assertEqual(gate.main([], out), 2)
        self.assertEqual(json.loads(out.getvalue()), gate.closed_report())

    def test_invalid_invocation_cannot_echo_or_activate(self):
        out = io.StringIO()
        with mock.patch.object(gate, "source_manifest", side_effect=AssertionError):
            self.assertEqual(gate.main(["--execute", "private_marker"], out), 2)
        self.assertNotIn("private_marker", out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["reason"], "admission_refused")

    def test_source_check_never_loads_runtime(self):
        out = io.StringIO()
        with mock.patch.object(gate, "source_manifest", return_value=manifest()), mock.patch.object(gate, "reviewed_module", side_effect=AssertionError):
            self.assertEqual(gate.main(["--check"], out), 0)
        self.assertEqual(set(json.loads(out.getvalue())), {"schemaVersion", "inertCheck", "sourceSHA256", "sourceFileCount"})

    def test_exact_hosted_admission_for_both_standard_runners(self):
        for runner, (arch, goarch, _) in gate.RUNNERS.items():
            env = dict(environment(), TRACEBOLT_RUNNER_LABEL=runner, RUNNER_ARCH=arch)
            self.assertEqual(gate.admission(env, "darwin", manifest())["architecture"], goarch)

    def test_admission_rejects_every_missing_binding(self):
        for key in environment():
            if key == "RUNNER_TEMP":
                continue
            env = environment()
            env.pop(key)
            with self.subTest(key=key), self.assertRaises(gate.Refused):
                gate.admission(env, "darwin", manifest())

    def test_wrong_platform_replay_source_ref_and_runner_rejected(self):
        cases = [("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "push"),
                 ("GITHUB_EVENT_NAME", "pull_request"), ("TRACEBOLT_SELECT_ENDPOINT", "false"),
                 ("RUNNER_ENVIRONMENT", "self-hosted"), ("GITHUB_SHA", "2" * 40),
                 ("GITHUB_WORKFLOW_SHA", "2" * 40), ("TRACEBOLT_REVIEWED_SOURCE_SHA256", "b" * 64),
                 ("TRACEBOLT_RUNNER_LABEL", "macos-latest"), ("GITHUB_REPOSITORY", "other/repo")]
        for key, value in cases:
            with self.subTest(key=key), self.assertRaises(gate.Refused):
                gate.admission(dict(environment(), **{key: value}), "darwin", manifest())
        with self.assertRaises(gate.Refused):
            gate.admission(environment(), "linux", manifest())

    def test_dispatch_verification_never_builds_or_executes(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, environment(), clear=True), mock.patch.object(gate.sys, "platform", "darwin"), mock.patch.object(gate, "source_manifest", return_value=manifest()), mock.patch.object(gate, "execute", side_effect=AssertionError):
            self.assertEqual(gate.main(["--verify-dispatch"], out), 0)
        self.assertEqual(json.loads(out.getvalue())["reason"], "dispatch_verified")

    def test_closed_public_provenance(self):
        report = gate.closed_report()
        report["provenance"] = public_provenance()
        self.assertEqual(json.loads(gate.evidence(report)), report)
        for location in (report, report["provenance"], report["provenance"]["hashes"]):
            location["private_marker"] = "private_marker"
            with self.assertRaises(gate.Refused):
                gate.evidence(report)
            del location["private_marker"]

    def test_provenance_rejects_unbounded_values_and_wrong_arch(self):
        for field, value in (("productVersion", "private_marker"), ("imageVersion", "x" * 1000),
                             ("architecture", "amd64"), ("commit", "x" * 40),
                             ("pythonVersion", "3.12.14 private_marker"), ("sourceFileCount", True)):
            report = gate.closed_report()
            report["provenance"] = public_provenance()
            report["provenance"][field] = value
            with self.subTest(field=field), self.assertRaises(gate.Refused):
                gate.evidence(report)

    def test_full_stage_cannot_pass_and_subset_requires_cleanup(self):
        fixture = types.SimpleNamespace(result_json=lambda _: None)
        report = gate.closed_report("endpoint_subset_passed")
        report.update(provenance=public_provenance(), endpoint=fake_result())
        gate.evidence(report, fixture)
        for field in ("stage1_passed", "custody_case_implemented"):
            report["endpoint"][field] = True
            with self.assertRaises(gate.Refused):
                gate.evidence(report, fixture)
            report["endpoint"][field] = False
        for field in ("buildChildrenReaped", "runtimeChildrenReaped", "taskTreeRemoved"):
            report[field] = False
            with self.assertRaises(gate.Refused):
                gate.evidence(report, fixture)
            report[field] = True

    def test_invalid_final_evidence_is_fixed_failure_not_traceback(self):
        out = io.StringIO()
        with mock.patch.object(gate, "source_manifest", return_value=manifest()), mock.patch.object(gate, "admission", return_value={}), mock.patch.object(gate, "execute", return_value=({"private_marker": "secret"}, None)):
            self.assertEqual(gate.main(["--execute"], out), 2)
        self.assertEqual(json.loads(out.getvalue()), gate.uncertain_report("internal_failure"))

    def test_execute_escape_cannot_claim_cleanup(self):
        out = io.StringIO()
        with mock.patch.object(gate, "source_manifest", return_value=manifest()), mock.patch.object(gate, "admission", return_value={}), mock.patch.object(gate, "execute", side_effect=RuntimeError("private_marker")):
            self.assertEqual(gate.main(["--execute"], out), 2)
        self.assertEqual(json.loads(out.getvalue()), gate.uncertain_report("internal_failure"))

    def test_source_byte_loader_ignores_pyc_and_rejects_wrong_hash(self):
        raw = b'answer = 7\n'
        with mock.patch.object(gate, "stable_bytes", return_value=(raw, None)):
            module = gate.reviewed_module(gate.FIXTURE, hashlib.sha256(raw).hexdigest(), "inert_gate_module")
            self.assertEqual(module.answer, 7)
            with self.assertRaises(gate.Refused):
                gate.reviewed_module(gate.FIXTURE, "0" * 64, "inert_gate_module")

    def test_public_source_reads_reject_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "public.txt"
            path.write_text("public source")
            data, _ = gate.stable_bytes(path)
            self.assertEqual(data, b"public source")
            link = Path(temp) / "alias"
            link.symlink_to(path)
            with self.assertRaises(gate.Refused):
                gate.stable_bytes(link)
            link.unlink()
            os.link(path, link)
            with self.assertRaises(gate.Refused):
                gate.stable_bytes(path)

    def test_binary_custody_detects_same_bytes_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "bin").mkdir(mode=0o700)
            path = root / "bin/endpoint-peer"
            path.write_bytes(b"inert binary marker")
            path.chmod(0o700)
            info = root.stat()
            tree = types.SimpleNamespace(path=root, identity=(info.st_dev, info.st_ino), uid=os.getuid())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            record = gate.binary_custody(tree, path, digest)
            replacement = root / "bin/replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o700)
            replacement.replace(path)
            with self.assertRaises(gate.Refused):
                gate.binary_custody(tree, path, digest, record)

    def test_binary_custody_rejects_mutability_and_wrong_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "bin").mkdir(mode=0o700)
            path = root / "bin/endpoint-peer"
            path.write_bytes(b"inert binary marker")
            path.chmod(0o700)
            info = root.stat()
            tree = types.SimpleNamespace(path=root, identity=(info.st_dev, info.st_ino), uid=os.getuid())
            with self.assertRaises(gate.Refused):
                gate.binary_custody(tree, path, "0" * 64)
            path.chmod(0o722)
            with self.assertRaises(gate.Refused):
                gate.binary_custody(tree, path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_each_child_rechecks_identity_immediately(self):
        calls = []
        class FakeNative:
            def __init__(self, inputs):
                calls.append("construct")
            def _spawn(self, argv, terminal):
                calls.append("spawn")
                return "fake child"
        fixture = types.SimpleNamespace(NativeRuntime=FakeNative, FutureInputs=lambda *args: args)
        tree = types.SimpleNamespace(path=Path("/fake"))
        hashes = {key: "a" * 64 for key in gate.BINARIES}
        identities = {key: () for key in gate.BINARIES}
        with mock.patch.object(gate, "binary_custody", side_effect=lambda *args: calls.append("custody")):
            runtime = gate.endpoint_runtime(fixture, tree, hashes, identities, lambda value: calls.append(value))
            self.assertEqual(runtime._spawn(["/fake/bin/enroll-agent"], True), "fake child")
        self.assertEqual(calls, ["construct", "custody", True, "spawn", False])
        with self.assertRaises(gate.Refused):
            runtime._spawn(["/arbitrary"], False)

    def test_custody_failure_prevents_spawn(self):
        native = mock.Mock()
        class FakeNative:
            def __init__(self, inputs): pass
            _spawn = native
        fixture = types.SimpleNamespace(NativeRuntime=FakeNative, FutureInputs=lambda *args: args)
        values = {key: "a" * 64 for key in gate.BINARIES}
        runtime = gate.endpoint_runtime(fixture, types.SimpleNamespace(path=Path("/fake")), values, values, lambda _: None)
        with mock.patch.object(gate, "binary_custody", side_effect=gate.Refused("custody_failed")), self.assertRaises(gate.Refused):
            runtime._spawn(["/fake/bin/endpoint-peer"])
        native.assert_not_called()

    def test_runtime_cleanup_masks_all_supported_signals_without_child_spawn(self):
        events = []
        class FakeNative:
            def __init__(self, inputs): self.children = []
            def cleanup(self, preserve_tree=False):
                events.append(("cleanup", preserve_tree))
                return (True, True, True, False)
        fixture = types.SimpleNamespace(NativeRuntime=FakeNative, FutureInputs=lambda *args: args)
        values = {key: "a" * 64 for key in gate.BINARIES}
        runtime = gate.endpoint_runtime(fixture, types.SimpleNamespace(path=Path("/fake")), values, values, lambda _: None, lambda v: events.append(("defer", v)))
        def mask(how, value):
            events.append(("mask", how, value))
            return {gate.signal.SIGUSR1}
        with mock.patch.object(gate.signal, "pthread_sigmask", side_effect=mask):
            self.assertEqual(runtime.cleanup(), (True, True, True, False))
        self.assertEqual(events[0], ("defer", True))
        self.assertEqual(events[1][2], {gate.signal.SIGINT, gate.signal.SIGTERM, gate.signal.SIGALRM})
        self.assertEqual(events[2], ("cleanup", False))
        self.assertEqual(events[3][1], gate.signal.SIG_SETMASK)
        self.assertEqual(events[4], ("defer", False))

    def test_outer_reap_preserves_handles_after_cleanup_failure(self):
        child_a, child_b = mock.Mock(), mock.Mock()
        child_a.stop.return_value = True
        child_b.stop.side_effect = RuntimeError("private_marker")
        class FakeNative:
            def __init__(self, inputs): self.children = [child_a, child_b]
            def cleanup(self, preserve_tree=False): raise KeyboardInterrupt()
        fixture = types.SimpleNamespace(NativeRuntime=FakeNative, FutureInputs=lambda *args: args)
        values = {key: "a" * 64 for key in gate.BINARIES}
        runtime = gate.endpoint_runtime(fixture, types.SimpleNamespace(path=Path("/fake")), values, values, lambda _: None, lambda _: None)
        with mock.patch.object(gate.signal, "pthread_sigmask"), self.assertRaises(KeyboardInterrupt):
            runtime.cleanup()
        self.assertFalse(runtime.reap_owned_children())
        child_a.stop.assert_called_once()
        child_b.stop.assert_called_once()

    def execute_fake(self, result=None, construction_failure=False, cleanup_signal=None, reap_ok=True, exercise_throws=False):
        helper = mock.Mock()
        helper.Processes.return_value.stop.return_value = True
        tree = helper.TaskTree.return_value
        tree.remove.return_value = True
        fixture = types.SimpleNamespace(_exercise=mock.Mock(return_value=fake_result() if result is None else result))
        flags = types.SimpleNamespace(isolated=1, dont_write_bytecode=1, no_site=1)
        handlers = {}
        runtime_builder = gate.endpoint_runtime
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(gate, "reviewed_module", side_effect=[helper, fixture]))
            stack.enter_context(mock.patch.object(gate, "canonical", return_value=Path("/fake-temp")))
            stack.enter_context(mock.patch.object(Path, "resolve", return_value=Path("/fake-temp")))
            stack.enter_context(mock.patch.object(gate, "prepare", return_value=({}, {})))
            stack.enter_context(mock.patch.object(gate, "provenance", return_value=public_provenance()))
            stack.enter_context(mock.patch.object(gate, "source_manifest", return_value=manifest()))
            runtime = stack.enter_context(mock.patch.object(gate, "endpoint_runtime", side_effect=RuntimeError("private_marker") if construction_failure else None))
            stack.enter_context(mock.patch.object(gate.sys, "flags", flags))
            for name, value in (("getuid", 501), ("geteuid", 501), ("getgid", 20), ("getegid", 20)):
                stack.enter_context(mock.patch.object(gate.os, name, return_value=value))
            for name in ("getsignal", "setitimer", "pthread_sigmask"):
                stack.enter_context(mock.patch.object(gate.signal, name))
            stack.enter_context(mock.patch.object(gate.signal, "signal", side_effect=lambda sig, handler: handlers.update({sig: handler})))
            runtime.return_value.reap_owned_children.return_value = reap_ok
            if cleanup_signal is not None:
                def exercise(_):
                    teardown = runtime.call_args.args[-1]
                    class FakeNative:
                        def __init__(self, inputs): self.children = []
                        def cleanup(self, preserve_tree=False): return (True, True, True, False)
                    fake = types.SimpleNamespace(NativeRuntime=FakeNative, FutureInputs=lambda *args: args)
                    values = {key: "a" * 64 for key in gate.BINARIES}
                    owned = runtime_builder(fake, types.SimpleNamespace(path=Path("/fake")), values, values, lambda _: None, teardown)
                    def deliver_on_restore(how, value):
                        if how == gate.signal.SIG_SETMASK:
                            handlers[cleanup_signal](cleanup_signal, None)
                        return set()
                    with mock.patch.object(gate.signal, "pthread_sigmask", side_effect=deliver_on_restore):
                        self.assertEqual(owned.cleanup(), (True, True, True, False))
                    return fake_result()
                fixture._exercise.side_effect = exercise
            if exercise_throws:
                fixture._exercise.side_effect = KeyboardInterrupt()
            report, _ = gate.execute(gate.admission(environment(), "darwin", manifest()), manifest(), environment())
        return report, tree, fixture, runtime

    def test_fake_subset_success_stays_full_stage_blocked(self):
        report, tree, fixture, runtime = self.execute_fake()
        self.assertEqual(report["reason"], "endpoint_subset_passed")
        self.assertTrue(report["blocked"])
        self.assertFalse(report["stage1Passed"])
        tree.remove.assert_called_once()
        fixture._exercise.assert_called_once_with(runtime.return_value)

    def test_term_and_alarm_during_cleanup_are_deferred_then_reported(self):
        for sig in (gate.signal.SIGTERM, gate.signal.SIGALRM):
            report, tree, _, runtime = self.execute_fake(cleanup_signal=sig)
            self.assertEqual(report["reason"], "cancelled")
            self.assertFalse(report["endpoint"]["endpoint_cases_passed"])
            self.assertTrue(report["endpoint"]["supervisor_failure"])
            runtime.return_value.reap_owned_children.assert_called_once()
            tree.remove.assert_called_once()

    def test_outer_runtime_reap_failure_prevents_parent_deletion(self):
        report, tree, _, runtime = self.execute_fake(reap_ok=False)
        self.assertEqual(report["reason"], "cleanup_failed")
        self.assertFalse(report["runtimeChildrenReaped"])
        runtime.return_value.reap_owned_children.assert_called_once()
        tree.remove.assert_not_called()

    def test_exercise_escape_still_reaps_owned_runtime(self):
        report, tree, _, runtime = self.execute_fake(exercise_throws=True)
        self.assertEqual(report["reason"], "cleanup_failed")
        runtime.return_value.reap_owned_children.assert_called_once()
        tree.remove.assert_not_called()

    def test_uncertain_endpoint_custody_preserves_parent_tree(self):
        for field, value in (("children_reaped", False), ("listeners_stopped", False),
                             ("owned_tree_removed", False), ("custody_mismatch", True)):
            result = fake_result()
            result[field] = value
            report, tree, _, _ = self.execute_fake(result)
            self.assertEqual(report["reason"], "cleanup_failed")
            tree.remove.assert_not_called()

    def test_failed_native_construction_preserves_unknown_partial_tree(self):
        report, tree, fixture, _ = self.execute_fake(construction_failure=True)
        self.assertEqual(report["reason"], "cleanup_failed")
        self.assertNotIn("private_marker", json.dumps(report))
        tree.remove.assert_not_called()
        fixture._exercise.assert_not_called()

    def test_workflow_is_manual_default_off_no_artifact_or_other_gate(self):
        path = Path(__file__).resolve().parents[2] / gate.WORKFLOW
        value = path.read_text()
        self.assertIn("workflow_dispatch:", value)
        self.assertIn("default: false", value)
        for forbidden in ("pull_request:", "push:", "schedule:", "workflow_run:", "upload-artifact", "macosnativeacceptance/run.py", "gate_a", "gate_b", "gate_i"):
            self.assertNotIn(forbidden, value)
        self.assertEqual(value.count("run: python3 -I -S -B"), 2)
        self.assertIn("persist-credentials: false", value)
    def test_source_ci_is_ubuntu_pure_fake_and_exact_crossbuild_only(self):
        value = (Path(__file__).resolve().parents[2] / ".github/workflows/macos-endpoint-source.yml").read_text()
        self.assertIn("runs-on: ubuntu-24.04", value)
        self.assertEqual(value.count("paths:"), 2)
        for expected in ("go-version: '1.27.1'", "token: ''", "cache: false", "GOOS: darwin",
                         "for arch in arm64 amd64", "-trimpath -buildvcs=false -tags=tracebolt_endpoint_native",
                         "go test -p 1 -buildvcs=false ./tests/macosendpointfixture", "-p 'test_*.py'"):
            self.assertIn(expected, value)
        for forbidden in ("workflow_dispatch:", "--execute", "upload-artifact", "runs-on: macos", "native_main.go ", "npm", "playwright"):
            self.assertNotIn(forbidden, value)



if __name__ == "__main__":
    unittest.main()
