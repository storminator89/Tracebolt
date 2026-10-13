"""Inert source, fixture-file and Python fake-child tests. Never run providers."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import marshal
import struct
import os
from pathlib import Path
import signal
import sys
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("native_supervisor_tested", Path(__file__).with_name("run.py"))
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)


def source_fixture(root):
    files = set(r.SOURCE_PUBLIC) | {"internal/sample/fixture.go"}
    for name in files:
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("fixture public source\n")
    return r.source_manifest(root)


def admitted_env(digest="b" * 64, gate_a="true", gate_b="false", gate_i="false"):
    return dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY="storminator89/Tracebolt", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="macOS", RUNNER_ARCH="ARM64", TRACEBOLT_RUNNER_LABEL="macos-15", TRACEBOLT_REPOSITORY_VISIBILITY="public", GITHUB_RUN_ATTEMPT="1", TRACEBOLT_REVIEWED_COMMIT="a" * 40, GITHUB_SHA="a" * 40, GITHUB_WORKFLOW_SHA="a" * 40, TRACEBOLT_REVIEWED_SOURCE_SHA256=digest, TRACEBOLT_SELECT_GATE_A=gate_a, TRACEBOLT_SELECT_GATE_B=gate_b, TRACEBOLT_SELECT_GATE_I=gate_i)


def inventory_fixture(passed=True):
    ids = ("hardware_sysctl_v1", "receipts_pkgutil_v1", "processes_ps_ucomm_v1", "interfaces_ipv4_ifconfig_v1", "interfaces_ipv6_ifconfig_v1")
    rows = []
    for i, name in enumerate(ids):
        row = dict(id=name, availability="observed" if passed else "unavailable", reason="none" if passed else "source_unavailable", parserPassed=passed, validationPassed=True, passed=passed, rows=1 if passed else None, addresses=1 if passed and i >= 3 else None, maxOutputBytes=4096 if i == 0 else 262144, maxRows=(1, 2048, 4096, 128, 128)[i], maxAddressesPerRow=16 if i >= 3 else 0, stdoutBytes=None, stderrBytes=None, elapsedMilliseconds=None, exitCode=None, childStarted=None, childReaped=None)
        rows.append(row)
    return dict(schemaVersion="tracebolt.macos-native-inventory-evidence.v1", gate="A", mode="native", status="passed" if passed else "failed", reason="none" if passed else "provider_outcome", collector="macosinventory.CollectNative", snapshotSchema="tracebolt.macos-read-inventory.v1", collectionCalls=1, collectionReturned=True, collectionElapsedMilliseconds=1, snapshotValidated=True, snapshotRoundTripValidated=True, snapshotBytes=100, sourcesObserved=5 if passed else 0, commandMetricsAvailable=False, limits=dict(commandMilliseconds=1000, pipeWaitMilliseconds=200, providerMilliseconds=2000, collectionMilliseconds=8000, snapshotMaxBytes=524288, reportMaxBytes=65536), sources=rows)


class SourceTests(unittest.TestCase):
    def test_import_and_default_check_never_launch_or_inspect_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = source_fixture(Path(directory))
            with mock.patch.object(r, "source_manifest", return_value=manifest), mock.patch.object(r.subprocess, "Popen", side_effect=AssertionError("process forbidden")), mock.patch.object(r, "current_identity", side_effect=AssertionError("identity forbidden")), mock.patch.object(r, "prepare", side_effect=AssertionError("build forbidden")), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(r.main([]), 0)
                self.assertEqual(r.main(["--check"]), 0)
            self.assertNotIn("fixture public source", out.getvalue())
            self.assertIn(manifest["sha256"], out.getvalue())

    def test_source_digest_tracks_content_modes_and_embedded_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = source_fixture(root)
            (root / "internal/sample/data.txt").write_text("embedded fixture")
            second = r.source_manifest(root)
            self.assertNotEqual(first["sha256"], second["sha256"])
            p = root / "internal/sample/fixture.go"
            p.chmod(0o755)
            self.assertNotEqual(second["sha256"], r.source_manifest(root)["sha256"])

    def test_source_rejects_symlink_file_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_fixture(root)
            p = root / "internal/sample/fixture.go"
            p.unlink()
            p.symlink_to(root / "go.mod")
            with self.assertRaises(r.Refused):
                r.source_manifest(root)
            p.unlink()
            (root / "internal/alias").symlink_to(root / "tests", target_is_directory=True)
            with self.assertRaises(r.Refused):
                r.source_manifest(root)

    def test_source_rejects_missing_required_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_fixture(root)
            (root / "tests/macosnativeacceptance/emitter.c").unlink()
            with self.assertRaises(r.Refused):
                r.source_manifest(root)

    def test_source_hash_refuses_oversize_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "fixture"
            p.write_bytes(b"1234")
            with self.assertRaises(r.Refused):
                r.bounded_hash(p, maximum=3)
            alias = p.with_name("alias")
            alias.symlink_to(p)
            with self.assertRaises(OSError):
                r.bounded_hash(alias)

    def test_workflow_is_manual_default_false_fixed_and_read_only(self):
        text = (Path(__file__).parents[2] / ".github/workflows/macos-native-acceptance.yml").read_text()
        self.assertIn("  workflow_dispatch:", text)
        self.assertNotIn("  push:", text)
        self.assertNotIn("  pull_request:", text)
        self.assertEqual(text.count("default: false"), 3)
        self.assertIn("runner: [macos-15, macos-15-intel]", text)
        self.assertIn("contents: read", text)
        self.assertNotIn("id-token:", text)
        self.assertNotIn("secrets.", text)
        self.assertIn("token: ''", text)
        self.assertIn("GO_DOWNLOAD_BASE_URL: ''", text)
        self.assertNotIn("go-download-base-url:", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("timeout-minutes: 20", text)
        self.assertIn("github.run_attempt == 1", text)
        self.assertEqual(text.count("uses: actions/"), 3)

    def test_source_ast_syntax_only(self):
        ast.parse(Path(r.__file__).read_text())


class AdmissionTests(unittest.TestCase):
    def test_each_gate_can_be_selected_independently(self):
        for a, b in (("true", "false"), ("false", "true"), ("true", "true")):
            ctx = r.hosted_admission(admitted_env(gate_a=a, gate_b=b), "darwin", {"sha256": "b" * 64})
            self.assertEqual(ctx["gateASelected"], a == "true")
            self.assertEqual(ctx["gateBSelected"], b == "true")

    def test_all_guards_fail_closed(self):
        env = admitted_env()
        for key in env:
            bad = dict(env)
            bad[key] = "unexpected"
            with self.subTest(key=key), self.assertRaises(r.Refused):
                r.hosted_admission(bad, "darwin", {"sha256": "b" * 64})
        for platform in ("linux", "win32", ""):
            with self.assertRaises(r.Refused):
                r.hosted_admission(env, platform, {"sha256": "b" * 64})
        with self.assertRaises(r.Refused):
            r.hosted_admission(admitted_env(gate_a="false", gate_b="false"), "darwin", {"sha256": "b" * 64})

    def test_intel_pairing(self):
        env = admitted_env()
        env.update(TRACEBOLT_RUNNER_LABEL="macos-15-intel", RUNNER_ARCH="X64")
        self.assertEqual(r.hosted_admission(env, "darwin", {"sha256": "b" * 64})["runnerArch"], "X64")
        env["RUNNER_ARCH"] = "ARM64"
        with self.assertRaises(r.Refused):
            r.hosted_admission(env, "darwin", {"sha256": "b" * 64})

    def test_verify_dispatch_never_looks_up_identity_or_starts_process(self):
        with mock.patch.object(r, "source_manifest", return_value={"sha256": "b" * 64}), mock.patch.dict(r.os.environ, admitted_env(), clear=True), mock.patch.object(r.sys, "platform", "darwin"), mock.patch.object(r.subprocess, "Popen", side_effect=AssertionError("forbidden")), mock.patch.object(r, "current_identity", side_effect=AssertionError("forbidden")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(r.main(["--verify-dispatch"]), 0)

    def test_invalid_cli_does_not_echo_input(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(r.main(["--unknown", "PRIVATE_INPUT"]), 2)
        self.assertNotIn("PRIVATE_INPUT", out.getvalue())


class ProjectionTests(unittest.TestCase):
    def test_pass_and_failed_inventory_are_valid(self):
        self.assertTrue(r.valid_inventory(inventory_fixture()))
        self.assertTrue(r.valid_inventory(inventory_fixture(False)))

    def test_empty_interface_is_rejected_but_empty_receipts_can_pass(self):
        value = inventory_fixture()
        value["sources"][1]["rows"] = 0
        self.assertTrue(r.valid_inventory(value))
        value["sources"][3]["rows"] = 0
        value["sources"][3]["addresses"] = 0
        self.assertFalse(r.valid_inventory(value))

    def test_unknown_fields_native_values_and_fake_metrics_rejected(self):
        for mutation in (
            lambda x: x.update(hostname="PRIVATE_HOST"),
            lambda x: x["sources"][0].update(stdoutBytes=0),
            lambda x: x["sources"][0].update(childReaped=True),
            lambda x: x["sources"][0].update(id="PRIVATE_LABEL"),
            lambda x: x["sources"][0].update(reason="PRIVATE_ERROR"),
            lambda x: x.update(commandMetricsAvailable=True),
            lambda x: x.update(collectionCalls=True),
            lambda x: x.update(mode="inert_fixture"),
            lambda x: x.update(sourcesObserved=4),
        ):
            value = inventory_fixture()
            mutation(value)
            self.assertFalse(r.valid_inventory(value))

    def test_duplicate_json_nonfinite_extra_document_rejected(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{}{}', b'"' + b'x' * r.REPORT_LIMIT + b'"'):
            with self.assertRaises(ValueError):
                r.strict_json(data)

    def report_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = source_fixture(Path(directory))
        return r.report_template(r.hosted_admission(admitted_env(manifest["sha256"]), "darwin", manifest), manifest)

    def test_report_schema_rejects_unknown_output(self):
        report = self.report_fixture()
        self.assertTrue(r.validate_report(report))
        for mutation in (
            lambda x: x.update(hostname="PRIVATE_HOST"),
            lambda x: x.update(reason="PRIVATE_ERROR"),
            lambda x: x.update(sourceTree="PRIVATE_TREE"),
            lambda x: x.update(imageOS="PRIVATE_IMAGE"),
            lambda x: x["source"]["files"].update({"PRIVATE_PATH": "a" * 64}),
            lambda x: x["cleanup"].update(hostLogsErased=True),
            lambda x: x.update(nativeReleaseAccepted=True),
            lambda x: x.update(status="passed", reason="ok"),
        ):
            value = copy.deepcopy(report)
            mutation(value)
            self.assertFalse(r.validate_report(value))

    def test_no_write_when_schema_rejected(self):
        with mock.patch.object(r.os, "open", side_effect=AssertionError("write forbidden")), self.assertRaises(r.Refused):
            r.write_report({"raw": "PRIVATE_CONTENT"})

    def test_fixed_report_destination_no_overwrite(self):
        report = self.report_fixture()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(r, "ROOT", Path(directory)), mock.patch.object(r.os, "getuid", return_value=Path(directory).stat().st_uid):
            r.write_report(report)
            output = Path(directory) / "artifacts/review/macos-native-acceptance.json"
            self.assertLessEqual(output.stat().st_size, 65536)
            self.assertEqual(json.loads(output.read_bytes()), report)
            with self.assertRaises(FileExistsError):
                r.write_report(report)


class FixtureFilesystemTests(unittest.TestCase):
    def test_three_home_absence_and_presence_without_read(self):
        with tempfile.TemporaryDirectory() as directory:
            homes = []
            for i in range(3):
                p = Path(directory) / str(i)
                p.mkdir()
                homes.append(str(p))
            self.assertTrue(r.logrc_absent(homes))
            for home in homes:
                p = Path(home) / ".logrc"
                p.write_text("PRIVATE_CONFIG")
                with mock.patch("builtins.open", side_effect=AssertionError("no file content read")):
                    self.assertFalse(r.logrc_absent(homes))
                p.unlink()
            p = Path(homes[0]) / ".logrc"
            p.symlink_to(Path(directory) / "missing")
            self.assertFalse(r.logrc_absent(homes))
            self.assertFalse(r.logrc_absent(homes[:2]))
            self.assertFalse(r.logrc_absent(["relative", *homes[1:]]))

    def test_logrc_permission_error_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(r.os, "lstat", side_effect=PermissionError("PRIVATE_PATH")):
            self.assertFalse(r.logrc_absent([directory] * 3))

    def test_task_cleanup_is_owned_no_follow_and_records_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            # Fixture-file owner metadata, not a current-account query.
            root = Path(directory)
            uid = root.stat().st_uid
            task = r.TaskTree(root, uid).create()
            outside = root / "outside"
            outside.write_text("fixture retained")
            (task.path / "home/link").symlink_to(outside)
            nested = task.path / "modules/readonly"
            nested.mkdir()
            (nested / "file").write_text("fixture")
            nested.chmod(0o500)
            self.assertTrue(r.TaskTree.remove(task))
            self.assertFalse(task.path.exists())
            self.assertEqual(outside.read_text(), "fixture retained")

    def test_cleanup_rejects_replaced_root_or_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = r.TaskTree(root, root.stat().st_uid).create()
            original = task.path.with_name("saved")
            task.path.rename(original)
            task.path.mkdir()
            self.assertFalse(task.remove())
            task.path.rmdir()
            original.rename(task.path)
            task.uid += 1
            self.assertFalse(task.remove())

    def test_identity_projection_is_mocked_and_never_names_user(self):
        with mock.patch.object(r.os, "getuid", return_value=501), mock.patch.object(r.os, "geteuid", return_value=501), mock.patch.object(r.os, "getgid", return_value=20), mock.patch.object(r.os, "getegid", return_value=20), mock.patch.object(r.os, "getgroups", return_value=[20, 10]), mock.patch("pwd.getpwuid", return_value=types.SimpleNamespace(pw_dir="/fixture/home", pw_name="PRIVATE_USER")):
            result, home = r.current_identity()
        self.assertEqual(home, "/fixture/home")
        self.assertNotIn("PRIVATE_USER", json.dumps(result))
        self.assertNotIn("home", json.dumps(result))
        self.assertIsNone(result["adminMembership"])
        self.assertEqual(result["groups"], [10, 20])

    def test_identity_limit_and_root_refused_without_native_lookup(self):
        for uid, groups in ((0, []), (501, list(range(65)))):
            with mock.patch.object(r.os, "getuid", return_value=uid), mock.patch.object(r.os, "geteuid", return_value=uid), mock.patch.object(r.os, "getgid", return_value=20), mock.patch.object(r.os, "getegid", return_value=20), mock.patch.object(r.os, "getgroups", return_value=groups), mock.patch("pwd.getpwuid", return_value=types.SimpleNamespace(pw_dir="/fixture/home")), self.assertRaises(r.Refused):
                r.current_identity()


class PythonFakeChildTests(unittest.TestCase):
    """Only an inert Python child; no macOS commands, Go, compiler or identities."""
    def capture(self, code, **kwargs):
        supervisor = r.Processes()
        with tempfile.TemporaryDirectory() as directory:
            result = supervisor.capture((sys.executable, "-I", "-c", code), env=dict(r.BASE_ENV), cwd=directory, seconds=kwargs.pop("seconds", 2), stdout_limit=kwargs.pop("stdout_limit", 64), stderr_limit=kwargs.pop("stderr_limit", 64), **kwargs)
        self.assertTrue(result.metadata["reaped"])
        self.assertEqual(supervisor.started, supervisor.reaped)
        self.assertTrue(supervisor.stop())
        return result

    def test_normal_capture(self):
        result = self.capture("print('fixture')")
        self.assertEqual(result.data, b"fixture\n")
        self.assertEqual(result.metadata["reason"], "ok")

    def test_stderr_discard_and_count(self):
        result = self.capture("import sys; print('fixture'); sys.stderr.write('synthetic-private')")
        self.assertEqual(result.data, b"")
        self.assertEqual(result.metadata["stderrBytes"], 17)
        self.assertEqual(result.metadata["reason"], "stderr_output")
        self.assertNotIn("synthetic-private", json.dumps(result.metadata))

    def test_only_preparation_can_allow_counted_stderr(self):
        result = self.capture("import sys; sys.stderr.write('synthetic-progress')", retain=False, allow_stderr=True)
        self.assertEqual(result.data, b"")
        self.assertEqual(result.metadata["reason"], "ok")
        self.assertGreater(result.metadata["stderrBytes"], 0)

    def test_stdout_and_stderr_limits_kill_and_reap(self):
        for stream in ("stdout", "stderr"):
            result = self.capture("import sys; sys." + stream + ".write('x'*10000); sys." + stream + ".flush()", stdout_limit=16, stderr_limit=16)
            self.assertEqual(result.data, b"")
            self.assertEqual(result.metadata["reason"], "output_limit")
            self.assertEqual(result.metadata[stream + "Bytes"], 17)

    def test_deadline_kills_and_reaps(self):
        result = self.capture("import time; time.sleep(30)", seconds=0.05)
        self.assertEqual(result.data, b"")
        self.assertEqual(result.metadata["reason"], "timeout")

    def test_nonzero_failure_projection_is_explicit_and_exit_one_only(self):
        for allow in (False, True):
            result = self.capture("import sys; print('{}'); sys.exit(1)", allow_failed_projection=allow)
            self.assertEqual(result.data, b"{}\n" if allow else b"")
            self.assertEqual(result.metadata["reason"], "nonzero_exit")
        result = self.capture("import sys; print('{}'); sys.exit(2)", allow_failed_projection=True)
        self.assertEqual(result.data, b"")

    def test_spawn_failure_sanitized(self):
        with mock.patch.object(r.subprocess, "Popen", side_effect=OSError("PRIVATE_PATH")):
            result = r.Processes().capture(("fixture",), env={}, cwd="/", seconds=1, stdout_limit=4, stderr_limit=4)
        self.assertEqual(result.metadata["reason"], "spawn_failed")
        self.assertNotIn("PRIVATE_PATH", str(result))
        self.assertFalse(result.metadata["started"])

    def test_native_deadline_exception_still_reaps_owned_fake_child(self):
        supervisor = r.Processes()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(r.selectors, "DefaultSelector", side_effect=r.NativeDeadline):
            with self.assertRaises(r.NativeDeadline):
                supervisor.capture((sys.executable, "-I", "-c", "import time; time.sleep(30)"), env=dict(r.BASE_ENV), cwd=directory, seconds=1, stdout_limit=4, stderr_limit=4)
        self.assertEqual(supervisor.started, 1)
        self.assertEqual(supervisor.reaped, 1)
        self.assertTrue(supervisor.stop())


class CorrectedBoundaryTests(unittest.TestCase):
    def test_selected_go_uses_pinned_path_not_stale_or_missing_goroot(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "toolcache"
            binary = cache / "go/1.27.1/arm64/bin/go"
            binary.parent.mkdir(parents=True)
            binary.write_text("inert executable fixture, never run")
            binary.chmod(0o700)
            ambient = {"RUNNER_TOOL_CACHE": str(cache), "PATH": str(binary.parent)}
            for goroot in (None, "/fixture/wrong"):
                if goroot:
                    ambient["GOROOT"] = goroot
                actual = r.selected_go(ambient, {"runnerArch": "ARM64"})
                self.assertEqual(actual, (binary.parent.parent, binary))
            shadow = Path(directory) / "shadow/go"
            shadow.parent.mkdir()
            shadow.write_text("wrong")
            shadow.chmod(0o700)
            ambient["PATH"] = str(shadow.parent) + os.pathsep + str(binary.parent)
            with self.assertRaises(r.Refused):
                r.selected_go(ambient, {"runnerArch": "ARM64"})

    def test_selected_go_rejects_symlink_and_wrong_arch(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "toolcache"
            binary = cache / "go/1.27.1/arm64/bin/go"
            binary.parent.mkdir(parents=True)
            outside = Path(directory) / "outside"
            outside.write_text("inert")
            outside.chmod(0o700)
            binary.symlink_to(outside)
            with self.assertRaises(r.Refused):
                r.selected_go({"RUNNER_TOOL_CACHE": str(cache), "PATH": str(binary.parent)}, {"runnerArch": "ARM64"})

    def test_partial_task_creation_remains_tracked_and_cleanable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = r.TaskTree(root, root.stat().st_uid)
            self.assertIsNone(task.path)
            with mock.patch.object(r.Path, "mkdir", side_effect=r.Cancelled):
                with self.assertRaises(r.Cancelled):
                    task.create()
            self.assertIsNotNone(task.path)
            self.assertTrue(task.path.exists())
            self.assertTrue(task.remove())
            self.assertFalse(task.path.exists())

    def test_binary_hash_and_custody_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = r.TaskTree(root, root.stat().st_uid).create()
            binary = task.path / "bin/inventory-probe"
            binary.write_bytes(b"inert binary fixture")
            binary.chmod(0o700)
            digest = r.bounded_hash(binary)[0]
            r.verify_binary_custody(task, "inventory-probe", digest)
            binary.write_bytes(b"changed")
            with self.assertRaises(r.Refused):
                r.verify_binary_custody(task, "inventory-probe", digest)
            binary.unlink()
            binary.symlink_to(root / "outside")
            with self.assertRaises(OSError):
                r.verify_binary_custody(task, "inventory-probe", digest)
            binary.unlink()
            binary.write_bytes(b"inert binary fixture")
            binary.chmod(0o777)
            with self.assertRaises(r.Refused):
                r.verify_binary_custody(task, "inventory-probe", digest)
            self.assertTrue(task.remove())

    def test_source_revalidated_after_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = source_fixture(root)
            with mock.patch.object(r, "ROOT", root):
                r.verify_source_unchanged(manifest)
                (root / "go.mod").write_text("changed")
                with self.assertRaises(r.Refused):
                    r.verify_source_unchanged(manifest)

    def test_report_parent_symlink_cannot_create_outside_directory(self):
        report = ProjectionTests().report_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            (root / "artifacts").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(r, "ROOT", root), self.assertRaises(OSError):
                r.write_report(report)
            self.assertFalse((outside / "review").exists())

    def test_ready_marker_is_static_and_not_written_after_refused_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runner_output"
            output.touch()
            with mock.patch.dict(r.os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True), mock.patch.object(r.os, "getuid", return_value=output.stat().st_uid):
                r.mark_report_ready()
            self.assertEqual(output.read_bytes(), b"report_ready=true\n")
        with mock.patch.object(r, "source_manifest", return_value={"sha256": "b" * 64}), mock.patch.dict(r.os.environ, admitted_env(), clear=True), mock.patch.object(r.sys, "platform", "darwin"), mock.patch.object(r, "execute", return_value=({}, None)), mock.patch.object(r, "write_report", side_effect=FileExistsError), mock.patch.object(r, "mark_report_ready") as ready:
            with self.assertRaises(FileExistsError):
                r.main(["--execute"])
            ready.assert_not_called()
        workflow = (Path(__file__).parents[2] / ".github/workflows/macos-native-acceptance.yml").read_text()
        self.assertIn("steps.native.outputs.report_ready == 'true'", workflow)

    def test_delayed_select_eof_cannot_pass_deadline(self):
        real_factory = r.selectors.DefaultSelector
        class DelayedSelector:
            def __init__(self):
                self.inner = real_factory()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.inner.close()
            def register(self, *args):
                return self.inner.register(*args)
            def unregister(self, *args):
                return self.inner.unregister(*args)
            def get_map(self):
                return self.inner.get_map()
            def select(self, timeout):
                r.time.sleep(0.08)
                return self.inner.select(0)
        with mock.patch.object(r.selectors, "DefaultSelector", DelayedSelector):
            result = PythonFakeChildTests().capture("pass", seconds=0.02)
        self.assertEqual(result.metadata["reason"], "timeout")
        self.assertEqual(result.data, b"")

    def test_cancellation_between_spawn_and_registration_is_deferred_and_reaped(self):
        owner = r.Processes()
        real_popen = r.subprocess.Popen
        def spawn_and_cancel(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            owner.interrupt(r.NativeDeadline())
            return child
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(r.subprocess, "Popen", side_effect=spawn_and_cancel):
            with self.assertRaises(r.NativeDeadline):
                owner.capture((sys.executable, "-I", "-c", "import time; time.sleep(30)"), env=dict(r.BASE_ENV), cwd=directory, seconds=1, stdout_limit=4, stderr_limit=4)
        self.assertEqual(owner.started, 1)
        self.assertEqual(owner.reaped, 1)
        self.assertTrue(owner.stop())
        self.assertFalse(owner.registering)
        self.assertIsNone(owner.pending)

    def test_reviewed_source_loader_never_reads_matching_bytecode_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "tests/macosnativeacceptance/log_probe.py"
            source.parent.mkdir(parents=True)
            source.write_text("ORIGIN = 'reviewed source'\n")
            info = source.stat()
            cache = Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir()
            # A valid timestamp/size header that ordinary source loading may trust.
            code = compile("ORIGIN = 'unreviewed cache'", str(source), "exec")
            cache.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(info.st_mtime), info.st_size) + marshal.dumps(code))
            expected = r.hashlib.sha256(source.read_bytes()).hexdigest()
            with mock.patch.object(r, "ROOT", root):
                module = r.load_log_probe(expected)
                self.assertEqual(module.ORIGIN, "reviewed source")
                with self.assertRaises(r.Refused):
                    r.load_log_probe("f" * 64)

    def test_stop_never_signals_reaped_pid_and_reap_accounting_is_idempotent(self):
        owner = r.Processes()
        process = mock.Mock(returncode=0, pid=123456)
        process.wait.return_value = 0
        owner.started = 1
        owner.active.add(process)
        with mock.patch.object(r.os, "killpg") as kill:
            self.assertTrue(owner.stop())
            self.assertEqual(owner.reaped, 1)
            # Simulate an interrupted discard or duplicate cleanup attempt.
            owner.active.add(process)
            self.assertTrue(owner.stop())
            self.assertEqual(owner.reaped, 1)
            kill.assert_not_called()

    def test_elapsed_observations_are_exact_or_null_never_saturated(self):
        for now, expected in ((135.0, 135000), (1199.0, 1199000), (1201.0, None), (-1.0, None)):
            with mock.patch.object(r.time, "monotonic", return_value=now):
                self.assertEqual(r.elapsed_milliseconds(0), expected)
        report = ProjectionTests().report_fixture()
        report["nativeElapsedMilliseconds"] = 135000
        self.assertTrue(r.validate_report(report))
        report["nativeElapsedMilliseconds"] = None
        self.assertTrue(r.validate_report(report))
        report["nativeElapsedMilliseconds"] = 1200001
        self.assertFalse(r.validate_report(report))

    def test_manual_guard_fixed_path_custody_hash_and_caps_with_fake_descriptors(self):
        data = b'.Dt LOG 1\n.Sh NAME\nlog\n.Sh SYNOPSIS\nfixture\n'
        def run_guard(*, bad_owner=False, bad_mode=False, oversize=False):
            next_fd = iter(range(10, 16))
            def info(fd):
                return types.SimpleNamespace(st_mode=(0o100644 if fd == 15 else 0o040755) | (0o020 if bad_mode else 0), st_uid=1 if bad_owner else 0, st_size=131073 if oversize else len(data), st_dev=1, st_ino=fd, st_mtime_ns=1, st_ctime_ns=1)
            with mock.patch.object(r.os, "open", side_effect=lambda *a, **k: next(next_fd)) as opened, mock.patch.object(r.os, "fstat", side_effect=info), mock.patch.object(r.os, "read", side_effect=[data, b""]), mock.patch.object(r.os, "close") as closed:
                result = r.installed_manual_hash()
                self.assertEqual([c.args[0] for c in opened.call_args_list], ["/", "usr", "share", "man", "man1", "log.1"])
                self.assertEqual(closed.call_count, 6)
                return result
        self.assertEqual(run_guard(), r.hashlib.sha256(data).hexdigest())
        for kwargs in ({"bad_owner": True}, {"bad_mode": True}, {"oversize": True}):
            with self.assertRaises(r.Refused):
                run_guard(**kwargs)

class InjectedExecuteTests(unittest.TestCase):
    """Top-level control flow with every host/build/provider edge injected."""
    def run_injected(self, inventory_passed=True, both=False, unreaped_log=False, changed_source=False, cleanup_cancel=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = source_fixture(root / "source")
            context = r.hosted_admission(admitted_env(manifest["sha256"], gate_b="true" if both else "false"), "darwin", manifest)
            ambient = dict(admitted_env(manifest["sha256"]), RUNNER_TEMP=str(root), HOME="/fixture/home", ImageOS="macos15-arm64", ImageVersion="20261013.1.1")
            owner = r.Processes()
            def fake_capture(argv, **kwargs):
                owner.started += 1
                owner.reaped += 1
                output = b""
                if argv[0].endswith("inventory-probe"):
                    output = json.dumps(inventory_fixture(inventory_passed)).encode()
                else:
                    fixed = {tuple(spec[0]): {"productVersion": "15.7.9", "productBuild": "24G830", "darwinRelease": "24.6.0", "machine": "arm64"}[key] for key, spec in r.VERSION_COMMANDS.items()}
                    output = fixed[tuple(argv)].encode()
                failed = argv[0].endswith("inventory-probe") and not inventory_passed
                return r.Capture(output, dict(reason="nonzero_exit" if failed else "ok", started=True, reaped=True, exitCode=1 if failed else 0, stdoutBytes=len(output), stderrBytes=0, elapsedMilliseconds=1))
            owner.capture = fake_capture
            build = dict(goVersion="go1.27.1", goSHA256="c" * 64, inventorySHA256="d" * 64, interfaceSHA256=None, emitterSHA256="e" * 64 if both else None, clangSHA256="f" * 64 if both else None, clangVersion="17.0.0" if both else None, sdkVersion="15.5" if both else None, sdkSettingsSHA256="f" * 64 if both else None)
            log_result = dict(status="failed" if unreaped_log else "passed", emitter=dict(started=True, reaped=not unreaped_log), queries=[dict(started=True, reaped=True)] * 3)
            log_module = types.SimpleNamespace(configure_admission=mock.Mock(return_value=contextlib.nullcontext()), run_log_gate=mock.Mock(return_value=log_result), validate_result=lambda _: True)
            identity = dict(uid=501, euid=501, gid=20, egid=20, groups=[20], adminMembership=None, adminMembershipReason="not_queried")
            real_mask = r.signal.pthread_sigmask
            cleanup_phase = False
            injected = False
            restored_handlers = []
            def mask_operation(how, mask):
                nonlocal cleanup_phase, injected
                if how == r.signal.SIG_BLOCK and mask == {r.signal.SIGTERM, r.signal.SIGINT, r.signal.SIGALRM}:
                    cleanup_phase = True
                    if cleanup_cancel in ("mask", "exhausted_mask") and (not injected or cleanup_cancel == "exhausted_mask"):
                        injected = True
                        raise r.Cancelled()
                if cleanup_phase and how == r.signal.SIG_SETMASK and cleanup_cancel == "restore_mask" and not injected:
                    injected = True
                    raise r.Cancelled()
                return real_mask(how, mask)
            def handler_operation(sig, handler):
                nonlocal injected
                if cleanup_phase:
                    if cleanup_cancel == "restore_handler" and not injected:
                        injected = True
                        raise r.Cancelled()
                    restored_handlers.append(sig)
            def timer_operation(which, seconds):
                nonlocal injected
                if cleanup_phase and seconds == 0 and cleanup_cancel == "disable_timer" and not injected:
                    injected = True
                    raise r.Cancelled()
            with mock.patch.object(r, "Processes", return_value=owner), mock.patch.object(r, "source_identity", return_value="c" * 40), mock.patch.object(r, "prepare", return_value=build), mock.patch.object(r, "verify_source_unchanged", side_effect=r.Refused("source_mismatch") if changed_source else None), mock.patch.object(r, "verify_binary_custody") as custody, mock.patch.object(r, "current_identity", return_value=(identity, "/fixture/passwd")) as identity_read, mock.patch.object(r.os, "getuid", return_value=root.stat().st_uid), mock.patch.object(r, "bounded_hash", return_value=("d" * 64, 1)), mock.patch.object(r, "installed_manual_hash", return_value=r.MANUAL_SHA256), mock.patch.object(r, "logrc_absent", return_value=True), mock.patch.object(r, "load_log_probe", return_value=log_module), mock.patch.object(r.signal, "signal", side_effect=handler_operation), mock.patch.object(r.signal, "setitimer", side_effect=timer_operation), mock.patch.object(r.signal, "pthread_sigmask", side_effect=mask_operation):
                report, module = r.execute(context, manifest, ambient)
            self.assertEqual(set(restored_handlers), {r.signal.SIGTERM, r.signal.SIGINT, r.signal.SIGALRM})
            return report, log_module, custody.call_count, identity_read.call_count

    def test_cleanup_transitions_survive_repeated_cancellation(self):
        for boundary in ("mask", "restore_handler", "restore_mask", "disable_timer", "exhausted_mask"):
            with self.subTest(boundary=boundary):
                report, _, _, _ = self.run_injected(cleanup_cancel=boundary)
                self.assertEqual(report["status"], "failed")
                self.assertIn(report["reason"], ("cancelled", "cleanup_failed"))
                self.assertTrue(report["cleanup"]["allDirectChildrenReaped"])
                self.assertTrue(report["cleanup"]["taskTreeRemoved"])

    def test_native_control_flow_is_fully_injected(self):
        report, _, custody, identity_reads = self.run_injected()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["cleanup"]["taskTreeRemoved"])
        self.assertTrue(r.validate_report(report))
        self.assertEqual(custody, 1)
        self.assertEqual(identity_reads, 1)

    def test_failed_a_projection_does_not_prevent_independent_selected_b(self):
        report, module, custody, _ = self.run_injected(inventory_passed=False, both=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["inventory"]["status"], "failed")
        self.assertEqual(report["syntheticLog"]["status"], "passed")
        self.assertEqual(module.run_log_gate.call_count, 1)
        self.assertEqual(custody, 2)
        self.assertTrue(report["cleanup"]["taskTreeRemoved"])

    def test_unreaped_log_child_retains_tree_and_fails_safety(self):
        report, _, _, _ = self.run_injected(both=True, unreaped_log=True)
        self.assertEqual(report["reason"], "cleanup_failed")
        self.assertFalse(report["cleanup"]["syntheticChildrenReaped"])
        self.assertFalse(report["cleanup"]["taskTreeRemoved"])

    def test_changed_source_stops_before_identity_and_native_edges(self):
        report, module, custody, identity_reads = self.run_injected(changed_source=True)
        self.assertEqual(report["reason"], "source_mismatch")
        self.assertEqual(custody, 0)
        self.assertEqual(identity_reads, 0)
        self.assertEqual(module.run_log_gate.call_count, 0)
        self.assertTrue(report["cleanup"]["taskTreeRemoved"])

if __name__ == "__main__":
    unittest.main()
