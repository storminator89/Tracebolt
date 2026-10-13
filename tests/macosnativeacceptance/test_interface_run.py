"""Gate I source/closed-schema tests. Every execution/build/provider edge is fake."""
import contextlib
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("interface_supervisor_tested", Path(__file__).with_name("run.py"))
r = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = r
SPEC.loader.exec_module(r)


def admitted_env(a=False, b=False, i=True):
    return dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY="storminator89/Tracebolt", GITHUB_SHA="a" * 40, GITHUB_WORKFLOW_SHA="a" * 40, GITHUB_RUN_ATTEMPT="1", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="macOS", RUNNER_ARCH="ARM64", TRACEBOLT_RUNNER_LABEL="macos-15", TRACEBOLT_REPOSITORY_VISIBILITY="public", TRACEBOLT_REVIEWED_COMMIT="a" * 40, TRACEBOLT_REVIEWED_SOURCE_SHA256="b" * 64, TRACEBOLT_SELECT_GATE_A=str(a).lower(), TRACEBOLT_SELECT_GATE_B=str(b).lower(), TRACEBOLT_SELECT_GATE_I=str(i).lower())


def manifest_fixture():
    return dict(sha256="b" * 64, fileCount=len(r.SOURCE_PUBLIC), bytes=1000, files={name: "c" * 64 for name in r.SOURCE_PUBLIC})


def family_fixture(index=0, outcome="succeeded", parser="none", validation="passed"):
    attempted = outcome != "not_run"
    parsed = outcome == "succeeded"
    return dict(id=("interfaces_ipv4_ifconfig_v1", "interfaces_ipv6_ifconfig_v1")[index], commandCalls=int(attempted), commandOutcome=outcome, parserCalls=int(parsed), parserCode=parser if parsed else "not_run", validation=validation if parsed and parser == "none" else "not_run", passed=parsed and parser == "none" and validation == "passed", stdoutBytes=None, stderrBytes=None, elapsedMilliseconds=None, exitCode=None, childStarted=None, childReaped=None)


def interface_fixture(first=None, second=None, reason=None):
    families = [family_fixture(0) if first is None else first, family_fixture(1) if second is None else second]
    passed = all(row["passed"] for row in families)
    return dict(schemaVersion="tracebolt.macos-native-interface-diagnostics.v1", gate="I", mode="native", status="passed" if passed else "failed", reason=("none" if passed else "interface_outcome") if reason is None else reason, commandMetricsAvailable=False, limits=dict(commandMilliseconds=1000, pipeWaitMilliseconds=200, maxOutputBytes=262144, maxInterfaces=128, maxAddressesPerInterface=16, reportMaxBytes=16384), families=families)


def process_fixture(data=b"", exit_code=0, reason=None):
    return dict(reason=("ok" if exit_code == 0 else "nonzero_exit") if reason is None else reason, started=True, reaped=True, exitCode=exit_code, stdoutBytes=len(data), stderrBytes=0, elapsedMilliseconds=1)


class InterfaceAdmissionTests(unittest.TestCase):
    def test_all_boolean_combinations_and_a_i_exclusion(self):
        for a, b, i in itertools.product((False, True), repeat=3):
            with self.subTest(a=a, b=b, i=i):
                if not (a or b or i) or (a and i):
                    with self.assertRaises(r.Refused):
                        r.hosted_admission(admitted_env(a, b, i), "darwin", manifest_fixture())
                else:
                    result = r.hosted_admission(admitted_env(a, b, i), "darwin", manifest_fixture())
                    self.assertEqual((result["gateASelected"], result["gateBSelected"], result["gateISelected"]), (a, b, i))

    def test_interface_selector_is_explicit_and_all_guards_are_reused(self):
        for key in admitted_env():
            for bad_value in (None, "unexpected"):
                env = admitted_env()
                if bad_value is None:
                    del env[key]
                else:
                    env[key] = bad_value
                with self.subTest(key=key, bad_value=bad_value), self.assertRaises(r.Refused):
                    r.hosted_admission(env, "darwin", manifest_fixture())
        with self.assertRaises(r.Refused):
            r.hosted_admission(admitted_env(), "linux", manifest_fixture())

    def test_workflow_i_defaults_false_and_only_a_or_i_uses_go(self):
        source = (Path(__file__).parents[2] / ".github/workflows/macos-native-acceptance.yml").read_text()
        self.assertIn("      gate_i:\n", source)
        self.assertEqual(source.count("default: false"), 3)
        self.assertIn("!(inputs.gate_a && inputs.gate_i)", source)
        self.assertIn("inputs.gate_a || inputs.gate_b || inputs.gate_i", source)
        self.assertIn("      - if: ${{ inputs.gate_a || inputs.gate_i }}\n        uses: actions/setup-go@", source)
        self.assertIn("TRACEBOLT_SELECT_GATE_I: ${{ inputs.gate_i }}", source)

    def test_all_new_probe_sources_are_required_hashed_and_change_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in r.SOURCE_PUBLIC | {"internal/fixture.go"}:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("public source fixture\n")
            original = r.source_manifest(root)
            for name in r.INTERFACE_PROBE_FILES:
                path = root / "tests/macosnativeacceptance/interfaceprobe" / name
                original_bytes = path.read_bytes()
                path.write_bytes(original_bytes + b"changed\n")
                self.assertNotEqual(r.source_manifest(root)["sha256"], original["sha256"])
                self.assertNotEqual(r.source_manifest(root)["files"][path.relative_to(root).as_posix()], original["files"][path.relative_to(root).as_posix()])
                path.unlink()
                with self.assertRaises(r.Refused):
                    r.source_manifest(root)
                path.write_bytes(original_bytes)
            self.assertEqual(r.source_manifest(root), original)


class InterfaceProjectionTests(unittest.TestCase):
    def test_success_failure_parser_codes_and_finite_outcomes(self):
        self.assertTrue(r.valid_interface_diagnostics(interface_fixture()))
        for code in r.INTERFACE_PARSER_CODES - {"none"}:
            for index in (0, 1):
                rows = [family_fixture(0), family_fixture(1)]
                rows[index] = family_fixture(index, parser=code)
                self.assertTrue(r.valid_interface_diagnostics(interface_fixture(*rows)), code)
        for outcome in ("access_denied", "source_unavailable", "unsupported_platform", "bounds_exceeded", "budget_exhausted", "command_panic"):
            self.assertTrue(r.valid_interface_diagnostics(interface_fixture(family_fixture(outcome=outcome))))
        self.assertTrue(r.valid_interface_diagnostics(interface_fixture(family_fixture(validation="failed"))))

    def test_invalid_input_and_cancellation_have_explicit_unattempted_states(self):
        unattempted = [family_fixture(i, outcome="not_run") for i in (0, 1)]
        for reason in ("invalid_input", "budget_exhausted"):
            self.assertTrue(r.valid_interface_diagnostics(interface_fixture(*unattempted, reason=reason)))
        self.assertTrue(r.valid_interface_diagnostics(interface_fixture(second=unattempted[1], reason="budget_exhausted")))
        self.assertFalse(r.valid_interface_diagnostics(interface_fixture(*unattempted)))
        self.assertFalse(r.valid_interface_diagnostics(interface_fixture(second=unattempted[1], reason="invalid_input")))
        cancelled = interface_fixture(reason="budget_exhausted")
        self.assertFalse(r.valid_interface_diagnostics(cancelled))
        cancelled["status"] = "failed"
        self.assertTrue(r.valid_interface_diagnostics(cancelled))

    def test_unknown_native_content_counts_hashes_and_fake_metrics_are_rejected(self):
        for mutation in (
            lambda v: v.update(raw="PRIVATE_NATIVE_VALUE"),
            lambda v: v.update(mode="inert_fixture"),
            lambda v: v.update(gate="A"),
            lambda v: v.update(schemaVersion="tracebolt.macos-native-interface-diagnostics.v2"),
            lambda v: v.update(reason="PRIVATE_ERROR"),
            lambda v: v.update(commandMetricsAvailable=True),
            lambda v: v.update(commandMetricsAvailable=0),
            lambda v: v["families"][0].update(name="PRIVATE_INTERFACE"),
            lambda v: v["families"][0].update(address="192.0.2.17"),
            lambda v: v["families"][0].update(rows=1),
            lambda v: v["families"][0].update(addresses=1),
            lambda v: v["families"][0].update(sourceSHA256="a" * 64),
            lambda v: v["families"][0].update(parserCode="PRIVATE_NATIVE_LINE"),
            lambda v: v["families"].reverse(),
            lambda v: v["families"].append(copy.deepcopy(v["families"][0])),
            lambda v: v["limits"].update(commandMilliseconds=True),
            lambda v: v["limits"].update(reportMaxBytes=65536),
            lambda v: v["limits"].update(maxRows=128),
        ):
            value = interface_fixture()
            mutation(value)
            self.assertFalse(r.valid_interface_diagnostics(value))
        for name in ("stdoutBytes", "stderrBytes", "elapsedMilliseconds", "exitCode", "childStarted", "childReaped"):
            for measured in (0, False, 1, "PRIVATE_VALUE"):
                value = interface_fixture()
                value["families"][0][name] = measured
                self.assertFalse(r.valid_interface_diagnostics(value), name)

    def test_inconsistent_and_noninteger_attempts_or_outcomes_are_rejected(self):
        changes = [dict(commandCalls=v) for v in (-1, 2, True, 1.0, None)]
        changes += [dict(parserCalls=v) for v in (-1, 2, True, 1.0, None)]
        changes += [dict(commandCalls=0), dict(commandOutcome="not_run"), dict(commandOutcome="access_denied"), dict(commandOutcome="raw_error"), dict(parserCalls=0), dict(parserCode="not_run"), dict(validation="not_run"), dict(passed=False), dict(passed=1)]
        for change in changes:
            value = interface_fixture()
            value["families"][0].update(change)
            self.assertFalse(r.valid_interface_diagnostics(value), change)
        for field, entries in (("status", ("failed", "blocked")), ("reason", ("interface_outcome", "invalid_input", "budget_exhausted"))):
            for entry in entries:
                value = interface_fixture()
                value[field] = entry
                self.assertFalse(r.valid_interface_diagnostics(value))
        failed = interface_fixture(family_fixture(outcome="source_unavailable"))
        for change in (dict(parserCalls=1), dict(parserCode="none"), dict(validation="failed"), dict(passed=True)):
            value = copy.deepcopy(failed)
            value["families"][0].update(change)
            self.assertFalse(r.valid_interface_diagnostics(value), change)

    def test_all_schema_keys_are_required_and_arbitrary_json_types_fail_closed(self):
        for key in interface_fixture():
            value = interface_fixture()
            del value[key]
            self.assertFalse(r.valid_interface_diagnostics(value), key)
        for key in family_fixture():
            value = interface_fixture()
            del value["families"][0][key]
            self.assertFalse(r.valid_interface_diagnostics(value), key)
        for value in (None, True, 0, "PRIVATE_VALUE", [], {}):
            self.assertFalse(r.valid_interface_diagnostics(value))
        for key in ("commandOutcome", "parserCode", "validation"):
            for bad in ([], {}, None, True):
                value = interface_fixture()
                value["families"][0][key] = bad
                self.assertFalse(r.valid_interface_diagnostics(value))

    def test_outer_schema_is_v2_and_projection_requires_matching_process(self):
        manifest = manifest_fixture()
        context = r.hosted_admission(admitted_env(), "darwin", manifest)
        report = r.report_template(context, manifest)
        self.assertTrue(r.validate_report(report))
        self.assertEqual(report["schemaVersion"], 2)
        self.assertEqual(report["scope"], "macos-native-evidence-v2")
        report["interfaceDiagnostics"] = interface_fixture()
        self.assertFalse(r.validate_report(report))
        report["interfaceProcess"] = process_fixture()
        self.assertTrue(r.validate_report(report))
        for update in (dict(exitCode=1), dict(stderrBytes=1), dict(reason="timeout"), dict(reaped=False), dict(stdoutBytes=16386)):
            value = copy.deepcopy(report)
            value["interfaceProcess"].update(update)
            self.assertFalse(r.validate_report(value), update)
        value = copy.deepcopy(report)
        value["context"].update(gateISelected=False, gateASelected=True)
        self.assertFalse(r.validate_report(value))
        value = copy.deepcopy(report)
        value["context"]["gateASelected"] = True
        self.assertFalse(r.validate_report(value))


class InterfacePreparationTests(unittest.TestCase):
    def test_only_selected_probe_builds_and_interface_tag_is_fixed(self):
        for a, i in ((True, False), (False, True)):
            calls = []
            owner = types.SimpleNamespace(capture=lambda argv, **kwargs: calls.append((argv, copy.deepcopy(kwargs))) or r.Capture(b"", process_fixture()))
            tree = types.SimpleNamespace(path=Path("/fixture/task"))
            context = r.hosted_admission(admitted_env(a=a, i=i), "darwin", manifest_fixture())
            with mock.patch.object(r, "selected_go", return_value=(Path("/fixture/go"), Path("/fixture/go/bin/go"))), mock.patch.object(r, "require_capture", return_value="go version go1.27.1 darwin/arm64"), mock.patch.object(r, "bounded_hash", return_value=("a" * 64, 1)), mock.patch.object(r.subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")):
                metadata = r.prepare(owner, tree, context, {})
            self.assertEqual(len(calls), 3)
            self.assertEqual([list(argv[1:]) for argv, _ in calls[:2]], [["mod", "download"], ["mod", "verify"]])
            argv, kwargs = calls[2]
            probe = "interface" if i else "inventory"
            expected = ("/fixture/go/bin/go", "build", "-trimpath", "-buildvcs=false") + (("-tags=tracebolt_interface_diagnostics",) if i else ()) + ("-o", "/fixture/task/bin/" + probe + "-probe", "./tests/macosnativeacceptance/" + probe + "probe")
            self.assertEqual(argv, expected)
            self.assertEqual(kwargs["env"]["GOPROXY"], "off")
            self.assertEqual(kwargs["env"]["GOSUMDB"], "off")
            self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")
            self.assertEqual(kwargs["env"]["CGO_ENABLED"], "0")
            self.assertEqual(metadata[probe + "SHA256"], "a" * 64)
            self.assertIsNone(metadata[("inventory" if i else "interface") + "SHA256"])

    def test_interface_binary_custody_uses_same_closed_task_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = r.TaskTree(root, root.stat().st_uid).create()
            binary = tree.path / "bin/interface-probe"
            binary.write_bytes(b"inert public file; never executable code")
            binary.chmod(0o700)
            digest = r.bounded_hash(binary)[0]
            r.verify_binary_custody(tree, "interface-probe", digest)
            binary.write_bytes(b"changed public fixture")
            with self.assertRaises(r.Refused):
                r.verify_binary_custody(tree, "interface-probe", digest)
            binary.unlink()
            binary.symlink_to(root / "absent")
            with self.assertRaises(OSError):
                r.verify_binary_custody(tree, "interface-probe", digest)
            self.assertTrue(tree.remove())

    def test_b_only_does_not_resolve_go_or_build_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clang, sdk = root / "clang", root / "sdk"
            clang.write_text("public fixture compiler")
            sdk.mkdir()
            calls = []
            owner = types.SimpleNamespace(capture=lambda argv, **kwargs: calls.append(argv) or r.Capture(b"", process_fixture()))
            context = r.hosted_admission(admitted_env(b=True, i=False), "darwin", manifest_fixture())
            with mock.patch.object(r, "selected_go", side_effect=AssertionError("Go forbidden")), mock.patch.object(r, "require_capture", side_effect=[str(clang), str(sdk), "Apple clang version 17.0.0", "15.5"]), mock.patch.object(r, "bounded_hash", return_value=("a" * 64, 1)), mock.patch.object(r.subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")):
                metadata = r.prepare(owner, types.SimpleNamespace(path=root), context, {})
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], str(clang))
            self.assertIsNone(metadata["goVersion"])
            self.assertIsNone(metadata["interfaceSHA256"])
            self.assertIsNone(metadata["inventorySHA256"])


class InterfaceInjectedExecuteTests(unittest.TestCase):
    def run_injected(self, payload=None, *, both=False, process_updates=None, raw=None, source_failure=False, custody_failure=False, cancel=False, cleanup_ok=True):
        payload = interface_fixture() if payload is None else payload
        manifest = manifest_fixture()
        env = dict(admitted_env(b=both), RUNNER_TEMP="/fixture/temp", HOME="/fixture/runner", ImageOS="macos15-arm64", ImageVersion="20261013.1.1", PRIVATE_CREDENTIAL="must_not_inherit")
        context = r.hosted_admission(env, "darwin", manifest)
        tree = types.SimpleNamespace(path=Path("/fixture/task"), create=mock.Mock(), remove=mock.Mock(return_value=cleanup_ok))
        owner = r.Processes()
        commands = []
        def capture(argv, **kwargs):
            commands.append((argv, kwargs))
            if argv[0].endswith("interface-probe") and cancel:
                raise r.NativeDeadline()
            owner.started += 1
            owner.reaped += 1
            if argv[0].endswith("interface-probe"):
                data = json.dumps(payload).encode() if raw is None else raw
                meta = process_fixture(data, 0 if payload.get("status") == "passed" else 1)
                meta.update(process_updates or {})
                return r.Capture(data, meta)
            outputs = {tuple(spec[0]): {"productVersion": "15.7.9", "productBuild": "24G830", "darwinRelease": "24.6.0", "machine": "arm64"}[key] for key, spec in r.VERSION_COMMANDS.items()}
            data = outputs[tuple(argv)].encode()
            return r.Capture(data, process_fixture(data))
        owner.capture = capture
        build = dict(goVersion="go1.27.1", goSHA256="c" * 64, inventorySHA256=None, interfaceSHA256="d" * 64, emitterSHA256="e" * 64 if both else None, clangSHA256="f" * 64 if both else None, clangVersion="17.0.0" if both else None, sdkVersion="15.5" if both else None, sdkSettingsSHA256="f" * 64 if both else None)
        log_result = dict(status="passed", emitter=dict(started=True, reaped=True), queries=[dict(started=True, reaped=True) for _ in range(3)])
        log_module = types.SimpleNamespace(configure_admission=mock.Mock(return_value=contextlib.nullcontext()), run_log_gate=mock.Mock(return_value=log_result), validate_result=lambda v: v == log_result)
        identity = dict(uid=501, euid=501, gid=20, egid=20, groups=[20], adminMembership=None, adminMembershipReason="not_queried")
        with contextlib.ExitStack() as stack:
            for name, options in (
                ("Processes", dict(return_value=owner)), ("TaskTree", dict(return_value=tree)),
                ("source_identity", dict(return_value="c" * 40)), ("prepare", dict(return_value=build)),
                ("verify_source_unchanged", dict(side_effect=r.Refused("source_mismatch") if source_failure else None)),
                ("verify_binary_custody", dict(side_effect=r.Refused("source_mismatch") if custody_failure else None)),
                ("current_identity", dict(return_value=(identity, "/fixture/passwd"))),
                ("bounded_hash", dict(return_value=("d" * 64, 1))), ("installed_manual_hash", dict(return_value=r.MANUAL_SHA256)),
                ("logrc_absent", dict(return_value=True)), ("load_log_probe", dict(return_value=log_module)),
            ):
                stack.enter_context(mock.patch.object(r, name, **options))
            for name in ("signal", "setitimer", "getsignal", "pthread_sigmask"):
                stack.enter_context(mock.patch.object(r.signal, name, return_value=set() if name == "pthread_sigmask" else None))
            stack.enter_context(mock.patch.object(r.os, "getuid", return_value=501))
            forbidden = stack.enter_context(mock.patch.object(r.subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")))
            report, module = r.execute(context, manifest, env)
            forbidden.assert_not_called()
        return report, log_module, commands, tree

    def test_i_only_calls_fixed_binary_env_and_args_with_outer_bounds(self):
        report, log, commands, tree = self.run_injected()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(r.validate_report(report))
        self.assertEqual(len(commands), 5)
        argv, kwargs = commands[-1]
        self.assertEqual(argv, ("/fixture/task/bin/interface-probe", "--native-interfaces-once"))
        self.assertEqual((kwargs["seconds"], kwargs["stdout_limit"], kwargs["stderr_limit"]), (12, 16384, 1024))
        self.assertTrue(kwargs["allow_failed_projection"])
        env = kwargs["env"]
        self.assertEqual(env["TRACEBOLT_NATIVE_GATE_I"], "enabled")
        self.assertEqual(env["GITHUB_RUN_ATTEMPT"], "1")
        self.assertEqual([env[k] for k in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "TRACEBOLT_REVIEWED_COMMIT")], ["a" * 40] * 3)
        self.assertEqual(env["TRACEBOLT_REVIEWED_SOURCE_SHA256"], "b" * 64)
        self.assertNotIn("TRACEBOLT_NATIVE_GATE_A", env)
        self.assertNotIn("PRIVATE_CREDENTIAL", env)
        self.assertIsNone(report["inventory"])
        log.run_log_gate.assert_not_called()
        tree.remove.assert_called_once()

    def test_failed_i_preserves_successful_sibling_and_independent_b(self):
        payload = interface_fixture(family_fixture(parser="address_numeric"))
        report, log, _, tree = self.run_injected(payload, both=True)
        self.assertEqual((report["status"], report["reason"]), ("failed", "probe_failed"))
        self.assertEqual(report["interfaceDiagnostics"], payload)
        self.assertEqual(report["interfaceProcess"]["exitCode"], 1)
        self.assertTrue(report["interfaceDiagnostics"]["families"][1]["passed"])
        self.assertEqual(report["syntheticLog"]["status"], "passed")
        self.assertTrue(r.validate_report(report, log))
        log.run_log_gate.assert_called_once()
        tree.remove.assert_called_once()

    def test_bad_output_or_outer_failure_is_discarded_b_still_runs_and_cleanup_finishes(self):
        cases = [dict(raw=raw) for raw in (b'{"status":"passed","status":"failed"}', b'{"x":NaN}', b'{}{}', b'[]', b'"PRIVATE_CONTENT"', b'\xff', b'[' * 2000 + b']' * 2000, b' ' * 16385)]
        cases += [dict(process_updates=update) for update in (dict(exitCode=1), dict(exitCode=2), dict(stderrBytes=1), dict(reason="timeout"), dict(reason="output_limit"), dict(reason="nonzero_exit"), dict(stdoutBytes=0), dict(reaped=False))]
        value = interface_fixture()
        value["families"][0]["raw"] = "PRIVATE_NATIVE_VALUE"
        cases.append(dict(payload=value))
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                report, log, _, tree = self.run_injected(both=True, **kwargs)
                self.assertEqual(report["status"], "failed")
                self.assertIsNone(report["interfaceDiagnostics"])
                self.assertEqual(report["syntheticLog"]["status"], "passed")
                self.assertNotIn("PRIVATE_NATIVE_VALUE", json.dumps(report))
                self.assertNotIn("PRIVATE_CONTENT", json.dumps(report))
                log.run_log_gate.assert_called_once()
                tree.remove.assert_called_once()

    def test_late_cancellation_preserves_both_completed_families_and_runs_b(self):
        payload = interface_fixture(reason="budget_exhausted")
        payload["status"] = "failed"
        report, log, _, tree = self.run_injected(payload, both=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["interfaceDiagnostics"], payload)
        self.assertTrue(all(row["passed"] for row in report["interfaceDiagnostics"]["families"]))
        self.assertTrue(r.validate_report(report, log))
        log.run_log_gate.assert_called_once()
        tree.remove.assert_called_once()

    def test_success_requires_interface_and_go_provenance_and_no_full_inventory_build(self):
        report, _, _, _ = self.run_injected()
        for key, value in (("interfaceSHA256", None), ("goSHA256", None), ("goVersion", None), ("inventorySHA256", "a" * 64)):
            malformed = copy.deepcopy(report)
            malformed["build"][key] = value
            self.assertFalse(r.validate_report(malformed), key)

    def test_source_and_custody_fail_closed_before_interface_or_log_calls(self):
        for key in ("source_failure", "custody_failure"):
            report, log, commands, tree = self.run_injected(both=True, **{key: True})
            self.assertEqual(report["reason"], "source_mismatch")
            self.assertFalse(any(argv[0].endswith("interface-probe") for argv, _ in commands))
            log.run_log_gate.assert_not_called()
            tree.remove.assert_called_once()

    def test_native_deadline_and_cleanup_failure_cannot_be_passes(self):
        report, log, _, tree = self.run_injected(both=True, cancel=True)
        self.assertEqual((report["status"], report["reason"]), ("failed", "native_deadline"))
        log.run_log_gate.assert_not_called()
        tree.remove.assert_called_once()
        self.assertTrue(r.validate_report(report, log))
        report, _, _, _ = self.run_injected(cleanup_ok=False)
        self.assertEqual((report["status"], report["reason"]), ("failed", "cleanup_failed"))
        self.assertTrue(r.validate_report(report))


if __name__ == "__main__":
    unittest.main()
