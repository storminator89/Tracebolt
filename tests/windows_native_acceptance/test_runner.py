"""Pure Python fixtures. Mock every subprocess; never run a native controller."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_acceptance as gate
import run_source_fixtures as fixtures

SOURCE = "a" * 40
PRIVATE = "private-output-sentinel::error::not-exportable"


def approved():
    return {
        "TRACEBOLT_COLLECTION_PROFILE":"basic-readonly-v1", "TRACEBOLT_TRANSPORT_PROFILE":"tls",
        "TRACEBOLT_APPROVE_INVENTORY_METADATA":"false", "TRACEBOLT_APPROVE_HTTP_PLAINTEXT":"false",
        "TRACEBOLT_EXPECTED_SOURCE_SHA": SOURCE, "GITHUB_SHA": SOURCE,
        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": gate.REPOSITORY, "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "GITHUB_RUN_ID": "123",
        **{name: "true" for name in gate.APPROVALS},
    }


def pass_report():
    return {
        "schema": gate.SCHEMA, "source": SOURCE, "status": "passed_native_subset",
        "stage": "owned_cleanup", "reason": "none", "approvalValidated": True,
        "nativeActionsAttempted": True,
        "selection":{"collectionProfile":"basic-readonly-v1","transport":"tls"},
        "inventory":{"frames":0,**{key:"not_run" for key in gate.QUALITIES}},
        "loopbackPeerExercised":True,"nativeInventorySenderExercised":False,
        "native": {"stage": "cleanup", "reason": "none",
                   **{key: True for key in gate.NATIVE_TRUE},
                   **{key: False for key in gate.NATIVE_FALSE}},
        "checks": [{"name": name, "status": "pass"} for name in gate.CHECK_NAMES],
        **{key: False for key in gate.COVERAGE_FALSE},
    }


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.platform = mock.patch.object(gate.sys, "platform", "win32")
        self.machine = mock.patch.object(gate.platform, "machine", return_value="AMD64")
        self.platform.start()
        self.machine.start()
        self.addCleanup(self.platform.stop)
        self.addCleanup(self.machine.stop)

    def test_valid_environment_is_pure(self):
        with mock.patch.object(gate.subprocess, "Popen") as spawn:
            self.assertEqual(gate.authorize(approved()), SOURCE)
            spawn.assert_not_called()

    def test_each_unapproved_or_invalid_input_spawns_nothing(self):
        invalid = []
        for name in gate.APPROVALS:
            for value in (None, "false", "True", "TRUE", "1", " true", "true\n", True, 1, PRIVATE):
                env = approved()
                if value is None:
                    del env[name]
                else:
                    env[name] = value
                invalid.append(env)
        for name, values in {
            "GITHUB_EVENT_NAME": ("push", "pull_request", "workflow_call", "schedule"),
            "GITHUB_ACTIONS": ("false", True), "GITHUB_REPOSITORY": ("foreign/Tracebolt", "storminator89/tracebolt"),
            "RUNNER_ENVIRONMENT": ("self-hosted", ""), "RUNNER_OS": ("Linux",),
            "RUNNER_ARCH": ("ARM64", "x64"), "GITHUB_RUN_ID": ("0", "000", "1\n", "-1", "1" * 25, 1),
            "TRACEBOLT_EXPECTED_SOURCE_SHA": ("b" * 40, "A" * 40, "a" * 39, SOURCE + "\n", PRIVATE, None),
            "GITHUB_SHA": ("b" * 40, None),
        }.items():
            for value in values:
                invalid.append(dict(approved(), **{name: value}))
        invalid.append({})
        for env in invalid:
            with self.subTest(env=env), mock.patch.object(gate.subprocess, "Popen") as spawn, mock.patch.object(gate, "command") as command:
                with self.assertRaises(gate.Rejected):
                    gate.run_native(env)
                command.assert_not_called()
                spawn.assert_not_called()

    def test_actual_platform_cannot_be_spoofed_by_workflow_environment(self):
        for host, arch in (("linux", "AMD64"), ("win32", "ARM64")):
            with mock.patch.object(gate.sys, "platform", host), mock.patch.object(gate.platform, "machine", return_value=arch), mock.patch.object(gate, "command") as command:
                with self.assertRaises(gate.Rejected):
                    gate.run_native(approved())
                command.assert_not_called()

    def test_default_and_unrecognized_cli_are_inert_and_redacted(self):
        for args in ([], ["--approve-services"], [PRIVATE], ["--run-native", PRIVATE]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(gate, "command") as command:
                self.assertEqual(gate.main(args, approved()), 1)
                command.assert_not_called()
            self.assertNotIn(PRIVATE, output.getvalue())

    def test_checkout_mismatch_or_dirty_state_fails_before_go(self):
        for results in ([b"b" * 40 + b"\n"], [SOURCE.encode() + b"\n", b"?? injected.go\n"]):
            with mock.patch.object(gate, "successful", side_effect=results) as run:
                with self.assertRaises(gate.Rejected):
                    gate.verify_checkout(approved(), SOURCE, gate.ROOT)
                for call in run.call_args_list:
                    self.assertEqual(call.args[0][0], "git")

    def test_native_go_architecture_is_required(self):
        value = {"GOHOSTOS": "windows", "GOHOSTARCH": "amd64", "GOOS": "windows", "GOARCH": "amd64"}
        with mock.patch.object(gate, "successful", return_value=encode(value)):
            gate.verify_go(approved(), gate.ROOT)
        for key in value:
            wrong = dict(value, **{key: "arm64"})
            with mock.patch.object(gate, "successful", return_value=encode(wrong)):
                with self.assertRaises(gate.Rejected):
                    gate.verify_go(approved(), gate.ROOT)

    def test_go_environment_cannot_inject_cross_build_or_flags(self):
        env = gate.child_environment(dict(approved(), GOOS="linux", GOARCH="arm64", GOFLAGS="-ldflags=other",
                                          GOTOOLCHAIN="auto", GOENV="other", GOWORK="other", GOEXPERIMENT="other"))
        for name in ("GOOS", "GOARCH", "GOFLAGS", "GOEXPERIMENT"):
            self.assertNotIn(name, env)
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOENV"], "off")
        self.assertEqual(env["GOWORK"], "off")


class ReportTests(unittest.TestCase):
    def reject(self, report):
        with self.assertRaises(gate.Rejected):
            gate.validate_report(encode(report), SOURCE)

    def test_pass_is_only_the_native_subset(self):
        report = pass_report()
        self.assertEqual(gate.validate_report(encode(report), SOURCE), report)
        self.assertEqual(gate.validate_report(gate.sanitized_bytes(report, SOURCE), SOURCE), report)

    def test_missing_extra_fields_and_wrong_types_at_every_level(self):
        for target in ("root", "native", "check"):
            original = pass_report()
            child = original if target == "root" else original["native"] if target == "native" else original["checks"][0]
            for key in tuple(child):
                report = copy.deepcopy(original)
                node = report if target == "root" else report["native"] if target == "native" else report["checks"][0]
                del node[key]
                self.reject(report)
            report = copy.deepcopy(original)
            node = report if target == "root" else report["native"] if target == "native" else report["checks"][0]
            node["privatePath"] = PRIVATE
            self.reject(report)
        for key in gate.COVERAGE_FALSE | {"approvalValidated", "nativeActionsAttempted"}:
            for value in (0, 1, "false", "true", None, [], {}):
                report = pass_report()
                report[key] = value
                self.reject(report)
        for key in gate.NATIVE_BOOLEANS:
            for value in (0, 1, "true", None):
                report = pass_report()
                report["native"][key] = value
                self.reject(report)
        for key in ("native", "checks", "status", "stage", "reason", "schema", "source"):
            for value in (None, True, 1, [], {}):
                report = pass_report()
                report[key] = value
                self.reject(report)

    def test_exact_source_finite_values_and_false_coverage(self):
        for key, value in (("source", "b" * 40), ("source", "A" * 40), ("status", "pass"),
                           ("status", "full_acceptance"), ("stage", PRIVATE), ("reason", PRIVATE), ("schema", PRIVATE)):
            report = pass_report()
            report[key] = value
            self.reject(report)
        for key in gate.COVERAGE_FALSE:
            report = pass_report()
            report[key] = True
            self.reject(report)
        for key in ("reason", "stage"):
            report = pass_report()
            report["native"][key] = PRIVATE
            self.reject(report)

    def test_every_required_proof_and_complete_terminal_state(self):
        for key in gate.NATIVE_BOOLEANS:
            report = pass_report()
            report["native"][key] = not report["native"][key]
            self.reject(report)
        for key, value in (("stage", "prerequisites"), ("reason", "operation-failed"), ("nativeActionsAttempted", False)):
            report = pass_report()
            report[key] = value
            self.reject(report)
        for key, value in (("stage", "stop"), ("reason", "operation-failed")):
            report = pass_report()
            report["native"][key] = value
            self.reject(report)

    def test_all_fourteen_checks_in_exact_order_are_required(self):
        for index in range(len(gate.CHECK_NAMES)):
            for status in ("fail", "blocked", "not_run", PRIVATE, True):
                report = pass_report()
                report["checks"][index]["status"] = status
                self.reject(report)
        for mutation in (lambda c: c.pop(), lambda c: c.append(c[0]), lambda c: c.reverse(), lambda c: c.__setitem__(1, c[0])):
            report = pass_report()
            mutation(report["checks"])
            self.reject(report)

    def test_failed_and_blocked_are_not_native_passes(self):
        for status in ("failed", "blocked"):
            report = pass_report()
            report.update(status=status, stage="prerequisites", reason="ancestor-prerequisite", nativeActionsAttempted=False, loopbackPeerExercised=False)
            report["native"] = {"stage": "preflight", "reason": "ancestor-prerequisite", **{key: False for key in gate.NATIVE_BOOLEANS}}
            report["checks"] = [{"name": name, "status": "blocked" if i == 0 else "not_run"} for i, name in enumerate(gate.CHECK_NAMES)]
            self.assertEqual(gate.validate_report(encode(report), SOURCE)["status"], status)
            with mock.patch.object(gate, "run_native", return_value=report), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(["--run-native"], approved()), 1)
            if status == "blocked":
                for key in ("provisioned", "installed", "prepared", "claim_committed"):
                    bad = copy.deepcopy(report)
                    bad["native"][key] = True
                    self.reject(bad)
                report["nativeActionsAttempted"] = True
                self.reject(report)

    def test_duplicate_keys_nonfinite_values_and_output_injection_rejected(self):
        raw = encode(pass_report())
        attacks = [b"", b"null", b"[]", b"\xef\xbb\xbf" + raw, b"\xff", raw + raw,
                   b"::error::" + raw, raw + b"\n" + PRIVATE.encode(),
                   raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
                   raw.replace(b'"stage":"cleanup"', b'"stage":"cleanup","stage":"cleanup"', 1),
                   raw.replace(b'"name":"prerequisites"', b'"name":"prerequisites","name":"prerequisites"', 1)]
        for literal in (b"NaN", b"Infinity", b"-Infinity", b"1e999"):
            attacks.append(raw.replace(b'"approvalValidated":true', b'"approvalValidated":' + literal))
        for value in attacks:
            with self.subTest(raw=value[:40]), self.assertRaises(gate.Rejected):
                gate.validate_report(value, SOURCE)

    def test_exact_32kib_bound_including_whitespace(self):
        raw = encode(pass_report())
        at_bound = raw + b" " * (gate.MAX_REPORT_BYTES - len(raw))
        gate.validate_report(at_bound, SOURCE)
        with self.assertRaises(gate.Rejected):
            gate.validate_report(at_bound + b" ", SOURCE)

    def test_schema_field_sets_and_enums_match_go_source(self):
        go_gate = (gate.ROOT / "internal/windowsacceptance/gate/gate.go").read_text()
        go_native = (gate.ROOT / "internal/windowsacceptance/native/driver.go").read_text()
        report_struct = go_gate.split("type Report struct {", 1)[1].split("\n}", 1)[0]
        native_struct = go_native.split("type Evidence struct {", 1)[1].split("\n}", 1)[0]
        self.assertEqual(set(re.findall(r'json:"([^"]+)"', report_struct)), gate.REPORT_FIELDS)
        self.assertEqual(set(re.findall(r'json:"([^"]+)"', native_struct)), gate.NATIVE_BOOLEANS | {"stage", "reason"})
        self.assertEqual(set(re.findall(r'Stage\w+\s+Stage\s*=\s*"([^"]+)"', go_native)), gate.STAGES)
        self.assertEqual(set(re.findall(r'Reason\w+\s+Reason\s*=\s*"([^"]+)"', go_native)), gate.REASONS)
        names = go_gate.split("var CheckNames = []string{", 1)[1].split("}", 1)[0]
        self.assertEqual(tuple(re.findall(r'"([^"]+)"', names)), gate.CHECK_NAMES)
        self.assertIn('const Schema = "' + gate.SCHEMA + '"', go_gate)
        self.assertIn("const MaxReportBytes = 32 << 10", go_gate)


class ExecutionTests(unittest.TestCase):
    def test_exact_argv_and_hashes_without_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            service = Path(directory) / "service with spaces.exe"
            controller = Path(directory) / "controller with spaces.exe"
            service.write_bytes(b"inert service fixture")
            controller.write_bytes(b"inert controller fixture")
            args = gate.controller_arguments(controller, service, SOURCE, gate.selection(approved()))
            self.assertEqual(args, [str(controller), "--expected-source=" + SOURCE,
                                   *[flag + "=true" for flag in gate.APPROVALS.values()],
                                   "--collection-profile=basic-readonly-v1", "--transport-profile=tls",
                                   "--approve-inventory-metadata=false", "--approve-http-plaintext=false",
                                   "--service-artifact=" + str(service),
                                   "--service-sha256=" + hashlib.sha256(service.read_bytes()).hexdigest(),
                                   "--controller-artifact=" + str(controller),
                                   "--controller-sha256=" + hashlib.sha256(controller.read_bytes()).hexdigest()])

    def fake_process(self, output, code=0):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stdout = io.BytesIO(output)
        process.wait.return_value = code
        return process

    def test_bounded_pipe_discards_stderr_and_never_uses_shell(self):
        process = self.fake_process(b"finite")
        with mock.patch.object(gate.subprocess, "Popen", return_value=process) as spawn:
            self.assertEqual(gate.command(["fixed.exe", "--fixed"], {}, gate.ROOT, 10), (0, b"finite"))
        self.assertIs(spawn.call_args.kwargs["shell"], False)
        self.assertEqual(spawn.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_oversized_output_is_drained_for_cleanup_and_rejected(self):
        process = self.fake_process(b"x" * (gate.MAX_REPORT_BYTES * 8))
        with mock.patch.object(gate.subprocess, "Popen", return_value=process), self.assertRaises(gate.Rejected):
            gate.command(["fixture.exe"], {}, gate.ROOT, gate.CONTROLLER_TIMEOUT_SECONDS)
        self.assertEqual(process.stdout.tell(), gate.MAX_REPORT_BYTES * 8)
        process.kill.assert_not_called()

    def test_timeout_does_not_export_captured_output_or_claim_cleanup(self):
        process = self.fake_process(PRIVATE.encode())
        process.wait.side_effect = [subprocess.TimeoutExpired(PRIVATE, 780), 1]
        with mock.patch.object(gate.subprocess, "Popen", return_value=process), self.assertRaises(gate.Rejected):
            gate.command(["fixture.exe"], {}, gate.ROOT, gate.CONTROLLER_TIMEOUT_SECONDS)
        process.kill.assert_called_once()

    def test_execution_error_is_finite_and_redacted(self):
        for error in (ValueError(PRIVATE), OSError(PRIVATE), subprocess.CalledProcessError(1, PRIVATE, output=PRIVATE, stderr=PRIVATE)):
            output = io.StringIO()
            with mock.patch.object(gate, "run_native", side_effect=error), contextlib.redirect_stdout(output):
                self.assertEqual(gate.main(["--run-native"], approved()), 1)
            self.assertNotIn(PRIVATE, output.getvalue())

    def test_pipeline_exports_only_reserialized_report_and_deletes_builds(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "output"
            output_file.touch()
            env = dict(approved(), RUNNER_TEMP=directory, GITHUB_OUTPUT=str(output_file))
            builds = []
            def fake_success(args, *_args, **_kwargs):
                if args[:2] == ["go", "build"]:
                    builds.append(args)
                    Path(args[args.index("-o") + 1]).write_bytes(b"not an executable")
                return b""
            raw = b"  " + encode(pass_report()) + b"\n\n"
            with mock.patch.object(gate, "authorize", return_value=SOURCE), mock.patch.object(gate, "verify_checkout") as checkout, mock.patch.object(gate, "verify_go"), mock.patch.object(gate, "successful", side_effect=fake_success), mock.patch.object(gate, "command", return_value=(0, raw)) as controller:
                self.assertEqual(gate.run_native(env)["status"], "passed_native_subset")
                self.assertEqual(checkout.call_count, 2)
            self.assertEqual(len(builds), 2)
            self.assertEqual(builds[1][builds[1].index("-ldflags") + 1], "-X main.compiledSource=" + SOURCE)
            self.assertEqual(controller.call_args.args[3], 13 * 60)
            self.assertEqual(output_file.read_text(), "report_validated=true\n")
            report_raw = (Path(directory) / gate.REPORT_NAME).read_bytes()
            self.assertEqual(report_raw, gate.sanitized_bytes(pass_report(), SOURCE))
            self.assertNotEqual(report_raw, raw)
            self.assertEqual({p.name for p in Path(directory).iterdir()}, {gate.REPORT_NAME, "output"})

    def test_pipeline_rejects_injection_and_false_success_without_artifact(self):
        variants = [(0, encode(pass_report()) + b"\n" + PRIVATE.encode()),
                    (1, encode(pass_report())),
                    (0, encode(dict(pass_report(), extra=PRIVATE))),
                    (0, b"x" * (gate.MAX_REPORT_BYTES + 1))]
        for code, raw in variants:
            with self.subTest(code=code, size=len(raw)), tempfile.TemporaryDirectory() as directory:
                output_file = Path(directory) / "output"
                output_file.touch()
                env = dict(approved(), RUNNER_TEMP=directory, GITHUB_OUTPUT=str(output_file))
                def fake_success(args, *_args, **_kwargs):
                    if args[:2] == ["go", "build"]:
                        Path(args[args.index("-o") + 1]).write_bytes(b"not an executable")
                    return b""
                output = io.StringIO()
                with mock.patch.object(gate, "authorize", return_value=SOURCE), mock.patch.object(gate, "verify_checkout"), mock.patch.object(gate, "verify_go"), mock.patch.object(gate, "successful", side_effect=fake_success), mock.patch.object(gate, "command", return_value=(code, raw)), contextlib.redirect_stdout(output):
                    self.assertEqual(gate.main(["--run-native"], env), 1)
                self.assertEqual(output_file.read_text(), "")
                self.assertEqual({p.name for p in Path(directory).iterdir()}, {"output"})
                self.assertNotIn(PRIVATE, output.getvalue())

    def test_failed_and_blocked_pipeline_retain_finite_report_but_fail_job(self):
        for status in ("failed", "blocked"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                output_file = Path(directory) / "output"
                output_file.touch()
                env = dict(approved(), RUNNER_TEMP=directory, GITHUB_OUTPUT=str(output_file))
                report = pass_report()
                report.update(status=status, stage="prerequisites", reason="ancestor-prerequisite", nativeActionsAttempted=False, loopbackPeerExercised=False)
                report["native"] = {"stage": "preflight", "reason": "ancestor-prerequisite", **{key: False for key in gate.NATIVE_BOOLEANS}}
                report["checks"] = [{"name": name, "status": "blocked" if i == 0 else "not_run"} for i, name in enumerate(gate.CHECK_NAMES)]
                def fake_success(args, *_args, **_kwargs):
                    if args[:2] == ["go", "build"]:
                        Path(args[args.index("-o") + 1]).write_bytes(b"not an executable")
                    return b""
                output = io.StringIO()
                with mock.patch.object(gate, "authorize", return_value=SOURCE), mock.patch.object(gate, "verify_checkout"), mock.patch.object(gate, "verify_go"), mock.patch.object(gate, "successful", side_effect=fake_success), mock.patch.object(gate, "command", return_value=(1, encode(report))), contextlib.redirect_stdout(output):
                    self.assertEqual(gate.main(["--run-native"], env), 1)
                self.assertEqual(output_file.read_text(), "report_validated=true\n")
                self.assertEqual((Path(directory) / gate.REPORT_NAME).read_bytes(), gate.sanitized_bytes(report, SOURCE))
                self.assertIn(status, output.getvalue())


class WorkflowTests(unittest.TestCase):
    def test_manual_only_default_off_exact_source_and_finite_artifact(self):
        workflow = (gate.ROOT / ".github/workflows/windows-native-acceptance.yml").read_text()
        trigger = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_]+):", trigger, re.M), ["workflow_dispatch"])
        self.assertEqual(re.findall(r"^      ([a-z_]+):", trigger, re.M),
                         ["expected_source_sha", "collection_profile", "transport_profile", "inventory_metadata", "http_plaintext", "services", "identity", "app_acls", "loopback_transport", "cleanup"])
        self.assertNotRegex(trigger, r"default:\s*true")
        for approval in ("inventory_metadata", "http_plaintext", "services", "identity", "app_acls", "loopback_transport", "cleanup"):
            block = re.split(r"\n      [a-z_]+:", trigger.split("      " + approval + ":\n", 1)[1], maxsplit=1)[0]
            for line in ("        default: false", "        required: true", "        type: boolean"):
                self.assertIn(line, block)
        source = trigger.split("      expected_source_sha:\n", 1)[1].split("\n      collection_profile:", 1)[0]
        self.assertIn("required: true", source)
        self.assertNotIn("default:", source)
        self.assertIn("runs-on: windows-2025", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertNotRegex(workflow, r"permissions:\s*write|contents:\s*write|id-token:")
        self.assertIn("github.repository == 'storminator89/Tracebolt'", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertLess(workflow.index("--check-authorization"), workflow.index("--run-native"))
        self.assertIn("path: ${{ runner.temp }}/" + gate.REPORT_NAME, workflow)
        self.assertIn("steps.native.outputs.report_validated == 'true'", workflow)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("cancel-in-progress: true", workflow)

    def test_inputs_are_only_environment_values_never_inline_commands(self):
        workflow = (gate.ROOT / ".github/workflows/windows-native-acceptance.yml").read_text()
        lines = workflow.splitlines()
        env_indent = None
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if env_indent is not None and indent <= env_indent:
                env_indent = None
            if line.strip() == "env:":
                env_indent = indent
            if "${{ inputs." in line:
                self.assertIsNotNone(env_indent)
            if "run:" in line:
                self.assertNotIn("${{", line)


class SourceFixtureTests(unittest.TestCase):
    def events(self):
        events = [{"Package": package, "Test": test, "Action": "pass"} for package, test in fixtures.REQUIRED]
        events.extend({"Package": "localrmm/" + package[2:], "Action": "pass"} for package in fixtures.PACKAGES)
        return events

    def test_source_checks_require_clock_and_shutdown_without_native_claim(self):
        events = self.events()
        fixtures.validate_events(b"\n".join(encode(event) for event in events))
        for missing in ("TestPendingOriginalDeadlineIsNeverExtended", "TestRuntimeShutdownDuringInitialization"):
            incomplete = [event for event in events if event.get("Test") != missing]
            with self.assertRaises(gate.Rejected):
                fixtures.validate_events(b"\n".join(encode(event) for event in incomplete))
        skipped = events + [{"Package": "localrmm/internal/windowsservice", "Test": "TestRuntimeShutdownDuringInitialization", "Action": "skip"}]
        with self.assertRaises(gate.Rejected):
            fixtures.validate_events(b"\n".join(encode(event) for event in skipped))



class ProfileScopeTests(unittest.TestCase):
    def test_only_finite_pairs_and_exact_additional_acknowledgements(self):
        for collection, transport in gate.VALID_SELECTIONS:
            env = dict(approved(), TRACEBOLT_COLLECTION_PROFILE=collection, TRACEBOLT_TRANSPORT_PROFILE=transport,
                       TRACEBOLT_APPROVE_INVENTORY_METADATA=str(collection == "windows-inventory-v1").lower(),
                       TRACEBOLT_APPROVE_HTTP_PLAINTEXT=str(transport == "http-test").lower())
            self.assertEqual(gate.selection(env), {"collectionProfile": collection, "transport": transport})
            for name in ("TRACEBOLT_APPROVE_INVENTORY_METADATA", "TRACEBOLT_APPROVE_HTTP_PLAINTEXT"):
                for value in (None, "TRUE", True, "false" if env[name] == "true" else "true"):
                    with self.subTest(selection=(collection, transport), field=name, value=value):
                        with self.assertRaises(gate.Rejected):
                            gate.selection(dict(env, **{name: value}))
        for collection, transport in (("basic-readonly-v1", "http-test"), ("managed-operations-v3", "tls"), ("windows-inventory-v1", "https"), (None, "tls")):
            with self.assertRaises(gate.Rejected):
                gate.selection(dict(approved(), TRACEBOLT_COLLECTION_PROFILE=collection, TRACEBOLT_TRANSPORT_PROFILE=transport))

    def test_late_failed_inventory_report_is_retained_after_successful_cleanup(self):
        for quality in ("denied", "unavailable"):
            report = pass_report()
            report["selection"] = {"collectionProfile": "windows-inventory-v1", "transport": "tls"}
            report["inventory"] = {"frames": 2, **{key: "healthy" for key in gate.QUALITIES}}
            report["inventory"]["services"] = quality
            report["nativeInventorySenderExercised"] = True
            report.update(status="failed", stage="profile_report", reason="operation-failed")
            for check in report["checks"]:
                if check["name"] == "profile_report": check["status"] = "fail"
            self.assertEqual(gate.validate_report(gate.sanitized_bytes(report, SOURCE), SOURCE), report)
            self.assertTrue(report["native"]["cleaned"])

    def test_inventory_report_requires_usable_scope_and_exact_dispatch_pair(self):
        report = pass_report()
        report["selection"] = {"collectionProfile": "windows-inventory-v1", "transport": "http-test"}
        report["inventory"] = {"frames": 2, **{key: "healthy" for key in gate.QUALITIES}}
        report["inventory"]["processes"] = "partial"
        report["nativeInventorySenderExercised"] = True
        self.assertEqual(gate.validate_report(encode(report), SOURCE, report["selection"]), report)
        with self.assertRaises(gate.Rejected):
            gate.validate_report(encode(report), SOURCE, {"collectionProfile": "windows-inventory-v1", "transport": "tls"})
        for key in gate.QUALITIES:
            for quality in ("denied", "unavailable"):
                bad = copy.deepcopy(report); bad["inventory"][key] = quality
                with self.assertRaises(gate.Rejected): gate.validate_report(encode(bad), SOURCE)
                bad["status"] = "failed"; bad["stage"] = "profile_report"
                self.assertEqual(gate.validate_report(encode(bad), SOURCE), bad)
        for quality in ("not_run", PRIVATE, None, 1):
            bad = copy.deepcopy(report); bad["inventory"]["cpu"] = quality
            with self.assertRaises(gate.Rejected): gate.validate_report(encode(bad), SOURCE)
        for frames in (0, 65, True, -1, "2"):
            bad = copy.deepcopy(report); bad["inventory"]["frames"] = frames
            with self.assertRaises(gate.Rejected): gate.validate_report(encode(bad), SOURCE)
        for section, key in (("selection", "collectionProfile"), ("inventory", "cpu")):
            for change in ("missing", "extra"):
                bad = copy.deepcopy(report)
                if change == "missing": del bad[section][key]
                else: bad[section]["rawData"] = PRIVATE
                with self.assertRaises(gate.Rejected): gate.validate_report(encode(bad), SOURCE)

if __name__ == "__main__":
    unittest.main()
