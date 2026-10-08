"""Pure read-only CI fixtures: every subprocess is mocked, never a host probe."""
import contextlib
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
import run_prerequisites as probe

SOURCE = "a" * 40
PRIVATE = "private-path::error::must-not-escape"


def environment():
    return {
        "TRACEBOLT_PREREQUISITE_SOURCE_SHA": SOURCE, "GITHUB_SHA": SOURCE,
        "GITHUB_EVENT_NAME": "pull_request", "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": probe.REPOSITORY, "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
    }


def report(status="supported"):
    check, reason = {
        "supported": ("complete", "none"),
        "blocked": ("ancestor-policy", "prerequisite-blocked"),
        "unverified": ("platform", "unsupported-platform"),
    }[status]
    return {"schema": probe.SCHEMA, "source": SOURCE, "status": status,
            "check": check, "reason": reason, "readOnly": True,
            "nativeServiceAcceptance": False, "effectiveServiceTokenAccessVerified": False,
            "hostMutated": False, "diagnostic": {"location":"program-data","failure":"untrusted-write-grant","rights":["add-file"]} if status=="blocked" else None}


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class ReadOnlyEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(probe.sys, "platform", "win32"))
        self.enterContext(mock.patch.object(probe.platform, "machine", return_value="AMD64"))

    def test_ordinary_ci_needs_no_native_approval(self):
        with mock.patch.object(probe.subprocess, "Popen") as spawn:
            for event in ("push", "pull_request", "workflow_dispatch"):
                env = dict(environment(), GITHUB_EVENT_NAME=event)
                self.assertEqual(probe.check_environment(env), SOURCE)
            spawn.assert_not_called()

    def test_bad_source_platform_or_context_spawns_nothing(self):
        invalid = [{}]
        for key, values in {
            "TRACEBOLT_PREREQUISITE_SOURCE_SHA": (None, "b" * 40, "A" * 40, SOURCE + "\n", PRIVATE),
            "GITHUB_SHA": (None, "b" * 40),
            "GITHUB_EVENT_NAME": ("pull_request_target", "workflow_call", "schedule", ""),
            "GITHUB_ACTIONS": (True, "false"), "GITHUB_REPOSITORY": ("foreign/repo",),
            "RUNNER_ENVIRONMENT": ("self-hosted",), "RUNNER_OS": ("Linux",), "RUNNER_ARCH": ("ARM64",),
        }.items():
            for value in values:
                invalid.append(dict(environment(), **{key: value}))
        for env in invalid:
            with self.subTest(env=env), mock.patch.object(probe, "command") as command:
                with self.assertRaises(probe.Rejected):
                    probe.run_measurement(env)
                command.assert_not_called()

    def test_nonwindows_or_arm_host_fails_before_process(self):
        for host, machine in (("linux", "AMD64"), ("win32", "ARM64")):
            with mock.patch.object(probe.sys, "platform", host), mock.patch.object(probe.platform, "machine", return_value=machine), mock.patch.object(probe, "command") as command:
                with self.assertRaises(probe.Rejected):
                    probe.run_measurement(environment())
                command.assert_not_called()

    def test_approval_looking_environment_is_removed_and_build_is_native(self):
        child = probe.child_environment(dict(environment(), TRACEBOLT_APPROVE_SERVICES="true",
                                              TRACEBOLT_APPROVE_IDENTITY="true", GOFLAGS=PRIVATE,
                                              GOOS="linux", GOARCH="arm64", GOWORK=PRIVATE))
        self.assertFalse(any(key.startswith("TRACEBOLT_APPROVE_") for key in child))
        self.assertNotIn("GOOS", child)
        self.assertNotIn("GOARCH", child)
        self.assertNotIn("GOFLAGS", child)
        self.assertEqual(child["GOTOOLCHAIN"], "local")
        self.assertEqual(child["GOENV"], "off")
        self.assertEqual(child["GOWORK"], "off")

    def test_missing_or_extra_cli_modes_are_inert(self):
        for args in ([], ["--run-native"], ["--approve-services"], ["--run-read-only", PRIVATE]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), mock.patch.object(probe, "command") as command:
                self.assertEqual(probe.main(args, environment()), 1)
            command.assert_not_called()
            self.assertNotIn(PRIVATE, out.getvalue())


class ReadOnlyReportTests(unittest.TestCase):
    def reject(self, value):
        with self.assertRaises(probe.Rejected):
            probe.validate_report(encode(value), SOURCE)

    def test_all_three_measurement_outcomes_are_complete_not_acceptance(self):
        for status in probe.STATUSES:
            value = report(status)
            self.assertEqual(probe.validate_report(encode(value), SOURCE), value)
            self.assertEqual(probe.validate_report(probe.sanitized_bytes(value, SOURCE), SOURCE), value)
            out = io.StringIO()
            with mock.patch.object(probe, "run_measurement", return_value=value), contextlib.redirect_stdout(out):
                self.assertEqual(probe.main(["--run-read-only"], environment()), 0)
            self.assertIn(status, out.getvalue())
            self.assertIn("native service acceptance unverified", out.getvalue())

    def test_exact_fields_types_source_and_false_safety_flags(self):
        for key in probe.REPORT_FIELDS:
            value = report()
            del value[key]
            self.reject(value)
        self.reject(dict(report(), privatePath=PRIVATE))
        for key in probe.FALSE_FLAGS | {"readOnly"}:
            for wrong in (0, 1, "true", "false", None, [], {}):
                self.reject(dict(report(), **{key: wrong}))
            self.reject(dict(report(), **{key: key != "readOnly"}))
        for key in ("schema", "source", "status", "check", "reason"):
            for wrong in (None, True, 0, [], {}, PRIVATE):
                self.reject(dict(report(), **{key: wrong}))
        self.reject(dict(report(), source="b" * 40))
        self.reject(dict(report(), source="A" * 40))

    def test_status_semantics_cannot_turn_static_read_into_native_proof(self):
        for wrong in ("passed_native_subset", "pass", "native-supported"):
            self.reject(dict(report(), status=wrong))
        for check in probe.CHECKS - {"complete"}:
            self.reject(dict(report(), check=check))
        for reason in probe.REASONS - {"none"}:
            self.reject(dict(report(), reason=reason))
        for check in ("idle", "platform", "complete"):
            self.reject(dict(report("blocked"), check=check))
        for reason in ("none", "inspection-failed", "unsupported-platform", "cancelled"):
            self.reject(dict(report("blocked"), reason=reason))
        self.reject(dict(report("blocked"), reason="existing-resource"))
        probe.validate_report(encode(dict(report("blocked"), check="resource-absence", reason="existing-resource", diagnostic=None)), SOURCE)
        for reason in ("none", "existing-resource", "prerequisite-blocked"):
            self.reject(dict(report("unverified"), reason=reason))
        self.reject(dict(report("unverified"), check="complete"))

    def test_duplicate_json_keys_output_injection_and_nonfinite_rejected(self):
        raw = encode(report())
        for invalid in (b"", b"[]", b"null", b"\xff", b"\xef\xbb\xbf" + raw,
                        b"::error::" + raw, raw + raw, raw + PRIVATE.encode(),
                        raw.replace(b'"source":', b'"source":"duplicate","source":', 1),
                        raw.replace(b'"hostMutated":false', b'"hostMutated":NaN'),
                        raw.replace(b'"hostMutated":false', b'"hostMutated":Infinity'),
                        raw.replace(b'"hostMutated":false', b'"hostMutated":1e999')):
            with self.subTest(raw=invalid[:40]), self.assertRaises(probe.Rejected):
                probe.validate_report(invalid, SOURCE)

    def test_nested_diagnostics_reject_unknown_host_details_and_noncanonical_rights(self):
        value = report("blocked")
        for key in ("location", "failure", "rights"):
            diagnostic = dict(value["diagnostic"])
            del diagnostic[key]
            self.reject(dict(value, diagnostic=diagnostic))
        for wrong in (None, [], True, 0, PRIVATE, {}, dict(value["diagnostic"], rawSID=PRIVATE)):
            self.reject(dict(value, diagnostic=wrong))
        for key in ("location", "failure"):
            for wrong in (None, [], {}, True, PRIVATE, "C:\\private", "S-1-5-21-private"):
                self.reject(dict(value, diagnostic=dict(value["diagnostic"], **{key: wrong})))
        for wrong in (None, [], [PRIVATE], [1], ["add-file", "add-file"], ["add-file", "generic-all"], ["add-file", PRIVATE]):
            self.reject(dict(value, diagnostic=dict(value["diagnostic"], rights=wrong)))
        self.reject(dict(report(), diagnostic=value["diagnostic"]))
        self.reject(dict(report("unverified"), diagnostic=value["diagnostic"]))
        self.reject(dict(value, diagnostic=dict(value["diagnostic"], failure="owner-untrusted")))
        for location in probe.DIAGNOSTIC_LOCATIONS:
            for failure in probe.DIAGNOSTIC_FAILURES:
                rights = ["add-file"] if failure == "untrusted-write-grant" else []
                diagnostic = {"location": location, "failure": failure, "rights": rights}
                if failure.startswith("root-") and location != "volume-root":
                    self.reject(dict(value, diagnostic=diagnostic))
                else:
                    probe.validate_report(encode(dict(value, diagnostic=diagnostic)), SOURCE)
        full = dict(value, diagnostic=dict(value["diagnostic"], rights=list(probe.DIAGNOSTIC_RIGHTS)))
        probe.validate_report(encode(full), SOURCE)
        raw = encode(value)
        duplicate = raw.replace(b'"location":', b'"location":"volume-root","location":', 1)
        with self.assertRaises(probe.Rejected):
            probe.validate_report(duplicate, SOURCE)

    def test_diagnostic_schema_enum_sets_match_go(self):
        native = (probe.ROOT / "internal/windowsacceptance/native/prerequisite_diagnostics.go").read_text()
        definition = native.split("type PrerequisiteDiagnostic struct {", 1)[1].split("\n}", 1)[0]
        self.assertEqual(set(re.findall(r'json:"([^\"]+)"', definition)), {"location", "failure", "rights"})
        failure = native.split("func validDiagnosticFailure", 1)[1].split("return true", 1)[0]
        self.assertEqual(set(re.findall(r'"([^\"]+)"', failure)), probe.DIAGNOSTIC_FAILURES)
        location = native.split("switch d.Location", 1)[1].split("default:", 1)[0]
        self.assertEqual(set(re.findall(r'"([^\"]+)"', location)), probe.DIAGNOSTIC_LOCATIONS)
        rights = native.split("var diagnosticRightNames", 1)[1].split("\n", 1)[0]
        self.assertEqual(tuple(re.findall(r'"([^\"]+)"', rights)), probe.DIAGNOSTIC_RIGHTS)

    def test_size_limit_is_32kib_including_whitespace(self):
        raw = encode(report())
        padded = raw + b" " * (probe.MAX_REPORT_BYTES - len(raw))
        probe.validate_report(padded, SOURCE)
        with self.assertRaises(probe.Rejected):
            probe.validate_report(padded + b" ", SOURCE)

    def test_report_fields_schema_and_checks_match_go(self):
        cli = (probe.ROOT / "cmd/windows-prerequisites/main.go").read_text()
        native = (probe.ROOT / "internal/windowsacceptance/native/prerequisites.go").read_text()
        cli_fields = cli.split("type report struct {", 1)[1].split("\n}", 1)[0]
        observation = native.split("type PrerequisiteObservation struct {", 1)[1].split("\n}", 1)[0]
        fields = set(re.findall(r'json:"([^"]+)"', cli_fields + observation))
        self.assertEqual(fields, probe.REPORT_FIELDS)
        self.assertIn('const schema = "' + probe.SCHEMA + '"', cli)
        checks = native.split("func validPrerequisiteCheck", 1)[1].split("return true", 1)[0]
        self.assertEqual(set(re.findall(r'"([^"]+)"', checks)), probe.CHECKS)
        self.assertIn('args[0] != "--read-only-prerequisites"', cli)
        self.assertIn('args[1] != "--expected-source="+compiledSource', cli)
        self.assertIn("native.InspectPrerequisites", cli)
        for forbidden in ("--approve-", "--internal-denial-probe", "executeNative", "ApplyInstall"):
            self.assertNotIn(forbidden, cli)


class ReadOnlyFixtureTests(unittest.TestCase):
    def events(self):
        events = [{"Package": package, "Test": test, "Action": "pass"} for package, test in probe.REQUIRED_FIXTURES]
        return events + [{"Package": package, "Action": "pass"} for package in probe.FIXTURE_PACKAGES]

    def test_windows_fixture_evidence_requires_actual_pass_without_skip(self):
        events = self.events()
        raw = b"\n".join(encode(event) for event in events)
        probe.validate_fixture_events(raw)
        for bad in (events[1:], events + [dict(events[0], Action="skip")], events + [{"Action":"fail"}]):
            with self.assertRaises(probe.Rejected):
                probe.validate_fixture_events(b"\n".join(encode(event) for event in bad))

    def test_fixture_mode_is_exact_source_and_runs_only_memory_packages(self):
        events = b"\n".join(encode(event) for event in self.events())
        with mock.patch.object(probe, "check_environment", return_value=SOURCE), mock.patch.object(probe, "verify_checkout") as checkout, mock.patch.object(probe, "verify_go"), mock.patch.object(probe, "command", return_value=events) as command:
            probe.run_fixtures(environment())
        checkout.assert_called_once()
        args = command.call_args.args[0]
        self.assertEqual(args[:2], ["go", "test"])
        self.assertEqual(args[-4:], ["./internal/windowsacceptance/native", "./cmd/windows-prerequisites", "./internal/windowspath", "./internal/windowsstate"])
        self.assertIn("-json", args)
        self.assertNotIn("--run-read-only", args)
        self.assertNotIn("--run-native", args)


class ReadOnlyExecutionTests(unittest.TestCase):
    def fake_process(self, raw, code=0):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stdout = io.BytesIO(raw)
        process.wait.return_value = code
        return process

    def test_no_shell_no_stdin_no_raw_stderr(self):
        process = self.fake_process(b"finite")
        with mock.patch.object(probe.subprocess, "Popen", return_value=process) as spawn:
            self.assertEqual(probe.command(["fixed.exe", "--read-only-prerequisites"], {}, probe.ROOT, 90), b"finite")
        self.assertIs(spawn.call_args.kwargs["shell"], False)
        self.assertEqual(spawn.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_execution_failure_overflow_and_timeout_are_failures(self):
        for process in (self.fake_process(encode(report()), 1), self.fake_process(b"x" * (probe.MAX_REPORT_BYTES + 1))):
            with mock.patch.object(probe.subprocess, "Popen", return_value=process), self.assertRaises(probe.Rejected):
                probe.command(["fixed.exe"], {}, probe.ROOT, 90)
        process = self.fake_process(PRIVATE.encode())
        process.wait.side_effect = [subprocess.TimeoutExpired(PRIVATE, 90), 1]
        with mock.patch.object(probe.subprocess, "Popen", return_value=process), self.assertRaises(probe.Rejected):
            probe.command(["fixed.exe"], {}, probe.ROOT, 90)
        process.kill.assert_called_once()

    def test_only_separate_readonly_binary_built_and_fixed_mode_invoked(self):
        for status in probe.STATUSES:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / "output"
                out.touch()
                env = dict(environment(), RUNNER_TEMP=directory, GITHUB_OUTPUT=str(out))
                calls = []
                raw = b" " + encode(report(status)) + b"\n\n"
                def fake_command(args, _env, _root, timeout, *_extra):
                    calls.append((args, timeout))
                    if args[:2] == ["go", "env"]:
                        return encode({"GOHOSTOS": "windows", "GOHOSTARCH": "amd64", "GOOS": "windows", "GOARCH": "amd64"})
                    if args[:2] == ["go", "build"]:
                        Path(args[args.index("-o") + 1]).write_bytes(b"inert file")
                    if args[0].endswith(".exe"):
                        return raw
                    return b""
                with mock.patch.object(probe, "check_environment", return_value=SOURCE), mock.patch.object(probe, "verify_checkout") as source_check, mock.patch.object(probe, "command", side_effect=fake_command):
                    self.assertEqual(probe.run_measurement(env)["status"], status)
                self.assertEqual(source_check.call_count, 2)
                builds = [args for args, _ in calls if args[:2] == ["go", "build"]]
                self.assertEqual(len(builds), 1)
                self.assertEqual(builds[0][-1], "./cmd/windows-prerequisites")
                self.assertEqual(builds[0][builds[0].index("-ldflags") + 1], "-X main.compiledSource=" + SOURCE)
                executions = [(args, timeout) for args, timeout in calls if args[0].endswith(".exe")]
                self.assertEqual(len(executions), 1)
                self.assertEqual(executions[0][0][1:], ["--read-only-prerequisites", "--expected-source=" + SOURCE])
                self.assertEqual(executions[0][1], probe.TIMEOUT_SECONDS)
                all_args = " ".join(arg for args, _ in calls for arg in args)
                for forbidden in ("--approve-", "--run-native", "--internal-denial-probe", "./cmd/windows-service", "./cmd/windows-native-acceptance"):
                    self.assertNotIn(forbidden, all_args)
                self.assertEqual(out.read_text(), "report_validated=true\n")
                self.assertEqual((Path(directory) / probe.REPORT_NAME).read_bytes(), probe.sanitized_bytes(report(status), SOURCE))
                self.assertEqual({p.name for p in Path(directory).iterdir()}, {"output", probe.REPORT_NAME})

    def test_injected_or_invalid_report_never_creates_artifact(self):
        for raw in (encode(report()) + PRIVATE.encode(), encode(dict(report(), privatePath=PRIVATE))):
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / "output"
                out.touch()
                env = dict(environment(), RUNNER_TEMP=directory, GITHUB_OUTPUT=str(out))
                def fake_command(args, *_args, **_kwargs):
                    if args[:2] == ["go", "env"]:
                        return encode({"GOHOSTOS": "windows", "GOHOSTARCH": "amd64", "GOOS": "windows", "GOARCH": "amd64"})
                    if args[:2] == ["go", "build"]:
                        Path(args[args.index("-o") + 1]).write_bytes(b"inert file")
                    return raw if args[0].endswith(".exe") else b""
                visible = io.StringIO()
                with mock.patch.object(probe, "check_environment", return_value=SOURCE), mock.patch.object(probe, "verify_checkout"), mock.patch.object(probe, "command", side_effect=fake_command), contextlib.redirect_stdout(visible):
                    self.assertEqual(probe.main(["--run-read-only"], env), 1)
                self.assertNotIn(PRIVATE, visible.getvalue())
                self.assertEqual(out.read_text(), "")
                self.assertEqual({p.name for p in Path(directory).iterdir()}, {"output"})

    def test_exceptions_are_finite_failures(self):
        for error in (ValueError(PRIVATE), OSError(PRIVATE), subprocess.CalledProcessError(1, PRIVATE, PRIVATE, PRIVATE)):
            out = io.StringIO()
            with mock.patch.object(probe, "run_measurement", side_effect=error), contextlib.redirect_stdout(out):
                self.assertEqual(probe.main(["--run-read-only"], environment()), 1)
            self.assertNotIn(PRIVATE, out.getvalue())


class ReadOnlyWorkflowTests(unittest.TestCase):
    def test_ordinary_workflow_has_only_readonly_execution_and_no_approval_inputs(self):
        workflow = (probe.ROOT / ".github/workflows/windows-prerequisites.yml").read_text()
        triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_]+):", triggers, re.M), ["push", "pull_request", "workflow_dispatch"])
        self.assertNotIn("inputs:", workflow)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertIn("runs-on: windows-2025", workflow)
        self.assertIn("github.repository == 'storminator89/Tracebolt'", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("TRACEBOLT_PREREQUISITE_SOURCE_SHA: ${{ github.sha }}", workflow)
        self.assertIn("run_prerequisites.py --run-read-only", workflow)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("path: ${{ runner.temp }}/" + probe.REPORT_NAME, workflow)
        self.assertIn("steps.measurement.outputs.report_validated == 'true'", workflow)
        self.assertNotIn("continue-on-error", workflow)
        for forbidden in ("run_acceptance.py", "--run-native", "--approve-", "TRACEBOLT_APPROVE_", "workflow_call", "contents: write"):
            self.assertNotIn(forbidden, workflow)
        for line in workflow.splitlines():
            if "run:" in line:
                self.assertNotIn("${{", line)

    def test_manual_native_workflow_remains_dispatch_only_default_off(self):
        workflow = (probe.ROOT / ".github/workflows/windows-native-acceptance.yml").read_text()
        trigger = workflow.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_]+):", trigger, re.M), ["workflow_dispatch"])
        self.assertNotRegex(trigger, r"default:\s*true")
        self.assertEqual(trigger.count("default: false"), 11)
        self.assertIn("run_acceptance.py --check-authorization", workflow)
        self.assertIn("run_acceptance.py --run-native", workflow)
        runner = (probe.ROOT / "tests/windows_native_acceptance/run_prerequisites.py").read_text()
        self.assertNotIn("import run_acceptance", runner)
        self.assertNotIn("./cmd/windows-native-acceptance", runner)


if __name__ == "__main__":
    unittest.main()
