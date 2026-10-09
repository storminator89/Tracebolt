"""Inert Windows gate diagnostics: every subprocess is mocked; no host APIs run."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "windows_source_gate_diagnostics", Path(__file__).with_name("run_windows_service_source.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
reporter = gate._reporter


PACKAGE, TEST = sorted(gate.REQUIRED)[0]
SECRET = "private-runtime-sentinel"
PREFIX = "WINDOWS_SOURCE_DIAGNOSTIC "
FAILURE = "FAIL: Windows service source gate at pure fixtures; raw output withheld.\n"


def event(action, test=None, **fields):
    value = {"Action": action, "Package": PACKAGE, **fields}
    if test is not None:
        value["Test"] = test
    return value


def lines(*values):
    return b"".join(json.dumps(value).encode() + b"\n" for value in values)


def passes():
    return [dict(Action="pass", Package=package, Test=root)
            for package, root in sorted(gate.REQUIRED)]


class SourceDiagnosticTests(unittest.TestCase):
    def run_gate(self, raw=b"", returncode=1, error=None, success=False):
        output, errors = io.StringIO(), io.StringIO()
        result = subprocess.CompletedProcess([SECRET], returncode, raw, SECRET.encode())
        replies = [subprocess.CompletedProcess([], 0, b"amd64\n", SECRET.encode()),
                   error if error is not None else result]
        # Declare the complete expected post-fixture plan. Responses are tied
        # to commands, so a missing GUI build cannot be hidden by extra padding.
        folder = Path("/inert/" + SECRET)
        post_fixture = [(["go", "vet", *gate.PACKAGES], 180, None)]
        for arch in ("amd64", "arm64"):
            post_fixture.extend([
                (["go", "build", "-buildvcs=false", "-trimpath", "-o",
                  str(folder / ("service-" + arch + ".exe")), "./cmd/windows-service"], 300, arch),
                (["go", "build", "-buildvcs=false", "-trimpath", "-tags=tracebolt_setup",
                  "-ldflags=-H windowsgui", "-o", str(folder / ("setup-source-" + arch + ".exe")),
                  "./cmd/windows-service"], 300, arch),
            ])
        if success:
            replies += [subprocess.CompletedProcess(args, 0, b"", SECRET.encode())
                        for args, _, _ in post_fixture]
        with mock.patch.object(gate.sys, "platform", "win32"), \
                mock.patch.object(gate.subprocess, "run", side_effect=replies) as run, \
                mock.patch.object(gate.tempfile, "TemporaryDirectory") as temporary, \
                mock.patch.object(reporter, "load_allowlist", side_effect=AssertionError("forbidden allowlist")), \
                mock.patch.object(reporter, "derive_allowlist", side_effect=AssertionError("forbidden source reads")), \
                mock.patch.object(reporter, "read_private", side_effect=AssertionError("forbidden private reads")), \
                mock.patch.object(reporter, "main", side_effect=AssertionError("forbidden reporter CLI")), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            temporary.return_value.__enter__.return_value = "/inert/" + SECRET
            code = gate.main()
        self.assertEqual(errors.getvalue(), "")
        self.assertNotIn(SECRET, output.getvalue())
        self.assertEqual(run.call_count, 2 + len(post_fixture) if success else 2)
        call = run.call_args_list[1]
        self.assertEqual(run.call_args_list[0], mock.call(
            ["go", "env", "GOHOSTARCH"], env=call.kwargs["env"],
            capture_output=True, timeout=30, check=False))
        self.assertEqual(call.args, (["go", "test", "-json", "-count=1", "-timeout=120s",
                                      "-buildvcs=false", *gate.PACKAGES],))
        self.assertEqual({key: value for key, value in call.kwargs.items() if key != "env"},
                         dict(capture_output=True, timeout=300, check=False))
        self.assertEqual(call.kwargs["env"]["GOTOOLCHAIN"], "local")
        for name in ("GOOS", "GOARCH", "TRACEBOLT_WINDOWS_READONLY_NATIVE",
                     "TRACEBOLT_KNOWNFOLDER_PROBE", "TRACEBOLT_UPDATE_SERVICE_STARTUP_FIXTURE"):
            self.assertNotIn(name, call.kwargs["env"])
        if success:
            for call, (args, timeout, arch) in zip(run.call_args_list[2:], post_fixture):
                self.assertEqual(call.args, (args,))
                self.assertEqual({key: value for key, value in call.kwargs.items() if key != "env"},
                                 dict(capture_output=True, timeout=timeout, check=False))
                expected_env = dict(run.call_args_list[1].kwargs["env"])
                if arch is not None:
                    expected_env.update(GOOS="windows", GOARCH=arch, CGO_ENABLED="0")
                self.assertEqual(call.kwargs["env"], expected_env)
            self.assertEqual(code, 0)
            self.assertNotIn(PREFIX, output.getvalue())
            self.assertTrue(output.getvalue().startswith("PASS: Windows source fixtures"))
            return
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue().count(PREFIX), 1)
        self.assertTrue(output.getvalue().endswith(FAILURE))
        diagnostic_line, failure_line = output.getvalue().splitlines()
        self.assertEqual(failure_line + "\n", FAILURE)
        value = json.loads(diagnostic_line.removeprefix(PREFIX))
        self.assertEqual(set(value), {"category", "records", "truncated"})
        self.assertIn(value["category"], {"failure", "unclassified", "diagnostic_unavailable"})
        self.assertIs(type(value["truncated"]), bool)
        self.assertLessEqual(len(value["records"]), 64)
        for record in value["records"]:
            self.assertLessEqual(set(record), {"category", "package", "test"})
            self.assertIn(record["category"], {"test_failure", "timeout", "data_race", "build_failure"})
            self.assertIn(record["package"], {package for package, _ in gate.REQUIRED})
            if "test" in record:
                self.assertIn((record["package"], record["test"]), gate.REQUIRED)
        return value

    def unavailable(self, raw=b"", error=None, returncode=1):
        self.assertEqual(self.run_gate(raw, error=error, returncode=returncode),
                         dict(category="diagnostic_unavailable", records=[], truncated=False))

    def test_known_root_only_no_runtime_fields_or_subtest_suffix(self):
        raw = lines(event("run", TEST),
                    event("output", TEST, Output=SECRET, Time=SECRET, OutputType="error"),
                    event("attr", TEST, Key=SECRET, Value=SECRET),
                    event("artifacts", TEST, Path=SECRET),
                    event("fail", TEST + "/" + SECRET, Output=SECRET, Time=SECRET, Path=SECRET),
                    event("fail", TEST), event("fail"))
        self.assertEqual(self.run_gate(raw)["records"], [
            dict(category="test_failure", package=PACKAGE),
            dict(category="test_failure", package=PACKAGE, test=TEST),
        ])

    def test_unknown_root_uses_only_known_package_and_unknown_package_is_omitted(self):
        optional = "TestSetupRuntimeReadPreflightStopsBeforeJournalOrClaim"
        self.assertNotIn((PACKAGE, optional), gate.REQUIRED)
        raw = lines(event("fail", "Test" + SECRET),
                    event("fail", optional),
                    event("fail", TEST, Package="localrmm/" + SECRET),
                    event("fail", TEST, Package="localrmm/internal/windowsagentconfig"))
        self.assertEqual(self.run_gate(raw)["records"], [dict(category="test_failure", package=PACKAGE)])

    def test_allowed_vocabulary_is_exactly_required(self):
        real_project = gate.project
        with mock.patch.object(gate, "project", wraps=real_project) as project:
            self.run_gate(lines(event("fail", TEST)))
        allowed = project.call_args.args[1]
        self.assertEqual({(package, root) for package, roots in allowed.items() for root in roots}, gate.REQUIRED)
        self.assertEqual(set(allowed), {package for package, _ in gate.REQUIRED})

    def test_build_failure_uses_only_known_package(self):
        descriptor = PACKAGE + " [" + PACKAGE + ".test]"
        raw = lines({"Action": "build-output", "ImportPath": descriptor, "Output": SECRET},
                    {"Action": "build-fail", "ImportPath": descriptor},
                    {"Action": "build-fail", "ImportPath": SECRET},
                    event("fail", FailedBuild=descriptor, Output=SECRET))
        self.assertEqual(self.run_gate(raw)["records"], [dict(category="build_failure", package=PACKAGE)])

    def test_failed_go_never_succeeds_even_with_all_required_passes(self):
        for status in (1, 2, 255, -9):
            with self.subTest(status=status):
                value = self.run_gate(lines(*passes()), returncode=status)
                self.assertEqual(value, dict(category="unclassified", records=[], truncated=False))

    def test_skipped_and_missing_required_roots_still_fail(self):
        for rows in (passes()[:-1], passes() + [event("skip", TEST)],
                     [dict(row, Action="skip") if row["Test"] == TEST else row for row in passes()]):
            with self.subTest(rows=len(rows)):
                self.assertEqual(self.run_gate(lines(*rows), returncode=0)["category"], "unclassified")

    def test_success_has_no_diagnostic_and_keeps_vet_and_cross_builds(self):
        self.run_gate(lines(*passes()), returncode=0, success=True)

    def test_subprocess_timeout_and_os_error_never_project_partial_stdout_or_exception(self):
        partial = lines(event("fail", TEST, Output=SECRET))
        for error in (subprocess.TimeoutExpired([SECRET], 300, output=partial, stderr=SECRET.encode()),
                      OSError(SECRET)):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(gate, "project", side_effect=AssertionError("partial output")):
                    self.unavailable(error=error)

    def test_go_120s_timeout_stays_generic_without_active_root_inference(self):
        raw = lines(event("run", TEST),
                    event("output", Output="panic: test timed out after 2m0s\n"),
                    event("output", Output=SECRET), event("fail"))
        self.assertEqual(self.run_gate(raw)["records"], [dict(category="test_failure", package=PACKAGE)])

    def test_malformed_truncated_duplicate_and_nonfinite_fail_closed(self):
        valid = lines(event("fail", TEST))
        invalid = [b"not JSON " + SECRET.encode() + b"\n", b"[]\n", b"null\n", b"{}\n",
                   b"\xff\n", b"\n", valid.rstrip(b"\n"), valid + b"{",
                   b'{"Action":"fail","Action":"pass"}\n',
                   b'{"Action":"fail","Elapsed":NaN}\n',
                   b'{"Action":"fail","Elapsed":1e999}\n',
                   b'{"Action":"fail","Elapsed":{"x":1,"x":2}}\n',
                   lines(event("fail", TEST, unexpected=SECRET)),
                   lines(event("fail", TEST, Output=[])),
                   lines(event("fail", TEST, Package=[])),
                   b"[" * 2000 + b"]" * 2000 + b"\n"]
        for raw in invalid:
            for status in (0, 1):
                with self.subTest(raw=raw[:40], status=status):
                    self.unavailable(raw, returncode=status)

    def test_valid_prefix_is_discarded_on_later_malformed_or_duplicate_record(self):
        prefix = lines(event("fail", TEST))
        for suffix in (b"not JSON\n", b'{"Action":"fail","Action":"pass"}\n'):
            self.unavailable(prefix + suffix)

    def test_32_mib_bound_is_checked_before_projection(self):
        with mock.patch.object(gate, "project", side_effect=AssertionError("oversize input")):
            self.unavailable(b" " * (32 * 1024 * 1024 + 1))
        expected = dict(category="unclassified", records=[], truncated=False)
        with mock.patch.object(gate, "project", return_value=expected) as project:
            self.assertEqual(self.run_gate(b" " * (32 * 1024 * 1024)), expected)
            project.assert_called_once()

    def test_line_and_event_bounds_fail_closed(self):
        self.unavailable(lines(event("fail", TEST, Output=SECRET + "x" * reporter.MAX_LINE)))
        with mock.patch.object(reporter, "MAX_EVENTS", 1):
            self.unavailable(lines(event("fail", TEST), event("fail", TEST)))

    def test_projection_exceptions_cannot_leak_or_change_failure(self):
        for error in (ValueError(SECRET), TypeError(SECRET), OverflowError(SECRET), RecursionError(SECRET)):
            with mock.patch.object(gate, "project", side_effect=error):
                self.unavailable(lines(event("fail", TEST)))

    def test_record_cap_is_at_most_64(self):
        rows = []
        for package, root in sorted(gate.REQUIRED):
            rows.append(dict(Action="fail", Package=package, Test=root))
        for package, root in sorted(gate.REQUIRED):
            rows.extend([dict(Action="output", Package=package, Output="WARNING: DATA RACE\n"),
                         dict(Action="fail", Package=package, Test=root)])
        value = self.run_gate(lines(*rows))
        self.assertEqual(len(value["records"]), 64)
        self.assertTrue(value["truncated"])

    def test_crlf_json_stream_can_be_projected_without_file_loading(self):
        raw = lines(event("fail", TEST, Output=SECRET)).replace(b"\n", b"\r\n")
        self.assertEqual(self.run_gate(raw)["records"],
                         [dict(category="test_failure", package=PACKAGE, test=TEST)])


if __name__ == "__main__":
    unittest.main()
