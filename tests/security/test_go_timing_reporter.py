"""Inert timing/privacy and runner-status fixtures; never execute Go tests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from unittest import mock

import report_go_failure as r

PACKAGE = "localrmm/internal/enrollmentstore"
TEST = "TestCompleteOverviewSteadyMinuteCadenceRetainsPagesAndCleans"
ALLOWED = {PACKAGE: frozenset({TEST})}
SECRET = "invented-private-timing-sentinel"


def event(action, test=None, **fields):
    return {"Action": action, "Package": PACKAGE,
            **({"Test": test} if test is not None else {}), **fields}


def lines(*events):
    return b"".join(json.dumps(value).encode() + b"\n" for value in events)


def successful(*extra):
    return lines(*extra, event("pass", TEST, Elapsed=1.23456), event("pass", Elapsed=2.34567))


class TimingTests(unittest.TestCase):
    def test_only_exact_source_names_and_numeric_elapsed_leave(self):
        raw = successful(
            event("output", TEST, Output=SECRET, Time=SECRET, OutputType="error"),
            event("attr", TEST, Key=SECRET, Value=SECRET),
            event("artifacts", TEST, Path=SECRET),
            event("pass", TEST + "/" + SECRET, Elapsed=9),
            event("pass", SECRET, Elapsed=99),
            {"Action": "pass", "Package": SECRET, "Elapsed": 999})
        value = r.project_timings(raw, ALLOWED)
        self.assertEqual(value, {
            "category": "success_timings", "packages": [{"package": PACKAGE, "elapsedSeconds": 2.346}],
            "tests": [{"package": PACKAGE, "test": TEST, "elapsedSeconds": 1.235}],
            "completedPackages": 1, "completedRoots": 1, "skippedPackages": 0, "truncated": False})
        self.assertNotIn(SECRET, json.dumps(value))

    def test_failures_missing_elapsed_and_incomplete_runs_reject(self):
        for raw in [b"", successful().rstrip(b"\n"),
                    lines(event("pass", TEST, Elapsed=1)), lines(event("pass")),
                    successful(event("fail", TEST)),
                    successful({"Action": "fail", "Package": SECRET}),
                    successful({"Action": "build-fail", "ImportPath": SECRET}),
                    successful(event("pass", TEST, Elapsed=3)),
                    successful(event("skip")),
                    successful(event("pass", Elapsed=2))]:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                r.project_timings(raw, ALLOWED)

    def test_malformed_nonfinite_wrong_types_and_bounds_reject(self):
        for value in [True, -1, float("nan"), float("inf"), 86401, "1", None]:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                r.project_timings(lines(event("pass", Elapsed=value)), ALLOWED)
        for raw in [b'{"Action":"pass","Action":"pass"}\n', b"[]\n", b"\xff\n"]:
            with self.assertRaises((ValueError, UnicodeError)):
                r.project_timings(raw, ALLOWED)
        for limit in ("MAX_EVENTS", "MAX_LINE", "MAX_FILE"):
            with mock.patch.object(r, limit, 1), self.assertRaises(ValueError):
                r.project_timings(successful(), ALLOWED)

    def test_package_skips_are_counted_without_invented_timings(self):
        other = "localrmm/cmd/inert"
        raw = successful({"Action": "skip", "Package": other})
        value = r.project_timings(raw, {**ALLOWED, other: frozenset()})
        self.assertEqual(value["skippedPackages"], 1)
        self.assertNotIn(other, json.dumps(value))
        with self.assertRaises(ValueError):
            r.project_timings(successful(event("skip"), event("skip")), ALLOWED)

    def test_top_limits_and_ties_are_deterministic(self):
        allowed = {f"localrmm/p{i:02}": frozenset({f"TestRoot{n:02}" for n in range(3)}) for i in range(25)}
        events = []
        for package, tests in reversed(list(allowed.items())):
            for test in sorted(tests, reverse=True):
                events.append({"Action": "pass", "Package": package, "Test": test, "Elapsed": 1})
            events.append({"Action": "pass", "Package": package, "Elapsed": 2})
        value = r.project_timings(lines(*events), allowed)
        self.assertTrue(value["truncated"])
        self.assertEqual((value["completedPackages"], value["completedRoots"]), (25, 75))
        self.assertEqual((len(value["packages"]), len(value["tests"])), (20, 32))
        self.assertEqual(value["packages"][0]["package"], "localrmm/p00")
        self.assertEqual(value["tests"][0]["test"], "TestRoot00")
        self.assertEqual(value, r.project_timings(lines(*reversed(events)), allowed))


class CLITests(unittest.TestCase):
    def test_isolated_cli_has_no_private_output_or_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            events, stderr = Path(temp) / "events", Path(temp) / "stderr"
            events.write_bytes(successful(event("output", TEST, Output=SECRET)))
            stderr.write_text(SECRET)
            for path in (events, stderr):
                path.chmod(0o600)
            args = [sys.executable, "-I", "-B", str(Path(r.__file__).resolve()), "--success",
                    "--events", str(events), "--stderr", str(stderr), "--exit-code", "0",
                    "--elapsed-seconds", "1715"]
            result = subprocess.run(args, cwd=temp, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertNotIn(SECRET, result.stdout)
            value = json.loads(result.stdout.removeprefix("GO_TEST_TIMINGS "))
            self.assertEqual(value["exitCode"], 0)
            self.assertEqual(value["elapsedSeconds"], 1715)
            events.chmod(0o644)
            result = subprocess.run(args, cwd=temp, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "")
            self.assertNotIn(str(events), result.stdout)
            self.assertIn('"category":"diagnostic_unavailable"', result.stdout)

    def test_success_mode_rejects_failed_command_exit(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = r.main(["--success", "--events", SECRET, "--stderr", SECRET,
                           "--exit-code", "7", "--elapsed-seconds", "0"])
        self.assertEqual(code, 1)
        self.assertNotIn(SECRET, output.getvalue())
        self.assertNotIn("success_timings", output.getvalue())

    def test_workflow_report_failure_neither_fails_success_nor_hides_go_failure(self):
        # Exercise the checked-in shard runner with an inert subprocess. Optional
        # timing diagnostics cannot turn a Go failure into success or vice versa;
        # mandatory exact completion evidence is checked separately by the runner.
        spec = importlib.util.spec_from_file_location("inert_shards", r.ROOT / "tests/security/go_race_shards.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        plan = {"schemaVersion": 1, "commit": "a" * 40, "runId": "1", "runAttempt": "1",
                "goSourceSha256": "b" * 64, "packages": {"localrmm/a": True},
                "shards": [["localrmm/a"], [], []]}
        for status in (0, 7):
            with tempfile.TemporaryDirectory() as temp:
                destination = Path(temp) / "report" / "completion.json"
                def inert_process(command, **kwargs):
                    for event in [{"Action": "start", "Package": "localrmm/a"},
                                  {"Action": "pass", "Package": "localrmm/a", "Elapsed": 1}]:
                        kwargs["stdout"].write(runner.canonical(event) + b"\n")
                    kwargs["stdout"].flush()
                    process = Mock(); process.wait.return_value = status
                    return process
                with patch.dict(os.environ, {"RUNNER_TEMP": temp}), \
                     patch.object(runner.subprocess, "Popen", side_effect=inert_process), \
                     patch.object(runner.reporter, "main", return_value=19) as report, \
                     contextlib.redirect_stdout(io.StringIO()):
                    if status == 0:
                        runner.run_shard(plan, {}, 0, destination)
                        self.assertTrue(destination.is_file())
                    else:
                        with self.assertRaises(ValueError):
                            runner.run_shard(plan, {}, 0, destination)
                        self.assertFalse(destination.exists())
                    args = report.call_args.args[0]
                    self.assertEqual("--success" in args, status == 0)
                    self.assertEqual(args[args.index("--exit-code") + 1], str(status))


if __name__ == "__main__":
    unittest.main()
