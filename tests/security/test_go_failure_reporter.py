"""Inert projection/privacy checks; no repository tests or host sources run."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import report_go_failure as r

PACKAGE = "localrmm/internal/enrollmentstore"
TEST = "TestCompleteOverviewSteadyMinuteCadenceRetainsPagesAndCleans"
ALLOWED = {PACKAGE: frozenset({TEST, "TestCompleteOverviewRealAuthorityPaginationRetryAndRestart"})}
SECRET = "invented-private-runtime-sentinel"


def event(action, test=None, **fields):
    value = {"Action": action, "Package": PACKAGE, **fields}
    if test is not None:
        value["Test"] = test
    return value


def lines(*values):
    return b"".join(json.dumps(value).encode() + b"\n" for value in values)


def private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


class ProjectionTests(unittest.TestCase):
    def test_known_root_and_subtests_emit_only_source_root(self):
        raw = lines(event("fail", TEST + "/" + SECRET, Elapsed=1.25),
                    event("fail", TEST, Elapsed=2), event("fail", Elapsed=3))
        value = r.project(raw, ALLOWED)
        self.assertEqual(value["category"], "failure")
        self.assertEqual(value["records"], [
            {"category": "test_failure", "package": PACKAGE},
            {"category": "test_failure", "package": PACKAGE, "test": TEST},
        ])
        self.assertNotIn(SECRET, json.dumps(value))

    def test_unknown_test_and_package_never_emit(self):
        raw = lines(event("fail", SECRET),
                    {"Action": "fail", "Package": SECRET, "Test": TEST},
                    event("output", SECRET, Output=SECRET + "\n"))
        value = r.project(raw, ALLOWED)
        self.assertEqual(value["records"], [{"category": "test_failure", "package": PACKAGE}])
        self.assertNotIn(SECRET, json.dumps(value))

    def test_timeout_uses_only_known_active_roots(self):
        second = "TestCompleteOverviewRealAuthorityPaginationRetryAndRestart"
        value = r.project(lines(event("run", TEST), event("run", second),
                                event("pass", second), event("run", SECRET),
                                event("output", Output="panic: test timed out after 15m0s\n"),
                                event("fail", Elapsed=900)), ALLOWED)
        self.assertEqual(value["records"], [
            {"category": "timeout", "package": PACKAGE},
            {"category": "timeout", "package": PACKAGE, "test": TEST},
        ])

    def test_subtest_pass_does_not_clear_active_parent(self):
        value = r.project(lines(event("run", TEST), event("run", TEST + "/" + SECRET),
                                event("pass", TEST + "/" + SECRET),
                                event("output", Output="panic: test timed out after 15m0s\n")), ALLOWED)
        self.assertIn({"category": "timeout", "package": PACKAGE, "test": TEST}, value["records"])

    def test_race_and_build_are_exact_fixed_syntax(self):
        for output, category in [("WARNING: DATA RACE\n", "data_race"),
                                 ("FAIL\t" + PACKAGE + " [build failed]\n", "build_failure")]:
            value = r.project(lines(event("output", Output=output), event("fail")), ALLOWED)
            self.assertEqual(value["records"], [{"category": category, "package": PACKAGE}])
            for bad in [output.rstrip("\n"), "prefix " + output, output + SECRET + "\n"]:
                value = r.project(lines(event("output", Output=bad), event("fail")), ALLOWED)
                self.assertEqual(value["records"], [{"category": "test_failure", "package": PACKAGE}])

    def test_build_field_can_only_select_fixed_category(self):
        value = r.project(lines(event("fail", FailedBuild=PACKAGE)), ALLOWED)
        self.assertEqual(value["records"], [{"category": "build_failure", "package": PACKAGE}])
        value = r.project(lines(event("fail", FailedBuild=SECRET)), ALLOWED)
        self.assertEqual(value["records"], [{"category": "test_failure", "package": PACKAGE}])

    def test_modern_go_build_events_and_descriptors(self):
        for descriptor in [PACKAGE, PACKAGE + " [" + PACKAGE + ".test]",
                           PACKAGE + "_test [" + PACKAGE + ".test]", PACKAGE + ".test"]:
            raw = lines({"ImportPath": descriptor, "Action": "build-output", "Output": SECRET + "\n"},
                        {"ImportPath": descriptor, "Action": "build-fail"},
                        event("fail", FailedBuild=descriptor))
            value = r.project(raw, ALLOWED)
            self.assertEqual(value["records"], [{"category": "build_failure", "package": PACKAGE}])
            self.assertNotIn(SECRET, json.dumps(value))
        for descriptor in [SECRET, PACKAGE + " [" + SECRET + ".test]",
                           PACKAGE + " [" + PACKAGE + ".test] suffix", PACKAGE + "_private"]:
            self.assertEqual(r.project(lines({"ImportPath": descriptor, "Action": "build-fail"}), ALLOWED)["records"], [])

    def test_modern_go_output_attributes_and_artifacts_are_never_exported(self):
        raw = lines(event("output", TEST, Output=SECRET + "\n", OutputType="error"),
                    event("attr", TEST, Key=SECRET, Value=SECRET),
                    event("artifacts", TEST, Path=SECRET), event("fail", TEST))
        value = r.project(raw, ALLOWED)
        self.assertEqual(value["records"], [{"category": "test_failure", "package": PACKAGE, "test": TEST}])
        self.assertNotIn(SECRET, json.dumps(value))

    def test_timeout_near_matches_stay_generic(self):
        for output in ["panic: test timed out after 15m\n", "panic: test timed out after 1h0m0s\n",
                       "panic: test timed out after 15m0s " + SECRET + "\n"]:
            value = r.project(lines(event("output", Output=output), event("fail", TEST)), ALLOWED)
            self.assertEqual(value["records"][0]["category"], "test_failure")

    def test_rejects_malformed_duplicate_nonfinite_and_wrong_shapes(self):
        invalid = [b"not JSON\n", b"[]\n", b"null\n", b"{}\n", b"\xff\n", b"\n",
                   b'{"Action":"fail","Action":"pass"}\n',
                   b'{"Action":"fail","Elapsed":NaN}\n',
                   b'{"Action":"fail","Elapsed":Infinity}\n',
                   b'{"Action":"fail","Elapsed":1e999}\n',
                   b'{"Action":"fail","Elapsed":true}\n',
                   b'{"Action":"fail","Elapsed":-1}\n',
                   b'{"Action":"fail","Elapsed":86401}\n',
                   b'{"Action":"fail","Elapsed":{"x":1,"x":2}}\n',
                   lines(event("fail", TEST)).rstrip(b"\n"),
                   lines(event("fail", Output=[])), lines(event("fail", unexpected=SECRET)),
                   lines({"Action": "build-fail", "ImportPath": PACKAGE, "Package": PACKAGE}),
                   lines({"Action": "build-fail", "ImportPath": []}),
                   lines({"Action": "build-fail"}),
                   lines({"Action": "future-action", "Package": PACKAGE})]
        for raw in invalid:
            with self.subTest(raw=raw[:80]):
                with self.assertRaises((ValueError, TypeError, OverflowError)):
                    r.project(raw, ALLOWED)

    def test_private_output_fields_are_ignored_even_for_failures(self):
        value = r.project(lines(event("output", TEST, Output=SECRET + "\n"),
                                event("fail", TEST, Output=SECRET + "\n", Time=SECRET)), ALLOWED)
        self.assertNotIn(SECRET, json.dumps(value))

    def test_bounds_and_deterministic_record_cap(self):
        names = frozenset("TestSynthetic%03d" % n for n in range(100))
        raw = lines(*(event("fail", name) for name in sorted(names)))
        value = r.project(raw, {PACKAGE: names})
        self.assertEqual(len(value["records"]), r.MAX_RECORDS)
        self.assertTrue(value["truncated"])
        with mock.patch.object(r, "MAX_EVENTS", 1):
            with self.assertRaises(ValueError):
                r.project(lines(event("fail"), event("fail")), ALLOWED)
        with mock.patch.object(r, "MAX_LINE", 10):
            with self.assertRaises(ValueError):
                r.project(lines(event("fail")), ALLOWED)
        with mock.patch.object(r, "MAX_ACTIVE", 0):
            with self.assertRaises(ValueError):
                r.project(lines(event("run", TEST)), ALLOWED)

    def test_empty_or_unrecognized_input_is_unclassified(self):
        self.assertEqual(r.project(b"", ALLOWED)["category"], "unclassified")
        self.assertEqual(r.project(lines({"Action": "fail", "Package": SECRET}), ALLOWED)["records"], [])


class ReaderAndCLITests(unittest.TestCase):
    def test_private_regular_file_reads_and_oversize_rejects(self):
        with tempfile.TemporaryDirectory() as temp:
            path = private(Path(temp) / "events", b"test")
            self.assertEqual(r.read_private(path, 4), b"test")
            with self.assertRaises(ValueError):
                r.read_private(path, 3)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                r.read_private(path, 4)

    def test_symlink_ancestor_hardlink_fifo_directory_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            path = private(base / "events", b"test")
            link = base / "link"
            link.symlink_to(path)
            fifo = base / "fifo"
            os.mkfifo(fifo, 0o600)
            parent = base / "parent"
            parent.symlink_to(base, target_is_directory=True)
            for target in [link, fifo, base, parent / "events"]:
                with self.subTest(target=target):
                    with self.assertRaises((ValueError, OSError)):
                        r.read_private(target, 100)
            os.link(path, base / "hardlink")
            with self.assertRaises(ValueError):
                r.read_private(path, 100)

    def test_changed_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = private(Path(temp) / "events", b"test")
            real = os.fstat
            calls = 0

            def changed(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    with path.open("ab") as stream:
                        stream.write(b"change")
                return real(fd)

            with mock.patch.object(r.os, "fstat", changed):
                with self.assertRaises(ValueError):
                    r.read_private(path, 100)

    def test_wrong_owner_is_rejected_without_changing_ownership(self):
        with tempfile.TemporaryDirectory() as temp:
            path = private(Path(temp) / "events", b"test")
            with mock.patch.object(r.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(ValueError):
                    r.read_private(path, 100)

    def test_ancestor_replacement_is_rejected_by_path_recheck(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            original = base / "original"
            original.mkdir()
            path = private(original / "events", b"test")
            real = r.open_log
            calls = 0

            def changed(target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    original.rename(base / "moved")
                    original.mkdir()
                    private(original / "events", b"test")
                return real(target)

            with mock.patch.object(r, "open_log", changed):
                with self.assertRaises(ValueError):
                    r.read_private(path, 100)

    def call(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = r.main(args)
        self.assertEqual(err.getvalue(), "")
        self.assertNotIn(SECRET, out.getvalue())
        self.assertTrue(out.getvalue().startswith("GO_TEST_DIAGNOSTIC "))
        return code, json.loads(out.getvalue().split(" ", 1)[1])

    def test_cli_preserves_bounded_exit_elapsed_and_never_stderr(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(r, "load_allowlist", return_value=ALLOWED):
            path = private(Path(temp) / "events", lines(event("fail", TEST)))
            err = private(Path(temp) / "stderr", (SECRET + "\n").encode())
            args = ["--events", str(path), "--stderr", str(err), "--exit-code", "1", "--elapsed-seconds", "1715"]
            code, value = self.call(args)
            self.assertEqual(code, 0)
            self.assertEqual((value["exitCode"], value["elapsedSeconds"]), (1, 1715))
            self.assertEqual(value["category"], "failure")
            private(path, lines(event("fail", TEST)) + b"broken\n")
            code, value = self.call(args)
            self.assertEqual(code, 1)
            self.assertEqual(value["category"], "diagnostic_unavailable")
            self.assertEqual(value["records"], [])

    def test_cli_bad_arguments_and_paths_never_echo(self):
        for args in [[], ["--help"], ["--unknown", SECRET],
                     ["--events", SECRET, "--stderr", SECRET, "--exit-code", "0", "--elapsed-seconds", "0"],
                     ["--events", SECRET, "--stderr", SECRET, "--exit-code", "256", "--elapsed-seconds", "0"],
                     ["--events", SECRET, "--stderr", SECRET, "--exit-code", "1", "--elapsed-seconds", "NaN"],
                     ["--events", SECRET, "--stderr", SECRET, "--exit-code", "1", "--elapsed-seconds", "86401"],
                     ["--events", SECRET, "--stderr", SECRET, "--exit-code", "1", "--elapsed-seconds", "0"]]:
            with self.subTest(args=args):
                code, value = self.call(args)
                self.assertEqual(code, 1)
                self.assertEqual(value["category"], "diagnostic_unavailable")
                self.assertEqual(value["records"], [])

    def test_isolated_cli_uses_fixed_envelope_and_source_vocabulary(self):
        with tempfile.TemporaryDirectory() as temp:
            path = private(Path(temp) / "events", lines(
                event("output", TEST, Output=SECRET + "\n", OutputType="error"),
                event("fail", TEST + "/" + SECRET), event("fail")))
            stderr = private(Path(temp) / "stderr", SECRET.encode())
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(Path(r.__file__).resolve()),
                 "--events", str(path), "--stderr", str(stderr), "--exit-code", "42",
                 "--elapsed-seconds", "1715"], cwd=temp, capture_output=True, text=True,
                check=False, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertNotIn(SECRET, result.stdout)
            self.assertTrue(result.stdout.startswith("GO_TEST_DIAGNOSTIC "))
            value = json.loads(result.stdout.split(" ", 1)[1])
            self.assertEqual((value["exitCode"], value["elapsedSeconds"]), (42, 1715))
            self.assertEqual(value["records"], [
                {"category": "test_failure", "package": PACKAGE},
                {"category": "test_failure", "package": PACKAGE, "test": TEST}])


class SourceVocabularyTests(unittest.TestCase):
    def test_checked_in_allowlist_matches_exact_go_sources(self):
        allowed = r.load_allowlist()
        self.assertIn(TEST, allowed[PACKAGE])
        self.assertNotIn("TestMain", set().union(*allowed.values()))

    def test_source_tokens_ignore_comments_strings_and_methods(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "go.mod").write_text("module localrmm\n")
            (root / "sample_test.go").write_text('''package sample
// func TestComment(t *testing.T) {}
/* func TestBlock(t *testing.T) {} */
var text = `func TestRawString(t *testing.T) {}`
var quoted = "func TestQuoted(t *testing.T) {}"
func (x Thing) TestMethod(t *testing.T) {}
func TestActual(t *testing.T) { t.Run("TestNested", func(t *testing.T) {}) }
func TestMain(m *testing.M) {}
''')
            value = r.derive_allowlist(root)
            self.assertEqual(value["packages"], {"localrmm": ["TestActual"]})
            before = value["goSourceSha256"]
            with (root / "sample_test.go").open("a") as stream:
                stream.write("\n// edited source\n")
            self.assertNotEqual(before, r.derive_allowlist(root)["goSourceSha256"])

    def test_stale_or_duplicate_allowlist_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "allow.json"
            path.write_text('{"schemaVersion":1,"schemaVersion":1}\n')
            with mock.patch.object(r, "ALLOWLIST", path):
                with self.assertRaises(ValueError):
                    r.load_allowlist()
            value = r.derive_allowlist(r.ROOT)
            value["schemaVersion"] = True
            path.write_text(json.dumps(value))
            with mock.patch.object(r, "ALLOWLIST", path):
                with self.assertRaises(ValueError):
                    r.load_allowlist()
            path.write_text('{"schemaVersion":1}\n')
            with mock.patch.object(r, "ALLOWLIST", path):
                with self.assertRaises(ValueError):
                    r.load_allowlist()

    def test_empty_module_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "go.mod").write_text("")
            with self.assertRaises(ValueError):
                r.derive_allowlist(root)


if __name__ == "__main__":
    unittest.main()
