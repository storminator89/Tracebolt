"""Inert shard contracts: no Go test, native execution or network access."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location("shards", Path(__file__).with_name("go_race_shards.py"))
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)


def events(packages):
    result = []
    for package, tests in sorted(packages.items()):
        result += [{"Action": "start", "Package": package},
                   {"Action": "output", "Package": package, "Output": "PRIVATE runtime value\n"},
                   {"Action": "pass" if tests else "skip", "Package": package, "Elapsed": 1.23456}]
    return result


def raw(records):
    return b"".join(shards.canonical(event) + b"\n" for event in records)


class ShardTests(unittest.TestCase):
    def setUp(self):
        self.packages = {"localrmm/a": True, "localrmm/b": True, "localrmm/c": False, "localrmm/new": True}
        self.groups = shards.partition(self.packages, {"localrmm/a": 20, "localrmm/b": 10})
        self.plan = {"schemaVersion": 1, "commit": "a" * 40, "runId": "123", "runAttempt": "1",
                     "goSourceSha256": "b" * 64, "packages": self.packages, "shards": self.groups}
        self.reports = [shards.make_report(self.plan, i, raw(events({p: self.packages[p] for p in group})), 0)
                        for i, group in enumerate(self.groups)]
        self.needs = {name: {"result": "success", "outputs": {}} for name in shards.NEEDS}

    def test_discovery_retains_test_and_no_test_and_new_packages(self):
        data = b"localrmm/new tests\nlocalrmm/c none\nlocalrmm/a tests\n"
        self.assertEqual(shards.package_rows(data, self.packages), {"localrmm/a": True, "localrmm/c": False, "localrmm/new": True})

    def test_bad_discovery_fails(self):
        for data in (b"", b"localrmm/a tests", b"localrmm/a tests\nlocalrmm/a tests\n", b"localrmm/foreign tests\n",
                     b"localrmm/a maybe\n", b"localrmm/a tests extra\n", b"../private tests\n", b"localrmm/a\ttests\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                shards.package_rows(data, self.packages)

    def test_partition_is_complete_deterministic_and_weights_never_select(self):
        expected = self.groups
        for packages in (dict(reversed(list(self.packages.items()))), self.packages):
            self.assertEqual(shards.partition(packages, {"localrmm/a": 20, "localrmm/b": 10, "localrmm/removed": 999999}), expected)
        self.assertEqual(sorted(p for g in expected for p in g), sorted(self.packages))
        shards.validate_partition(self.packages, shards.partition(self.packages, {}))

    def test_partition_rejects_missing_extra_duplicate_overlap_and_malformed(self):
        bad = [[], {}, self.groups[:-1], self.groups + [[]], [["localrmm/a"]] * 3,
               [["localrmm/a", "localrmm/a"], ["localrmm/b"], ["localrmm/c", "localrmm/new"]],
               [["localrmm/a"], ["localrmm/b"], ["localrmm/c", "localrmm/new", "localrmm/foreign"]],
               [[None], [], []], [["localrmm/new", "localrmm/a"], ["localrmm/b"], ["localrmm/c"]]]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                shards.validate_partition(self.packages, value)

    def test_weights_schema_finite_integer_positive_bounded(self):
        value = {"schemaVersion": 1, "sourceRun": "38058537360/114231878636", "milliseconds": {"localrmm/a": 100}}
        self.assertEqual(shards.weights(shards.canonical(value)), {"localrmm/a": 100})
        for weight in (True, -1, 0, 900001, 1.1, "100", None):
            value["milliseconds"]["localrmm/a"] = weight
            with self.subTest(weight=weight), self.assertRaises(ValueError):
                shards.weights(shards.canonical(value))
        for data in (b'{}', b'null', b'{"milliseconds":{"localrmm/a":NaN}}', b'{"schemaVersion":1,"schemaVersion":1}'):
            with self.assertRaises(ValueError):
                shards.weights(data)
        self.assertEqual(len(shards.weights(shards.WEIGHTS.read_bytes())), 20)

    def test_exact_go_list_and_race_commands(self):
        self.assertEqual(shards.LIST_COMMAND, ["go", "list", "-race", "-buildvcs=false", "-f", "{{.ImportPath}} {{if or .TestGoFiles .XTestGoFiles}}tests{{else}}none{{end}}", "./..."])
        self.assertEqual(shards.command_for(["localrmm/a", "localrmm/b"]), ["go", "test", "-race", "-json", "-p", "1", "-buildvcs=false", "localrmm/a", "localrmm/b", "-skip", "^(TestIndependentPackageStoreDenseCapacityAndActualIngress|TestGuidedThreeBinaryEnrollmentAndForeground)$", "-count=1", "-timeout=15m"])
        for packages in ([], ["./..."], ["-run=none"]):
            with self.assertRaises(ValueError):
                shards.command_for(packages)

    def test_actual_go_metadata_includes_race_only_packages_and_tests(self):
        # Metadata only: no package is compiled or executed, no dependencies
        # downloaded. Match the race build context rather than default tags.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text("module localrmm\n\ngo 1.27.1\n")
            files = {
                "base/base.go": "package base\n",
                "base/race_test.go": "//go:build race\n\npackage base\nimport \"testing\"\nfunc TestRace(t *testing.T) {}\n",
                "raceonly/only.go": "//go:build race\n\npackage raceonly\n",
                "norace/only.go": "//go:build !race\n\npackage norace\n",
            }
            for name, source in files.items():
                path = root / name; path.parent.mkdir(exist_ok=True); path.write_text(source)
            env = {**os.environ, "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
                   "GOFLAGS": "", "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "1"}
            allowed = {"localrmm/base", "localrmm/raceonly", "localrmm/norace"}
            def metadata(command):
                result = shards.subprocess.run(command, cwd=root, env=env, stdout=shards.subprocess.PIPE,
                                               stderr=shards.subprocess.PIPE, timeout=30, check=True)
                return shards.package_rows(result.stdout, allowed)
            race = metadata(shards.LIST_COMMAND)
            plain = metadata([arg for arg in shards.LIST_COMMAND if arg != "-race"])
            self.assertEqual(race, {"localrmm/base": True, "localrmm/raceonly": False})
            self.assertEqual(plain, {"localrmm/base": False, "localrmm/norace": False})
            self.assertEqual(sorted(p for group in shards.partition(race, {}) for p in group), sorted(race))

    def test_normalization_withholds_output_subtests_paths_and_stderr(self):
        records = events(self.packages)
        records.insert(1, {"Action": "output", "Package": "localrmm/a", "Test": "TestFixture/PRIVATE_SUBTEST", "Output": "PRIVATE_TOKEN"})
        result = shards.normalize(raw(records), self.packages)
        rendered = shards.canonical(result)
        self.assertNotIn(b"PRIVATE", rendered)
        self.assertEqual(len(result), len(self.packages))
        self.assertEqual(result[0], {"package": "localrmm/a", "status": "pass", "elapsedSeconds": 1.235})

    def test_root_skip_is_legitimate_package_skip_with_tests_is_not(self):
        records = events({"localrmm/a": True})
        records.insert(1, {"Action": "skip", "Package": "localrmm/a", "Test": "TestOptionalNative", "Elapsed": 0})
        shards.normalize(raw(records), {"localrmm/a": True})
        records[-1]["Action"] = "skip"
        with self.assertRaises(ValueError):
            shards.normalize(raw(records), {"localrmm/a": True})

    def test_fails_on_any_test_build_or_foreign_failure(self):
        for failure in ({"Action": "fail", "Package": "localrmm/a", "Test": "TestFixture"},
                        {"Action": "fail", "Package": "localrmm/foreign"},
                        {"Action": "build-fail", "ImportPath": "example.org/dependency"}):
            records = events(self.packages); records.insert(1, failure)
            with self.assertRaises(ValueError):
                shards.normalize(raw(records), self.packages)

    def test_completion_failures_missing_duplicate_reordered_unknown(self):
        data = events({"localrmm/a": True})
        for records in (data[:-1], data[1:], data + [data[-1]], [data[0], data[0], *data[1:]],
                        [data[-1], *data[:-1]], data + [{"Action": "start", "Package": "localrmm/foreign"}],
                        [*data[:-1], {"Action": "pass", "Package": "localrmm/a"}]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                shards.normalize(raw(records), {"localrmm/a": True})

    def test_malformed_duplicate_json_keys_invalid_numbers_and_truncation_fail(self):
        for data in (b"", b"null\n", b"[]\n", b'{}\n', b'{"Action":"start","Action":"pass"}\n',
                     b'{"Action":"start","Package":"localrmm/a","Elapsed":NaN}\n',
                     raw(events(self.packages))[:-1], raw(events(self.packages)) + b"private text\n"):
            with self.subTest(data=data[:30]), self.assertRaises((ValueError, TypeError)):
                shards.normalize(data, self.packages)
        for elapsed in (True, -1, 86401, "12", float("inf")):
            records = events({"localrmm/a": True}); records[-1]["Elapsed"] = elapsed
            with self.assertRaises(ValueError):
                shards.normalize(("\n".join(json.dumps(e) for e in records) + "\n").encode(), {"localrmm/a": True})

    def test_nonzero_exit_never_creates_success_evidence(self):
        for code in (-9, 1, 2, 124, 255, True, "0"):
            with self.subTest(code=code), self.assertRaises(ValueError):
                shards.make_report(self.plan, 0, raw(events({p: self.packages[p] for p in self.groups[0]})), code)

    def test_report_round_trip_covers_all_packages(self):
        self.assertEqual(shards.verify_reports(self.plan, self.reports), len(self.packages))
        self.assertEqual(shards.verify_reports(self.plan, list(reversed(self.reports))), len(self.packages))

    def test_missing_duplicate_extra_or_malformed_reports_fail(self):
        for value in (None, [], self.reports[:-1], self.reports + [self.reports[0]],
                      [self.reports[0]] * 3, [None] * 3):
            with self.subTest(value=value), self.assertRaises(ValueError):
                shards.verify_reports(self.plan, value)

    def test_report_binding_rejects_foreign_source_commit_run_attempt_and_plan(self):
        for key, value in (("commit", "c" * 40), ("runId", "999"), ("runAttempt", "2"),
                           ("goSourceSha256", "c" * 64), ("planSha256", "c" * 64), ("exitCode", 1),
                           ("exitCode", False), ("schemaVersion", True), ("shard", True)):
            reports = copy.deepcopy(self.reports); reports[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                shards.verify_reports(self.plan, reports)

    def test_report_records_reject_missing_duplicate_unexpected_or_unbounded_fields(self):
        for mutate in (lambda x: x.clear(), lambda x: x.append(x[0]), lambda x: x[0].update(package="localrmm/foreign"),
                       lambda x: x[0].update(status="fail"), lambda x: x[0].update(Output="SECRET"),
                       lambda x: x[0].update(elapsedSeconds=1.23456), lambda x: x[0].update(elapsedSeconds=True)):
            reports = copy.deepcopy(self.reports); mutate(reports[0]["packages"])
            with self.assertRaises(ValueError):
                shards.verify_reports(self.plan, reports)

    def test_all_prerequisites_must_explicitly_succeed(self):
        shards.check_needs(shards.canonical(self.needs))
        for status in ("failure", "cancelled", "skipped", "pending", None, True):
            for name in self.needs:
                needs = copy.deepcopy(self.needs); needs[name]["result"] = status
                with self.subTest(status=status, name=name), self.assertRaises(ValueError):
                    shards.check_needs(shards.canonical(needs))
        for value in ({}, {"go-race": {"result": "success"}}, {**self.needs, "extra": {"result": "success"}}):
            with self.assertRaises(ValueError):
                shards.check_needs(shards.canonical(value))

    def test_artifact_layout_exact_names_current_attempt_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for report in self.reports:
                folder = root / f"go-race-1-{report['shard']}"; folder.mkdir()
                (folder / "completion.json").write_bytes(shards.canonical(report))
            self.assertEqual(shards.load_reports(root, "1"), self.reports)
            with self.assertRaises(ValueError):
                shards.load_reports(root, "2")
            (root / "extra").mkdir()
            with self.assertRaises(ValueError):
                shards.load_reports(root, "1")
            (root / "extra").rmdir()
            path = root / "go-race-1-0" / "completion.json"
            original = path.read_bytes(); path.unlink(); path.symlink_to(root / "go-race-1-1" / "completion.json")
            with self.assertRaises(ValueError):
                shards.load_reports(root, "1")
            path.unlink(); path.write_bytes(original)
            (root / "go-race-1-0" / "raw.jsonl").touch()
            with self.assertRaises(ValueError):
                shards.load_reports(root, "1")

    def test_provenance_and_target_discovery(self):
        env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.dict(os.environ, env, clear=True), patch.object(shards.reporter, "load_allowlist", return_value=self.packages), \
             patch.object(shards.reporter, "derive_allowlist", return_value={"goSourceSha256": "b" * 64}), \
             patch.object(shards, "checked_capture", side_effect=[b"a" * 40 + b"\n", b"linux\namd64\n", b"localrmm/a tests\nlocalrmm/b tests\nlocalrmm/c none\n"]):
            plan, _ = shards.discover()
            self.assertEqual(plan["commit"], "a" * 40)
            self.assertEqual(len(plan["packages"]), 3)
        for bad in ({}, {**env, "GITHUB_RUN_ATTEMPT": "0"}, {**env, "GITHUB_SHA": "PRIVATE"}):
            with self.assertRaises(ValueError):
                shards.context(bad)
        for answers in ([b"c" * 40 + b"\n"], [b"a" * 40 + b"\n", b"windows\namd64\n"]):
            with patch.dict(os.environ, env, clear=True), patch.object(shards.reporter, "load_allowlist", return_value=self.packages), \
                 patch.object(shards, "checked_capture", side_effect=answers), self.assertRaises(ValueError):
                shards.discover()

    def test_source_digest_failure_is_fatal_before_go_discovery(self):
        with patch.object(shards.reporter, "load_allowlist", side_effect=ValueError("PRIVATE")), \
             patch.object(shards, "checked_capture") as capture:
            with self.assertRaises(ValueError):
                shards.discover()
            capture.assert_not_called()

    def test_cli_failure_output_is_finite_and_needs_fail_before_go(self):
        for argv in (["--invalid", "SECRET"], ["--shard", "4"], ["--verify", "/PRIVATE"]):
            output = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), patch.object(shards, "discover") as discover, contextlib.redirect_stdout(output):
                self.assertEqual(shards.main(argv), 1)
                discover.assert_not_called()
            self.assertNotIn("SECRET", output.getvalue()); self.assertNotIn("PRIVATE", output.getvalue())
        with patch.dict(os.environ, {"TRACEBOLT_GO_NEEDS": shards.canonical(self.needs).decode()}, clear=True), patch.object(shards, "discover") as discover:
            self.assertEqual(shards.main(["--check-needs"]), 0); discover.assert_not_called()

    def test_runner_mocked_process_nonzero_and_normalized_success(self):
        # Popen is inert; only fixtures are written. No Go/native code executes.
        for status in (0, 2):
            with tempfile.TemporaryDirectory() as tmp:
                destination = Path(tmp) / "report" / "completion.json"
                def start(command, **kwargs):
                    kwargs["stdout"].write(raw(events({p: self.packages[p] for p in self.groups[0]})))
                    kwargs["stdout"].flush()
                    kwargs["stderr"].write(b"PRIVATE STDERR"); kwargs["stderr"].flush()
                    process = Mock(); process.wait.side_effect = [shards.subprocess.TimeoutExpired(command, 60), status]
                    return process
                output = io.StringIO()
                with patch.dict(os.environ, {"RUNNER_TEMP": tmp}), patch.object(shards.subprocess, "Popen", side_effect=start), \
                     patch.object(shards.reporter, "main", return_value=0), contextlib.redirect_stdout(output):
                    if status:
                        with self.assertRaises(ValueError):
                            shards.run_shard(self.plan, self.packages, 0, destination)
                        self.assertFalse(destination.exists())
                    else:
                        shards.run_shard(self.plan, self.packages, 0, destination)
                        self.assertEqual(json.loads(destination.read_bytes()), self.reports[0])
                self.assertIn("GO_RACE_PROGRESS shard=0", output.getvalue())
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertEqual(list(Path(tmp).glob("go-race-*")), [])


if __name__ == "__main__":
    unittest.main()
