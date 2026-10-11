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


def inventory_events(names):
    package = shards.INVENTORY_PACKAGE
    result = [{"Action": "start", "Package": package}]
    for name in names:
        result += [{"Action": "run", "Package": package, "Test": name},
                   {"Action": "output", "Package": package, "Test": name, "Output": "PRIVATE fixture\n"},
                   {"Action": "pass", "Package": package, "Test": name, "Elapsed": 1}]
    result += [{"Action": "pass", "Package": package, "Elapsed": 12.345}]
    return result


class ShardTests(unittest.TestCase):
    def setUp(self):
        self.packages = {"localrmm/a": True, "localrmm/b": True, "localrmm/c": False, "localrmm/new": True}
        self.groups = shards.partition(self.packages, {"localrmm/a": 20, "localrmm/b": 10})
        self.plan = {"schemaVersion": 1, "commit": "a" * 40, "runId": "123", "runAttempt": "1",
                     "goSourceSha256": "b" * 64, "packages": self.packages, "shards": self.groups, "inventoryTests": {}}
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
        with patch.dict(os.environ, env, clear=True), patch.object(shards.reporter, "load_allowlist", return_value={**self.packages, shards.INVENTORY_PACKAGE: frozenset()}), \
             patch.object(shards.reporter, "derive_allowlist", return_value={"goSourceSha256": "b" * 64}), \
             patch.object(shards, "inventory_tests", return_value={}), \
             patch.object(shards, "checked_capture", side_effect=[b"a" * 40 + b"\n", b"linux\namd64\n", b"localrmm/a tests\nlocalrmm/b tests\nlocalrmm/c none\nlocalrmm/internal/enrollmentstore tests\n"]):
            plan, _ = shards.discover()
            self.assertEqual(plan["commit"], "a" * 40)
            self.assertEqual(len(plan["packages"]), 4)
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


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.allowed = shards.reporter.load_allowlist()
        self.groups = shards.inventory_tests(self.allowed)
        self.moved = sorted(name for names in self.groups.values() for name in names)
        self.package = shards.INVENTORY_PACKAGE
        self.plan = {"schemaVersion": 1, "commit": "a" * 40, "runId": "123", "runAttempt": "1",
                     "goSourceSha256": "b" * 64, "packages": {self.package: True},
                     "shards": [[self.package], [], []], "inventoryTests": self.groups}
        self.raw = {group: raw(inventory_events(names)) for group, names in self.groups.items()}
        self.default = raw(events({self.package: True}))

    def test_exact_source_partition_is_complete_disjoint_and_keeps_future_defaults(self):
        names = self.allowed[self.package]
        default = set(names) - set(self.moved)
        self.assertEqual({group: len(roots) for group, roots in self.groups.items()},
                         {"services": 14, "software": 14, "processes": 16, "network-context": 13})
        self.assertEqual(default | set(self.moved), names)
        self.assertEqual(len(self.moved), len(set(self.moved)))
        self.assertFalse(default.intersection(self.moved))
        command = shards.command_for([self.package], excluded=self.moved)
        self.assertNotIn("-run", command)
        skip = command[command.index("-skip") + 1]
        for name in names:
            self.assertEqual(bool(shards.re.fullmatch(skip, name)),
                             name in self.moved or bool(shards.re.fullmatch(shards.SKIP, name)))
        for name in ("TestNewUnrelated", "ExampleNew", "FuzzNew", self.moved[0] + "New"):
            self.assertIsNone(shards.re.fullmatch(skip, name))
        for group, prefix in shards.INVENTORY_PREFIXES.items():
            new = prefix + "New"
            changed = {**self.allowed, self.package: names | {new}}
            self.assertIn(new, shards.inventory_tests(changed)[group])
            self.assertNotIn(new, self.groups[group])

    def test_selected_commands_keep_race_count_budget_and_exact_roots(self):
        for names in self.groups.values():
            command = shards.command_for([self.package], selected=names)
            for flag in ("-race", "-json", "-count=1", "-timeout=15m"):
                self.assertIn(flag, command)
            pattern = command[command.index("-run") + 1]
            self.assertEqual({name for name in self.allowed[self.package] if shards.re.fullmatch(pattern, name)}, set(names))
        with self.assertRaises(ValueError):
            shards.command_for(["localrmm/other"], excluded=self.moved)
        with self.assertRaises(ValueError):
            shards.command_for([self.package], selected=self.moved, excluded=self.moved)
        with self.assertRaises(ValueError):
            shards.inventory_tests({self.package: {"TestUnrelated"}})

    def test_inventory_requires_all_roots_once_passed_and_no_default_overlap(self):
        for group, names in self.groups.items():
            with self.subTest(group=group):
                data = inventory_events(names)
                shards.normalize(raw(data), {self.package: True}, names)
                missing = data[:1] + data[4:]
                skipped = copy.deepcopy(data); skipped[3]["Action"] = "skip"
                duplicate = data[:4] + data[1:4] + data[4:]
                foreign = copy.deepcopy(data); foreign[1]["Test"] = "TestOther"
                failed = copy.deepcopy(data); failed[3]["Action"] = "fail"
                skipped_child = data[:2] + [{"Action": "skip", "Package": self.package,
                                             "Test": names[0] + "/child"}] + data[2:]
                for records in (missing, skipped, duplicate, foreign, failed, skipped_child):
                    with self.assertRaises(ValueError):
                        shards.normalize(raw(records), {self.package: True}, names)
                with self.assertRaises(ValueError):
                    shards.normalize(raw(data), {self.package: True}, excluded_tests=self.moved)

    def test_aggregate_requires_all_exact_source_bound_inventory_completions(self):
        report = shards.make_report(self.plan, 0, self.default, 0, self.raw)
        reports = [report] + [shards.make_report(self.plan, i, b"", 0) for i in (1, 2)]
        self.assertEqual(shards.verify_reports(self.plan, reports), 1)
        self.assertNotIn(b"PRIVATE", shards.canonical(report))
        for group in self.groups:
            with self.subTest(group=group):
                for change in (lambda r: r["inventory"].pop(group),
                               lambda r: r["inventory"][group].update(status="skip"),
                               lambda r: r["inventory"][group]["tests"].pop(),
                               lambda r: r["inventory"][group]["tests"].append(self.groups[group][0]),
                               lambda r: r["inventory"][group].update(Output="PRIVATE"),
                               lambda r: r["inventory"][group].update(elapsedSeconds=True)):
                    changed = copy.deepcopy(reports); change(changed[0])
                    with self.assertRaises(ValueError):
                        shards.verify_reports(self.plan, changed)
                incomplete = {key: value for key, value in self.raw.items() if key != group}
                with self.assertRaises(ValueError):
                    shards.make_report(self.plan, 0, self.default, 0, incomplete)
                changed_plan = copy.deepcopy(self.plan)
                changed_plan["inventoryTests"][group].append(shards.INVENTORY_PREFIXES[group] + "New")
                with self.assertRaises(ValueError):
                    shards.verify_reports(changed_plan, reports)

    def test_runner_splits_only_enrollmentstore_and_fails_closed_per_invocation(self):
        plan = copy.deepcopy(self.plan)
        plan["packages"]["localrmm/other"] = True
        plan["shards"][0].append("localrmm/other")
        for fail_group in (None, "packages", "default", *self.groups):
            with tempfile.TemporaryDirectory() as tmp:
                destination = Path(tmp) / "report" / "completion.json"
                commands = []
                def start(command, **kwargs):
                    commands.append(command)
                    if self.package not in command:
                        group, data = "packages", raw(events({"localrmm/other": True}))
                    elif "-run" not in command:
                        group, data = "default", self.default
                    else:
                        group = next(group for group, names in self.groups.items()
                                     if command[command.index("-run") + 1] == shards.exact_tests(names))
                        data = self.raw[group]
                    kwargs["stdout"].write(data); kwargs["stdout"].flush()
                    process = Mock(); process.wait.return_value = 2 if group == fail_group else 0
                    return process
                output = io.StringIO()
                with patch.dict(os.environ, {"RUNNER_TEMP": tmp}), \
                     patch.object(shards.subprocess, "Popen", side_effect=start), \
                     patch.object(shards.reporter, "main", return_value=0) as diagnose, contextlib.redirect_stdout(output):
                    if fail_group:
                        with self.assertRaises(ValueError):
                            shards.run_shard(plan, self.allowed, 0, destination)
                        self.assertFalse(destination.exists())
                        expected = ["packages", "default", *self.groups].index(fail_group) + 1
                        self.assertEqual(len(commands), expected)
                    else:
                        shards.run_shard(plan, self.allowed, 0, destination)
                        self.assertEqual(len(commands), 2 + len(self.groups))
                        report = json.loads(destination.read_bytes())
                        reports = [report] + [shards.make_report(plan, i, b"", 0) for i in (1, 2)]
                        self.assertEqual(shards.verify_reports(plan, reports), 2)
                    self.assertEqual(diagnose.call_count, len(commands))
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertEqual(list(Path(tmp).glob("go-race-*")), [])


if __name__ == "__main__":
    unittest.main()
