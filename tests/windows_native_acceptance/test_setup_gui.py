"""Portable/injected checks only. Never build, launch a GUI or invoke Windows APIs."""
from contextlib import ExitStack, redirect_stdout
import copy
import io
import subprocess
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("setup_gui_runner", Path(__file__).with_name("run_setup_gui.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

def allowed():
    source = "a" * 40
    env = {"TRACEBOLT_SETUP_SOURCE": source, "GITHUB_SHA": source, "TRACEBOLT_SETUP_PROFILE": runner.PROFILE, "TRACEBOLT_SETUP_CASE": "install-uninstall", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_REPOSITORY_OWNER": "storminator89", "GITHUB_ACTOR": "storminator89", "GITHUB_TRIGGERING_ACTOR": "storminator89", "GITHUB_REPOSITORY_OWNER_ID": "30489872", "GITHUB_ACTOR_ID": "30489872", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ID": "123"}
    env.update({"TRACEBOLT_SETUP_APPROVE_" + a: "true" for a in runner.APPROVALS})
    return env

def report(which="install-uninstall"):
    return {"setupSHA256":"c"*64,"serviceSHA256":"d"*64,"driverSHA256":"b"*64,"sourceInputsSHA256":"e"*64,"runID":"123","machine":"fresh-vm","schema": "tracebolt.windows-setup-acceptance.v1", "source": "a" * 40, "case": which, "status": "passed_packaged_gui_subset", "stage": "completed", "reason": "none", "approvalValidated": True, "nativeActionsAttempted": True, "checks": {k: True for k in runner.CHECKS[which]}, "coverage": {k: False for k in runner.FALSE_COVERAGE}, "startup": "absent" if which in runner.NORMAL else "disabled", "frames": 2 if which in runner.NORMAL else 0, "platformDisposalRequired": True}

class SetupPreNativeDiagnostics(unittest.TestCase):
    def test_each_pre_native_failure_is_finite_private_and_stops_before_launch(self):
        stages = ["authorization", "checkout", "toolchain", "dependencies", "staging",
                  "package-build", "package-validation", "driver-build", "source-recheck", "run-binding"]
        self.assertEqual(set(stages), runner.PRE_NATIVE_STAGES)
        secret = "DO_NOT_EXPORT_PATH_COMMAND_ENV_BODY"
        errors = [runner.shared.Rejected(secret), OSError(secret),
                  subprocess.CalledProcessError(9, [secret], output=secret, stderr=secret)]
        for failed in stages:
            for error in errors:
                with self.subTest(stage=failed, error=type(error).__name__), tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                    events = []
                    def step(stage, value=None):
                        events.append(stage)
                        if stage == failed:
                            raise error
                        return value
                    checkout_stages = iter(["checkout", "source-recheck"])
                    process_stages = iter(["dependencies", "package-build", "driver-build"])
                    stack.enter_context(mock.patch.object(runner, "authorize", side_effect=lambda env: step("authorization", "a" * 40)))
                    stack.enter_context(mock.patch.object(runner.shared, "child_environment", return_value={}))
                    stack.enter_context(mock.patch.object(runner.shared, "verify_checkout", side_effect=lambda *a: step(next(checkout_stages))))
                    stack.enter_context(mock.patch.object(runner.shared, "verify_go", side_effect=lambda *a: step("toolchain")))
                    stack.enter_context(mock.patch.object(runner.shared, "successful", side_effect=lambda *a: step(next(process_stages))))
                    stack.enter_context(mock.patch.object(runner.tempfile, "mkdtemp", side_effect=lambda **kw: step("staging", str(Path(tmp) / "stage"))))
                    stack.enter_context(mock.patch.object(runner, "read_public_package", return_value={}))
                    stack.enter_context(mock.patch.object(runner, "validate_public_package", side_effect=lambda *a: step("package-validation")))
                    stack.enter_context(mock.patch.object(runner, "bind_run", side_effect=lambda *a: step("run-binding", {})))
                    native = stack.enter_context(mock.patch.object(runner.shared, "command", side_effect=AssertionError("native forbidden")))
                    out = stack.enter_context(redirect_stdout(io.StringIO()))
                    env = allowed()
                    env.update(RUNNER_TEMP=tmp, GITHUB_OUTPUT=str(Path(tmp) / "outputs"), GITHUB_TOKEN=secret)
                    self.assertEqual(runner.main(["--run-native"], env), 1)
                    self.assertEqual(events, stages[:stages.index(failed) + 1])
                    native.assert_not_called()
                    self.assertEqual(out.getvalue(), "FAIL: packaged Setup gate; stage=" + failed + "; reason=pre_native_failed; private output withheld; inspect assigned VM/disposal status.\n")
                    self.assertNotIn(secret, out.getvalue())
                    self.assertEqual(list(Path(tmp).iterdir()), [])  # No success/report/package artifacts.

    def test_invalid_labels_and_unclassified_errors_cannot_export_details(self):
        secret = "DO_NOT_EXPORT"
        for value in (secret, "", None, [], {"stage": secret}):
            with self.subTest(value=value), self.assertRaises(runner.shared.Rejected):
                runner.PreNativeFailure(value)
        error = runner.PreNativeFailure("authorization")
        error.stage = secret  # Even a corrupted internal label is not exported.
        with mock.patch.object(runner, "run_native", side_effect=error), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(runner.main(["--run-native"], allowed()), 1)
        self.assertIn("stage=unknown; reason=pre_native_failed", out.getvalue())
        self.assertNotIn(secret, out.getvalue())
        with mock.patch.object(runner, "run_native", side_effect=RuntimeError(secret)), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(runner.main(["--run-native"], allowed()), 1)
        self.assertEqual(out.getvalue(), "FAIL: packaged Setup gate or evidence rejected; private output withheld; inspect assigned VM/disposal status.\n")

class SetupGate(unittest.TestCase):
    def validate(self, r):
        return runner.validate_report(json.dumps(r).encode(), "a" * 40, r["case"])
    def test_each_scope_and_binding_required_before_any_process(self):
        env = allowed()
        self.assertEqual(runner.authorize(env), "a" * 40)
        for key in env:
            bad = dict(env)
            bad.pop(key)
            with self.subTest(key=key), self.assertRaises(runner.shared.Rejected):
                runner.authorize(bad)
        for name in runner.APPROVALS:
            for value in ("false", "True", "1", ""):
                bad = dict(env)
                bad["TRACEBOLT_SETUP_APPROVE_" + name] = value
                with mock.patch.object(runner.shared, "verify_checkout") as checkout:
                    with self.assertRaises(runner.shared.Rejected):
                        runner.run_native(bad)
                    checkout.assert_not_called()
    def test_four_distinct_passes_no_cross_case_invention(self):
        for case in runner.CHECKS:
            r = report(case)
            self.assertEqual(self.validate(r), r)
            for check in r["checks"]:
                bad = copy.deepcopy(r)
                bad["checks"][check] = False
                with self.assertRaises(runner.shared.Rejected): self.validate(bad)
            for field in ("startup", "frames"):
                bad = copy.deepcopy(r)
                bad[field] = "inspection_required" if field == "startup" else True
                with self.assertRaises(runner.shared.Rejected): self.validate(bad)
    def test_no_claim_for_untested_or_sensitive_evidence(self):
        for key in runner.FALSE_COVERAGE:
            r = report()
            r["coverage"][key] = True
            with self.assertRaises(runner.shared.Rejected): self.validate(r)
        r = report()
        r["rawConsole"] = "private material"
        with self.assertRaises(runner.shared.Rejected): self.validate(r)
        raw = json.dumps(report()).encode()
        with self.assertRaises(runner.shared.Rejected):
            runner.parse_controller(b"setup-gui-report=" + raw + b"\nsetup-gui-report=" + raw, "a" * 40, "install-uninstall")
        with self.assertRaises(runner.shared.Rejected):
            runner.validate_report(raw.replace(b'"stage": "completed"', b'"stage":"completed","stage":"completed"'), "a" * 40, "install-uninstall")
    def test_desktop_block_cannot_claim_native_or_disabled(self):
        r = report()
        r.update(status="blocked", stage="desktop", reason="desktop_unavailable", nativeActionsAttempted=False, startup="inspection_required", frames=0, platformDisposalRequired=False)
        r["checks"] = dict.fromkeys(r["checks"], False)
        self.validate(r)
        r["nativeActionsAttempted"] = True
        with self.assertRaises(runner.shared.Rejected): self.validate(r)
    def test_finite_go_python_contract_parity(self):
        source = (ROOT / "internal/windowsacceptance/setupgate/gate.go").read_text()
        for name in runner.APPROVALS:
            self.assertIn('"' + name + '"', source)
        for name in runner.FALSE_COVERAGE | runner.STAGES | set(runner.CHECKS):
            self.assertIn('"' + name + '"', source)
        for checks in runner.CHECKS.values():
            for name in checks: self.assertIn('"' + name + '"', source)
    def test_fresh_failure_labels_are_finite_and_inert(self):
        for stage in ("fresh-environment", "fresh-layout", "fresh-service", "fresh-program-files", "fresh-program-data"):
            r = report()
            r.update(status="blocked", stage=stage, reason="operation_failed", nativeActionsAttempted=False,
                     startup="inspection_required", frames=0, platformDisposalRequired=False)
            r["checks"] = dict.fromkeys(r["checks"], False)
            self.validate(r)
            for key, value in (("stage", "private path or error"), ("nativeActionsAttempted", True),
                               ("frames", 1), ("platformDisposalRequired", True)):
                bad = copy.deepcopy(r)
                bad[key] = value
                with self.subTest(stage=stage, key=key), self.assertRaises(runner.shared.Rejected):
                    self.validate(bad)

    def test_controller_restores_trusted_drive_before_layout_and_mutation(self):
        driver = (ROOT / "cmd/windows-service/setup_acceptance_native_windows_test.go").read_text()
        controller = driver.split("func setupGUIController(", 1)[1]
        restore = "setupgate.PrepareControllerEnvironment(windows.GetSystemWindowsDirectory, os.Setenv)"
        self.assertLess(controller.index("setupInteractiveDesktop()"), controller.index(restore))
        self.assertLess(controller.index(restore), controller.index("windowsservice.ResolveLayout()"))
        self.assertLess(controller.index("setupgate.CheckFreshPrerequisites("), controller.index("r.NativeActionsAttempted = true"))
        self.assertIn("if !errors.Is(e, os.ErrNotExist)", driver)
        for stage in ("fresh-environment", "fresh-layout", "fresh-service", "fresh-program-files", "fresh-program-data"):
            stages = (ROOT / "internal/windowsacceptance/setupgate/environment.go").read_text()
            self.assertIn('"' + stage + '"', stages)

    def test_workflow_manual_only_false_defaults_and_fresh_matrix(self):
        path = ROOT / ".github/workflows/windows-setup-acceptance.yml"
        text = path.read_text()
        self.assertIn("workflow_dispatch:", text)
        for event in ("push:", "pull_request:", "schedule:", "workflow_call:", "workflow_run:"):
            self.assertNotIn(event, text)
        self.assertEqual(text.count("default: false"), len(runner.APPROVALS))
        for case in runner.CHECKS: self.assertIn(case, text)
        for binding in ("github.actor_id == '30489872'", "github.repository_owner_id == '30489872'", "github.run_attempt == 1", "runs-on: windows-2025", "report_validated == 'true'", "persist-credentials: false"):
            self.assertIn(binding, text)
        for other in (ROOT / ".github/workflows").glob("*.yml"):
            if other != path:
                self.assertNotIn("tracebolt_setup_native", other.read_text())
    def test_actual_packaged_gui_not_coordinator_substitute(self):
        driver = (ROOT / "cmd/windows-service/setup_acceptance_native_windows_test.go").read_text()
        ui = (ROOT / "cmd/windows-service/setup_acceptance_ui_windows_test.go").read_text()
        for forbidden in ("installReadObservation(", "setupWizardInstall(", "ApplyStop(", "ApplyUninstall(", "ConfigureWindowsCapabilities(", "Provision(", "ResumeService("):
            self.assertNotIn(forbidden, driver + ui)
        for required in ("setupLaunch(ctx, exe)", "f.Approve(fp, comparison)", "setupDisabled(ctx, l)", "Service deletion is pending. Waiting for SCM to confirm absence.", "windows.QueryServiceStatus(hold, &status)", "before.DeadlineAt", "receipt.ReadSetup.GrantDigests", "v.Extensions.V5Frames >= 2"):
            self.assertIn(required, driver)
        self.assertIn("windows.CREATE_SUSPENDED", ui)
        self.assertLess(ui.index("windows.AssignProcessToJobObject"), ui.index("windows.ResumeThread"))
        self.assertIn('"WriteConsoleInputW"', ui)
        self.assertIn('"ReadConsoleOutputCharacterW"', ui)
        self.assertIn('"SendMessageTimeoutW"', ui)
        self.assertNotIn('"GetWindowTextW"', ui)
        self.assertIn("setupInteractiveDesktop()", ui)
        self.assertIn('strings.ReplaceAll(setupText(setupControl(g.window, 2)), "&", "") == "Close"', ui)
        for name in ("setup_acceptance_native_windows_test.go", "setup_acceptance_ui_windows_test.go"):
            self.assertTrue((ROOT / "cmd/windows-service" / name).read_text().startswith("//go:build windows && tracebolt_setup_native\n"))
    def test_sensitive_native_child_environment_is_not_forwarded(self):
        env = allowed()
        env.update(COMPUTERNAME="fresh-machine", GITHUB_TOKEN="secret", TRACEBOLT_SETUP_OTHER="inert", SystemDrive="Z:", SYSTEMDRIVE="Y:", ProgramData="private", ProgramFiles="private")
        with mock.patch.object(runner.shared, "binary_digest", side_effect=["b" * 64, "c" * 64, "d" * 64, "e" * 64]):
            result = runner.bind_run(env, "a" * 40, Path("driver.exe"), Path("Setup.exe"), Path("service.exe"), "fresh-machine", 1900000000)
        self.assertNotIn("GITHUB_TOKEN", result)
        self.assertNotIn("TRACEBOLT_SETUP_OTHER", result)
        for key in ("SystemDrive", "SYSTEMDRIVE", "ProgramData", "ProgramFiles"):
            self.assertNotIn(key, result)
        self.assertEqual(result["TRACEBOLT_SETUP_SETUP_SHA256"], "c" * 64)

def fake_pe(_raw, _version, _source, _arch, *, setup):
    return {"architecture": "amd64", "subsystem": "windows-gui" if setup else "windows-console", "uac": "requireAdministrator" if setup else "asInvoker", "authenticode": "unsigned", "resourcesVerified": True}

def public_fixture():
    source = "a" * 40
    service = b"SYNTHETIC_INERT_SERVICE"
    inputs = runner.canonical({"schemaVersion": "tracebolt.windows-setup-source-inputs.v1", "files": [{"path": "go.mod", "size": 1, "sha256": "f" * 64}]})
    package = runner.canonical({"schemaVersion": "tracebolt.windows-setup-package.v1", "version": runner.VERSION, "sourceCommit": source, "architecture": "amd64", "sha256": runner.digest(service)})
    files = {runner.SERVICE_NAME: service, runner.SETUP_NAME: b"SYNTHETIC_INERT_GUI" + service + package, "setup-package-amd64.json": package, "source-inputs.json": inputs}
    pe = {}
    for name, setup in ((runner.SETUP_NAME, True), (runner.SERVICE_NAME, False)):
        pe[name] = fake_pe(None, None, None, None, setup=setup)
        pe[name]["repeatBuildIdentical"] = True
        if not setup: pe[name]["runtimeManifestValidated"] = True
    manifest = {"schemaVersion": "tracebolt.windows-setup-build.v1", "repository": "storminator89/Tracebolt", "version": runner.VERSION, "sourceCommit": source, "sourceKind": "clean-git-commit", "sourceCommitRole": "exact", "sourceInputsSHA256": runner.digest(inputs), "goVersion": "go1.27.1", "architectures": ["amd64"], "authenticode": "unsigned", "distributionStatus": "source-candidate-not-released", "nativeExecution": False, "repeatBuildIdentical": True, "assets": {name: {"size": len(raw), "sha256": runner.digest(raw)} for name, raw in files.items()}, "peChecks": pe}
    files["build-manifest.json"] = runner.canonical(manifest)
    files["SHA256SUMS"] = "".join(runner.digest(raw) + "  " + name + "\n" for name, raw in sorted(files.items())).encode("ascii")
    reports = {}
    for index, case in enumerate(runner.CHECKS):
        r = report(case)
        r.update(machine="fresh-vm-" + str(index), setupSHA256=runner.digest(files[runner.SETUP_NAME]), serviceSHA256=runner.digest(service), sourceInputsSHA256=runner.digest(inputs))
        reports[case] = runner.canonical(r)
    return files, reports

class SetupPublicDelivery(unittest.TestCase):
    def test_four_reports_require_all_passed_same_run_and_exact_bytes(self):
        _, reports = public_fixture()
        runner.aggregate_reports(reports, "a" * 40, "123")
        for key in ("source", "runID", "setupSHA256", "serviceSHA256", "driverSHA256", "sourceInputsSHA256", "machine", "status"):
            bad = dict(reports)
            r = json.loads(bad["pending-transport"])
            r[key] = {"source": "f" * 40, "runID": "456", "machine": "FRESH-VM-0", "status": "failed"}.get(key, "f" * 64)
            bad["pending-transport"] = runner.canonical(r)
            with self.subTest(key=key), self.assertRaises(runner.shared.Rejected):
                runner.aggregate_reports(bad, "a" * 40, "123")
        missing = dict(reports)
        missing.pop("cancel-hidden-input")
        with self.assertRaises(runner.shared.Rejected): runner.aggregate_reports(missing, "a" * 40, "123")
    def test_public_manifest_and_report_binding_and_no_snapshot_relabel(self):
        files, reports = public_fixture()
        tls = json.loads(reports["install-uninstall"])
        with mock.patch.object(runner.resources, "verify_pe", side_effect=fake_pe) as pe:
            runner.validate_public_package(files, "a" * 40, tls)
            self.assertEqual(pe.call_count, 2)
            for field, value in (("sourceKind", "uncommitted-snapshot"), ("sourceCommitRole", "base"), ("sourceCommit", "f" * 40), ("nativeExecution", True), ("architectures", ["arm64"]), ("authenticode", "signed")):
                bad = dict(files)
                manifest = json.loads(bad["build-manifest.json"])
                manifest[field] = value
                bad["build-manifest.json"] = runner.canonical(manifest)
                with self.subTest(field=field), self.assertRaises(runner.shared.Rejected): runner.validate_public_package(bad, "a" * 40, tls)
            for name in runner.PUBLIC_FILES:
                bad = dict(files)
                bad[name] += b"unexpected"
                with self.subTest(name=name), self.assertRaises(Exception): runner.validate_public_package(bad, "a" * 40, tls)
            bad_report = dict(tls, setupSHA256="f" * 64)
            with self.assertRaises(runner.shared.Rejected): runner.validate_public_package(files, "a" * 40, bad_report)
        # These synthetic bytes are never mistaken for a real PE without the
        # explicitly injected verifier used above.
        with self.assertRaises(Exception): runner.validate_public_package(files, "a" * 40, tls)
    def test_only_six_public_files_preserved_and_unknown_paths_rejected(self):
        files, reports = public_fixture()
        tls = json.loads(reports["install-uninstall"])
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.resources, "verify_pe", side_effect=fake_pe):
            destination = Path(tmp) / "public"
            runner.preserve_public_package(files, destination, "a" * 40, tls)
            self.assertEqual(runner.read_public_package(destination), files)
            with self.assertRaises(runner.shared.Rejected): runner.preserve_public_package(files, destination, "a" * 40, tls)
            (destination / "bootstrap.json").write_bytes(b"never-export")
            with self.assertRaises(runner.shared.Rejected): runner.read_public_package(destination)
    def test_aggregate_copies_actual_bytes_without_build_or_native_execution(self):
        files, reports = public_fixture()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(runner.resources, "verify_pe", side_effect=fake_pe), mock.patch.object(runner.shared, "verify_checkout"), mock.patch.object(runner.shared, "command", side_effect=AssertionError("execution forbidden")):
            temp = Path(tmp)
            env = allowed()
            env.update(RUNNER_OS="Linux", RUNNER_TEMP=str(temp), GITHUB_OUTPUT=str(temp / "outputs"))
            downloads = temp / "tracebolt-setup-reports"
            downloads.mkdir()
            for case, raw in reports.items():
                folder = downloads / ("windows-setup-gui-" + case + "-" + "a" * 40)
                folder.mkdir()
                (folder / runner.REPORT_NAME).write_bytes(raw)
            package = temp / "tracebolt-setup-package-input"
            package.mkdir()
            for name, raw in files.items(): (package / name).write_bytes(raw)
            evidence = runner.run_aggregate(env)
            self.assertEqual(runner.read_public_package(temp / runner.ACCEPTED_DIRECTORY), files)
            self.assertFalse(evidence["crossOSRebuildEquivalence"])
            self.assertTrue(all(v is False for v in evidence["coverage"].values()))
            self.assertEqual((temp / "outputs").read_text(), "accepted_package_validated=true\n")
            self.assertEqual(set(p.name for p in (temp / runner.ACCEPTED_DIRECTORY).iterdir()), runner.PUBLIC_FILES)
    def test_aggregation_has_no_new_native_authority_or_broad_upload(self):
        workflow = (ROOT / ".github/workflows/windows-setup-acceptance.yml").read_text()
        aggregate = workflow.split("  accepted-public-package:", 1)[1]
        self.assertIn("needs: packaged-gui", aggregate)
        self.assertIn("merge-multiple: false", aggregate)
        self.assertIn("--aggregate", aggregate)
        self.assertNotIn("--run-native", aggregate)
        self.assertNotIn("go build", aggregate)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("run-id:", aggregate)
        for name in runner.PUBLIC_FILES:
            self.assertIn("tracebolt-setup-accepted-public/" + name, aggregate)
        self.assertNotIn("tracebolt-setup-accepted-public/\n", aggregate)
        self.assertIn('"GetWindowRect"', (ROOT / "cmd/windows-service/setup_acceptance_ui_windows_test.go").read_text())
        geometry = (ROOT / "cmd/windows-service/setup_acceptance_ui_windows_test.go").read_text()
        self.assertIn('"GetMonitorInfoW"', geometry)
        self.assertIn('"SetThreadDpiAwarenessContext"', geometry)
        self.assertIn("runtime.LockOSThread()", geometry)
        self.assertIn('setupCall("SetThreadDpiAwarenessContext", previous)', geometry)


if __name__ == "__main__": unittest.main()
