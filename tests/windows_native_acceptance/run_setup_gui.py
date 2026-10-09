#!/usr/bin/env python3
"""Manual packaged-GUI gate. Import, ordinary tests and missing approvals are inert.

Build errors, GUI text, console buffers, identities and observations are never
exported. Only strict finite reports and an exact allowlisted public package
can reach artifact uploads. Delivered package bytes are never rebuilt.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("_setup_shared", Path(__file__).with_name("run_acceptance.py"))
shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)
require = shared.require
PROFILE = "packaged-setup-gui-v1"
VERSION = "v0.0.0-setup-candidate"
REPORT_NAME = "tracebolt-windows-setup-acceptance.json"
PUBLIC_DIRECTORY = "tracebolt-setup-tested-public"
ACCEPTED_DIRECTORY = "tracebolt-setup-accepted-public"
AGGREGATE_REPORT = "tracebolt-setup-native-subset.json"
SETUP_NAME = "Tracebolt-" + VERSION + "-windows-amd64-Setup.exe"
SERVICE_NAME = "tracebolt-" + VERSION + "-windows-amd64-service.exe"
PUBLIC_FILES = {SETUP_NAME, SERVICE_NAME, "setup-package-amd64.json", "build-manifest.json", "source-inputs.json", "SHA256SUMS"}
_resource_spec = importlib.util.spec_from_file_location("_setup_public_pe", ROOT / "deploy/windows-setup/pe_resources.py")
resources = importlib.util.module_from_spec(_resource_spec)
_resource_spec.loader.exec_module(resources)
APPROVALS = ("APP_ACLS", "SERVICES", "IDENTITY", "FIVE_READ_SCOPES", "SYNTHETIC_CONSOLE", "LOOPBACK_TLS", "HTTP_PLAINTEXT", "STOP_REMOVE_OWNED_SERVICE", "RETAIN_FOR_VM_DISPOSAL")
NORMAL = {"install-uninstall", "http-install-uninstall"}
BASE = {"acknowledgementsOff", "publicBootstrapChosen", "realGUIExercised", "hiddenConsoleExercised", "noEchoVerified", "pendingStoppedDisabled", "reopenBlocked", "filesAndStateRetained", "workerTerminated", "consoleReleased"}
CHECKS = {
 "install-uninstall": BASE | {"preflightCancelUnchanged", "approvalWithheld", "managerFixtureApproved", "completedReceipt", "limitedServiceToken", "twoFiveScopeFrames", "volumeCapacity", "processCPUDelta", "tcpFixture", "uninstallCancelUnchanged", "deletePendingObserved", "serviceAbsent", "receiptAndGrantsVerified"},
 "cancel-hidden-input": BASE | {"cancelWhileHiddenInput", "partialStateRetained", "incompleteUninstallBlocked"},
 "pending-transport": BASE | {"approvalWithheld", "transportInterrupted", "sameIdentityAndDeadline", "noFalseConnected", "partialStateRetained", "incompleteUninstallBlocked"},
}
CHECKS["http-install-uninstall"] = CHECKS["install-uninstall"] | {"httpAcknowledgementOff", "httpExplicitlyAcknowledged"}
FALSE_COVERAGE = {"humanUAC", "humanInvitation", "realLinuxManager", "sharedDashboard", "arm64Runtime", "osReboot", "upgrade", "vmDisposalVerified", "secretsExported", "rawTelemetryExported"}
STAGES = {"authorization", "desktop", "fresh", "fixture", "preflight-cancel", "bootstrap", "consent", "install", "hidden-input", "pending", "transport", "completion", "frames", "reopen", "uninstall-cancel", "uninstall", "verify-retention", "completed"}

# Wrapper-only diagnostics: these are not native controller reports or evidence.
# Never include exception messages, commands, paths, output, or environment values.
PRE_NATIVE_STAGES = frozenset({"authorization", "checkout", "toolchain", "dependencies",
    "staging", "package-build", "package-validation", "driver-build", "source-recheck", "run-binding"})

class PreNativeFailure(shared.Rejected):
    def __init__(self, stage):
        require(type(stage) is str and stage in PRE_NATIVE_STAGES)
        self.stage = stage
        super().__init__("pre_native_failed")

@contextmanager
def pre_native_step(stage):
    require(type(stage) is str and stage in PRE_NATIVE_STAGES)
    try:
        yield
    except Exception:
        raise PreNativeFailure(stage) from None

def authorize_common(env):
    source = env.get("TRACEBOLT_SETUP_SOURCE", "")
    require(shared.valid_source(source) and env.get("GITHUB_SHA") == source)
    require(env.get("TRACEBOLT_SETUP_PROFILE") == PROFILE)
    fixed = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_REPOSITORY_OWNER": "storminator89", "GITHUB_ACTOR": "storminator89", "GITHUB_TRIGGERING_ACTOR": "storminator89", "GITHUB_REPOSITORY_OWNER_ID": "30489872", "GITHUB_ACTOR_ID": "30489872", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted"}
    require(all(env.get(k) == v for k, v in fixed.items()))
    require(re.fullmatch(r"[1-9][0-9]{0,23}", env.get("GITHUB_RUN_ID", "")) is not None)
    require(all(env.get("TRACEBOLT_SETUP_APPROVE_" + a) == "true" for a in APPROVALS))
    return source

def authorize(env):
    source = authorize_common(env)
    require(env.get("TRACEBOLT_SETUP_CASE") in CHECKS and env.get("RUNNER_OS") == "Windows")
    return source

def authorize_aggregate(env):
    source = authorize_common(env)
    require(env.get("RUNNER_OS") == "Linux")
    return source

def validate_report(raw, source, which):
    r = shared.strict_json(raw, 16 << 10)
    require(type(r) is dict and set(r) == {"setupSHA256", "serviceSHA256", "driverSHA256", "sourceInputsSHA256", "runID", "machine", "schema", "source", "case", "status", "stage", "reason", "approvalValidated", "nativeActionsAttempted", "checks", "coverage", "startup", "frames", "platformDisposalRequired"})
    require(all(type(r[k]) is str and re.fullmatch(r"[0-9a-f]{64}", r[k]) for k in ("setupSHA256", "serviceSHA256", "driverSHA256", "sourceInputsSHA256")))
    require(type(r["runID"]) is str and re.fullmatch(r"[1-9][0-9]{0,23}", r["runID"]) and type(r["machine"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", r["machine"]))
    require(r["schema"] == "tracebolt.windows-setup-acceptance.v1" and r["source"] == source and r["case"] == which and which in CHECKS)
    require(shared.member(r["status"], {"blocked", "failed", "passed_packaged_gui_subset"}) and shared.member(r["stage"], STAGES))
    require(shared.member(r["reason"], {"none", "authorization", "desktop_unavailable", "operation_failed", "deadline", "inspection_required"}))
    require(shared.member(r["startup"], {"inspection_required", "disabled", "automatic", "absent"}))
    require(type(r["checks"]) is dict and set(r["checks"]) == CHECKS[which] and all(type(v) is bool for v in r["checks"].values()))
    require(type(r["coverage"]) is dict and set(r["coverage"]) == FALSE_COVERAGE and all(v is False for v in r["coverage"].values()))
    require(all(type(r[k]) is bool for k in ("approvalValidated", "nativeActionsAttempted", "platformDisposalRequired")))
    require(type(r["frames"]) is int and 0 <= r["frames"] <= 64)
    require(not r["nativeActionsAttempted"] or r["approvalValidated"])
    require(not r["platformDisposalRequired"] or r["nativeActionsAttempted"])
    if r["status"] == "blocked":
        require(not r["nativeActionsAttempted"] and r["frames"] == 0 and r["startup"] == "inspection_required" and not any(r["checks"].values()))
    if r["status"] == "passed_packaged_gui_subset":
        require(all(r["checks"].values()) and r["nativeActionsAttempted"] and r["platformDisposalRequired"] and r["stage"] == "completed" and r["reason"] == "none")
        require((r["startup"] == "absent" and r["frames"] >= 2) if which in NORMAL else (r["startup"] == "disabled" and r["frames"] == 0))
    return r

def parse_controller(raw, source, which):
    require(type(raw) is bytes and len(raw) <= 32 << 10)
    rows = [line[len(b"setup-gui-report="):] for line in raw.splitlines() if line.startswith(b"setup-gui-report=")]
    require(len(rows) == 1)
    return validate_report(rows[0], source, which)

def bind_run(env, source, driver, setup, service, machine, deadline):
    require(authorize(env) == source and machine == env.get("COMPUTERNAME") and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", machine) and type(deadline) is int)
    # Native controller receives only explicit run scope and ordinary OS facts.
    child = {k: v for k, v in env.items() if k in {"TRACEBOLT_SETUP_SOURCE", "TRACEBOLT_SETUP_PROFILE", "TRACEBOLT_SETUP_CASE", *("TRACEBOLT_SETUP_APPROVE_" + a for a in APPROVALS)} or k in {"GITHUB_SHA", "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_ACTOR", "GITHUB_ACTOR_ID", "GITHUB_TRIGGERING_ACTOR", "GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "COMPUTERNAME", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP"}}
    child.update(TRACEBOLT_SETUP_MACHINE=machine, TRACEBOLT_SETUP_RUN_ID=env["GITHUB_RUN_ID"], TRACEBOLT_SETUP_EXPIRES_UNIX=str(deadline), TRACEBOLT_SETUP_DRIVER_SHA256=shared.binary_digest(driver), TRACEBOLT_SETUP_SETUP_SHA256=shared.binary_digest(setup), TRACEBOLT_SETUP_SERVICE_SHA256=shared.binary_digest(service), TRACEBOLT_SETUP_SETUP_ARTIFACT=str(setup), TRACEBOLT_SETUP_SERVICE_ARTIFACT=str(service), TRACEBOLT_SETUP_SOURCE_INPUTS_SHA256=shared.binary_digest(setup.parent / "source-inputs.json"), TRACEBOLT_SETUP_SOURCE_INPUTS_ARTIFACT=str(setup.parent / "source-inputs.json"), TRACEBOLT_SETUP_PUBLIC_INPUT=str(driver.parent / "public-bootstrap.json"), GOTRACEBACK="none")
    return child

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def regular_file(path, bound):
    require(not path.is_symlink() and not (hasattr(path, "is_junction") and path.is_junction()))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= bound)
    with path.open("rb") as stream:
        raw = stream.read(bound + 1)
    require(len(raw) == info.st_size and len(raw) <= bound)
    return raw

def exact_directory(path, names):
    require(path.is_dir() and not path.is_symlink() and not (hasattr(path, "is_junction") and path.is_junction()))
    require({p.name for p in path.iterdir()} == set(names))

def read_public_package(path):
    # Never traverse the build stage: it also contains controller/public bootstrap.
    exact_directory(path, PUBLIC_FILES)
    bounds = {SETUP_NAME: 128 << 20, SERVICE_NAME: 128 << 20, "source-inputs.json": 4 << 20, "build-manifest.json": 64 << 10, "setup-package-amd64.json": 2048, "SHA256SUMS": 4096}
    return {name: regular_file(path / name, bounds[name]) for name in sorted(PUBLIC_FILES)}

def validate_public_package(files, source, report=None):
    require(type(files) is dict and set(files) == PUBLIC_FILES and shared.valid_source(source))
    hashes = {name: digest(raw) for name, raw in files.items()}
    manifest = shared.strict_json(files["build-manifest.json"], 64 << 10)
    expected_keys = {"schemaVersion", "repository", "version", "sourceCommit", "sourceKind", "sourceCommitRole", "sourceInputsSHA256", "goVersion", "architectures", "authenticode", "distributionStatus", "nativeExecution", "repeatBuildIdentical", "assets", "peChecks"}
    require(type(manifest) is dict and set(manifest) == expected_keys and files["build-manifest.json"] == canonical(manifest))
    for key, value in {"schemaVersion": "tracebolt.windows-setup-build.v1", "repository": "storminator89/Tracebolt", "version": VERSION, "sourceCommit": source, "sourceKind": "clean-git-commit", "sourceCommitRole": "exact", "sourceInputsSHA256": hashes["source-inputs.json"], "architectures": ["amd64"], "authenticode": "unsigned", "distributionStatus": "source-candidate-not-released", "nativeExecution": False, "repeatBuildIdentical": True}.items():
        require(manifest[key] == value and type(manifest[key]) is type(value))
    require(type(manifest["goVersion"]) is str and re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", manifest["goVersion"]))
    assets = PUBLIC_FILES - {"build-manifest.json", "SHA256SUMS"}
    require(type(manifest["assets"]) is dict and set(manifest["assets"]) == assets)
    for name in assets:
        require(manifest["assets"][name] == {"size": len(files[name]), "sha256": hashes[name]})
        require(type(manifest["assets"][name].get("size")) is int)
    package = shared.strict_json(files["setup-package-amd64.json"], 2048)
    require(package == {"schemaVersion": "tracebolt.windows-setup-package.v1", "version": VERSION, "sourceCommit": source, "architecture": "amd64", "sha256": hashes[SERVICE_NAME]} and files["setup-package-amd64.json"] == canonical(package))
    inputs = shared.strict_json(files["source-inputs.json"], 4 << 20)
    require(type(inputs) is dict and set(inputs) == {"schemaVersion", "files"} and inputs["schemaVersion"] == "tracebolt.windows-setup-source-inputs.v1" and type(inputs["files"]) is list and 1 <= len(inputs["files"]) <= 4096 and files["source-inputs.json"] == canonical(inputs))
    paths = []
    for item in inputs["files"]:
        require(type(item) is dict and set(item) == {"path", "size", "sha256"})
        path = item["path"]
        require(type(path) is str and 0 < len(path) <= 512 and "\\" not in path and all(p not in ("", ".", "..") for p in path.split("/")) and (path in {"go.mod", "go.sum"} or path.startswith(("cmd/", "internal/", "deploy/windows-setup/"))))
        require(type(item["size"]) is int and 0 <= item["size"] <= 128 << 20 and type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
        paths.append(path)
    require(len(paths) == len(set(paths)) == len({path.casefold() for path in paths}))
    require(sum(item["size"] for item in inputs["files"]) <= 128 << 20)
    require(type(manifest["peChecks"]) is dict and set(manifest["peChecks"]) == {SETUP_NAME, SERVICE_NAME})
    for name, setup in ((SETUP_NAME, True), (SERVICE_NAME, False)):
        actual = resources.verify_pe(files[name], VERSION, source, "amd64", setup=setup)
        actual["repeatBuildIdentical"] = True
        if not setup:
            actual["runtimeManifestValidated"] = True
        require(manifest["peChecks"][name] == actual)
    require(files[SERVICE_NAME] in files[SETUP_NAME] and files["setup-package-amd64.json"] in files[SETUP_NAME])
    sums = "".join(hashes[name] + "  " + name + "\n" for name in sorted(PUBLIC_FILES - {"SHA256SUMS"})).encode("ascii")
    require(files["SHA256SUMS"] == sums)
    if report is not None:
        require(report["status"] == "passed_packaged_gui_subset" and report["source"] == source)
        require(report["setupSHA256"] == hashes[SETUP_NAME] and report["serviceSHA256"] == hashes[SERVICE_NAME] and report["sourceInputsSHA256"] == hashes["source-inputs.json"])
    return hashes

def preserve_public_package(files, destination, source, report):
    validate_public_package(files, source, report)
    require(not destination.exists() and destination.parent.is_dir())
    destination.mkdir(mode=0o700)
    for name in sorted(PUBLIC_FILES):
        with (destination / name).open("xb") as stream:
            stream.write(files[name])
    copied = read_public_package(destination)
    require(copied == files)
    validate_public_package(copied, source, report)

def aggregate_reports(reports, source, run_id):
    require(type(reports) is dict and set(reports) == set(CHECKS))
    accepted = {case: validate_report(raw, source, case) for case, raw in reports.items()}
    require(all(r["status"] == "passed_packaged_gui_subset" and r["runID"] == run_id for r in accepted.values()))
    require(len({r["machine"].lower() for r in accepted.values()}) == len(CHECKS))
    for key in ("setupSHA256", "serviceSHA256", "driverSHA256", "sourceInputsSHA256"):
        require(len({r[key] for r in accepted.values()}) == 1)
    return accepted

def run_aggregate(env, root=ROOT):
    source = authorize_aggregate(env)
    shared.verify_checkout(shared.child_environment(env), source, root)
    temp = Path(env.get("RUNNER_TEMP", ""))
    require(temp.is_absolute() and temp.is_dir())
    downloads = temp / "tracebolt-setup-reports"
    names = {case: "windows-setup-gui-" + case + "-" + source for case in CHECKS}
    exact_directory(downloads, names.values())
    raw_reports = {}
    for case, name in names.items():
        exact_directory(downloads / name, {REPORT_NAME})
        raw_reports[case] = regular_file(downloads / name / REPORT_NAME, 16 << 10)
    reports = aggregate_reports(raw_reports, source, env["GITHUB_RUN_ID"])
    package = read_public_package(temp / "tracebolt-setup-package-input")
    hashes = validate_public_package(package, source, reports["install-uninstall"])
    preserve_public_package(package, temp / ACCEPTED_DIRECTORY, source, reports["install-uninstall"])
    evidence = {"schema": "tracebolt.windows-setup-native-subset.v1", "source": source, "runID": env["GITHUB_RUN_ID"], "status": "four_case_packaged_gui_subset", "distributionStatus": "unsigned-source-candidate-native-subset", "crossOSRebuildEquivalence": False, "coverage": dict.fromkeys(sorted(FALSE_COVERAGE), False), "reports": reports, "publicFilesSHA256": hashes}
    with (temp / AGGREGATE_REPORT).open("xb") as stream:
        stream.write(canonical(evidence))
    require(env.get("GITHUB_OUTPUT", "") != "")
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as stream:
        stream.write("accepted_package_validated=true\n")
    return evidence

def run_native(env, root=ROOT):
    with pre_native_step("authorization"):
        source = authorize(env)  # Before staging/build/processes/native actions.
    with pre_native_step("checkout"):
        child = shared.child_environment(env)
        shared.verify_checkout(child, source, root)
    with pre_native_step("toolchain"):
        shared.verify_go(child, root)
    with pre_native_step("dependencies"):
        shared.successful(["go", "mod", "verify"], child, root, 180)
    with pre_native_step("staging"):
        temp = Path(env.get("RUNNER_TEMP", ""))
        require(temp.is_absolute() and temp.is_dir() and not (temp / REPORT_NAME).exists())
        # Retain the exact built artifacts and all app/private state for VM disposal.
        stage = Path(tempfile.mkdtemp(prefix="tracebolt-setup-gui-", dir=temp))
        package = stage / "package"
    with pre_native_step("package-build"):
        shared.successful([sys.executable, "-I", "-B", "deploy/windows-setup/build-setup.py", "--version", VERSION, "--source-commit", source, "--output", str(package), "--arch", "amd64"], child, root, 600)
    with pre_native_step("package-validation"):
        original_public = read_public_package(package)
        validate_public_package(original_public, source)
    with pre_native_step("driver-build"):
        setup = package / SETUP_NAME
        service = package / SERVICE_NAME
        driver = stage / "setup-gui.test.exe"
        shared.successful(["go", "test", "-c", "-mod=readonly", "-buildvcs=false", "-trimpath", "-tags", "tracebolt_setup_native", "-ldflags", "-X localrmm/cmd/windows-service.setupCompiledSource=" + source, "-o", str(driver), "./cmd/windows-service"], child, root, 300)
    with pre_native_step("source-recheck"):
        shared.verify_checkout(child, source, root)
    with pre_native_step("run-binding"):
        native_env = bind_run(env, source, driver, setup, service, socket.gethostname(), int(time.time()) + 14 * 60)
    code, raw = shared.command([str(driver), "-test.run=^TestPackagedSetupGUINative$", "-test.count=1", "-test.timeout=15m"], native_env, root, 15 * 60, 32 << 10)
    report = parse_controller(raw, source, env["TRACEBOLT_SETUP_CASE"])
    for key, name in (("setupSHA256", "SETUP"), ("serviceSHA256", "SERVICE"), ("driverSHA256", "DRIVER"), ("sourceInputsSHA256", "SOURCE_INPUTS")):
        require(report[key] == native_env["TRACEBOLT_SETUP_" + name + "_SHA256"])
    require(report["runID"] == env["GITHUB_RUN_ID"] and report["machine"] == native_env["TRACEBOLT_SETUP_MACHINE"])
    require(report["status"] != "passed_packaged_gui_subset" or code == 0)
    preserve = report["status"] == "passed_packaged_gui_subset" and report["case"] == "install-uninstall"
    if report["status"] == "passed_packaged_gui_subset":
        current_public = read_public_package(package)
        require(current_public == original_public)
        validate_public_package(current_public, source, report)
    if preserve:
        preserve_public_package(original_public, temp / PUBLIC_DIRECTORY, source, report)
    sanitized = canonical(report)
    validate_report(sanitized, source, env["TRACEBOLT_SETUP_CASE"])
    with (temp / REPORT_NAME).open("xb") as f:
        f.write(sanitized)
    require(env.get("GITHUB_OUTPUT", "") != "")
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as f:
        f.write("report_validated=true\n")
        if preserve:
            f.write("public_package_validated=true\n")
    return report

def main(argv=None, env=None):
    args = sys.argv[1:] if argv is None else argv
    values = dict(os.environ if env is None else env)
    try:
        require(args in (["--check-authorization"], ["--run-native"], ["--aggregate"]))
        if args == ["--check-authorization"]:
            source = authorize(values)
            shared.verify_checkout(shared.child_environment(values), source, ROOT)
            print("PASS: separate packaged-GUI approvals and exact clean source verified; no native effects.")
            return 0
        if args == ["--aggregate"]:
            run_aggregate(values)
            print("PASS: four same-run cases match exact tested public package bytes; unsigned source-candidate native subset only.")
            return 0
        r = run_native(values)
        print("Packaged Setup GUI subset: " + r["status"] + "; stage=" + r["stage"] + "; reason=" + r["reason"] + "; retained app/state requires platform VM disposal, unverified.")
        return 0 if r["status"] == "passed_packaged_gui_subset" else 1
    except PreNativeFailure as error:
        # Recheck the finite label at the output boundary; never stringify errors.
        stage = error.stage if type(error.stage) is str and error.stage in PRE_NATIVE_STAGES else "unknown"
        print("FAIL: packaged Setup gate; stage=" + stage + "; reason=pre_native_failed; private output withheld; inspect assigned VM/disposal status.")
        return 1
    except Exception:
        print("FAIL: packaged Setup gate or evidence rejected; private output withheld; inspect assigned VM/disposal status.")
        return 1
if __name__ == "__main__":
    raise SystemExit(main())
