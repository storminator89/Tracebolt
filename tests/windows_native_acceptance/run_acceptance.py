#!/usr/bin/env python3
"""Manual exact-source Windows gate. No import or default invocation has effects.

The only export is a freshly serialized, strict finite report. Child output is
never forwarded or written to a log, including build errors and tracebacks.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import threading

REPOSITORY = "storminator89/Tracebolt"
SCHEMA = "tracebolt.windows-native-acceptance.v1"
MAX_REPORT_BYTES = 32 * 1024
CONTROLLER_TIMEOUT_SECONDS = 13 * 60  # 10-minute controller + 2-minute cleanup.
REPORT_NAME = "tracebolt-windows-native-acceptance.json"
APPROVALS = {
    "TRACEBOLT_APPROVE_SERVICES": "--approve-services",
    "TRACEBOLT_APPROVE_IDENTITY": "--approve-identity",
    "TRACEBOLT_APPROVE_APP_ACLS": "--approve-app-acls",
    "TRACEBOLT_APPROVE_LOOPBACK_TLS": "--approve-loopback-tls",
    "TRACEBOLT_APPROVE_CLEANUP": "--approve-cleanup",
}
CHECK_NAMES = (
    "prerequisites", "app_only_provisioning", "service_prepare", "pending_claim",
    "limited_token", "pending_stop_identity", "delayed_approval_report",
    "unrelated_service_denied", "outage_pending_retained",
    "outage_restart_same_bytes", "recovery_same_identity",
    "uninstall_retains_state", "owned_cleanup",
)
STAGES = {
    "idle", "preflight", "provision", "install", "prepare", "claim", "start",
    "token", "status", "state-continuity", "probe", "stop", "uninstall", "cleanup",
}
REASONS = {
    "none", "approval-required", "unsupported-platform", "ancestor-prerequisite",
    "existing-resource", "artifact-mismatch", "ownership-rejected",
    "operation-failed", "deadline-or-cancellation", "state-rejected",
}
COVERAGE_FALSE = {
    "productionManagerExercised", "hiddenConsoleExercised", "osShutdownExercised",
    "osRebootExercised", "broadAncestorAclChanged", "existingResourcesAdopted",
    "secretsExported", "rawTelemetryExported",
}
NATIVE_TRUE = {
    "prerequisites", "provisioned", "prepared", "claim_committed",
    "limited_token", "ready", "identity_retained", "sender_floor_retained",
    "pending_bytes_retained", "unrelated_service_denied", "stopped",
    "uninstalled", "uninstall_state_retained", "cleaned",
}
NATIVE_FALSE = {"installed", "running", "pending_present", "cleanup_retained"}
NATIVE_BOOLEANS = NATIVE_TRUE | NATIVE_FALSE
REPORT_FIELDS = {
    "schema", "source", "status", "stage", "reason", "approvalValidated",
    "nativeActionsAttempted", "native", "checks",
} | COVERAGE_FALSE
ROOT = Path(__file__).resolve().parents[2]


class Rejected(Exception):
    """Only fixed messages are reported; exception details are never exported."""


def require(condition: bool) -> None:
    if not condition:
        raise Rejected()


def valid_source(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def authorize(env: dict[str, str]) -> str:
    """Pure, first boundary: invalid/unapproved inputs cannot spawn a process."""
    source = env.get("TRACEBOLT_EXPECTED_SOURCE_SHA")
    require(valid_source(source) and source == env.get("GITHUB_SHA"))
    for name in APPROVALS:
        require(type(env.get(name)) is str and env[name] == "true")
    for name, value in {
        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY, "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
    }.items():
        require(env.get(name) == value)
    run_id = env.get("GITHUB_RUN_ID", "")
    require(type(run_id) is str and re.fullmatch(r"[0-9]{1,24}", run_id) is not None
            and run_id.strip("0") != "")
    require(sys.platform == "win32" and platform.machine().lower() in {"amd64", "x86_64"})
    return source


def unique_object(items: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in items:
        require(key not in value)
        value[key] = item
    return value


def reject_constant(_value: str) -> None:
    raise Rejected()


def strict_json(raw: bytes, bound: int) -> object:
    require(type(raw) is bytes and 0 < len(raw) <= bound)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected() from None


def member(value: object, allowed: set | tuple) -> bool:
    return type(value) is str and value in allowed


def validate_report(raw: bytes, source: str) -> dict:
    """Mirror Go gate.Report/native.Evidence exactly; reject unknown data."""
    require(valid_source(source))
    report = strict_json(raw, MAX_REPORT_BYTES)
    require(type(report) is dict and set(report) == REPORT_FIELDS)
    require(report["schema"] == SCHEMA and report["source"] == source)
    require(report["approvalValidated"] is True)
    require(type(report["nativeActionsAttempted"]) is bool)
    require(all(report[key] is False for key in COVERAGE_FALSE))
    require(member(report["status"], {"passed_native_subset", "failed", "blocked"}))
    require(member(report["stage"], CHECK_NAMES) and member(report["reason"], REASONS))
    native = report["native"]
    require(type(native) is dict and set(native) == NATIVE_BOOLEANS | {"stage", "reason"})
    require(member(native["stage"], STAGES) and member(native["reason"], REASONS))
    require(all(type(native[key]) is bool for key in NATIVE_BOOLEANS))
    checks = report["checks"]
    require(type(checks) is list and len(checks) == len(CHECK_NAMES))
    for check, expected in zip(checks, CHECK_NAMES):
        require(type(check) is dict and set(check) == {"name", "status"})
        require(check["name"] == expected and member(check["status"], {"pass", "fail", "blocked", "not_run"}))
    if report["status"] == "passed_native_subset":
        require(report["nativeActionsAttempted"] is True)
        require(report["stage"] == "owned_cleanup" and report["reason"] == "none")
        require(native["stage"] == "cleanup" and native["reason"] == "none")
        require(all(check["status"] == "pass" for check in checks))
        require(all(native[key] is True for key in NATIVE_TRUE))
        require(all(native[key] is False for key in NATIVE_FALSE))
    if report["status"] == "blocked":
        require(report["stage"] == "prerequisites" and report["nativeActionsAttempted"] is False)
        require(all(native[key] is False for key in {"provisioned", "installed", "prepared", "claim_committed"}))
    return report


def sanitized_bytes(report: dict, source: str) -> bytes:
    # Re-validate even when called independently. Never preserve untrusted raw
    # whitespace, escaped text, JSON formatting or any extra output.
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    validate_report(raw, source)
    return raw


def command(args: list[str], env: dict[str, str], cwd: Path, timeout: int,
            limit: int = MAX_REPORT_BYTES) -> tuple[int, bytes]:
    """Bound memory; discard stderr and excess stdout without skipping cleanup.

    Malformed/oversized output does not terminate an otherwise running controller:
    it is drained and discarded so its independent two-minute cleanup can run.
    A hard timeout is failure, never evidence that native cleanup succeeded.
    """
    require(type(args) is list and all(type(arg) is str for arg in args))
    retained = bytearray()
    read_failed = []
    with subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          shell=False) as process:
        def drain() -> None:
            try:
                while chunk := process.stdout.read(8192):
                    remaining = limit + 1 - len(retained)
                    if remaining > 0:
                        retained.extend(chunk[:remaining])
            except (OSError, ValueError):
                read_failed.append(True)
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            reader.join(timeout=10)
            raise Rejected() from None
        reader.join(timeout=10)
        require(not reader.is_alive() and not read_failed and len(retained) <= limit)
    return code, bytes(retained)


def successful(args: list[str], env: dict[str, str], cwd: Path, timeout: int,
               limit: int = MAX_REPORT_BYTES) -> bytes:
    code, raw = command(args, env, cwd, timeout, limit)
    require(code == 0)
    return raw


def child_environment(env: dict[str, str]) -> dict[str, str]:
    result = dict(env)
    # Do not let environment-selected cross compilation, extra Go flags, a
    # workspace or a remembered go env file change these reviewed builds.
    for name in ("GOOS", "GOARCH", "GOFLAGS", "GOEXPERIMENT", "TRACEBOLT_WINDOWS_READONLY_NATIVE"):
        result.pop(name, None)
    result.update(GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GO111MODULE="on", CGO_ENABLED="0",
                  PYTHONDONTWRITEBYTECODE="1", GIT_OPTIONAL_LOCKS="0")
    return result


def verify_checkout(env: dict[str, str], source: str, root: Path) -> None:
    git = ["git", "-c", "core.fsmonitor=false", "--no-optional-locks"]
    head = successful(git + ["rev-parse", "--verify", "HEAD"], env, root, 30, 128)
    require(head in {(source + "\n").encode("ascii"), (source + "\r\n").encode("ascii")})
    # Even ignored source files can affect Go builds. Builds/reports live only
    # in RUNNER_TEMP, outside this checkout; -B prevents Python cache pollution.
    require(successful(git + ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"], env, root, 30) == b"")


def verify_go(env: dict[str, str], root: Path) -> None:
    raw = successful(["go", "env", "-json", "GOHOSTOS", "GOHOSTARCH", "GOOS", "GOARCH"], env, root, 30)
    value = strict_json(raw, 1024)
    require(value == {"GOHOSTOS": "windows", "GOHOSTARCH": "amd64", "GOOS": "windows", "GOARCH": "amd64"})


def binary_digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink())
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def controller_arguments(controller: Path, service: Path, source: str) -> list[str]:
    require(valid_source(source))
    return [str(controller), "--expected-source=" + source,
            *[flag + "=true" for flag in APPROVALS.values()],
            "--service-artifact=" + str(service), "--service-sha256=" + binary_digest(service),
            "--controller-artifact=" + str(controller), "--controller-sha256=" + binary_digest(controller)]


def run_native(env: dict[str, str], root: Path = ROOT) -> dict:
    source = authorize(env)  # Must precede filesystem staging and every process.
    child = child_environment(env)
    verify_checkout(child, source, root)
    verify_go(child, root)
    successful(["go", "mod", "verify"], child, root, 180)
    runner_temp = Path(env.get("RUNNER_TEMP", ""))
    require(runner_temp.is_absolute() and runner_temp.is_dir())
    require(not (runner_temp / REPORT_NAME).exists())
    with tempfile.TemporaryDirectory(prefix="tracebolt-native-build-", dir=runner_temp) as stage:
        service = Path(stage) / "tracebolt-windows-service.exe"
        controller = Path(stage) / "tracebolt-windows-acceptance.exe"
        successful(["go", "build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-o", str(service),
                    "./cmd/windows-service"], child, root, 300)
        successful(["go", "build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-ldflags",
                    "-X main.compiledSource=" + source, "-o", str(controller),
                    "./cmd/windows-native-acceptance"], child, root, 300)
        verify_checkout(child, source, root)
        code, raw = command(controller_arguments(controller, service, source), child,
                            root, CONTROLLER_TIMEOUT_SECONDS)
        report = validate_report(raw, source)
        require(report["status"] != "passed_native_subset" or code == 0)
    # Staged executables have gone away. Only this finite reserialization is
    # retained, never private keys, controller output, telemetry or native paths.
    with (runner_temp / REPORT_NAME).open("xb") as stream:
        stream.write(sanitized_bytes(report, source))
    output = env.get("GITHUB_OUTPUT")
    require(type(output) is str and output != "")
    with open(output, "a", encoding="utf-8", newline="\n") as stream:
        stream.write("report_validated=true\n")
    return report


def main(argv: list[str] | None = None, env: dict[str, str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    environment = dict(os.environ if env is None else env)
    try:
        require(args in (["--check-authorization"], ["--run-native"]))
        if args == ["--check-authorization"]:
            source = authorize(environment)
            verify_checkout(child_environment(environment), source, ROOT)
            print("PASS: manual exact-source authorization; no native operations executed.")
            return 0
        report = run_native(environment)
        print("Windows native acceptance: " + report["status"] + "; stage=" + report["stage"]
              + "; reason=" + report["reason"] + ".")
        return 0 if report["status"] == "passed_native_subset" else 1
    except Exception:
        # Never echo input values, paths, subprocess errors or exception text.
        print("FAIL: Windows native acceptance authorization, execution or evidence rejected; raw output withheld.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
