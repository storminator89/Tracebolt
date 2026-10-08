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
SCHEMA = "tracebolt.windows-native-acceptance.v2"
EXPANDED_SCHEMA = "tracebolt.windows-native-acceptance.v3"
MAX_REPORT_BYTES = 32 * 1024
CONTROLLER_TIMEOUT_SECONDS = 13 * 60  # 10-minute controller + 2-minute cleanup.
REPORT_NAME = "tracebolt-windows-native-acceptance.json"
APPROVALS = {
    "TRACEBOLT_APPROVE_SERVICES": "--approve-services",
    "TRACEBOLT_APPROVE_IDENTITY": "--approve-identity",
    "TRACEBOLT_APPROVE_APP_ACLS": "--approve-app-acls",
    "TRACEBOLT_APPROVE_LOOPBACK": "--approve-loopback",
    "TRACEBOLT_APPROVE_CLEANUP": "--approve-cleanup",
}
EXTENSION_APPROVALS = {
    "TRACEBOLT_APPROVE_EVENT_HEADERS": "--approve-event-headers",
    "TRACEBOLT_APPROVE_VISIBLE_VOLUMES": "--approve-visible-volumes",
    "TRACEBOLT_APPROVE_PROCESS_METRICS": "--approve-process-metrics",
    "TRACEBOLT_APPROVE_NETWORK_ENDPOINTS": "--approve-network-endpoints",
}


def extension_approval(env: dict[str, str]) -> bool:
    # Missing new flags retain the old base-only meaning, never expanded consent.
    values = [env.get(name, "false") for name in EXTENSION_APPROVALS]
    require(all(type(v) is str and v in {"true", "false"} for v in values))
    require(all(v == "false" for v in values) or all(v == "true" for v in values))
    expanded = values[0] == "true"
    require(not expanded or env.get("TRACEBOLT_COLLECTION_PROFILE") == "windows-inventory-v1")
    return expanded


CHECK_NAMES = (
    "prerequisites", "app_only_provisioning", "service_prepare", "pending_claim",
    "limited_token", "pending_stop_identity", "delayed_approval_report", "profile_report",
    "unrelated_service_denied", "outage_pending_retained",
    "outage_restart_same_bytes", "recovery_same_identity",
    "uninstall_retains_state", "owned_cleanup",
)
STAGES = {
    "idle", "preflight", "provision", "install", "prepare", "claim", "start",
    "token", "status", "state-continuity", "capabilities", "probe", "stop", "uninstall", "cleanup",
}
REASONS = {
    "none", "approval-required", "unsupported-platform", "ancestor-prerequisite",
    "existing-resource", "artifact-mismatch", "ownership-rejected",
    "operation-failed", "deadline-or-cancellation", "state-rejected",
}
COVERAGE_FALSE = {
    "productionIngressExercised", "sharedDashboardExercised", "productionManagerExercised", "hiddenConsoleExercised", "osShutdownExercised",
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
    "nativeActionsAttempted", "native", "checks", "selection", "inventory", "loopbackPeerExercised", "nativeInventorySenderExercised",
} | COVERAGE_FALSE
ROOT = Path(__file__).resolve().parents[2]


class Rejected(Exception):
    """Only fixed messages are reported; exception details are never exported."""


def require(condition: bool) -> None:
    if not condition:
        raise Rejected()


def valid_source(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


QUALITIES = ("cpu", "memory", "disk", "hostname", "processes", "services", "software", "interfaces")
VALID_SELECTIONS = {("basic-readonly-v1", "tls"), ("windows-inventory-v1", "tls"), ("windows-inventory-v1", "http-test")}

def selection(env: dict[str, str]) -> dict:
    collection, transport = env.get("TRACEBOLT_COLLECTION_PROFILE"), env.get("TRACEBOLT_TRANSPORT_PROFILE")
    require(type(collection) is str and type(transport) is str and (collection, transport) in VALID_SELECTIONS)
    require(env.get("TRACEBOLT_APPROVE_INVENTORY_METADATA") == ("true" if collection == "windows-inventory-v1" else "false"))
    require(env.get("TRACEBOLT_APPROVE_HTTP_PLAINTEXT") == ("true" if transport == "http-test" else "false"))
    return {"collectionProfile": collection, "transport": transport}


def authorize(env: dict[str, str]) -> str:
    """Pure, first boundary: invalid/unapproved inputs cannot spawn a process."""
    selection(env)
    extension_approval(env)
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


def validate_extensions(value: object, inventory_frames: int, status: str) -> None:
    qualities = {"eventApplication", "eventSystem", "volumes", "volumeCapacity", "processCPU", "processMemory", "network"}
    rows = {"eventRows": 32, "volumeRows": 64, "processRows": 128, "networkRows": 64, "peerLoopbackRows": 64, "processCPUFirstSampleRows": 128}
    counts = {"volumeCapacityCounts": "volumeRows", "processCPUCounts": "processRows", "processMemoryCounts": "processRows"}
    require(type(value) is dict and set(value) == qualities | set(rows) | set(counts) | {"frames", "v5Frames", "freshOrchestrationAcceptance"})
    require(value["freshOrchestrationAcceptance"] is False)
    for key, bound in {**rows, "frames": 64, "v5Frames": 64}.items():
        require(type(value[key]) is int and 0 <= value[key] <= bound)
    require(value["frames"] == value["v5Frames"] and value["frames"] <= inventory_frames)
    for key, row_key in counts.items():
        c = value[key]
        require(type(c) is dict and set(c) == {"observed", "denied", "unavailable", "firstSample", "reset"})
        require(all(type(n) is int and 0 <= n <= rows[row_key] for n in c.values()))
        require(sum(c.values()) == value[row_key])
        require(key == "processCPUCounts" or c["firstSample"] == c["reset"] == 0)
        present = [label for name, label in (("observed", "observed"), ("denied", "denied"), ("unavailable", "unavailable"), ("firstSample", "first-sample"), ("reset", "reset")) if c[name] > 0]
        expected = "empty" if not present else present[0] if len(present) == 1 else "partial"
        if value["frames"] > 0:
            require(value[key[:-6]] == expected)
    require(value["peerLoopbackRows"] <= value["networkRows"])
    require(value["processCPUFirstSampleRows"] == value["processCPUCounts"]["firstSample"])
    if value["frames"] == 0:
        require(all(value[key] == "not_run" for key in qualities) and all(value[key] == 0 for key in rows))
    else:
        for key in ("eventApplication", "eventSystem", "volumes"):
            require(member(value[key], {"observed", "bounded", "partial", "denied", "unavailable"}))
        require(member(value["network"], {"observed", "partial", "denied", "unavailable"}))
        require(value["volumes"] not in {"denied", "unavailable"} or value["volumeRows"] == 0)
        require(value["network"] not in {"denied", "unavailable"} or value["networkRows"] == 0)
        require(not all(value[key] in {"denied", "unavailable"} for key in ("eventApplication", "eventSystem")) or value["eventRows"] == 0)
    if status == "passed_native_subset":
        require(value["frames"] > 0 and all(value[key] in {"observed", "bounded", "partial"} for key in ("eventApplication", "eventSystem", "volumes")))
        require(all(value[key]["observed"] > 0 for key in counts) and value["network"] in {"observed", "partial"} and value["peerLoopbackRows"] > 0)
    if status == "blocked":
        require(value["frames"] == 0)


def validate_report(raw: bytes, source: str, expected: dict | None = None, expanded: bool | None = None) -> dict:
    """Mirror Go gate.Report/native.Evidence exactly; reject unknown data."""
    require(valid_source(source))
    report = strict_json(raw, MAX_REPORT_BYTES)
    require(type(report) is dict)
    is_expanded = report.get("schema") == EXPANDED_SCHEMA
    require(set(report) == REPORT_FIELDS | ({"extensions"} if is_expanded else set()))
    require(member(report["schema"], {SCHEMA, EXPANDED_SCHEMA}) and report["source"] == source)
    require(expanded is None or is_expanded == expanded)
    selected = report["selection"]
    require(type(selected) is dict and set(selected) == {"collectionProfile", "transport"})
    require(type(selected["collectionProfile"]) is str and type(selected["transport"]) is str and (selected["collectionProfile"], selected["transport"]) in VALID_SELECTIONS)
    require(expected is None or selected == expected)
    inventory = report["inventory"]
    require(type(inventory) is dict and set(inventory) == {"frames", *QUALITIES})
    require(type(inventory["frames"]) is int and 0 <= inventory["frames"] <= 64)
    allowed = {"not_run"} if inventory["frames"] == 0 else {"healthy", "partial", "denied", "unavailable"}
    require(all(member(inventory[key], allowed) for key in QUALITIES))
    is_inventory = selected["collectionProfile"] == "windows-inventory-v1"
    require(is_inventory or inventory["frames"] == 0)
    if is_expanded:
        require(is_inventory)
        validate_extensions(report["extensions"], inventory["frames"], report["status"])
        require(report["extensions"]["frames"] == 0 or report["loopbackPeerExercised"] is True)
    require(type(report["loopbackPeerExercised"]) is bool and type(report["nativeInventorySenderExercised"]) is bool)
    require(report["nativeInventorySenderExercised"] == (is_inventory and inventory["frames"] > 0 and report["loopbackPeerExercised"]))
    require(report["approvalValidated"] is True)
    require(type(report["nativeActionsAttempted"]) is bool)
    require(not report["loopbackPeerExercised"] or report["nativeActionsAttempted"])
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
        require(report["loopbackPeerExercised"] is True)
        require(not is_inventory or (report["nativeInventorySenderExercised"] is True and all(inventory[key] in {"healthy", "partial"} for key in QUALITIES)))
        require(report["nativeActionsAttempted"] is True)
        require(report["stage"] == "owned_cleanup" and report["reason"] == "none")
        require(native["stage"] == "cleanup" and native["reason"] == "none")
        require(all(check["status"] == "pass" for check in checks))
        require(all(native[key] is True for key in NATIVE_TRUE))
        require(all(native[key] is False for key in NATIVE_FALSE))
    if report["status"] == "blocked":
        require(not report["loopbackPeerExercised"] and inventory["frames"] == 0)
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


def controller_arguments(controller: Path, service: Path, source: str, selected: dict, expanded: bool = False) -> list[str]:
    require(valid_source(source) and type(selected) is dict and (selected.get("collectionProfile"), selected.get("transport")) in VALID_SELECTIONS)
    require(type(expanded) is bool and (not expanded or selected["collectionProfile"] == "windows-inventory-v1"))
    return [str(controller), "--expected-source=" + source,
            *[flag + "=true" for flag in APPROVALS.values()],
            *([flag + "=true" for flag in EXTENSION_APPROVALS.values()] if expanded else []),
            "--collection-profile=" + selected["collectionProfile"], "--transport-profile=" + selected["transport"],
            "--approve-inventory-metadata=" + str(selected["collectionProfile"] == "windows-inventory-v1").lower(),
            "--approve-http-plaintext=" + str(selected["transport"] == "http-test").lower(),
            "--service-artifact=" + str(service), "--service-sha256=" + binary_digest(service),
            "--controller-artifact=" + str(controller), "--controller-sha256=" + binary_digest(controller)]


def run_native(env: dict[str, str], root: Path = ROOT) -> dict:
    source = authorize(env)  # Must precede filesystem staging and every process.
    selected = selection(env)
    expanded = extension_approval(env)
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
        code, raw = command(controller_arguments(controller, service, source, selected, expanded), child,
                            root, CONTROLLER_TIMEOUT_SECONDS)
        report = validate_report(raw, source, selected, expanded)
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
