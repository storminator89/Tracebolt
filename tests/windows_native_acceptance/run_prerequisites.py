#!/usr/bin/env python3
"""Read-only hosted Windows prerequisite measurement; never service acceptance.

This independent CI runner cannot select the manual native acceptance mode.
Only a strict, finite reserialization leaves the disposable hosted runner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "storminator89/Tracebolt"
SCHEMA = "tracebolt.windows-prerequisites.v2"
REPORT_NAME = "tracebolt-windows-prerequisites.json"
MAX_REPORT_BYTES = 32 * 1024
TIMEOUT_SECONDS = 90
STATUSES = {"supported", "blocked", "unverified"}
CHECKS = {"idle", "platform", "layout", "elevation", "filesystem", "ancestor-policy", "resource-absence", "complete"}
REASONS = {"none", "unsupported-platform", "prerequisite-blocked", "existing-resource", "inspection-failed", "cancelled"}
FALSE_FLAGS = {"nativeServiceAcceptance", "effectiveServiceTokenAccessVerified", "hostMutated"}
REPORT_FIELDS = {"schema", "source", "status", "check", "reason", "readOnly", "diagnostic"} | FALSE_FLAGS

DIAGNOSTIC_LOCATIONS = {"volume-root", "program-files", "program-data", "intermediate"}
DIAGNOSTIC_FAILURES = {
    "path-syntax", "open-access-denied", "open-sharing-violation", "open-failed",
    "metadata-query-failed", "reparse-point", "object-kind", "multiple-links",
    "final-path-query-failed", "final-path-mismatch", "case-query-denied",
    "case-query-unsupported", "case-query-invalid", "case-query-failed", "case-sensitive-directory",
    "descriptor-query-failed", "descriptor-invalid", "owner-unavailable", "owner-untrusted",
    "dacl-unavailable", "dacl-missing", "ace-malformed", "ace-type-unsupported", "untrusted-write-grant",
}
DIAGNOSTIC_RIGHTS = ("generic-all", "generic-write", "change-owner", "change-dacl",
                     "delete-child", "delete", "add-file", "write-ea", "write-attributes")


class Rejected(Exception):
    """Fixed failure only; never export exception details or child output."""


def require(condition: bool) -> None:
    if not condition:
        raise Rejected()


def valid_source(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def check_environment(env: dict[str, str]) -> str:
    """Pure platform/provenance check, before any subprocess or staging."""
    source = env.get("TRACEBOLT_PREREQUISITE_SOURCE_SHA")
    require(valid_source(source) and env.get("GITHUB_SHA") == source)
    require(env.get("GITHUB_EVENT_NAME") in {"push", "pull_request", "workflow_dispatch"})
    for name, value in {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY,
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
    }.items():
        require(env.get(name) == value)
    require(sys.platform == "win32" and platform.machine().lower() in {"amd64", "x86_64"})
    return source


def unique_object(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise Rejected()


def strict_json(raw: bytes, limit: int = MAX_REPORT_BYTES) -> object:
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected() from None


def validate_report(raw: bytes, source: str) -> dict:
    require(valid_source(source))
    report = strict_json(raw)
    require(type(report) is dict and set(report) == REPORT_FIELDS)
    require(report["schema"] == SCHEMA and report["source"] == source)
    for key, allowed in (("status", STATUSES), ("check", CHECKS), ("reason", REASONS)):
        require(type(report[key]) is str and report[key] in allowed)
    require(report["readOnly"] is True and all(report[key] is False for key in FALSE_FLAGS))
    if report["status"] == "supported":
        require(report["check"] == "complete" and report["reason"] == "none")
    elif report["status"] == "blocked":
        require(report["check"] in {"layout", "elevation", "filesystem", "ancestor-policy", "resource-absence"})
        require(report["reason"] in {"prerequisite-blocked", "existing-resource"})
        require(report["reason"] != "existing-resource" or report["check"] == "resource-absence")
    else:
        require(report["check"] != "complete")
        require(report["reason"] in {"unsupported-platform", "inspection-failed", "cancelled"})
    diagnostic = report["diagnostic"]
    ancestor_block = report["status"] == "blocked" and report["check"] == "ancestor-policy"
    if not ancestor_block:
        require(diagnostic is None)
    else:
        require(type(diagnostic) is dict and set(diagnostic) == {"location", "failure", "rights"})
        require(type(diagnostic["location"]) is str and diagnostic["location"] in DIAGNOSTIC_LOCATIONS)
        require(type(diagnostic["failure"]) is str and diagnostic["failure"] in DIAGNOSTIC_FAILURES)
        rights = diagnostic["rights"]
        require(type(rights) is list and all(type(right) is str for right in rights))
        if diagnostic["failure"] == "untrusted-write-grant":
            require(0 < len(rights) <= len(DIAGNOSTIC_RIGHTS))
            require(rights == [right for right in DIAGNOSTIC_RIGHTS if right in rights])
        else:
            require(rights == [])
    return report


def sanitized_bytes(report: dict, source: str) -> bytes:
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    validate_report(raw, source)
    return raw


def command(args: list[str], env: dict[str, str], root: Path, timeout: int,
            limit: int = MAX_REPORT_BYTES) -> bytes:
    """No shell, no stdin, stderr discarded, bounded in-memory stdout only."""
    require(type(args) is list and all(type(arg) is str for arg in args))
    retained = bytearray()
    read_failed = []
    with subprocess.Popen(args, cwd=root, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False) as process:
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
        require(code == 0 and not reader.is_alive() and not read_failed and len(retained) <= limit)
    return bytes(retained)


def child_environment(env: dict[str, str]) -> dict[str, str]:
    child = dict(env)
    for name in ("GOOS", "GOARCH", "GOFLAGS", "GOEXPERIMENT", "TRACEBOLT_WINDOWS_READONLY_NATIVE"):
        child.pop(name, None)
    # The read-only measurement has no dependency on approval environment from
    # another workflow. Strip it rather than carrying authority-looking inputs.
    for name in tuple(child):
        if name.startswith("TRACEBOLT_APPROVE_"):
            del child[name]
    child.update(GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GO111MODULE="on",
                 CGO_ENABLED="0", PYTHONDONTWRITEBYTECODE="1", GIT_OPTIONAL_LOCKS="0")
    return child


def verify_checkout(env: dict[str, str], source: str, root: Path) -> None:
    git = ["git", "-c", "core.fsmonitor=false", "--no-optional-locks"]
    head = command(git + ["rev-parse", "--verify", "HEAD"], env, root, 30, 128)
    require(head in {(source + "\n").encode("ascii"), (source + "\r\n").encode("ascii")})
    require(command(git + ["status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"], env, root, 30) == b"")


def verify_go(child: dict[str, str], root: Path) -> None:
    host = strict_json(command(["go", "env", "-json", "GOHOSTOS", "GOHOSTARCH", "GOOS", "GOARCH"], child, root, 30), 1024)
    require(host == {"GOHOSTOS": "windows", "GOHOSTARCH": "amd64", "GOOS": "windows", "GOARCH": "amd64"})


def run_measurement(env: dict[str, str], root: Path = ROOT) -> dict:
    source = check_environment(env)
    child = child_environment(env)
    verify_checkout(child, source, root)
    verify_go(child, root)
    command(["go", "mod", "verify"], child, root, 180)
    destination = Path(env.get("RUNNER_TEMP", ""))
    require(destination.is_absolute() and destination.is_dir())
    require(not (destination / REPORT_NAME).exists())
    with tempfile.TemporaryDirectory(prefix="tracebolt-prerequisite-build-", dir=destination) as stage:
        executable = Path(stage) / "tracebolt-windows-prerequisites.exe"
        command(["go", "build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-ldflags",
                 "-X main.compiledSource=" + source, "-o", str(executable),
                 "./cmd/windows-prerequisites"], child, root, 300)
        require(executable.is_file() and not executable.is_symlink())
        verify_checkout(child, source, root)
        # This is the only executable invocation. There is no configurable mode,
        # manual scope flag, service artifact, native acceptance or repair path.
        raw = command([str(executable), "--read-only-prerequisites", "--expected-source=" + source],
                      child, root, TIMEOUT_SECONDS)
        report = validate_report(raw, source)
    with (destination / REPORT_NAME).open("xb") as stream:
        stream.write(sanitized_bytes(report, source))
    output = env.get("GITHUB_OUTPUT")
    require(type(output) is str and output != "")
    with open(output, "a", encoding="utf-8", newline="\n") as stream:
        stream.write("report_validated=true\n")
    return report


FIXTURE_PACKAGES = ("localrmm/internal/windowsacceptance/native", "localrmm/cmd/windows-prerequisites")
REQUIRED_FIXTURES = {
    (FIXTURE_PACKAGES[0], "TestAncestorDiagnosticMatchesUnchangedAdmissionDecision"),
    (FIXTURE_PACKAGES[0], "TestNativeReadFailureClassificationDoesNotPublishNativeError"),
    (FIXTURE_PACKAGES[0], "TestPrerequisiteDiagnosticsRejectNativeDetailsAndMisleadingFacts"),
    (FIXTURE_PACKAGES[0], "TestOSAncestorsRequireTrustedPathsWithoutTokenClaims"),
    (FIXTURE_PACKAGES[1], "TestReadOnlyPrerequisitesRejectSourceAndEveryMutatingMode"),
}


def validate_fixture_events(raw: bytes) -> None:
    require(type(raw) is bytes and 0 < len(raw) <= 4 * 1024 * 1024)
    passed, skipped, packages = set(), set(), set()
    for line in raw.splitlines():
        event = strict_json(line, 1024 * 1024)
        require(type(event) is dict and event.get("Action") != "fail")
        pair = (event.get("Package"), event.get("Test"))
        if pair in REQUIRED_FIXTURES and event.get("Action") == "pass":
            passed.add(pair)
        if pair in REQUIRED_FIXTURES and event.get("Action") == "skip":
            skipped.add(pair)
        if "Test" not in event and event.get("Action") == "pass":
            packages.add(event.get("Package"))
    require(passed == REQUIRED_FIXTURES and not skipped and packages == set(FIXTURE_PACKAGES))


def run_fixtures(env: dict[str, str], root: Path = ROOT) -> None:
    source = check_environment(env)
    child = child_environment(env)
    verify_checkout(child, source, root)
    verify_go(child, root)
    raw = command(["go", "test", "-json", "-mod=readonly", "-buildvcs=false", "-count=1", "-timeout=60s",
                   "./internal/windowsacceptance/native", "./cmd/windows-prerequisites"],
                  child, root, 600, 4 * 1024 * 1024)
    validate_fixture_events(raw)


def main(argv: list[str] | None = None, env: dict[str, str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    environment = dict(os.environ if env is None else env)
    try:
        require(args in (["--check-source"], ["--run-read-only"], ["--check-fixtures"]))
        if args == ["--check-fixtures"]:
            run_fixtures(environment)
            print("PASS: in-memory Windows diagnostic fixtures only; native service acceptance unverified.")
            return 0
        if args == ["--check-source"]:
            source = check_environment(environment)
            verify_checkout(child_environment(environment), source, ROOT)
            print("PASS: exact source for read-only prerequisite measurement; native service acceptance unverified.")
            return 0
        report = run_measurement(environment)
        print("Windows read-only prerequisites: " + report["status"] + "; check=" + report["check"]
              + "; reason=" + report["reason"] + "; native service acceptance unverified.")
        if report["diagnostic"] is not None:
            diagnostic = report["diagnostic"]
            print("Ancestor diagnostic: location=" + diagnostic["location"] + "; failure="
                  + diagnostic["failure"] + "; rejected-rights=" + ",".join(diagnostic["rights"]) + ".")
        # Blocked/unverified are complete measurements, never native passes.
        return 0
    except Exception:
        print("FAIL: read-only prerequisite execution or evidence rejected; raw output withheld; native service acceptance unverified.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
