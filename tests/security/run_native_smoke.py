#!/usr/bin/env python3
"""Actual local-agent runtime smoke test; never prints or uploads telemetry."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

from validate_bundle import MAX_BYTES, validate

PACKAGES = (
    "./internal/collector", "./internal/bundle", "./cmd/agent",
)


def safe_failed_test_names(raw):
    allowed = {"localrmm/internal/collector", "localrmm/internal/bundle", "localrmm/cmd/agent", "localrmm/tests/security"}
    failures = set()
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict) or event.get("Action") != "fail" or event.get("Package") not in allowed:
            continue
        name = event.get("Test", "")
        if isinstance(name, str) and re.fullmatch(r"Test[A-Za-z0-9_]{1,120}", name):
            failures.add(name)
    # No subtest labels, output events, values, paths or telemetry are emitted.
    return ", ".join(sorted(failures)[:10])


class SmokeFailure(Exception):
    pass


def require(condition, safe_message):
    if not condition:
        raise SmokeFailure(safe_message)


def command(args, env, timeout, stage):
    # Both streams stay in process memory and are never printed, even on failure.
    # In particular, pre-existing Go assertion messages can contain live samples.
    try:
        result = subprocess.run(args, env=env, capture_output=True, timeout=timeout,
                                check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise SmokeFailure(f"{stage} could not complete") from None
    if result.returncode != 0:
        names = safe_failed_test_names(result.stdout) if "Go" in stage else ""
        raise SmokeFailure(f"{stage} failed" + (f"; failed tests: {names}" if names else ""))
    return result


def check_native_contract(value, expected_platform, expected_arch):
    require(value["architecture"] == expected_arch, "agent architecture mismatch")
    device = value["observation"]
    evidence = {item["id"]: item for item in device["evidence"]}
    if expected_platform == "linux":
        required_metrics = ("cpu", "memory", "disk")
        required_evidence = ("sandbox-os", "sandbox-uptime")
        absent_metrics = ()
    elif expected_platform == "windows":
        required_metrics = ("memory", "disk")
        required_evidence = ("local-windows-os", "local-windows-uptime")
        absent_metrics = ("cpu",)
    else:
        required_metrics = ("disk",)
        required_evidence = ("local-macos-os", "local-macos-kernel",
                             "local-macos-uptime", "local-macos-memory-capacity")
        absent_metrics = ("cpu", "memory")
    for field in required_metrics:
        metric = device[field]
        require(metric["quality"] == "healthy" and metric["value"] is not None,
                f"required {expected_platform} {field} observation unavailable")
    for field in absent_metrics:
        metric = device[field]
        require(metric["quality"] == "unknown" and metric["value"] is None,
                f"unsupported {expected_platform} {field} was presented as collected")
    for identifier in required_evidence:
        require(identifier in evidence and evidence[identifier]["quality"] == "healthy",
                f"required {expected_platform} native evidence unavailable")
    if expected_platform == "macos":
        capacity = evidence["local-macos-memory-capacity"]["value"]
        parts = capacity.split()
        require(len(parts) == 2 and parts[1] == "bytes" and parts[0].isdigit()
                and int(parts[0]) > 0, "macOS RAM capacity is not a positive byte count")
    metrics = Counter(device[k]["quality"] for k in ("cpu", "memory", "disk"))
    observations = Counter(item["quality"] for item in device["evidence"])
    return metrics, observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-platform", required=True, choices=("linux", "windows", "macos"))
    parser.add_argument("--expect-arch", required=True, choices=("amd64", "arm64"))
    args = parser.parse_args()
    try:
        host = {"linux": "linux", "win32": "windows", "darwin": "macos"}.get(sys.platform)
        require(host == args.expect_platform, "runner does not match requested native platform")
        env = os.environ.copy()
        # Do not accidentally cross-compile the test or executable on this job.
        env.pop("GOOS", None)
        env.pop("GOARCH", None)
        tests = command(["go", "test", "-json", "-count=1", "-timeout=120s", *PACKAGES],
                        env, 600, "native Go package tests")
        # The rest of tests/security includes Linux-only manager/developer
        # transport tests. Keep those in the full Linux job; this native job
        # executes every independent native support-bundle contract unchanged.
        bundle_tests = command(["go", "test", "-json", "-count=1", "-timeout=120s",
                                "-run", "^TestSupportBundle", "./tests/security"],
                               env, 600, "native Go independent bundle tests")
        passed = set()
        for line in (tests.stdout + b"\n" + bundle_tests.stdout).splitlines():
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if event.get("Action") == "pass" and "Test" not in event:
                passed.add(event.get("Package"))
        expected = {"localrmm/" + package[2:] for package in PACKAGES} | {"localrmm/tests/security"}
        require(expected <= passed, "native package execution was not fully confirmed")
        print("PASS: native Go package tests.")
        suffix = ".exe" if host == "windows" else ""
        with tempfile.TemporaryDirectory(prefix="tracebolt-native-smoke-") as temporary:
            agent = Path(temporary) / ("tracebolt-agent" + suffix)
            command(["go", "build", "-buildvcs=false", "-trimpath", "-o", str(agent), "./cmd/agent"],
                    env, 300, "native agent build")
            output = command([str(agent), "--support-bundle"], env, 30, "native agent CLI")
            require(not output.stderr, "native agent emitted unexpected stderr")
            require(len(output.stdout) <= MAX_BYTES, "native agent exceeded support-bundle byte cap")
            try:
                validate(output.stdout, args.expect_platform)
                bundle = json.loads(output.stdout)
            except Exception:
                # jsonschema and JSON errors can contain the input; suppress them.
                raise SmokeFailure("native support-bundle schema or privacy contract failed") from None
            metrics, evidence = check_native_contract(bundle, args.expect_platform, args.expect_arch)
        available_metrics = metrics["healthy"]
        unavailable_metrics = sum(metrics.values()) - available_metrics
        available_evidence = evidence["healthy"]
        unavailable_evidence = sum(evidence.values()) - available_evidence
        print(f"PASS: {args.expect_platform}/{args.expect_arch} native CLI schema, cap and privacy.")
        print(f"Availability counts: metrics available={available_metrics} unavailable={unavailable_metrics}; "
              f"evidence available={available_evidence} unavailable={unavailable_evidence}.")
        return 0
    except SmokeFailure as failure:
        # This exception only carries developer-authored fixed messages.
        print(f"FAIL: {failure}.", file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: native smoke test could not complete safely.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
