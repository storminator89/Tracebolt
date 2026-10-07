#!/usr/bin/env python3
"""Native Windows read-only gate. Runtime telemetry stays in memory, never logs/artifacts."""
from __future__ import annotations

import json
from datetime import datetime
import unicodedata
import os
from pathlib import Path
import subprocess
import sys
import tempfile

PACKAGES = ("./internal/windowsinventory", "./internal/windowsevents", "./cmd/windows-agent")
REQUIRED = {
    ("localrmm/internal/windowsinventory", "TestNativeWindowsReadOnlyInventory"),
    ("localrmm/internal/windowsevents", "TestNativeWindowsEventMetadata"),
}
MAX_BYTES = 4 * 1024 * 1024


class GateFailure(Exception):
    pass


def require(value, message):
    if not value:
        raise GateFailure(message)


def command(args, env, timeout, stage):
    try:
        result = subprocess.run(args, env=env, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise GateFailure(stage + " could not complete") from None
    require(result.returncode == 0, stage + " failed; raw output withheld")
    return result


def check_test_events(raw):
    require(len(raw) <= 8 * MAX_BYTES, "native test output exceeded gate limit")
    passed, skipped = set(), set()
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            raise GateFailure("native test stream is malformed") from None
        require(isinstance(event, dict), "native test event is malformed")
        key = (event.get("Package"), event.get("Test"))
        if key in REQUIRED:
            if event.get("Action") == "pass":
                passed.add(key)
            if event.get("Action") == "skip":
                skipped.add(key)
    require(passed == REQUIRED and not skipped, "required native reads did not pass without skips")


def check_document(raw, include_events):
    require(0 < len(raw) <= MAX_BYTES, "native document exceeds gate limit")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise GateFailure("native document is malformed") from None
    require(isinstance(value, dict), "native document root is invalid")
    require(set(value) == ({"inventory", "eventMetadata"} if include_events else {"inventory"}),
            "event consent boundary is invalid")
    report = value["inventory"]
    require(isinstance(report, dict) and report.get("schema") == "tracebolt.windows-readonly.v1"
            and report.get("platform") == "windows", "native inventory schema is invalid")
    require(report.get("nativeVerification") == "installed-service-and-enrollment-unverified",
            "native service boundary is missing")
    for name, limit in (("hostname", 1), ("processes", 2048), ("services", 2048),
                        ("software", 2048), ("network", 512)):
        section = report.get(name)
        require(isinstance(section, dict) and isinstance(section.get("rows"), list)
                and len(section["rows"]) <= limit
                and section.get("quality") in {"healthy", "limited", "unknown", "denied"}
                and type(section.get("complete")) is bool
                and type(section.get("truncated")) is bool, "native section contract is invalid")
        require(not section["complete"] or (section["quality"] == "healthy" and not section["truncated"]),
                "native completeness claim is inconsistent")
    for name in ("cpu", "memory", "disk"):
        metric = report.get(name)
        require(isinstance(metric, dict) and metric.get("quality") == "healthy"
                and type(metric.get("value")) in {int, float}
                and 0 <= metric["value"] <= 100, "native capacity sample is unavailable")
    if include_events:
        check_events(value["eventMetadata"])
    return value


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return 1601 <= parsed.year <= 9999


def check_events(report):
    require(isinstance(report, dict) and set(report) == {"source", "quality", "collected_at", "limit_per_channel", "complete", "truncated", "channels"},
            "event report fields are invalid")
    require(report["source"] == "windows-event-log-system-metadata"
            and report["quality"] in {"observed", "bounded", "partial", "unavailable"}
            and timestamp(report["collected_at"])
            and type(report["limit_per_channel"]) is int and report["limit_per_channel"] == 25
            and type(report["complete"]) is bool and type(report["truncated"]) is bool,
            "event report provenance or bounds are invalid")
    channels = report["channels"]
    require(isinstance(channels, list) and len(channels) == 2, "event channel count is invalid")
    names, total = set(), 0
    reasons = {"windows_events_access_denied", "windows_events_source_unavailable", "windows_events_read_failed",
               "windows_events_invalid_metadata", "windows_events_metadata_buffer_limit",
               "context canceled", "context deadline exceeded", "windows_events_unsupported_platform"}
    for part in channels:
        require(isinstance(part, dict) and set(part) <= {"channel", "source", "quality", "complete", "truncated", "reason", "events"}
                and {"channel", "source", "quality", "complete", "truncated", "events"} <= set(part), "event channel fields are invalid")
        require(part["channel"] in {"Application", "System"} and part["channel"] not in names
                and part["source"] == report["source"]
                and part["quality"] in {"observed", "bounded", "partial", "unavailable"}
                and type(part["complete"]) is bool and type(part["truncated"]) is bool,
                "event channel provenance is invalid")
        names.add(part["channel"])
        require(not part["complete"] or (part["quality"] == "observed" and not part["truncated"] and not part.get("reason")),
                "event channel completeness is invalid")
        require(not part.get("reason") or part["reason"] in reasons, "event channel error is not sanitized")
        events = part["events"]
        require(isinstance(events, list) and len(events) <= 25, "event row bound is invalid")
        for event in events:
            require(isinstance(event, dict) and set(event) == {"record_id", "event_id", "level", "provider", "timestamp", "channel"},
                    "event row includes unapproved fields")
            require(type(event["record_id"]) is int and 0 < event["record_id"] < 2 ** 64
                    and type(event["event_id"]) is int and 0 <= event["event_id"] < 2 ** 16
                    and type(event["level"]) is int and 0 <= event["level"] <= 255
                    and event["channel"] == part["channel"] and timestamp(event["timestamp"]),
                    "event scalar metadata is invalid")
            provider = event["provider"]
            require(isinstance(provider, str) and 0 < len(provider) <= 256 and provider.strip() == provider
                    and all(unicodedata.category(c) not in {"Cc", "Cf", "Cs"} for c in provider),
                    "event provider metadata is invalid")
        total += len(events)
    require(total > 0, "event gate did not exercise actual metadata rendering")
    require(report["complete"] == all(part["complete"] for part in channels)
            and report["truncated"] == any(part["truncated"] for part in channels),
            "event aggregate completeness is invalid")


def main():
    stage = "platform"
    try:
        require(sys.platform == "win32", "this gate requires native Windows")
        env = os.environ.copy()
        env.pop("GOOS", None)
        env.pop("GOARCH", None)
        env["GOTOOLCHAIN"] = "local"
        env["TRACEBOLT_WINDOWS_READONLY_NATIVE"] = "1"
        stage = "architecture"
        arch = command(["go", "env", "GOHOSTARCH"], env, 30, stage).stdout.strip()
        require(arch == b"amd64", "hosted Windows gate requires native amd64")
        stage = "tests"
        tests = command(["go", "test", "-json", "-count=1", "-timeout=120s", "-buildvcs=false", *PACKAGES], env, 300, stage)
        check_test_events(tests.stdout)
        with tempfile.TemporaryDirectory(prefix="tracebolt-readonly-") as temp:
            binary = Path(temp) / "windows-agent.exe"
            stage = "build"
            command(["go", "build", "-buildvcs=false", "-trimpath", "-o", str(binary), "./cmd/windows-agent"], env, 300, stage)
            stage = "unacknowledged scope"
            result = subprocess.run([str(binary)], env=env, capture_output=True, timeout=20, check=False)
            require(result.returncode == 2 and not result.stdout, "unacknowledged collection was allowed")
            stage = "inventory CLI"
            result = command([str(binary), "--collect-read-only"], env, 45, stage)
            require(not result.stderr, "inventory CLI wrote unexpected stderr")
            check_document(result.stdout, False)
            stage = "event metadata CLI"
            result = command([str(binary), "--collect-read-only", "--event-metadata"], env, 45, stage)
            require(not result.stderr, "event metadata CLI wrote unexpected stderr")
            check_document(result.stdout, True)
            stage = "arm64 cross-build"
            cross_env = dict(env, GOOS="windows", GOARCH="arm64", CGO_ENABLED="0")
            command(["go", "build", "-buildvcs=false", "-trimpath", "-o", str(Path(temp) / "windows-agent-arm64.exe"), "./cmd/windows-agent"], cross_env, 300, stage)
        print("PASS: native Windows amd64 inventory and event metadata; explicit scope; no skips, service installation, enrollment or telemetry export. Windows arm64 cross-build only.")
        return 0
    except (GateFailure, OSError, subprocess.TimeoutExpired):
        print("FAIL: Windows read-only gate at " + stage + "; raw output withheld.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
