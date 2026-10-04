"""Require exact native completion and bounded endpoint-consent evidence.

Reads private Go JSON only. Success/failure output never includes source values.
"""
from contextlib import closing
import json
import os
import re
import stat
import sys

from report_complete_mvp import MAX_FILE, MAX_LINE, PACKAGE, ROOT, PREFIX, unique_object, reject_constant

REQUIRED = {ROOT, ROOT + "/tls", ROOT + "/http-test"}
LEAVES = {ROOT + "/tls", ROOT + "/http-test"}
ORDER = ("preview", "enable", "first", "restart", "disable", "disabled_restart")
FIXED = {
    "endpoint identity consent: stage=preview enabled=false existingState=unchanged": "preview",
    "endpoint identity consent: stage=enable enabled=true existingState=unchanged": "enable",
    "endpoint identity consent: stage=disable enabled=false existingState=unchanged": "disable",
    "endpoint identity retained: stage=disabled_restart ordinary=advanced endpoint=original_age sequence=unchanged receipt=unchanged expiry=unchanged payload=unchanged": "disabled_restart",
}
COUNT = r"(0|[1-9][0-9]{0,2})"
OBSERVATION = re.compile(
    r"endpoint identity observation: stage=(first|restart) hostname=complete interfaces=complete countExact=true observedRows="
    + COUNT + r" addresses=complete countExact=true ipv4Rows=" + COUNT
    + r" ipv6Rows=" + COUNT + r" assignedRows=" + COUNT
)


OVERVIEW_ORDER = ("preview", "enable", "first", "restart", "disable", "disabled_restart")
OVERVIEW_FIXED = {
    "complete overview consent: stage=preview enabled=false existingState=unchanged": "preview",
    "complete overview consent: stage=enable enabled=true existingState=unchanged": "enable",
    "complete overview consent: stage=disable enabled=false existingState=unchanged": "disable",
    "complete overview retained: stage=restart ordinary=advanced generations=unchanged capture=original_age receipt=unchanged expiry=unchanged rows=unchanged": "restart",
    "complete overview retained: stage=disabled_restart ordinary=advanced generations=unchanged capture=original_age receipt=unchanged expiry=unchanged rows=unchanged": "disabled_restart",
}
OVERVIEW_COUNT = r"(0|[1-9][0-9]{0,4})"
OVERVIEW_OBSERVATION = re.compile(
    r"complete overview observation: stage=first processes=complete countExact=true processRows="
    + OVERVIEW_COUNT + r" volumes=complete countExact=true volumeRows=" + OVERVIEW_COUNT
    + r" processPages=" + OVERVIEW_COUNT + r" volumePages=" + OVERVIEW_COUNT + r" manifest=validated"
)


def overview_evidence_stage(payload):
    if payload in OVERVIEW_FIXED:
        return OVERVIEW_FIXED[payload]
    match = OVERVIEW_OBSERVATION.fullmatch(payload)
    if match is None:
        raise ValueError("invalid complete-overview evidence")
    processes, volumes, process_pages, volume_pages = map(int, match.groups())
    if not (1 <= processes <= 32768 and 1 <= volumes <= 16384
            and (processes + 99) // 100 <= process_pages <= processes
            and (volumes + 99) // 100 <= volume_pages <= volumes):
        raise ValueError("invalid complete-overview counts")
    return "first"


def evidence_stage(payload):
    if payload in FIXED:
        return FIXED[payload]
    match = OBSERVATION.fullmatch(payload)
    if match is None:
        raise ValueError("invalid endpoint evidence")
    rows, ipv4, ipv6, total = map(int, match.groups()[1:])
    if not (1 <= rows <= 32 and 0 <= ipv4 <= 128 and 0 <= ipv6 <= 128
            and 1 <= total <= 128 and ipv4 + ipv6 == total):
        raise ValueError("invalid endpoint counts")
    return match.group(1)


def validate(events, require_overview=False):
    passed = set()
    package_passed = False
    stages = {leaf: [] for leaf in LEAVES}
    overview_stages = {leaf: [] for leaf in LEAVES}
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("invalid event")
        action, test, package = event.get("Action"), event.get("Test"), event.get("Package")
        if action in ("fail", "build-fail"):
            raise ValueError("failed event")
        if test is not None and not isinstance(test, str):
            raise ValueError("invalid test")
        if test in REQUIRED:
            if package != PACKAGE or action == "skip":
                raise ValueError("wrong package or skipped case")
            if action == "pass":
                if test in passed:
                    raise ValueError("duplicate completion")
                if test == ROOT and not LEAVES.issubset(passed):
                    raise ValueError("premature root completion")
                if test in LEAVES and tuple(stages[test]) != ORDER:
                    raise ValueError("incomplete endpoint evidence")
                if test in LEAVES and require_overview and tuple(overview_stages[test]) != OVERVIEW_ORDER:
                    raise ValueError("incomplete complete-overview evidence")
                passed.add(test)
        if package == PACKAGE and "Test" not in event and action == "pass":
            if package_passed or passed != REQUIRED:
                raise ValueError("invalid package completion")
            package_passed = True
        if package != PACKAGE or action != "output" or test not in REQUIRED:
            continue
        output = event.get("Output")
        if not isinstance(output, str):
            raise ValueError("invalid output")
        match = PREFIX.fullmatch(output)
        if match is None:
            continue
        payload = match.group(1)
        if payload.startswith("endpoint identity "):
            selected_stages, selected_order = stages, ORDER
            stage = evidence_stage(payload)
        elif require_overview and payload.startswith("complete overview "):
            selected_stages, selected_order = overview_stages, OVERVIEW_ORDER
            stage = overview_evidence_stage(payload)
        else:
            continue
        if test not in LEAVES or test in passed or package_passed:
            raise ValueError("evidence outside live profile")
        if len(selected_stages[test]) >= len(selected_order) or stage != selected_order[len(selected_stages[test])]:
            raise ValueError("missing, duplicate or reordered native evidence")
        selected_stages[test].append(stage)
    if passed != REQUIRED or not package_passed or any(tuple(v) != ORDER for v in stages.values()):
        raise ValueError("incomplete native result")
    if require_overview and any(tuple(v) != OVERVIEW_ORDER for v in overview_stages.values()):
        raise ValueError("incomplete complete-overview result")


def read_events(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE:
            raise ValueError("invalid log file")
        total = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > MAX_LINE or total > MAX_FILE or not line.endswith(b"\n"):
                    raise ValueError("invalid log bounds")
                yield json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
    finally:
        os.close(fd)


def main(argv):
    require_overview = len(argv) == 3 and argv[1] == "--require-complete-overview"
    try:
        if len(argv) != 2 and not require_overview:
            raise ValueError("invalid arguments")
        with closing(read_events(argv[2] if require_overview else argv[1])) as events:
            validate(events, require_overview=require_overview)
    except Exception:
        if require_overview:
            print("FAIL: missing, skipped, malformed or incomplete endpoint/complete-overview native evidence.")
        else:
            print("FAIL: missing, skipped, malformed or incomplete endpoint-identity native evidence.")
        return 1
    if require_overview:
        print("PASS: TLS and HTTP-test endpoint and complete-overview consent, positive delivered process/mount pages, restart and disable retention; no raw inventory data exported.")
    else:
        print("PASS: TLS and HTTP-test consent preview, enable, fresh reporting, restart and disable retain the original endpoint metadata age; no raw identity data exported.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
