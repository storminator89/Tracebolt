"""Require exact ordinary-user Linux action IPC tests, with no skipped evidence.

Only bounded Go JSON is read. Raw test output is never printed. The caller must
supply the actual Go command status and checked-out source SHA; this is CI source
attribution, not a claim of installed root-helper or systemd acceptance.
"""
from contextlib import closing
from datetime import datetime
import json
import math
import os
import re
import stat
import sys

MAX_FILE = 4 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_EVENTS = 16384
HELPER = "localrmm/internal/actionhelper"
CLIENT = "localrmm/internal/actionclient"
MISMATCH = "TestAuthorityInheritedListenerRejectsMismatch"
REQUIRED = {
    HELPER: frozenset({
        "TestAuthorityKernelPeerCredentials",
        "TestAuthorityInheritedListenerFixture",
        MISMATCH,
        *(MISMATCH + "/" + name for name in (
            "pid", "fds", "fdnames", "name", "group", "mode", "symlink",
            "ancestor", "descriptor",
        )),
    }),
    CLIENT: frozenset({"TestCredentialReaderNativePasscredRejectsNonRootWriter"}),
}
# Select entire roots, including every subtest. A narrow subtest filter cannot
# satisfy REQUIRED, and future skipped or unrecognized subtests also fail closed.
RUN_PATTERN = "^(TestAuthorityKernelPeerCredentials|TestAuthorityInheritedListenerFixture|TestAuthorityInheritedListenerRejectsMismatch|TestCredentialReaderNativePasscredRejectsNonRootWriter)$"
FAILURE = "FAIL: missing, skipped, failed, duplicate, malformed or incomplete native action IPC evidence."
EVENT_KEYS = {"Time", "Action", "Package", "Test", "Elapsed", "Output", "OutputType"}
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("non-finite JSON value")


def validate(events, command_status, source_sha):
    if type(command_status) is not int or command_status != 0:
        raise ValueError("Go command failed")
    if not isinstance(source_sha, str) or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("invalid source attribution")
    packages = {}
    tests = {package: {} for package in REQUIRED}
    for count, event in enumerate(events, 1):
        if count > MAX_EVENTS:
            raise ValueError("too many events")
        if not isinstance(event, dict) or not {"Time", "Action", "Package"} <= event.keys() or not event.keys() <= EVENT_KEYS:
            raise ValueError("invalid event shape")
        action, package, test = event["Action"], event["Package"], event.get("Test")
        # No skip is acceptable, even for a package, an unexpected test or a
        # descendant whose parent later passes. Failed builds are never ignored.
        if not isinstance(action, str) or action not in {"start", "run", "output", "pass"}:
            raise ValueError("non-passing event")
        if not isinstance(package, str) or package not in REQUIRED:
            raise ValueError("unexpected package")
        if not isinstance(event["Time"], str) or TIME.fullmatch(event["Time"]) is None:
            raise ValueError("invalid event time")
        datetime.fromisoformat(event["Time"].replace("Z", "+00:00"))
        if (action == "pass") != ("Elapsed" in event):
            raise ValueError("missing or misplaced elapsed time")
        if "Elapsed" in event and (type(event["Elapsed"]) not in (int, float)
                                   or not math.isfinite(event["Elapsed"]) or event["Elapsed"] < 0):
            raise ValueError("invalid elapsed time")
        if "Test" in event and (not isinstance(test, str) or test not in REQUIRED[package]):
            raise ValueError("unexpected test or subtest")
        if action == "output":
            if not isinstance(event.get("Output"), str) or not event["Output"]:
                raise ValueError("invalid output event")
            # Go 1.27 identifies test framing separately from error output.
            if "OutputType" in event and event["OutputType"] != "frame":
                raise ValueError("error or invalid output type")
        elif "Output" in event or "OutputType" in event:
            raise ValueError("misplaced output")
        if action == "start":
            if "Test" in event or package in packages:
                raise ValueError("duplicate or invalid package start")
            packages[package] = "running"
            continue
        if packages.get(package) != "running":
            raise ValueError("event outside live package")
        if test is None:
            if action == "output":
                continue
            if action != "pass" or set(tests[package]) != REQUIRED[package] or any(state != "passed" for state in tests[package].values()):
                raise ValueError("incomplete package completion")
            packages[package] = "passed"
            continue
        states = tests[package]
        if action == "run":
            if test in states:
                raise ValueError("duplicate test start")
            if "/" in test and states.get(test.rsplit("/", 1)[0]) != "running":
                raise ValueError("subtest outside live parent")
            states[test] = "running"
            continue
        if states.get(test) != "running":
            raise ValueError("event outside live test")
        if action == "pass":
            children = {name for name in REQUIRED[package] if name.startswith(test + "/")}
            if any(states.get(name) != "passed" for name in children):
                raise ValueError("incomplete parent completion")
            states[test] = "passed"
    if set(packages) != set(REQUIRED) or any(state != "passed" for state in packages.values()):
        raise ValueError("missing or partial packages")


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
    try:
        if len(argv) != 6 or argv[2] != "--go-exit-code" or argv[4] != "--source-sha" or re.fullmatch(r"0|[1-9][0-9]{0,2}", argv[3]) is None:
            raise ValueError("invalid arguments")
        with closing(read_events(argv[1])) as events:
            validate(events, int(argv[3]), argv[5])
    except Exception:
        print(FAILURE)
        return 1
    print("PASS: 13 exact native action IPC tests/subtests with no skips; source=" + argv[5]
          + "; ordinary-user kernel peer/inherited-listener checks and non-root writer rejection only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
