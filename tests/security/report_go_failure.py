"""Finite Go failure/timing projection. Never emit Output, stderr or subtests."""
import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

MAX_FILE = 64 * 1024 * 1024
MAX_STDERR = 8 * 1024 * 1024
MAX_LINE = 1024 * 1024
MAX_EVENTS = 250000
MAX_RECORDS = 64
MAX_ACTIVE = 512
MAX_SECONDS = 86400
MAX_TIMING_PACKAGES = 20
MAX_TIMING_TESTS = 32
SOURCE_COMMIT = "fccc4b00cd8a144afd58e4b995747afab7a10022"
ALLOWLIST = Path(__file__).with_name("go_failure_allowlist.json")
ROOT = Path(__file__).resolve().parents[2]
ACTIONS = {"start", "run", "pause", "cont", "pass", "bench", "fail", "output", "skip", "attr", "artifacts"}
KEYS = {"Time", "Action", "Package", "Test", "Elapsed", "Output", "OutputType", "FailedBuild", "Key", "Value", "Path"}
BUILD_ACTIONS = {"build-output", "build-fail"}
BUILD_KEYS = {"ImportPath", "Action", "Output"}
IDENT = re.compile(r"Test(?:[A-Z0-9_][A-Za-z0-9_]*)?\Z")
PACKAGE = re.compile(r"localrmm(?:/[A-Za-z0-9_.-]+)*\Z")
# Strings and comments are tokenized away before recognizing top-level functions.
TOKENS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|`[^`]*`|"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|[A-Za-z_][A-Za-z0-9_]*|[^\s]')


def reject_constant(_):
    raise ValueError("invalid")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("invalid")
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def derive_allowlist(root):
    """Read source only; never import, compile or evaluate repository code."""
    if (root / "go.mod").read_text().splitlines()[:1] != ["module localrmm"]:
        raise ValueError("invalid")
    files = sorted(p for p in root.rglob("*.go")
                   if not any(x in {".git", "node_modules", "vendor"} for x in p.relative_to(root).parts))
    digest = hashlib.sha256()
    packages = {}
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError("invalid")
        name = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        digest.update(name.encode() + b"\0" + hashlib.sha256(raw).digest())
        package = "localrmm" + ("/" + path.parent.relative_to(root).as_posix()
                                if path.parent != root else "")
        if not PACKAGE.fullmatch(package):
            raise ValueError("invalid")
        names = packages.setdefault(package, set())
        if not name.endswith("_test.go"):
            continue
        tokens = [m.group() for m in TOKENS.finditer(raw.decode("utf-8"))
                  if not m.group().startswith(("//", "/*", '"', "'", "`"))]
        depth = 0
        for i, token in enumerate(tokens):
            if token == "func" and depth == 0 and i + 2 < len(tokens):
                candidate = tokens[i + 1]
                if IDENT.fullmatch(candidate) and tokens[i + 2] == "(" and candidate != "TestMain":
                    names.add(candidate)
            if token == "{":
                depth += 1
            elif token == "}":
                depth -= 1
                if depth < 0:
                    raise ValueError("invalid")
        if depth:
            raise ValueError("invalid")
    return {"schemaVersion": 1, "sourceCommit": SOURCE_COMMIT,
            "goSourceSha256": digest.hexdigest(),
            "packages": {p: sorted(names) for p, names in sorted(packages.items())}}


def load_allowlist():
    value = decode(ALLOWLIST.read_bytes())
    if not isinstance(value, dict) or type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        raise ValueError("invalid")
    # Exact source content proves this finite vocabulary belongs to this checkout.
    if value != derive_allowlist(ROOT):
        raise ValueError("invalid")
    return {package: frozenset(names) for package, names in value["packages"].items()}


def open_log(path):
    """Open every component without following symlinks."""
    path = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory = os.open(path.anchor, flags | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_dir = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = next_dir
        return os.open(path.name, flags, dir_fd=directory)
    finally:
        os.close(directory)


def read_private(path, limit):
    """Reject unsafe/changing inode contents; recheck pathname binding at return."""
    fd = open_log(path)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_mode & 0o077
                or before.st_size > limit):
            raise ValueError("invalid")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) > limit or any(getattr(before, f) != getattr(after, f) for f in fields):
            raise ValueError("invalid")
        rebound_fd = open_log(path)
        try:
            rebound = os.fstat(rebound_fd)
        finally:
            os.close(rebound_fd)
        if any(getattr(after, f) != getattr(rebound, f) for f in fields):
            raise ValueError("invalid")
        return raw
    finally:
        if fd is not None:
            os.close(fd)


def validate_event(event):
    if not isinstance(event, dict) or not isinstance(event.get("Action"), str):
        raise ValueError("invalid")
    build = event["Action"] in BUILD_ACTIONS
    if set(event) - (BUILD_KEYS if build else KEYS):
        raise ValueError("invalid")
    if not build and event["Action"] not in ACTIONS:
        raise ValueError("invalid")
    if build and "ImportPath" not in event:
        raise ValueError("invalid")
    for key, limit in (("Package", 512), ("Test", 4096), ("Output", MAX_LINE),
                       ("Time", 128), ("FailedBuild", 1024), ("ImportPath", 1024),
                       ("OutputType", 32), ("Key", MAX_LINE), ("Value", MAX_LINE), ("Path", MAX_LINE)):
        if key in event and (not isinstance(event[key], str) or len(event[key]) > limit):
            raise ValueError("invalid")
    if "Elapsed" in event:
        elapsed = event["Elapsed"]
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed <= MAX_SECONDS:
            raise ValueError("invalid")


def source_package(descriptor, allowed):
    """Normalize fixed Go package descriptors without emitting their input text."""
    if descriptor in allowed:
        return descriptor
    base, separator, suffix = descriptor.partition(" [")
    if separator:
        if not suffix.endswith(".test]") or suffix[:-6] not in allowed:
            return ""
    elif descriptor.endswith(".test"):
        base = descriptor[:-5]
    else:
        return ""
    if base in allowed:
        return base
    if base.endswith("_test") and base[:-5] in allowed:
        return base[:-5]
    return ""


def project(raw, allowed):
    if raw and not raw.endswith(b"\n"):
        raise ValueError("invalid")
    records = set()
    active = {}
    signals = {}
    truncated = False

    def record(category, package, root=""):
        nonlocal truncated
        value = (category, package, root)
        if value not in records:
            if len(records) >= MAX_RECORDS:
                truncated = True
            else:
                records.add(value)

    for count, line in enumerate(io.BytesIO(raw), 1):
        if count > MAX_EVENTS or not line or len(line) > MAX_LINE:
            raise ValueError("invalid")
        event = decode(line)
        validate_event(event)
        if event["Action"] in BUILD_ACTIONS:
            package = source_package(event["ImportPath"], allowed)
            if package and event["Action"] == "build-fail":
                signals.setdefault(package, set()).add("build_failure")
                record("build_failure", package)
            continue
        package = event.get("Package", "")
        if package not in allowed:
            continue
        test = event.get("Test", "")
        candidate = test.split("/", 1)[0]
        root = candidate if candidate in allowed[package] else ""
        action = event["Action"]
        if action == "run" and root:
            active.setdefault(package, set()).add(root)
            if sum(map(len, active.values())) > MAX_ACTIVE:
                raise ValueError("invalid")
        if action in {"pass", "skip", "fail"} and test == root:
            active.setdefault(package, set()).discard(root)
        if action == "output":
            output = event.get("Output", "")
            category = None
            if output == "panic: test timed out after 15m0s\n":
                category = "timeout"
            elif output == "WARNING: DATA RACE\n":
                category = "data_race"
            elif output == "FAIL\t" + package + " [build failed]\n":
                category = "build_failure"
            if category:
                signals.setdefault(package, set()).add(category)
                if category == "timeout":
                    for known in sorted(active.get(package, set())):
                        record(category, package, known)
                record(category, package, root)
        if action == "fail":
            if source_package(event.get("FailedBuild", ""), allowed):
                signals.setdefault(package, set()).add("build_failure")
            categories = signals.get(package, set()) or {"test_failure"}
            for category in sorted(categories):
                record(category, package, root)
    result = [{"category": category, "package": package, **({"test": root} if root else {})}
              for category, package, root in sorted(records)]
    return {"category": "failure" if result else "unclassified", "records": result,
            "truncated": truncated}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid")


def project_timings(raw, allowed):
    """Bounded elapsed metadata from successful runs; never runtime text."""
    if not raw or len(raw) > MAX_FILE or not raw.endswith(b"\n"):
        raise ValueError("invalid")
    packages, tests = {}, {}
    skipped_packages = set()
    for count, line in enumerate(io.BytesIO(raw), 1):
        if count > MAX_EVENTS or len(line) > MAX_LINE:
            raise ValueError("invalid")
        event = decode(line)
        validate_event(event)
        action = event["Action"]
        if action in {"fail", "build-fail"}:
            raise ValueError("unsuccessful run")
        package = event.get("Package", "")
        if package not in allowed:
            continue
        test = event.get("Test", "")
        if action == "skip" and not test:
            if (package, "") in packages or package in skipped_packages:
                raise ValueError("duplicate completion")
            skipped_packages.add(package)
        if action != "pass":
            continue
        if test and test not in allowed[package]:
            continue  # Includes every subtest, even beneath a known root.
        if "Elapsed" not in event:
            raise ValueError("missing elapsed")
        key = (package, test)
        target = tests if test else packages
        if key in target or package in skipped_packages:
            raise ValueError("duplicate completion")
        target[key] = event["Elapsed"]
    if not packages or any((package, "") not in packages for package, _ in tests):
        raise ValueError("incomplete package completion")

    def slowest(values, limit):
        # Source names break elapsed ties deterministically. Root and package
        # durations overlap; they must never be summed together as CPU time.
        return [{"package": package, **({"test": test} if test else {}),
                 "elapsedSeconds": round(elapsed, 3)}
                for (package, test), elapsed in
                sorted(values.items(), key=lambda item: (-item[1], item[0]))[:limit]]

    return {"category": "success_timings", "packages": slowest(packages, MAX_TIMING_PACKAGES),
            "tests": slowest(tests, MAX_TIMING_TESTS),
            "completedPackages": len(packages), "completedRoots": len(tests),
            "skippedPackages": len(skipped_packages),
            "truncated": len(packages) > MAX_TIMING_PACKAGES or len(tests) > MAX_TIMING_TESTS}


def main(argv=None):
    exit_code = elapsed = None
    success = False
    try:
        parser = SafeParser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--events", required=True)
        parser.add_argument("--stderr", required=True)
        parser.add_argument("--exit-code", required=True)
        parser.add_argument("--elapsed-seconds", required=True)
        parser.add_argument("--success", action="store_true")
        args = parser.parse_args(argv)
        success = args.success
        if (not re.fullmatch(r"[0-9]{1,3}", args.exit_code)
                or not (int(args.exit_code) == 0 if success else 1 <= int(args.exit_code) <= 255)):
            raise ValueError("invalid")
        exit_code = int(args.exit_code)
        if not re.fullmatch(r"[0-9]{1,5}", args.elapsed_seconds) or int(args.elapsed_seconds) > MAX_SECONDS:
            raise ValueError("invalid")
        elapsed = int(args.elapsed_seconds)
        allowed = load_allowlist()
        raw = read_private(args.events, MAX_FILE)
        read_private(args.stderr, MAX_STDERR)  # Verified privately, never interpreted or emitted.
        result = project_timings(raw, allowed) if success else project(raw, allowed)
        code = 0
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        result = {"category": "diagnostic_unavailable", "records": [], "truncated": False}
        code = 1
    result.update(exitCode=exit_code, elapsedSeconds=elapsed)
    prefix = "GO_TEST_TIMINGS " if success else "GO_TEST_DIAGNOSTIC "
    print(prefix + json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
