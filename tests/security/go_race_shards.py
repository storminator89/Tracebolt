"""Exact, source-bound Go race shards. Only normalized completion evidence leaves CI."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import tempfile
import time

# Load this exact sibling even under Python -I; never search the environment.
_spec = importlib.util.spec_from_file_location("tracebolt_go_reporter", Path(__file__).with_name("report_go_failure.py"))
reporter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reporter)
ROOT = Path(__file__).resolve().parents[2]
SHARDS = 3
SKIP = "^(TestIndependentPackageStoreDenseCapacityAndActualIngress|TestGuidedThreeBinaryEnrollmentAndForeground)$"
WEIGHTS = Path(__file__).with_name("go_race_weights.json")
MAX_PACKAGES = 1024
MAX_REPORT = 1024 * 1024
LIST_COMMAND = ["go", "list", "-race", "-buildvcs=false", "-f", "{{.ImportPath}} {{if or .TestGoFiles .XTestGoFiles}}tests{{else}}none{{end}}", "./..."]
NEEDS = {"backend-checks", "go-race", "package-dense-race"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def package_rows(raw, allowed):
    """Only go list ./... selects packages; source names constrain exported text."""
    if not raw or len(raw) > MAX_REPORT or not raw.endswith(b"\n"):
        raise ValueError("invalid package list")
    rows = {}
    for line in raw.decode("utf-8").splitlines():
        fields = line.split(" ")
        if len(fields) != 2 or fields[0] not in allowed or fields[1] not in {"tests", "none"} or fields[0] in rows:
            raise ValueError("invalid package list")
        rows[fields[0]] = fields[1] == "tests"
    if not 1 <= len(rows) <= MAX_PACKAGES:
        raise ValueError("invalid package count")
    return dict(sorted(rows.items()))


def weights(raw):
    value = reporter.decode(raw)
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "sourceRun", "milliseconds"}
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["sourceRun"] != "38058537360/114231878636"
            or not isinstance(value["milliseconds"], dict) or len(value["milliseconds"]) > MAX_PACKAGES):
        raise ValueError("invalid weights")
    for package, weight in value["milliseconds"].items():
        if not reporter.PACKAGE.fullmatch(package) or type(weight) is not int or not 1 <= weight <= 900000:
            raise ValueError("invalid weight")
    return value["milliseconds"]


def partition(packages, timings):
    if (not isinstance(packages, dict) or not 1 <= len(packages) <= MAX_PACKAGES
            or any(not reporter.PACKAGE.fullmatch(p) or type(t) is not bool for p, t in packages.items())):
        raise ValueError("invalid packages")
    result, loads = [[] for _ in range(SHARDS)], [0] * SHARDS
    # Historical weights schedule, never select, packages. New test packages get
    # a 3-second scheduling weight; no-test packages remain covered at zero.
    cost = {p: timings.get(p, 3000) if has_tests else 0 for p, has_tests in packages.items()}
    for package in sorted(packages, key=lambda p: (-cost[p], p)):
        shard = min(range(SHARDS), key=lambda s: (loads[s], len(result[s]), s))
        result[shard].append(package)
        loads[shard] += cost[package]
    result = [sorted(group) for group in result]
    validate_partition(packages, result)
    return result


def validate_partition(packages, groups):
    if not isinstance(groups, list) or len(groups) != SHARDS:
        raise ValueError("invalid shards")
    seen = []
    for group in groups:
        if not isinstance(group, list) or any(not isinstance(p, str) for p in group) or group != sorted(set(group)):
            raise ValueError("invalid shard packages")
        seen.extend(group)
    if len(seen) != len(set(seen)) or set(seen) != set(packages):
        raise ValueError("incomplete or overlapping partition")


def context(env):
    value = {"commit": env.get("GITHUB_SHA", ""), "runId": env.get("GITHUB_RUN_ID", ""),
             "runAttempt": env.get("GITHUB_RUN_ATTEMPT", "")}
    if not re.fullmatch(r"[0-9a-f]{40}", value["commit"]):
        raise ValueError("invalid commit")
    if any(not re.fullmatch(r"[1-9][0-9]{0,19}", value[k]) for k in ("runId", "runAttempt")):
        raise ValueError("invalid run")
    return value


def checked_capture(command):
    # Go list/build errors can include arbitrary source text. Never print them.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=error, check=False)
        output.seek(0)
        raw = output.read(MAX_REPORT + 1)
    if result.returncode or len(raw) > MAX_REPORT:
        raise ValueError("discovery failed")
    return raw


def discover():
    allowed = reporter.load_allowlist()  # Exact existing Go source digest guard.
    ctx = context(os.environ)
    if checked_capture(["git", "rev-parse", "HEAD"]).decode().strip() != ctx["commit"]:
        raise ValueError("wrong checkout")
    if checked_capture(["go", "env", "GOOS", "GOARCH"]) != b"linux\namd64\n":
        raise ValueError("wrong target")
    packages = package_rows(checked_capture(LIST_COMMAND), allowed)
    groups = partition(packages, weights(WEIGHTS.read_bytes()))
    plan = {"schemaVersion": 1, **ctx, "goSourceSha256": reporter.derive_allowlist(ROOT)["goSourceSha256"],
            "packages": packages, "shards": groups}
    return plan, allowed


def normalize(raw, expected):
    if not raw or len(raw) > reporter.MAX_FILE or not raw.endswith(b"\n"):
        raise ValueError("invalid events")
    started, completed = set(), {}
    for count, line in enumerate(io.BytesIO(raw), 1):
        if count > reporter.MAX_EVENTS or len(line) > reporter.MAX_LINE:
            raise ValueError("invalid events")
        event = reporter.decode(line)
        reporter.validate_event(event)
        action = event["Action"]
        if action in {"fail", "build-fail"}:
            raise ValueError("failed events")
        if action == "build-output":
            continue
        package = event.get("Package", "")
        if package not in expected or package in completed:
            raise ValueError("unexpected package")
        test = event.get("Test", "")
        if not test and action == "start":
            if package in started:
                raise ValueError("duplicate start")
            started.add(package)
        elif package not in started:
            raise ValueError("missing package start")
        if not test and action in {"pass", "skip"}:
            if action == "skip" and expected[package]:
                raise ValueError("skipped test package")
            if "Elapsed" not in event:
                raise ValueError("missing duration")
            completed[package] = {"package": package, "status": action,
                                  "elapsedSeconds": round(event["Elapsed"], 3)}
    if started != set(expected) or set(completed) != set(expected):
        raise ValueError("missing package completion")
    return [completed[p] for p in sorted(completed)]


def command_for(packages):
    if not packages or any(not reporter.PACKAGE.fullmatch(p) for p in packages):
        raise ValueError("invalid selected packages")
    return ["go", "test", "-race", "-json", "-p", "1", "-buildvcs=false", *packages,
            "-skip", SKIP, "-count=1", "-timeout=15m"]


def make_report(plan, shard, raw, exit_code):
    if type(shard) is not int or not 0 <= shard < SHARDS or type(exit_code) is not int or exit_code != 0:
        raise ValueError("failed shard")
    validate_partition(plan["packages"], plan["shards"])
    selected = {p: plan["packages"][p] for p in plan["shards"][shard]}
    records = normalize(raw, selected) if selected else []
    if not selected and raw:
        raise ValueError("unexpected empty-shard output")
    return {"schemaVersion": 1, "planSha256": digest(plan),
            **{k: plan[k] for k in ("commit", "runId", "runAttempt", "goSourceSha256")},
            "shard": shard, "exitCode": 0, "packages": records}


def check_needs(raw):
    value = reporter.decode(raw)
    if not isinstance(value, dict) or set(value) != NEEDS:
        raise ValueError("missing prerequisite")
    if any(not isinstance(job, dict) or job.get("result") != "success" for job in value.values()):
        raise ValueError("unsuccessful prerequisite")


def verify_reports(plan, reports):
    validate_partition(plan["packages"], plan["shards"])
    if not isinstance(reports, list) or len(reports) != SHARDS:
        raise ValueError("missing reports")
    seen = set()
    for report in reports:
        if not isinstance(report, dict) or type(report.get("shard")) is not int or report["shard"] in seen or not 0 <= report["shard"] < SHARDS:
            raise ValueError("duplicate or invalid shard")
        shard = report["shard"]
        seen.add(shard)
        reference = make_report(plan, shard, b"", 0) if not plan["shards"][shard] else {
            "schemaVersion": 1, "planSha256": digest(plan),
            **{k: plan[k] for k in ("commit", "runId", "runAttempt", "goSourceSha256")},
            "shard": shard, "exitCode": 0, "packages": []}
        if set(report) != set(reference) or any(type(report[k]) is not type(reference[k]) or report[k] != reference[k]
                for k in reference if k != "packages"):
            raise ValueError("foreign report")
        records = report["packages"]
        if not isinstance(records, list) or len(records) != len(plan["shards"][shard]):
            raise ValueError("missing package records")
        for package, record in zip(plan["shards"][shard], records):
            if (not isinstance(record, dict) or set(record) != {"package", "status", "elapsedSeconds"}
                    or record["package"] != package or record["status"] not in {"pass", "skip"}
                    or (record["status"] == "skip" and plan["packages"][package])):
                raise ValueError("invalid package record")
            reporter.validate_event({"Action": "pass", "Elapsed": record["elapsedSeconds"]})
            if record["elapsedSeconds"] != round(record["elapsedSeconds"], 3):
                raise ValueError("unnormalized duration")
    return len(plan["packages"])


def load_reports(directory, attempt):
    expected_dirs = {f"go-race-{attempt}-{shard}" for shard in range(SHARDS)}
    if directory.is_symlink() or {p.name for p in directory.iterdir()} != expected_dirs:
        raise ValueError("missing or extra artifact")
    result = []
    for name in sorted(expected_dirs):
        folder = directory / name
        path = folder / "completion.json"
        if folder.is_symlink() or not folder.is_dir() or list(folder.iterdir()) != [path] or path.is_symlink():
            raise ValueError("invalid artifact layout")
        # Normalized downloaded files are public metadata (artifact mode 0644),
        # so do not apply the raw-log private-mode requirement here.
        with os.fdopen(reporter.open_log(path), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT:
                raise ValueError("invalid artifact file")
            raw = stream.read(MAX_REPORT + 1)
        if len(raw) > MAX_REPORT:
            raise ValueError("oversized artifact")
        report = reporter.decode(raw)
        if not isinstance(report, dict) or report.get("shard") != int(name.rsplit("-", 1)[1]):
            raise ValueError("artifact shard mismatch")
        result.append(report)
    return result


def run_shard(plan, allowed, shard, destination):
    if destination.exists() or destination.is_symlink() or destination.parent.is_symlink():
        raise ValueError("existing report")
    packages = plan["shards"][shard]
    raw, elapsed, status = b"", 0, 0
    with tempfile.TemporaryDirectory(prefix="go-race-", dir=os.environ["RUNNER_TEMP"]) as private:
        events, errors = Path(private) / "events.jsonl", Path(private) / "stderr"
        for path in (events, errors):
            path.touch(mode=0o600, exist_ok=False)
        if packages:
            start = time.monotonic()
            with events.open("wb") as output, errors.open("wb") as error:
                process = subprocess.Popen(command_for(packages), cwd=ROOT, stdout=output, stderr=error)
                while True:
                    try:
                        status = process.wait(timeout=60)
                        break
                    except subprocess.TimeoutExpired:
                        print(f"GO_RACE_PROGRESS shard={shard} elapsedSeconds={int(time.monotonic() - start)}", flush=True)
            elapsed = int(time.monotonic() - start)
            raw = reporter.read_private(events, reporter.MAX_FILE)
            reporter.read_private(errors, reporter.MAX_STDERR)
            # Existing exact-source allowlisted bounded diagnostics remain intact.
            reporter.main((["--success"] if status == 0 else []) + ["--events", str(events), "--stderr", str(errors),
                          "--exit-code", str(status), "--elapsed-seconds", str(elapsed)])
        report = make_report(plan, shard, raw, status)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(canonical(report) + b"\n")
    print(f"GO_RACE_COMPLETE shard={shard} packages={len(packages)} elapsedSeconds={elapsed}", flush=True)


def main(argv=None):
    try:
        parser = reporter.SafeParser(add_help=False, allow_abbrev=False)
        modes = parser.add_mutually_exclusive_group(required=True)
        modes.add_argument("--shard", type=int, choices=range(SHARDS))
        modes.add_argument("--verify", type=Path)
        modes.add_argument("--check-needs", action="store_true")
        parser.add_argument("--report", type=Path)
        args = parser.parse_args(argv)
        if (args.shard is not None) != (args.report is not None):
            raise ValueError("invalid arguments")
        if args.check_needs or args.verify is not None:
            check_needs(os.environ.get("TRACEBOLT_GO_NEEDS", ""))
        if args.check_needs:
            return 0
        plan, allowed = discover()
        if args.shard is not None:
            run_shard(plan, allowed, args.shard, args.report)
        else:
            count = verify_reports(plan, load_reports(args.verify, plan["runAttempt"]))
            print(f"PASS: exact Go race coverage across {SHARDS} shards and {count} packages; build/runtime and dedicated dense gates succeeded.")
        return 0
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, KeyError):
        print("FAIL: incomplete or invalid Go race coverage; raw source/runtime output withheld.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
