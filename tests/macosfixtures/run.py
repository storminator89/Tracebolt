#!/usr/bin/env python3
"""Run only reviewed native fixtures; --check is source-only and invokes no Go."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SUITE = Path(__file__).with_name("suite.json")
PACKAGES = {
    "./internal/darwinprotect",
    "./internal/macosinventory",
    "./internal/macosinventorystate",
    "./internal/macosinventorysender",
}
RUNNERS = {"macos-15": ("arm64", "ARM64"), "macos-15-intel": ("amd64", "X64")}


def check_suite():
    suite = json.loads(SUITE.read_text())
    if suite.get("schemaVersion") != 1 or set(suite["packages"]) != PACKAGES:
        raise ValueError("unexpected fixture suite")
    for package, names in suite["packages"].items():
        if not names or len(names) != len(set(names)):
            raise ValueError("empty or duplicate fixture selection")
        files = list((ROOT / package).glob("*.go"))
        texts = [(path, path.read_text()) for path in files]
        # A new package initializer/TestMain requires a fresh safety review. This
        # structural check is not a sandbox or a substitute for reviewing changes.
        if any(re.search(r"^func\s+(?:init|TestMain)\s*\(", text, re.M) for _, text in texts):
            raise ValueError("fixture package initializer requires review")
        for name in names:
            if not re.fullmatch(r"Test[A-Za-z0-9_]+", name):
                raise ValueError("invalid test name")
            count = sum(len(re.findall(r"^func\s+" + name + r"\s*\(", text, re.M))
                        for path, text in texts if path.name.endswith("_test.go"))
            if count != 1:
                raise ValueError("fixture missing or duplicated: " + name)
    return suite


def output(command, env=None):
    return subprocess.check_output(command, cwd=ROOT, env=env, text=True).strip()


def clean_source():
    if output(["git", "status", "--porcelain=v1", "--untracked-files=all"]):
        raise ValueError("fixture checkout has modified or untracked source inputs")


def run(suite):
    label = os.environ.get("TRACEBOLT_RUNNER_LABEL")
    if sys.platform != "darwin" or label not in RUNNERS:
        raise ValueError("native macOS standard runner required")
    arch, runner_arch = RUNNERS[label]
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("TRACEBOLT_RUNNER_OS") != "macOS" or
            os.environ.get("TRACEBOLT_RUNNER_ARCH") != runner_arch):
        raise ValueError("unexpected hosted runner context")
    source = output(["git", "rev-parse", "HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40}", source) or source != os.environ.get("GITHUB_SHA"):
        raise ValueError("checkout differs from workflow source")
    clean_source()
    env = dict(os.environ, GOTOOLCHAIN="local", GOFLAGS="-mod=readonly", CGO_ENABLED="0",
               GOPROXY="off", GOSUMDB="off", GOWORK="off")
    env.pop("GOOS", None)
    env.pop("GOARCH", None)
    env.pop("TRACEBOLT_SYNTHETIC_INVENTORY_LOCK_PATH", None)
    go = json.loads(output(["go", "env", "-json", "GOOS", "GOARCH", "GOVERSION"], env))
    machine = platform.machine()
    if go["GOOS"] != "darwin" or go["GOARCH"] != arch or machine != {"amd64": "x86_64", "arm64": "arm64"}[arch]:
        raise ValueError("cross-execution or unexpected native architecture")
    version = re.search(r"^go ([0-9.]+)$", (ROOT / "go.mod").read_text(), re.M)
    macos_version = output(["/usr/bin/sw_vers", "-productVersion"])
    if not version or go["GOVERSION"] != "go" + version.group(1) or macos_version.split(".")[0] != "15":
        raise ValueError("unexpected Go or macOS version")
    evidence = {
        "schemaVersion": 1, "scope": suite["scope"], "sourceSHA": source,
        "sourceTree": output(["git", "rev-parse", "HEAD^{tree}"]),
        "suiteSHA256": hashlib.sha256(SUITE.read_bytes()).hexdigest(),
        "runnerLabel": label, "runnerOS": "macOS", "runnerArch": runner_arch,
        "machine": machine, "macOSVersion": macos_version,
        "imageOS": os.environ.get("ImageOS", "unknown"),
        "imageVersion": os.environ.get("ImageVersion", "unknown"), "go": go,
        "agentAcceptance": False, "packages": [], "result": "failed",
    }
    destination = ROOT / "artifacts/review/macos-native-fixtures.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    failed = False
    finished = False
    try:
        # Canonicalize only the task's temporary root, never product input paths.
        # Product descriptor/no-follow/ACL checks remain unchanged.
        runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="tracebolt-fixtures-", dir=runner_temp) as temp:
            os.chmod(temp, 0o700)
            env["TMPDIR"] = str(Path(temp).resolve(strict=True))
            for package, names in suite["packages"].items():
                pattern = "^(" + "|".join(names) + ")$"
                command = ["go", "test", "-json", "-count=1", "-timeout=5m", "-buildvcs=false", "-run", pattern, package]
                print("Running " + package + ": " + ", ".join(names), flush=True)
                completed = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                statuses = {}
                unexpected = False
                for line in completed.stdout.splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        print(line, flush=True)
                        continue
                    name = event.get("Test", "")
                    action = event.get("Action", "")
                    if name:
                        root_name = name.split("/", 1)[0]
                        unexpected |= root_name not in names
                        if action in ("pass", "fail", "skip"):
                            statuses[name] = action
                    if event.get("Output"):
                        print(event["Output"], end="", flush=True)
                passed = (completed.returncode == 0 and not unexpected and
                          all(statuses.get(name) == "pass" for name in names) and
                          all(status == "pass" for status in statuses.values()))
                evidence["packages"].append({"package": package, "tests": statuses, "passed": passed})
                failed |= not passed
        clean_source()
        if source != output(["git", "rev-parse", "HEAD"]):
            raise ValueError("checkout changed during fixture execution")
        finished = True
    finally:
        evidence["result"] = "passed" if finished and not failed else "failed"
        destination.write_text(json.dumps(evidence, indent=2) + "\n")
    if failed:
        raise RuntimeError("a selected fixture failed, was skipped, or did not run")
    print("Native fixture evidence written; actual agent acceptance remains pending.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate source selections without execution")
    args = parser.parse_args()
    suite = check_suite()
    if args.check:
        print("Fixture selection verified: " + str(sum(map(len, suite["packages"].values()))) + " named tests; no tests executed.")
    else:
        run(suite)
