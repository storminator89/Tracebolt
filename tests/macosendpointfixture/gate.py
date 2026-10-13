#!/usr/bin/env python3
"""Manual hosted endpoint-subset gate. Default --check is source-only.

This source is not runtime approval. No log/interface/inventory probe is called.
The peer is simulated; even a subset pass leaves the full stage blocked.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 8 * 1024 * 1024
REPORT_LIMIT = 16 * 1024
RUNNERS = {"macos-15": ("ARM64", "arm64", "arm64"),
           "macos-15-intel": ("X64", "amd64", "x86_64")}
HELPER = "tests/macosnativeacceptance/run.py"
FIXTURE = "tests/macosendpointfixture/run.py"
WORKFLOW = ".github/workflows/macos-endpoint-acceptance.yml"
SOURCE_FIXED = ("go.mod", "go.sum", "AGENTS.md", WORKFLOW,
                ".github/workflows/macos-endpoint-source.yml", "docs/macos-status.md")
SOURCES = ("cmd", "internal", "tests/macosendpointfixture", "tests/macosnativeacceptance")
BINARIES = {"peer": ("endpoint-peer", "./tests/macosendpointfixture"),
            "enroll": ("enroll-agent", "./cmd/enroll-agent"),
            "sender": ("macos-agent", "./cmd/macos-agent")}
REASONS = frozenset(("not_selected", "source_checked", "dispatch_verified", "admission_refused",
                     "source_mismatch", "preparation_failed", "metadata_unavailable",
                     "endpoint_failed", "custody_failed", "cleanup_failed", "cancelled",
                     "endpoint_subset_passed", "internal_failure"))


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "internal_failure"


def require(ok, reason="source_mismatch"):
    if not ok:
        raise Refused(reason)


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)))
    require(path.resolve(strict=True) == path)
    return path


def stable_bytes(path, maximum=LIMIT):
    """Bounded public source/tool bytes; no symlink parent or final component."""
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        require(0 < before.st_size <= maximum)
        deadline = time.monotonic() + 10
        data = bytearray()
        while len(data) <= maximum:
            require(time.monotonic() < deadline)
            block = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(data) == before.st_size and time.monotonic() < deadline)
        require(all(getattr(before, k) == getattr(after, k) for k in fields))
        require((after.st_dev, after.st_ino) == (path.lstat().st_dev, path.lstat().st_ino))
        return bytes(data), after
    finally:
        os.close(fd)


def source_manifest(root=ROOT):
    """Read only public source. Never inspect native state or start a child."""
    root = canonical(root)
    names = set(SOURCE_FIXED)
    for prefix in SOURCES:
        base = canonical(root / prefix)
        require(base.is_dir())
        for directory, dirs, files in os.walk(base, followlinks=False):
            require(not any((Path(directory) / n).is_symlink() for n in dirs))
            dirs[:] = sorted(n for n in dirs if n != "__pycache__")
            for name in sorted(files):
                if not name.endswith(".pyc"):
                    names.add((Path(directory) / name).relative_to(root).as_posix())
            require(len(names) <= 8192)
    require({HELPER, FIXTURE, "tests/macosendpointfixture/gate.py",
             "tests/macosendpointfixture/native_main.go"} <= names)
    digest = hashlib.sha256(b"tracebolt-macos-endpoint-gate-source-v1\n")
    total, hashes = 0, {}
    for name in sorted(names):
        data, info = stable_bytes(root / name)
        value = hashlib.sha256(data).hexdigest()
        total += len(data)
        require(total <= 128 * 1024 * 1024)
        digest.update((name + "\0" + ("x" if info.st_mode & 0o111 else "-") + "\0" +
                       str(len(data)) + "\0" + value + "\n").encode())
        hashes[name] = value
    return {"sha256": digest.hexdigest(), "fileCount": len(names), "files": hashes}


def reviewed_module(relative, expected, name):
    # Compile exact source bytes, never a timestamp-valid injected .pyc.
    data, _ = stable_bytes(ROOT / relative)
    require(hashlib.sha256(data).hexdigest() == expected)
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / relative)
    sys.modules[name] = module
    exec(compile(data, "reviewed_endpoint_gate_dependency", "exec", dont_inherit=True), module.__dict__)
    return module


def admission(env, platform, manifest):
    label = env.get("TRACEBOLT_RUNNER_LABEL")
    require(platform == "darwin" and label in RUNNERS, "admission_refused")
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REPOSITORY": "storminator89/Tracebolt", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "macOS", "RUNNER_ARCH": RUNNERS[label][0],
                "TRACEBOLT_REPOSITORY_VISIBILITY": "public", "GITHUB_RUN_ATTEMPT": "1",
                "TRACEBOLT_SELECT_ENDPOINT": "true"}
    require(all(env.get(k) == v for k, v in expected.items()), "admission_refused")
    commit = env.get("TRACEBOLT_REVIEWED_COMMIT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None)
    require(commit == env.get("GITHUB_SHA") == env.get("GITHUB_WORKFLOW_SHA"))
    require(env.get("TRACEBOLT_REVIEWED_SOURCE_SHA256") == manifest["sha256"])
    return {"runner": label, "architecture": RUNNERS[label][1], "commit": commit}


def closed_report(reason="not_selected"):
    return {"schemaVersion": "tracebolt.macos-endpoint-gate.v1", "blocked": True,
            "stage1Passed": False, "simulatedManager": True, "reason": reason,
            "provenance": None, "endpoint": None, "buildChildrenReaped": True, "runtimeChildrenReaped": True,
            "taskTreeRemoved": True}


def uncertain_report(reason):
    report = closed_report(reason)
    for field in ("buildChildrenReaped", "runtimeChildrenReaped", "taskTreeRemoved"):
        report[field] = False
    return report


def evidence(report, fixture=None):
    require(set(report) == set(closed_report()), "internal_failure")
    require(report["schemaVersion"] == "tracebolt.macos-endpoint-gate.v1")
    require(report["blocked"] is True and report["stage1Passed"] is False and report["simulatedManager"] is True)
    require(report["reason"] in REASONS)
    require(all(type(report[k]) is bool for k in ("buildChildrenReaped", "runtimeChildrenReaped", "taskTreeRemoved")))
    p = report["provenance"]
    if p is not None:
        require(type(p) is dict and set(p) == {"sourceSHA256", "sourceFileCount", "commit", "tree", "runner", "architecture", "imageOS", "imageVersion", "productVersion", "productBuild", "darwinRelease", "pythonVersion", "goVersion", "hashes"})
        require(re.fullmatch(r"[0-9a-f]{64}", p["sourceSHA256"]) is not None)
        require(type(p["sourceFileCount"]) is int and 1 <= p["sourceFileCount"] <= 8192)
        for k in ("commit", "tree"):
            require(re.fullmatch(r"[0-9a-f]{40}", p[k]) is not None)
        require(p["runner"] in RUNNERS and p["architecture"] == RUNNERS[p["runner"]][1])
        patterns = {"imageOS": r"macos15(?:-arm64)?", "imageVersion": r"[0-9]{8}\.[0-9]{1,4}\.[0-9]{1,4}",
                    "productVersion": r"15(?:\.[0-9]{1,3}){1,2}", "productBuild": r"[0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?",
                    "darwinRelease": r"[0-9]{1,3}(?:\.[0-9]{1,3}){2}", "pythonVersion": r"3\.[0-9]{1,2}\.[0-9]{1,3}",
                    "goVersion": r"go1\.27\.1"}
        for k, pattern in patterns.items():
            require(type(p[k]) is str and re.fullmatch(pattern, p[k]) is not None)
        require(type(p["hashes"]) is dict and set(p["hashes"]) == {"wrapper", "fixture", "helper", "python", "go", "compile", "link", "peer", "enroll", "sender"})
        require(all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) is not None for v in p["hashes"].values()))
    result = report["endpoint"]
    if result is not None:
        require(fixture is not None)
        fixture.result_json(result)
        require(result["blocked"] is True and result["stage1_passed"] is False and result["custody_case_implemented"] is False)
    if report["reason"] == "endpoint_subset_passed":
        require(p is not None and result is not None and result["endpoint_cases_passed"] is True)
        require(report["buildChildrenReaped"] and report["runtimeChildrenReaped"] and report["taskTreeRemoved"])
    raw = json.dumps(report, separators=(",", ":"), sort_keys=True, allow_nan=False) + "\n"
    require(len(raw.encode()) <= REPORT_LIMIT)
    return raw


def binary_custody(tree, path, expected, identity=None):
    require(canonical(tree.path) == tree.path, "custody_failed")
    root = tree.path.stat()
    require((root.st_dev, root.st_ino) == tree.identity and root.st_uid == tree.uid and stat.S_IMODE(root.st_mode) == 0o700, "custody_failed")
    directory = canonical(tree.path / "bin")
    info = directory.stat()
    require(info.st_uid == tree.uid and stat.S_IMODE(info.st_mode) == 0o700, "custody_failed")
    require(Path(path).parent == directory and Path(path).name in {v[0] for v in BINARIES.values()}, "custody_failed")
    data, info = stable_bytes(path, 32 * 1024 * 1024)
    require(info.st_uid == tree.uid and info.st_mode & 0o022 == 0 and info.st_mode & 0o100 != 0, "custody_failed")
    require(hashlib.sha256(data).hexdigest() == expected, "custody_failed")
    record = (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)
    require(identity is None or record == identity, "custody_failed")
    return record


def prepare(helper, processes, tree, context, manifest, ambient):
    env = helper.clean_environment(tree)
    go_root, go = helper.selected_go(ambient, {"runnerArch": RUNNERS[context["runner"]][0]})
    env.update(GOROOT=str(go_root), GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GOFLAGS="-mod=readonly",
               CGO_ENABLED="0", GOPROXY="https://proxy.golang.org", GOSUMDB="sum.golang.org",
               GOPRIVATE="", GONOPROXY="", GONOSUMDB="", GOVCS="*:off", GOMAXPROCS="2",
               GOPATH=str(tree.path / "gopath"), GOCACHE=str(tree.path / "cache"), GOMODCACHE=str(tree.path / "modules"))
    version = helper.require_capture(processes, (str(go), "version"), env, ROOT)
    require(version == "go version go1.27.1 darwin/" + context["architecture"], "preparation_failed")
    for args in (("mod", "download"), ("mod", "verify")):
        result = processes.capture((str(go), *args), env=env, cwd=ROOT, seconds=240,
                                   stdout_limit=1024 * 1024, stderr_limit=1024 * 1024, retain=False, allow_stderr=True)
        require(result.metadata["reason"] == "ok" and result.metadata["reaped"], "preparation_failed")
    env.update(GOPROXY="off", GOSUMDB="off")
    hashes = {"wrapper": manifest["files"]["tests/macosendpointfixture/gate.py"],
              "fixture": manifest["files"][FIXTURE], "helper": manifest["files"][HELPER]}
    tools = {"python": Path(sys.executable).resolve(strict=True), "go": go,
             "compile": go_root / "pkg/tool" / ("darwin_" + context["architecture"]) / "compile",
             "link": go_root / "pkg/tool" / ("darwin_" + context["architecture"]) / "link"}
    for name, path in tools.items():
        hashes[name] = helper.bounded_hash(path, helper.COMPILER_LIMIT)[0]
    identities = {}
    for name, (filename, package) in BINARIES.items():
        path = tree.path / "bin" / filename
        tags = ("-tags=tracebolt_endpoint_native",) if name == "peer" else ()
        result = processes.capture((str(go), "build", "-p", "1", "-trimpath", "-buildvcs=false", *tags, "-o", str(path), package),
                                   env=env, cwd=ROOT, seconds=240, stdout_limit=65536, stderr_limit=65536, retain=False)
        require(result.metadata["reason"] == "ok" and result.metadata["reaped"], "preparation_failed")
        hashes[name] = helper.bounded_hash(path)[0]
        identities[name] = binary_custody(tree, path, hashes[name])
    require(source_manifest() == manifest)
    return hashes, identities


def provenance(helper, processes, tree, context, manifest, ambient, hashes):
    p = {"sourceSHA256": manifest["sha256"], "sourceFileCount": manifest["fileCount"], **context,
         "tree": helper.source_identity(processes, ambient, {"commit": context["commit"]}),
         "imageOS": ambient.get("ImageOS", ""), "imageVersion": ambient.get("ImageVersion", ""),
         "pythonVersion": ".".join(str(v) for v in sys.version_info[:3]), "goVersion": "go1.27.1", "hashes": hashes}
    for key, (argv, pattern) in helper.VERSION_COMMANDS.items():
        value = helper.require_capture(processes, argv, helper.clean_environment(tree), tree.path / "home")
        require(re.fullmatch(pattern, value) is not None, "metadata_unavailable")
        if key == "machine":
            require(value == RUNNERS[context["runner"]][2], "metadata_unavailable")
        else:
            p[key] = value
    test = closed_report()
    test["provenance"] = p
    evidence(test)
    return p


def endpoint_runtime(fixture, tree, hashes, identities, before_spawn, teardown=None):
    class ReviewedRuntime(fixture.NativeRuntime):
        def cleanup(self, preserve_tree=False):
            # Parent-only teardown never starts a child: defer every supported
            # interrupt until all child handles/descriptors have been processed.
            # No subprocess inherits this temporary signal mask.
            signals = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}
            if teardown is not None:
                teardown(True)
            previous = None
            try:
                previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
                return super().cleanup(preserve_tree=preserve_tree)
            finally:
                try:
                    if previous is not None:
                        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                finally:
                    if teardown is not None:
                        teardown(False)

        def reap_owned_children(self):
            # A last bounded reap owns the handles even if fixture cleanup threw.
            # Never repeat uncertain tree deletion or descriptor close here.
            reaped = True
            for child in reversed(self.children):
                try:
                    reaped = child.stop() and reaped
                except BaseException:
                    reaped = False
            return reaped

        def _spawn(self, argv, terminal=False):
            name = next((key for key, (filename, _) in BINARIES.items()
                         if argv[0] == str(tree.path / "bin" / filename)), None)
            require(name is not None, "custody_failed")
            binary_custody(tree, argv[0], hashes[name], identities[name])
            before_spawn(True)
            try:
                return super()._spawn(argv, terminal)
            finally:
                before_spawn(False)
    inputs = fixture.FutureInputs(str(tree.path / "tmp"),
        str(tree.path / "bin/endpoint-peer"), hashes["peer"],
        str(tree.path / "bin/enroll-agent"), hashes["enroll"],
        str(tree.path / "bin/macos-agent"), hashes["sender"])
    return ReviewedRuntime(inputs)


def execute(context, manifest, ambient):
    helper = reviewed_module(HELPER, manifest["files"][HELPER], "endpoint_gate_helpers")
    fixture = reviewed_module(FIXTURE, manifest["files"][FIXTURE], "endpoint_gate_fixture")
    report, processes, tree = closed_report("preparation_failed"), helper.Processes(), None
    runtime_attempted, runtime = False, None
    spawning, tearing_down, pending = False, False, False
    old = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
    entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

    def interrupt(*_):
        nonlocal pending
        if spawning or tearing_down:
            pending = True
        else:
            processes.interrupt(KeyboardInterrupt())

    def teardown(value):
        nonlocal tearing_down
        tearing_down = value

    def registering(value):
        nonlocal spawning, pending
        spawning = value
        if not value and pending:
            pending = False
            raise KeyboardInterrupt()

    try:
        for s in old:
            signal.signal(s, interrupt)
        require(sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site, "admission_refused")
        require(os.getuid() != 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), "admission_refused")
        # Resolve the runner-owned temporary alias once; all product inputs are
        # already canonical paths below the new mode-0700 invocation tree.
        parent = canonical(Path(ambient["RUNNER_TEMP"]).resolve(strict=True))
        tree = helper.TaskTree(parent, os.getuid())
        report["taskTreeRemoved"] = False
        tree.create()
        report["buildChildrenReaped"] = False
        hashes, identities = prepare(helper, processes, tree, context, manifest, ambient)
        report["provenance"] = provenance(helper, processes, tree, context, manifest, ambient, hashes)
        require(source_manifest() == manifest)
        # From here on, only the fixture's seven fixed children and simulated
        # peer run. No compiler, helper capture or native probe can run here.
        runtime_attempted = True
        report["runtimeChildrenReaped"] = False
        signal.setitimer(signal.ITIMER_REAL, 300)
        runtime = endpoint_runtime(fixture, tree, hashes, identities, registering, teardown)
        report["endpoint"] = fixture._exercise(runtime)
        if pending:
            report["endpoint"]["supervisor_failure"] = True
            report["endpoint"]["endpoint_cases_passed"] = False
        report["reason"] = "cancelled" if pending else ("endpoint_subset_passed" if report["endpoint"]["endpoint_cases_passed"] else "endpoint_failed")
    except Refused as exc:
        report["reason"] = exc.reason
    except KeyboardInterrupt:
        report["reason"] = "cancelled"
    except BaseException:
        report["reason"] = "internal_failure"
    finally:
        # Reuse the established parent-only signal mask pattern for finalization.
        # No new process is started under this mask. Preserve uncertain fixture
        # state: TaskTree.remove must never bypass the fixture's custody refusal.
        masked = False
        for _ in range(3):
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, set(old))
                masked = True
                break
            except (Exception, KeyboardInterrupt):
                report["reason"] = "cancelled"
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            report["buildChildrenReaped"] = processes.stop()
            if runtime is not None:
                report["runtimeChildrenReaped"] = runtime.reap_owned_children()
            result = report["endpoint"]
            endpoint_clean = not runtime_attempted or (result is not None and result["children_reaped"] and result["listeners_stopped"] and result["owned_tree_removed"] and not result["custody_mismatch"])
            if masked and tree is not None and report["buildChildrenReaped"] and report["runtimeChildrenReaped"] and endpoint_clean:
                report["taskTreeRemoved"] = tree.remove()
        except BaseException:
            report["reason"] = "cleanup_failed"
        finally:
            restored = masked
            for sig, handler in old.items():
                try:
                    signal.signal(sig, handler)
                except BaseException:
                    restored = False
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, entry_mask)
            except BaseException:
                restored = False
            if not restored or not report["buildChildrenReaped"] or not report["runtimeChildrenReaped"] or not report["taskTreeRemoved"]:
                report["reason"] = "cleanup_failed"
    return report, fixture


def main(argv=None, output=None):
    args = sys.argv[1:] if argv is None else argv
    output = sys.stdout if output is None else output
    report, fixture = closed_report(), None
    execution_attempted = False
    try:
        # An arbitrary argument cannot echo attacker text or activate anything.
        require(args in ([], ["--check"], ["--verify-dispatch"], ["--execute"]), "admission_refused")
        if not args:
            output.write(evidence(report))
            return 2
        manifest = source_manifest()
        if args == ["--check"]:
            output.write(json.dumps({"schemaVersion": "tracebolt.macos-endpoint-source.v1", "inertCheck": True,
                                     "sourceSHA256": manifest["sha256"], "sourceFileCount": manifest["fileCount"]}, separators=(",", ":")) + "\n")
            return 0
        context = admission(os.environ, sys.platform, manifest)
        if args == ["--verify-dispatch"]:
            report["reason"] = "dispatch_verified"
        else:
            execution_attempted = True
            report, fixture = execute(context, manifest, os.environ)
    except Refused as exc:
        report = uncertain_report(exc.reason) if execution_attempted else closed_report(exc.reason)
    except BaseException:
        report = uncertain_report("internal_failure") if execution_attempted else closed_report("internal_failure")
    try:
        raw = evidence(report, fixture)
    except BaseException:
        report = uncertain_report("internal_failure")
        raw = evidence(report)
    output.write(raw)
    return 0 if report["reason"] in ("dispatch_verified", "endpoint_subset_passed") else 2


if __name__ == "__main__":
    raise SystemExit(main())
