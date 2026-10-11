#!/usr/bin/env python3
"""Opt-in, human-coordinated real Windows -> Linux -> dashboard acceptance subset.

No host execution by default. Native operation requires actual action-time
approval outside this program; neither a plan nor its flags grant authority.
Use --check-plan for portable input validation (never contacts either target).
"""
from __future__ import annotations
import sys
if not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("CONTRACT_REJECTED: invoke with Python -I -B.")
import argparse
import os
import signal
from pathlib import Path
import sys
import time
# Supports python -I -B without accepting an ambient PYTHONPATH.
# -B prevents writes, not reads: reject cached local modules before importing.
_here = Path(__file__).resolve().parent
if sys.pycache_prefix is not None or (_here / "__pycache__").exists() or any(_here.glob("*.py[co]")):
    raise SystemExit("CONTRACT_REJECTED: cached harness modules are not allowed.")
# Explicitly compile local .py bytes: -B alone still reads caches, and normal
# imports can prefer an extension or package with the same name.
def _source_only(name):
    import types
    path = Path(__file__).resolve().parent / (name + ".py")
    if path.is_symlink() or not path.is_file():
        raise SystemExit("CONTRACT_REJECTED: harness source file unavailable.")
    existing = sys.modules.get(name)
    if existing is not None and getattr(existing, "__source_only_loaded__", False) and getattr(existing, "__file__", None) == str(path):
        return existing
    module = types.ModuleType(name); module.__file__ = str(path)
    module.__source_only_loaded__ = True; sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module
_source_only("contract")
import contract
from contract import Rejected, PHASES, CURRENT_PHASES, is_current, need, load_plan, require_native_opt_in, verify_inventory, verify_commit, trusted_path, validate_phase_report, begin_phase, report, write_new, private_directory, read_regular, strict_json

ORDER = ("setup", "event-fixture", "event-enable", "updates-enable", "event-disable", "updates-disable")

def previous_phase(p, phase, plan_hash):
    order = ("setup", "event-fixture", "own-restart", "remove") if is_current(p) else ORDER
    if phase in order and phase != order[0]:
        prior = order[order.index(phase) - 1]
        path = Path(p["targets"]["windows"]["workspace"]) / (p["runId"] + "-" + prior + ".result.json")
        r = strict_json(read_regular(path, 32 << 10), 32 << 10)
        validate_phase_report(r, p, plan_hash, prior)
        marker = strict_json(read_regular(path.with_name(p["runId"] + "-" + prior + ".started.json"), 2048), 2048)
        need(type(marker) is dict and set(marker) == {"planSHA256", "phase", "startedUnix", "startedMonotonic"}
             and marker["planSHA256"] == plan_hash and marker["phase"] == prior
             and type(marker["startedUnix"]) in {int, float} and p["notBeforeUnix"] <= marker["startedUnix"] < p["expiresUnix"], "native_observation_unavailable")
        need(type(marker["startedMonotonic"]) in {int, float} and time.monotonic() >= marker["startedMonotonic"]
             and abs((time.time() - marker["startedUnix"]) - (time.monotonic() - marker["startedMonotonic"])) <= 1.5, "clock_changed")

class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "CONTRACT_REJECTED: invalid invocation; no host action attempted.\n")

def main(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check-plan", action="store_true")
    action.add_argument("--execute", action="store_true")
    parser.add_argument("--target-id")
    parser.add_argument("--phase", choices=tuple(dict.fromkeys((*PHASES, *CURRENT_PHASES))))
    parser.add_argument("--approval-reference")
    parser.add_argument("--browser-report-sha256")
    args = parser.parse_args(argv)
    p = None; workspace = None; checks = {}; start = time.monotonic(); lock = None; old_signals = {}
    try:
        p = load_plan(args.plan, args.plan_sha256)
        if args.check_plan:
            need(args.target_id is None and args.phase is None and args.approval_reference is None and args.browser_report_sha256 is None)
            print("SOURCE CONTRACT VALIDATED ONLY; native execution and authorization not established.")
            return 0
        contract._active_budget = contract.RunBudget(p["expiresUnix"])
        role = "linux" if args.phase == "manager-browser" else "windows"
        require_native_opt_in(args, role, p)
        cancelled = False
        def terminate_owned(signum, frame):
            nonlocal cancelled
            if cancelled: return
            cancelled = True
            raise Rejected("native_operation_failed")
        for sig in (signal.SIGTERM, signal.SIGINT):
            old_signals[sig] = signal.signal(sig, terminate_owned)
        target = p["targets"][role]
        # Check intended host before even importing native adapters.
        need((os.name == "nt") == (role == "windows"), "target_mismatch")
        if role == "windows":
            adapter = _source_only("windows_native")
        else:
            adapter = _source_only("linux_native")
        adapter.verify_target(target)
        candidate_lock = adapter.target_lock(); candidate_lock.__enter__(); lock = candidate_lock
        trusted_path(args.plan)
        private_directory(target["workspace"])
        verify_commit(target["sourceCommitObject"], p["source"])
        verify_inventory(target["sourceRoot"], target["sourceInventory"], p["source"]["inventorySHA256"], p["source"]["tree"], trusted=True)
        need(Path(__file__).resolve() == Path(target["sourceRoot"]) / "tests/windows_linux_native_parity/run.py", "source_mismatch")
        previous_phase(p, args.phase, args.plan_sha256)
        if is_current(p) and args.phase == "remove":
            # Transfer only the completed sanitized Linux phase evidence under
            # private custody. Bind every field to this exact plan/artifact set.
            path = Path(target["workspace"]) / (p["runId"] + "-manager-browser.result.json")
            trusted_path(path)
            raw = read_regular(path, 32 << 10)
            need(contract.digest(raw) == args.browser_report_sha256, "browser_incomplete")
            value = strict_json(raw, 32 << 10)
            need(raw == contract.canonical(value), "native_observation_unavailable")
            validate_phase_report(value, p, args.plan_sha256, "manager-browser")
            checks["browser_evidence_verified"] = True
        if role == "windows":
            adapter.verify_package(p)
        contract.check_time(p["expiresUnix"])
        workspace = begin_phase(p, role, args.phase, args.plan_sha256)
        if role == "windows":
            adapter.operate(p, args.phase, checks, args.plan_sha256)
        else:
            adapter.operate(p, args.plan_sha256, checks)
        result = report(p, args.plan_sha256, args.phase, checks, "observed_phase", "complete", time.monotonic() - start)
        write_new(workspace / (p["runId"] + "-" + args.phase + ".result.json"), result)
        if is_current(p) and args.phase == "manager-browser":
            print("PUBLIC MANAGER/BROWSER PHASE SHA256=" + contract.digest(contract.canonical(result)), flush=True)
        print("OBSERVED NATIVE PHASE ONLY; full acceptance remains false.")
        return 0
    except Exception as exc:
        reason = exc.reason if isinstance(exc, Rejected) else "native_operation_failed"
        # Do not print exceptions, argv, paths, state, OS error prose or traceback.
        if workspace is not None and p is not None:
            try:
                result = report(p, args.plan_sha256, args.phase, checks, "unknown" if checks.get("native_actions_attempted") else "blocked", reason, min(7200, time.monotonic() - start))
                write_new(workspace / (p["runId"] + "-" + args.phase + ".result.json"), result)
            except Exception:
                pass
        print("BLOCKED_OR_UNKNOWN: " + reason + "; preserve private state. No retry, repair or acceptance inferred.")
        return 2
    finally:
        contract._active_budget = None
        for sig, previous in old_signals.items(): signal.signal(sig, previous)
        if lock is not None:
            lock.__exit__(None, None, None)

if __name__ == "__main__":
    raise SystemExit(main())
