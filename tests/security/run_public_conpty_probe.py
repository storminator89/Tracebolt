#!/usr/bin/env python3
"""Run only the isolated fixed-public-output ConPTY observation test."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "localrmm/internal/conptyrendering"
TEST = "TestNativePublicRendering"
MAX_OUTPUT = 1024 * 1024
FIELDS = ("cursor_position", "clear", "cursor_visibility", "presentation", "title",
          "unknown", "overflow", "incomplete", "win32_input_enable", "win32_input_disable",
          "focus_reporting_enable", "focus_reporting_disable", "residual_unknown")
TEXT_FIELDS = ("live_output", "public_trust", "exact_prompt", "prompt_without_final_space")
RESIDUAL_KINDS = ("none", "text_control", "non_ascii", "escape", "csi", "osc")
SUMMARY = re.compile(r"    native_windows_test\.go:[1-9][0-9]*: " +
                     " ".join(name + r"=(true|false)" for name in FIELDS) +
                     r" first_residual_kind=(" + "|".join(RESIDUAL_KINDS) + r") " + " ".join(name + r"=(true|false)" for name in TEXT_FIELDS) + r"\n")
ARGS = ("go", "test", "-mod=readonly", "-json", "-count=1", "-timeout=45s",
        "-buildvcs=false", "-run=^TestNativePublicRendering$", "./internal/conptyrendering")


def require(value):
    if not value:
        raise ValueError("public rendering probe incomplete")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def project(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT and raw.endswith(b"\n"))
    passed = package_passed = False
    summary = None
    for line in raw.splitlines():
        event = json.loads(line, object_pairs_hook=unique_object)
        require(type(event) is dict and event.get("Package") == PACKAGE)
        action = event.get("Action")
        require(action in {"start", "run", "output", "pass"})
        name = event.get("Test")
        require(name is None or name == TEST)
        if action == "pass":
            if name == TEST:
                require(not passed)
                passed = True
            elif name is None:
                require(not package_passed)
                package_passed = True
        if action == "output" and name == TEST:
            output = event.get("Output")
            require(type(output) is str)
            match = SUMMARY.fullmatch(output)
            if match:
                require(summary is None)
                summary = dict(zip(FIELDS, (x == "true" for x in match.groups()[:len(FIELDS)])))
                summary["first_residual_kind"] = match.groups()[len(FIELDS)]
                summary.update(zip(TEXT_FIELDS, (x == "true" for x in match.groups()[len(FIELDS)+1:])))
    require(passed and package_passed and summary is not None)
    require(not summary["overflow"] and not summary["incomplete"])
    require(summary["residual_unknown"] == (summary["first_residual_kind"] != "none"))
    require(summary["unknown"] == any(summary[name] for name in FIELDS[8:]))
    require(not (summary["exact_prompt"] and summary["prompt_without_final_space"]))
    require(summary["live_output"] or not any(summary[name] for name in TEXT_FIELDS[1:]))
    return summary


def capture(env):
    # Drain continuously but retain at most the bound. Stderr is never retained.
    raw = bytearray()
    failed = threading.Event()
    process = subprocess.Popen(ARGS, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def drain():
        try:
            while True:
                chunk = process.stdout.read(8192)
                if not chunk:
                    break
                if len(raw) + len(chunk) > MAX_OUTPUT:
                    failed.set()
                elif not failed.is_set():
                    raw.extend(chunk)
        except (OSError, ValueError):
            failed.set()
        finally:
            process.stdout.close()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=120)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        failed.set()
        code = -1
    reader.join(timeout=5)
    require(code == 0 and not reader.is_alive() and not failed.is_set())
    return bytes(raw)


def main():
    try:
        require(sys.platform == "win32")
        env = os.environ.copy()
        for name in ("GOOS", "GOARCH", "GOFLAGS"):
            env.pop(name, None)
        env["GOTOOLCHAIN"] = "local"
        summary = project(capture(env))
        print("OBSERVED: fixed public ConPTY sequence families " +
              " ".join(name + "=" + str(summary[name]).lower() for name in FIELDS) +
              " first_residual_kind=" + summary["first_residual_kind"] +
              " " + " ".join(name + "=" + str(summary[name]).lower() for name in TEXT_FIELDS) +
              "; no coordinator or guard compatibility claim.")
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("FAIL: public ConPTY rendering probe incomplete; raw output withheld; no cleanup or native acceptance claim.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
