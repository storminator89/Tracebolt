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
MAX_LINE = 1024
FIELDS = ("cursor_position", "clear", "cursor_visibility", "presentation", "title",
          "unknown", "overflow", "incomplete", "win32_input_enable", "win32_input_disable",
          "focus_reporting_enable", "focus_reporting_disable", "residual_unknown")
TEXT_FIELDS = ("live_output", "public_trust", "exact_prompt", "prompt_without_final_space")
DESTINATION_FIELDS = ("stdout_char", "stdout_pipe", "stdout_console", "stderr_char", "stderr_pipe", "stderr_console",
                      "conout_console", "conout_live_output", "conout_public_trust", "conout_exact_prompt",
                      "conout_prompt_without_final_space", "conout_overflow", "conout_incomplete", "conout_residual_unknown")
PREINPUT_FIELDS = ("preinput_live_output", "preinput_public_trust", "preinput_prompt_ready",
                   "preinput_no_rejection", "preinput_mode_restored")
OUTPUT_REJECTIONS = ("none", "output_limit", "echo", "escape_unsupported", "csi_limit", "csi_unsupported",
                     "csi_malformed", "osc_limit", "osc_malformed", "osc_unsupported", "post_input_title",
                     "carriage_return", "text_unsupported", "line_limit", "protocol", "incomplete", "state")
FIRST_CSI_KINDS = ("none", "cursor_blink_enable", "cursor_blink_disable", "cursor_style_default",
                   "cursor_style_blink_block", "cursor_style_steady_block", "cursor_style_blink_underline",
                   "cursor_style_steady_underline", "cursor_style_blink_bar", "cursor_style_steady_bar",
                   "erase_line_default", "erase_line_right", "erase_line_all", "cursor_position",
                   "cursor_movement", "sgr", "other")
RESIDUAL_KINDS = ("none", "text_control", "non_ascii", "escape", "csi", "osc")
SUMMARY_TEXT = (" ".join(name + r"=(true|false)" for name in FIELDS) +
                r" first_residual_kind=(" + "|".join(RESIDUAL_KINDS) + r") " +
                " ".join(name + r"=(true|false)" for name in TEXT_FIELDS) + r"\n")
SUMMARY = re.compile(r"    native_windows_test\.go:[1-9][0-9]*: " + SUMMARY_TEXT)
SUMMARY_BODY = re.compile(SUMMARY_TEXT)
DESTINATION = re.compile(" ".join(name + r"=(true|false)" for name in DESTINATION_FIELDS) +
                         r" conout_first_residual_kind=(" + "|".join(RESIDUAL_KINDS) + r")\n")
PREINPUT = re.compile(" ".join(name + r"=(true|false)" for name in PREINPUT_FIELDS) +
                      r" preinput_rejection=(" + "|".join(OUTPUT_REJECTIONS) + r")" +
                      r" preinput_first_csi=(" + "|".join(FIRST_CSI_KINDS) + r")\n")
ARGS = ("go", "test", "-mod=readonly", "-json", "-count=1", "-timeout=45s",
        "-buildvcs=false", "-run=^TestNativePublicRendering$", "./internal/conptyrendering")


# Only labels already emitted by the fixed-public Go test can cross this boundary.
PREINPUT_FAILURES = frozenset({"preinput_guard_rejected", "preinput_prompt_missing"})
NATIVE_FAILURES = PREINPUT_FAILURES | frozenset({
    "input_pipe", "output_pipe", "conpty_create", "conpty_close_deadline",
    "attributes_create", "attributes_update", "executable", "command",
    "child_create", "child_terminate", "child_reap", "child_wait", "child_exit",
    "output_peek", "output_read", "output_empty_read", "output_missing", "deadline",
    "rendering_bound_or_incomplete", "preinput_guard_setup",
})
LAUNCHER_FAILURES = frozenset({
    "go_test_failed", "capture_deadline", "capture_incomplete", "platform",
    "projection_frame", "projection_json", "projection_package", "projection_action",
    "projection_test", "projection_duplicate_pass", "projection_output",
    "projection_duplicate_summary", "projection_missing_pass", "projection_missing_summary",
    "projection_bounds", "projection_residual", "projection_unknown", "projection_prompt",
    "projection_live", "launch_or_io_failed", "projection_line_bound", "projection_line_incomplete",
    "projection_summary_crlf", "projection_summary_prefix", "projection_summary_fields",
    "projection_summary_attribution", "projection_destination_fields", "projection_destination_duplicate",
    "projection_destination_missing", "projection_destination_invariants",
    "projection_preinput_fields", "projection_preinput_duplicate", "projection_preinput_missing",
    "projection_preinput_invariants", "projection_preinput_success",
})
FAILURE_LINE = re.compile(r"    native_windows_test\.go:[1-9][0-9]*: (" +
                          "|".join(sorted(NATIVE_FAILURES)) + r")\n")


class ProbeFailure(ValueError):
    def __init__(self, reason, preinput=None):
        self.reason = reason if reason in NATIVE_FAILURES | LAUNCHER_FAILURES else "go_test_failed"
        self.preinput = preinput
        super().__init__("public rendering probe incomplete")


class OutputLines:
    """Reassemble only contiguous exact-test Output fragments, never export them."""
    def __init__(self):
        self.pending = ""

    def feed(self, output):
        require(type(output) is str, "projection_output")
        parts = output.split("\n")
        for index, part in enumerate(parts):
            require(len(self.pending) + len(part) <= MAX_LINE, "projection_line_bound")
            self.pending += part
            if index < len(parts) - 1:
                line, self.pending = self.pending + "\n", ""
                yield line

    def finish(self):
        require(not self.pending, "projection_line_incomplete")


def native_failure_reason(raw):
    """Project one existing fixed label, never stderr, console bytes or paths."""
    try:
        require(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT and raw.endswith(b"\n"))
        reasons = []
        test_failed = package_failed = False
        for line in raw.splitlines():
            event = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
            require(type(event) is dict and event.get("Package") == PACKAGE)
            action, name = event.get("Action"), event.get("Test")
            require(action in {"start", "run", "output", "fail"})
            require(name is None or name == TEST)
            if action == "fail":
                if name == TEST:
                    require(not test_failed)
                    test_failed = True
                else:
                    require(not package_failed)
                    package_failed = True
            if action == "output" and name == TEST:
                output = event.get("Output")
                require(type(output) is str)
                match = FAILURE_LINE.fullmatch(output)
                if match:
                    reasons.append(match.group(1))
        require(test_failed and package_failed and len(reasons) == 1)
        return reasons[0]
    except (ValueError, TypeError, KeyError):
        return "go_test_failed"


def require(value, reason="projection_json"):
    if not value:
        raise ProbeFailure(reason)


def reject_constant(_):
    raise ProbeFailure("projection_json")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


class PreinputRecord:
    """Accept exactly one closed record, with its presentation prefix discarded."""
    def __init__(self):
        self.value = None

    def feed(self, output):
        marker = "preinput_live_output="
        start = output.find(marker)
        if start < 0:
            return False
        require(output.count(marker) == 1 and self.value is None, "projection_preinput_duplicate")
        require("cursor_position=" not in output and "stdout_char=" not in output, "projection_line_incomplete")
        match = PREINPUT.fullmatch(output[start:])
        require(match is not None, "projection_preinput_fields")
        self.value = dict(zip(PREINPUT_FIELDS, (x == "true" for x in match.groups()[:len(PREINPUT_FIELDS)])))
        self.value["preinput_rejection"], self.value["preinput_first_csi"] = match.groups()[-2:]
        return True

    def finish(self, failure_reason=None):
        value = self.value
        require(value is not None, "projection_preinput_missing")
        require(value["preinput_no_rejection"] == (value["preinput_rejection"] == "none"), "projection_preinput_invariants")
        require(value["preinput_live_output"] or not (value["preinput_public_trust"] or value["preinput_prompt_ready"]),
                "projection_preinput_invariants")
        require(not value["preinput_prompt_ready"] or (value["preinput_public_trust"] and value["preinput_no_rejection"]),
                "projection_preinput_invariants")
        require(value["preinput_first_csi"] == "none" or value["preinput_rejection"] == "csi_unsupported",
                "projection_preinput_invariants")
        if failure_reason == "preinput_guard_rejected":
            require(not value["preinput_no_rejection"], "projection_preinput_invariants")
        elif failure_reason == "preinput_prompt_missing":
            require(value["preinput_no_rejection"] and not all(value[name] for name in PREINPUT_FIELDS),
                    "projection_preinput_invariants")
        else:
            require(failure_reason is None, "projection_preinput_invariants")
            require(all(value[name] for name in PREINPUT_FIELDS) and value["preinput_rejection"] == "none" and
                    value["preinput_first_csi"] == "none", "projection_preinput_success")
        return value


def failed_preinput_record(raw, reason):
    """Retain diagnostics only for the two exact, attributed pre-input failures."""
    try:
        require(reason in PREINPUT_FAILURES and native_failure_reason(raw) == reason)
        record, lines = PreinputRecord(), OutputLines()
        labels = []
        for line in raw.splitlines():
            event = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
            if event.get("Action") == "output" and event.get("Test") == TEST and event.get("OutputType") != "frame":
                for output in lines.feed(event.get("Output")):
                    record.feed(output)
                    match = FAILURE_LINE.fullmatch(output)
                    if match:
                        labels.append(match.group(1))
            else:
                lines.finish()
        lines.finish()
        require(labels == [reason])
        return record.finish(reason)
    except (ValueError, TypeError, KeyError):
        return None


def format_preinput(value):
    return (" ".join(name + "=" + str(value[name]).lower() for name in PREINPUT_FIELDS) +
            " preinput_rejection=" + value["preinput_rejection"] +
            " preinput_first_csi=" + value["preinput_first_csi"])


def project(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_OUTPUT and raw.endswith(b"\n"), "projection_frame")
    passed = package_passed = False
    summary = destination = None
    label_seen = wrong_owner = crlf = prefix = False
    lines = OutputLines()
    preinput = PreinputRecord()
    for line in raw.splitlines():
        try:
            event = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
        except (ValueError, TypeError):
            raise ProbeFailure("projection_json") from None
        require(type(event) is dict and event.get("Package") == PACKAGE, "projection_package")
        action = event.get("Action")
        require(action in {"start", "run", "output", "pass"}, "projection_action")
        name = event.get("Test")
        require(name is None or name == TEST, "projection_test")
        if action == "pass":
            if name == TEST:
                require(not passed, "projection_duplicate_pass")
                passed = True
            elif name is None:
                require(not package_passed, "projection_duplicate_pass")
                package_passed = True
        if action == "output" and name == TEST and event.get("OutputType") != "frame":
            for output in lines.feed(event.get("Output")):
                if preinput.feed(output):
                    continue
                marker = "stdout_char="
                start = output.find(marker)
                if start >= 0:
                    require("cursor_position=" not in output, "projection_line_incomplete")
                    require(output.count(marker) == 1 and destination is None, "projection_destination_duplicate")
                    match = DESTINATION.fullmatch(output[start:])
                    require(match is not None, "projection_destination_fields")
                    destination = dict(zip(DESTINATION_FIELDS, (x == "true" for x in match.groups()[:-1])))
                    destination["conout_first_residual_kind"] = match.groups()[-1]
                    continue
                label_seen |= "cursor_position=" in output
                crlf |= output.endswith("\r\n") and SUMMARY.fullmatch(output[:-2] + "\n") is not None
                prefix |= SUMMARY_BODY.search(output) is not None
                # The caller prefix is test-log presentation, not observation
                # data. Discard it without exporting paths or other prefix text.
                # The fixed first field delimits one complete finite record.
                marker = "cursor_position="
                start = output.find(marker)
                if start >= 0:
                    require(output.count(marker) == 1, "projection_duplicate_summary")
                match = SUMMARY_BODY.fullmatch(output[start:]) if start >= 0 else None
                if match:
                    require(summary is None, "projection_duplicate_summary")
                    summary = dict(zip(FIELDS, (x == "true" for x in match.groups()[:len(FIELDS)])))
                    summary["first_residual_kind"] = match.groups()[len(FIELDS)]
                    summary.update(zip(TEXT_FIELDS, (x == "true" for x in match.groups()[len(FIELDS)+1:])))
        else:
            lines.finish()
            if action == "output" and isinstance(event.get("Output"), str):
                wrong_owner |= "cursor_position=" in event["Output"]
    lines.finish()
    require(passed and package_passed, "projection_missing_pass")
    if summary is None:
        if crlf:
            raise ProbeFailure("projection_summary_crlf")
        if prefix:
            raise ProbeFailure("projection_summary_prefix")
        if label_seen:
            raise ProbeFailure("projection_summary_fields")
        if wrong_owner:
            raise ProbeFailure("projection_summary_attribution")
        raise ProbeFailure("projection_missing_summary")
    require(not summary["overflow"] and not summary["incomplete"], "projection_bounds")
    require(summary["residual_unknown"] == (summary["first_residual_kind"] != "none"), "projection_residual")
    require(summary["unknown"] == any(summary[name] for name in FIELDS[8:]), "projection_unknown")
    require(not (summary["exact_prompt"] and summary["prompt_without_final_space"]), "projection_prompt")
    require(summary["live_output"] or not any(summary[name] for name in TEXT_FIELDS[1:]), "projection_live")
    require(destination is not None, "projection_destination_missing")
    for stream in ("stdout", "stderr"):
        require(not (destination[stream+"_char"] and destination[stream+"_pipe"]) and
                (not destination[stream+"_console"] or destination[stream+"_char"]), "projection_destination_invariants")
    require(destination["conout_console"] and not destination["conout_overflow"] and not destination["conout_incomplete"], "projection_destination_invariants")
    require(destination["conout_residual_unknown"] == (destination["conout_first_residual_kind"] != "none"), "projection_destination_invariants")
    require(not (destination["conout_exact_prompt"] and destination["conout_prompt_without_final_space"]), "projection_destination_invariants")
    require(destination["conout_live_output"] or not any(destination[name] for name in
            ("conout_public_trust", "conout_exact_prompt", "conout_prompt_without_final_space")), "projection_destination_invariants")
    summary.update(destination)
    summary.update(preinput.finish())
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
    timed_out = False
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
        timed_out = True
    reader.join(timeout=5)
    if timed_out:
        raise ProbeFailure("capture_deadline")
    if reader.is_alive() or failed.is_set():
        raise ProbeFailure("capture_incomplete")
    if code != 0:
        reason = native_failure_reason(bytes(raw))
        raise ProbeFailure(reason, failed_preinput_record(bytes(raw), reason))
    return bytes(raw)


def main():
    try:
        require(sys.platform == "win32", "platform")
        env = os.environ.copy()
        for name in ("GOOS", "GOARCH", "GOFLAGS"):
            env.pop(name, None)
        env["GOTOOLCHAIN"] = "local"
        summary = project(capture(env))
        print("OBSERVED: fixed public ConPTY sequence families " +
              " ".join(name + "=" + str(summary[name]).lower() for name in FIELDS) +
              " first_residual_kind=" + summary["first_residual_kind"] +
              " " + " ".join(name + "=" + str(summary[name]).lower() for name in TEXT_FIELDS) +
              " " + " ".join(name + "=" + str(summary[name]).lower() for name in DESTINATION_FIELDS) +
              " conout_first_residual_kind=" + summary["conout_first_residual_kind"] +
              " " + format_preinput(summary) +
              "; no coordinator or guard compatibility claim.")
        return 0
    except ProbeFailure as failure:
        if failure.preinput is not None:
            print("OBSERVED: fixed public ConPTY pre-input guard " + format_preinput(failure.preinput) +
                  "; failed public fixture; no coordinator or native acceptance claim.")
        print("FAIL: public ConPTY rendering probe incomplete; reason=" + failure.reason +
              "; raw output withheld; no cleanup or native acceptance claim.")
        return 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("FAIL: public ConPTY rendering probe incomplete; reason=launch_or_io_failed; raw output withheld; no cleanup or native acceptance claim.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
