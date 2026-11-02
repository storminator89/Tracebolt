"""Bounded GUI-only fixture protocol. Importing this module has no native effect."""
import json
import re
import time

CASES = frozenset({"tls", "http", "renewal", "cancel", "failure", "uninstall",
                   "modal-resize", "close-input"})
STAGES = frozenset({"approval", "platform", "ci", "source", "desktop", "image-path", "image-lease",
    "image-digest", "launch", "window-identity", "control-identity", "message", "window",
    "provenance", "thread-dpi", "layout", "font", "consent", "back", "operation", "cancel", "uninstall",
    "privacy", "cleanup", "fixture-report", "deadline", "unexpected"})
COVERAGE = {k: False for k in ("installation", "secretConsole", "uac", "realManager",
    "telemetry", "physicalKeyboard", "pixelVisibility", "publicFileChooser", "realBootstrapParser",
    "mixedDPI", "unavailableNativeLayout", "adversarialImageBinding", "fullParity")}

class Failure(Exception):
    def __init__(self, stage):
        self.stage = stage if stage in STAGES else "unexpected"
        super().__init__(self.stage)

def need(condition, stage):
    if not condition:
        raise Failure(stage)

class Deadline:
    def __init__(self, seconds=60, clock=time.monotonic, sleeper=time.sleep):
        self.clock, self.sleeper, self.end = clock, sleeper, clock() + seconds
    def check(self):
        need(self.clock() < self.end, "deadline")
    def pause(self, seconds=.05):
        self.check()
        self.sleeper(min(seconds, max(0, self.end - self.clock())))
        self.check()

def eventually(predicate, budget, stage):
    while True:
        budget.check()
        if predicate():
            return
        budget.pause()

def authorization(platform, acknowledged, which, source, digest, env):
    need(acknowledged is True, "approval")
    need(platform == "nt", "platform")
    need(which in CASES and re.fullmatch(r"[0-9a-f]{40}", source or "") is not None
         and re.fullmatch(r"[0-9a-f]{64}", digest or "") is not None, "approval")
    denied = {"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILD_BUILDID", "TF_BUILD", "JENKINS_URL",
              "CONTINUOUS_INTEGRATION", "TEAMCITY_VERSION", "CIRCLECI", "BUILDKITE"}
    need(not any(k.upper() in denied for k in env), "ci")

def unique_object(pairs):
    value = {}
    for k, v in pairs:
        need(k not in value, "fixture-report")
        value[k] = v
    return value

def parse_fixture(raw, which):
    need(which in CASES, "fixture-report")
    need(type(raw) is bytes and len(raw) <= 65536, "fixture-report")
    rows = [line[len(b"RUST_GUI_FIXTURE_RESULT "):] for line in raw.splitlines()
            if line.startswith(b"RUST_GUI_FIXTURE_RESULT ")]
    need(len(rows) == 1 and len(rows[0]) <= 4096, "fixture-report")
    try:
        value = json.loads(rows[0], object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        raise Failure("fixture-report") from None
    keys = {"schema", "case", "hook", "hookCount", "cancelled", "cleanupJoined",
            "exactHookSelection", "layoutAtHookAdmission", "uiReturned", "installerHostActionsAttempted",
            "installerAcceptance", "fontProbeCount", "fontProbesValid", "probeReaderJoined"}
    need(type(value) is dict and set(value) == keys and value["case"] == which
         and value["schema"] == "tracebolt.rust-gui-inert-hook-result.v1", "fixture-report")
    booleans = keys - {"schema", "case", "hook", "hookCount", "fontProbeCount"}
    need(all(type(value[k]) is bool for k in booleans) and type(value["hookCount"]) is int,
         "fixture-report")
    need(value["installerHostActionsAttempted"] is False and value["installerAcceptance"] is False
         and value["uiReturned"] and value["exactHookSelection"], "fixture-report")
    need(type(value["fontProbeCount"]) is int and 1 <= value["fontProbeCount"] <= 16
         and value["fontProbesValid"] and value["probeReaderJoined"], "fixture-report")
    if which == "close-input":
        need(value["hookCount"] == 0 and value["hook"] == "" and not value["cancelled"], "fixture-report")
    else:
        hook = "uninstall" if which in {"uninstall", "modal-resize"} else (
            "renewable-read-admin" if which == "renewal" else "read-admin")
        need(value["hook"] == hook and value["hookCount"] == 1 and value["cleanupJoined"]
             and value["layoutAtHookAdmission"]
             and value["cancelled"] == (which == "cancel"), "fixture-report")
    return value

def parse_font_probe(raw, ordinal):
    need(type(raw) is bytes and len(raw) <= 65536 and type(ordinal) is int and 1 <= ordinal <= 16, "fixture-report")
    rows = [line[len(b"RUST_GUI_FIXTURE_FONT "):] for line in raw.split(b"\n")[:-1]
            if line.startswith(b"RUST_GUI_FIXTURE_FONT ")]
    need(len(rows) <= ordinal, "fixture-report")
    for number, row in enumerate(rows, 1):
        need(len(row) <= 128, "fixture-report")
        try:
            value = json.loads(row, object_pairs_hook=unique_object)
        except (ValueError, UnicodeError):
            raise Failure("fixture-report") from None
        need(type(value) is dict and set(value) == {"ordinal", "matchesOriginal"}
             and type(value["ordinal"]) is int and value["ordinal"] == number
             and type(value["matchesOriginal"]) is bool, "fixture-report")
        need(value["matchesOriginal"], "font")
    return True if len(rows) == ordinal else None

def drain_bounded(stream, buffer):
    failed = False
    while True:
        part = stream.read1(4096)  # A short probe must not wait for a full 4-KiB buffer.
        if not part:
            return failed
        room = 65536 - len(buffer)
        buffer.extend(part[:room])
        failed |= len(part) > room

def drive(ui, which, budget):
    """Only a PID-bound adapter can perform these actions; no host backend exists."""
    need(which in CASES, "approval")
    ui.wait_root(budget)
    need("INERT_GUI_FIXTURE_NO_HOST_ACTION" in ui.text(201), "provenance")
    ui.check_layout()
    ui.exercise_geometry()
    checks = {"nativeWindow": True, "geometryAndFont": True, "scopeUncheckedAndBack": False,
              "singleAttempt": False, "cancelWait": False, "defaultNoUninstall": False,
              "modalGeometry": False, "publicOutputOnly": False}
    if which == "close-input":
        ui.close()
        return checks
    if which in {"uninstall", "modal-resize"}:
        ui.click(103)
        ui.wait_dialog(budget)
        need(ui.default_no(), "uninstall")
        ui.dialog_click(7)
        eventually(lambda: not ui.dialog_present(), budget, "uninstall")
        need(ui.present(103), "uninstall")
        ui.click(103)
        ui.wait_dialog(budget)
        need(ui.default_no(), "uninstall")
        if which == "modal-resize":
            ui.resize_client(800, 600)
            checks["modalGeometry"] = True
        ui.dialog_click(6)
        checks["defaultNoUninstall"] = True
    else:
        ui.click(1)
        eventually(lambda: ui.present(104), budget, "consent")
        ui.check_layout()
        ids = [104, 105, 106, 107]
        if which == "http":
            ids.append(108)
        if which == "renewal":
            ids.append(111)
        need(all(not ui.checked(k) for k in ids) and not ui.enabled(1), "consent")
        for k in ids:
            ui.click(k)
        need(ui.enabled(1), "consent")
        ui.click(101)
        eventually(lambda: ui.present(102), budget, "back")
        ui.click(1)
        eventually(lambda: ui.present(104), budget, "back")
        need(all(not ui.checked(k) for k in ids) and not ui.enabled(1), "back")
        checks["scopeUncheckedAndBack"] = True
        for k in ids:
            ui.click(k)
        need(ui.enabled(1), "consent")
        ui.click(1)
        ui.repeat_submit()  # Synthetic queued event, not a physical-input claim.
    eventually(lambda: ui.present(205), budget, "operation")
    if which == "cancel":
        eventually(lambda: "INERT GUI fixture hook entered" in ui.text(205), budget, "operation")
        ui.close()
        budget.pause(.15)
        need(ui.root_alive(), "cancel")
        checks["cancelWait"] = True
    terminal = "The operation did not complete" if which in {"cancel", "failure"} else (
        "Service removal completed" if which in {"uninstall", "modal-resize"} else "Service start requested")
    eventually(lambda: terminal in ui.text(205), budget, "operation")
    ui.check_layout()
    need("SYNTHETIC_PRIVATE_ERROR_MUST_NOT_REACH_VIEW" not in ui.text(205), "privacy")
    checks["singleAttempt"], checks["publicOutputOnly"] = True, True
    ui.click(2)
    return checks
