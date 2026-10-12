#!/usr/bin/env python3
"""Manual packaged-GUI gate. Import, ordinary tests and missing approvals are inert.

Build errors, GUI text, console buffers, identities and observations are never
exported. Only strict finite reports and an exact allowlisted public package
can reach artifact uploads. Delivered package bytes are never rebuilt.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("_setup_shared", Path(__file__).with_name("run_acceptance.py"))
shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)
_provenance_spec = importlib.util.spec_from_file_location("_setup_job_provenance", Path(__file__).with_name("current_setup_job_provenance.py"))
provenance = importlib.util.module_from_spec(_provenance_spec)
_provenance_spec.loader.exec_module(provenance)
require = shared.require
PROFILE = "packaged-setup-gui-read-admin-current-v3"
VERSION = "v0.0.0-setup-candidate"
REPORT_NAME = "tracebolt-windows-current-setup-acceptance.json"
PUBLIC_DIRECTORY = "tracebolt-current-setup-tested-public"
ACCEPTED_DIRECTORY = "tracebolt-current-setup-accepted-public"
AGGREGATE_REPORT = "tracebolt-current-setup-native-subset.json"
SETUP_NAME = "Tracebolt-" + VERSION + "-windows-amd64-Setup.exe"
SERVICE_NAME = "tracebolt-" + VERSION + "-windows-amd64-service.exe"
PUBLIC_FILES = {SETUP_NAME, SERVICE_NAME, "setup-package-amd64.json", "build-manifest.json", "source-inputs.json", "SHA256SUMS"}
_resource_spec = importlib.util.spec_from_file_location("_setup_public_pe", ROOT / "deploy/windows-setup/pe_resources.py")
resources = importlib.util.module_from_spec(_resource_spec)
_resource_spec.loader.exec_module(resources)
APPROVALS = ("APP_ACLS", "SERVICES", "IDENTITY", "TWENTY_ONE_READ_ADMIN_SCOPES", "AUTOMATIC_RENEWAL", "SYNTHETIC_CONSOLE", "LOOPBACK_TLS", "STOP_REMOVE_OWNED_SERVICE", "RETAIN_FOR_VM_DISPOSAL")
NORMAL = {"install-uninstall"}
BASE = {"renewalConsentOff", "renewalConsentExplicit", "optionalActionsOff", "acknowledgementsOff", "publicBootstrapChosen", "realGUIExercised", "hiddenConsoleExercised", "noEchoVerified", "pendingStoppedDisabled", "reopenBlocked", "filesAndStateRetained", "workerTerminated", "consoleReleased"}
CHECKS = {
 "install-uninstall": BASE | {"preflightCancelUnchanged", "approvalWithheld", "managerFixtureApproved", "completedReceipt", "limitedServiceToken", "currentFrames", "uninstallCancelUnchanged", "deletePendingObserved", "serviceAbsent", "receiptAndGrantsVerified"},
 "cancel-hidden-input": BASE | {"cancelWhileHiddenInput", "partialStateRetained", "incompleteUninstallBlocked"},
 "pending-transport": BASE | {"approvalWithheld", "transportInterrupted", "sameIdentityAndDeadline", "noFalseConnected", "partialStateRetained", "incompleteUninstallBlocked"},
}
FALSE_COVERAGE = {"humanUAC", "humanInvitation", "realLinuxManager", "sharedDashboard", "arm64Runtime", "osReboot", "upgrade", "vmDisposalVerified", "secretsExported", "rawTelemetryExported", "windows11", "providerCompleteness", "eventHistoryQuery", "eventHistoryMessage", "renewalCutover", "selectedUpdates", "serviceControl", "selectedUserSoftware"}
_removal_spec=importlib.util.spec_from_file_location("_removal_service_pairs",Path(__file__).with_name("fresh_child_diagnostics.py"))
_removal_pairs=importlib.util.module_from_spec(_removal_spec)
_removal_spec.loader.exec_module(_removal_pairs)
REMOVAL_FAILURE_STAGES={"uninstall-failure-"+step for step in ("unknown","validate","context","receipt","owned","state","stop","stop-observe","stop-state","stop-wait","pre-delete","delete","delete-result","absence-inspect","absence-owned","absence-wait")}
REMOVAL_FAILURE_REASONS={"failed","receipt_rejected","canceled","deadline","access_denied","cannot_accept_control","not_active","dependent_services","delete_pending"}|{"service:"+s+":"+c+":"+cause for s,c in _removal_pairs.SERVICE_FAILURE_PAIRS if s!="unknown" for cause in ("failed","canceled","deadline","access_denied","cannot_accept_control","not_active","dependent_services","delete_pending")}
HIDDEN_INPUT_FAILURE_STAGES = {
    "hidden-input-process-inspect", "hidden-input-process-exited",
    "hidden-input-installer-compatibility", "hidden-input-installer-before-mutation",
    "hidden-input-installer-failed", "hidden-input-installer-returned",
    "hidden-input-console-observation", "hidden-input-console-attach",
    "hidden-input-console-open-input", "hidden-input-console-open-output",
    "hidden-input-console-mode", "hidden-input-console-screen-info",
    "hidden-input-console-screen-bound", "hidden-input-console-screen-read",
    "hidden-input-console-no-echo", "hidden-input-echo-enabled", "hidden-input-prompt-absent",
}
RETENTION_FAILURE_STAGES = {"current-platform", "current-receipt", "current-grants", "current-identity", "current-optionals", "current-retention", "current-consent", 'retention-baseline-immutable-unchanged', 'retention-stopped-immutable-unchanged', 'verify-retention-immutable-unchanged', 'verify-retention-stopped-unchanged', 'retention-baseline-owned', 'retention-baseline-material', 'retention-baseline-receipt', 'retention-baseline-runtime', 'retention-baseline-enrollment', 'retention-baseline-identity', 'retention-stopped-receipt', 'retention-stopped-runtime', 'retention-stopped-enrollment', 'retention-stopped-identity', 'verify-retention-receipt', 'verify-retention-runtime', 'verify-retention-enrollment', 'verify-retention-identity', 'retention-stopped-event-grant', 'retention-stopped-volume-grant', 'retention-stopped-process-grant', 'retention-stopped-network-grant', 'retention-stopped-sender', 'verify-retention-event-grant', 'verify-retention-volume-grant', 'verify-retention-process-grant', 'verify-retention-network-grant', 'verify-retention-sender', 'verify-retention-binary', 'verify-retention-tree'}
INITIAL_CHOOSER_FAILURE_STAGES = {"initial-chooser-" + step for step in
    ("attempt", "context", "process", "deadline", "discovery", "identity", "ready", "post")}
CHOOSER_CLICK_FAILURE_STAGES = {"current-platform", "current-receipt", "current-grants", "current-identity", "current-optionals", "current-retention", "current-consent", 'chooser-click-client-bottom-right', 'chooser-click-client-contained', 'chooser-click-client-rect', 'chooser-click-client-top-left', 'chooser-click-control', 'chooser-click-control-rect', 'chooser-click-dpi-restore', 'chooser-click-dpi-set', 'chooser-click-enabled', 'chooser-click-monitor', 'chooser-click-monitor-info', 'chooser-click-not-iconic', 'chooser-click-post', 'chooser-click-root', 'chooser-click-visible', 'chooser-click-work-contained', 'chooser-open-client-bottom-right', 'chooser-open-client-contained', 'chooser-open-client-rect', 'chooser-open-client-top-left', 'chooser-open-control', 'chooser-open-control-rect', 'chooser-open-dpi-restore', 'chooser-open-dpi-set', 'chooser-open-enabled', 'chooser-open-monitor', 'chooser-open-monitor-info', 'chooser-open-not-iconic', 'chooser-open-post', 'chooser-open-root', 'chooser-open-visible', 'chooser-open-work-contained'}
STAGES = {"current-platform", "current-receipt", "current-grants", "current-identity", "current-optionals", "current-retention", "current-consent", "bootstrap-launch", "chooser-click", "chooser-dialog", "chooser-title", "chooser-edit", "chooser-set-text", "chooser-open", "chooser-validated", "uninstall-held-status-delete-pending", "uninstall-held-status-invalid-handle", "uninstall-held-status-access-denied", "uninstall-pending-close-failed", "uninstall-pending-close-completed", "authorization", "desktop", "fresh", "fresh-environment", "fresh-layout", "fresh-service", "fresh-program-files", "fresh-program-data", "fixture", "preflight-cancel", "bootstrap", "consent", "install", "hidden-input", "pending", "pending-capture", "pending-claim", "pending-service", "pending-console", "pending-invariant", "pending-retention", "transport", "transport-service", "completion", "frames", "frames-evidence", "reopen", "uninstall-cancel", "uninstall", "verify-retention", "completed", "consent-back", "consent-first-compared", "consent-first-disabled", "consent-first-enabled", "consent-first-http", "consent-first-http-reset", "consent-first-identity", "consent-first-reset", "consent-first-scope", "consent-first-service", "consent-http-absent", "consent-input", "consent-open", "consent-reopen", "consent-review", "consent-review-reset", "consent-second-compared", "consent-second-disabled", "consent-second-enabled", "consent-second-http", "consent-second-http-reset", "consent-second-identity", "consent-second-reset", "consent-second-scope", "consent-second-service", "preflight-cancel-click", "preflight-choose", "preflight-consent", "preflight-exit", "preflight-fresh-service", "preflight-fresh-program-files", "preflight-fresh-program-data", "preflight-launch", "uninstall-absence-inspect", "uninstall-absence-present", "uninstall-cancel-confirmation", "uninstall-cancel-invariant", "uninstall-cancel-return", "uninstall-confirmation", "uninstall-exit", "uninstall-finish", "uninstall-finish-message", "uninstall-held-close", "uninstall-held-close-completed", "uninstall-held-close-failed", "uninstall-held-status", "uninstall-held-stopped", "uninstall-hold-scm", "uninstall-hold-service", "uninstall-launch", "uninstall-operation-failed", "uninstall-owned", "uninstall-pending-close", "uninstall-pending-text", "uninstall-receipt", "uninstall-release", "uninstall-removing", "uninstall-stopping"} | REMOVAL_FAILURE_STAGES | CHOOSER_CLICK_FAILURE_STAGES | RETENTION_FAILURE_STAGES | HIDDEN_INPUT_FAILURE_STAGES | INITIAL_CHOOSER_FAILURE_STAGES

HIDDEN_INPUT_PACKAGE_CODES = {'created-descriptor', 'bootstrap-size', 'file-streams', 'cancelled', 'filesystem-unsupported', 'manifest-invalid', 'payload-machine', 'directory-create', 'file-write', 'file-duplicate', 'object-metadata', 'object-reparse', 'ancestor-dacl', 'existing-resource', 'file-pin', 'object-kind', 'close-failed', 'elevation-unverified', 'payload-pe', 'file-size', 'payload-digest', 'package-incomplete', 'descriptor-query', 'ancestor-writer', 'elevation-required', 'ancestor-ace', 'object-role', 'file-read', 'package-failed', 'file-create', 'payload-size', 'existing-service', 'file-handle', 'layout-invalid', 'directory-case', 'path-binding', 'service-inspection', 'unsupported-platform', 'ancestor-open', 'ancestor-descriptor', 'ancestor-owner', 'architecture-mismatch', 'absence-unverified', 'descriptor-create', 'architecture-invalid', 'file-flush', 'file-digest'}
HIDDEN_INPUT_SERVICE_PHASES = {'handoff', 'receipt', 'bootstrap', 'unknown', 'runtime_installation', 'lifecycle', 'sender', 'setup', 'retained_state', 'enrollment', 'pending_approval', 'runtime_identity', 'runtime_dispatch'}
HIDDEN_INPUT_SERVICE_REASONS = {'approval_expired', 'sender_failed', 'invalid_arguments', 'invalid_configuration', 'runtime_read_denied', 'interrupted', 'enrollment_failed', 'result_write', 'input_rejected', 'operation_failed', 'unsupported_platform', 'state_unavailable', 'enrollment_terminal', 'state_rejected', 'unknown', 'identity_rejected', 'handoff_invalid', 'unexpected_exit', 'result_encoding', 'input_failed', 'unsafe_path', 'dispatcher_unavailable'}

def hidden_input_failure_reason(reason):
    if type(reason) is not str:
        return False
    parts = reason.split(":")
    if len(parts) < 2 or parts[1] not in HIDDEN_INPUT_PACKAGE_CODES:
        return False
    return ((len(parts) == 2 and parts[0] == "setup_package") or
            (len(parts) == 4 and parts[0] == "setup_service" and
             parts[2] in HIDDEN_INPUT_SERVICE_PHASES and parts[3] in HIDDEN_INPUT_SERVICE_REASONS))

# Wrapper-only diagnostics: these are not native controller reports or evidence.
# Never include exception messages, commands, paths, output, or environment values.
PRE_NATIVE_STAGES = frozenset({"authorization", "native-profile", "checkout", "toolchain", "dependencies",
    "staging", "package-build", "package-validation", "driver-build", "source-recheck", "run-binding"})

class PreNativeFailure(shared.Rejected):
    def __init__(self, stage):
        require(type(stage) is str and stage in PRE_NATIVE_STAGES)
        self.stage = stage
        super().__init__("pre_native_failed")

@contextmanager
def pre_native_step(stage):
    require(type(stage) is str and stage in PRE_NATIVE_STAGES)
    try:
        yield
    except Exception:
        raise PreNativeFailure(stage) from None

def authorize_common(env):
    source = env.get("TRACEBOLT_SETUP_SOURCE", "")
    require(shared.valid_source(source) and env.get("GITHUB_SHA") == source)
    require(env.get("TRACEBOLT_SETUP_PROFILE") == PROFILE)
    require(all("TRACEBOLT_SETUP_APPROVE_" + old not in env for old in ("FIVE_READ_SCOPES", "TWELVE_READ_ADMIN_SCOPES", "HTTP_PLAINTEXT")))
    fixed = {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_REPOSITORY_OWNER": "storminator89", "GITHUB_ACTOR": "storminator89", "GITHUB_TRIGGERING_ACTOR": "storminator89", "GITHUB_REPOSITORY_OWNER_ID": "30489872", "GITHUB_ACTOR_ID": "30489872", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted"}
    require(all(env.get(k) == v for k, v in fixed.items()))
    require(re.fullmatch(r"[1-9][0-9]{0,23}", env.get("GITHUB_RUN_ID", "")) is not None)
    require(all(env.get("TRACEBOLT_SETUP_APPROVE_" + a) == "true" for a in APPROVALS))
    return source

def require_native_profile():
    # Current driver has distinct receipt/grant/frame validators; never an override
    # into the preserved five-scope driver or historical report schema.
    require(PROFILE == "packaged-setup-gui-read-admin-current-v3")

def authorize(env):
    source = authorize_common(env)
    require(env.get("TRACEBOLT_SETUP_CASE") in CHECKS and env.get("RUNNER_OS") == "Windows")
    return source

def authorize_aggregate(env):
    source = authorize_common(env)
    require(env.get("RUNNER_OS") == "Linux")
    return source

# Filled by the independently bounded current fixture contract below.
def zero_frame_progress():
    return current_frames.zero_observation()

def validate_frame_progress(value):
    return current_frames.validate(value)

_current_spec = importlib.util.spec_from_file_location("_current_setup_frames", Path(__file__).with_name("current_setup_frames.py"))
current_frames = importlib.util.module_from_spec(_current_spec)
_current_spec.loader.exec_module(current_frames)

def validate_report(raw, source, which):
    r = shared.strict_json(raw, 32 << 10)
    require(type(r) is dict and set(r) == {"setupSHA256", "serviceSHA256", "driverSHA256", "sourceInputsSHA256", "runID", "machine", "schema", "source", "case", "status", "stage", "reason", "approvalValidated", "nativeActionsAttempted", "checks", "coverage", "startup", "frames", "frameProgress", "platformDisposalRequired", "sourceTree", "machineIDSHA256", "osBuild", "osRevision", "receiptProof"})
    require(all(type(r[k]) is str and re.fullmatch(r"[0-9a-f]{64}", r[k]) for k in ("setupSHA256", "serviceSHA256", "driverSHA256", "sourceInputsSHA256")))
    require(type(r["runID"]) is str and re.fullmatch(r"[1-9][0-9]{0,23}", r["runID"]) and type(r["machine"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", r["machine"]))
    require(shared.valid_source(r["sourceTree"]) and type(r["machineIDSHA256"]) is str and re.fullmatch(r"[0-9a-f]{64}",r["machineIDSHA256"]))
    require(type(r["osBuild"]) is int and r["osBuild"] == 26100 and type(r["osRevision"]) is int and 0 < r["osRevision"] <= 2**32-1)
    validate_receipt_proof(r["receiptProof"])
    require(r["schema"] == "tracebolt.windows-current-setup-acceptance.v1" and r["source"] == source and r["case"] == which and which in CHECKS)
    require(shared.member(r["status"], {"blocked", "failed", "passed_packaged_gui_subset"}) and shared.member(r["stage"], STAGES))
    base_reasons={"none", "authorization", "desktop_unavailable", "operation_failed", "deadline", "inspection_required"}
    require(shared.member(r["reason"], base_reasons | REMOVAL_FAILURE_REASONS) or hidden_input_failure_reason(r["reason"]))
    if r["stage"] in RETENTION_FAILURE_STAGES:
        require(r["status"] == "failed" and r["case"] in NORMAL)
    if r["stage"] in CHOOSER_CLICK_FAILURE_STAGES | INITIAL_CHOOSER_FAILURE_STAGES:
        require(r["status"] == "failed")
    if r["stage"] in REMOVAL_FAILURE_STAGES or r["reason"] not in base_reasons and not hidden_input_failure_reason(r["reason"]):
        require(r["status"] == "failed" and r["case"] in NORMAL and r["stage"] in REMOVAL_FAILURE_STAGES and r["reason"] in REMOVAL_FAILURE_REASONS)
    require(shared.member(r["startup"], {"inspection_required", "disabled", "automatic", "absent"}))
    require(type(r["checks"]) is dict and set(r["checks"]) == CHECKS[which] and all(type(v) is bool for v in r["checks"].values()))
    if hidden_input_failure_reason(r["reason"]):
        require(r["status"] == "failed" and r["checks"]["hiddenConsoleExercised"] is False and
                ((r["reason"].startswith("setup_package:") and r["stage"] == "hidden-input-installer-before-mutation") or
                 (r["reason"].startswith("setup_service:") and r["stage"] == "hidden-input-installer-failed")))
    if r["stage"] in HIDDEN_INPUT_FAILURE_STAGES:
        require(r["status"] == "failed" and r["checks"]["hiddenConsoleExercised"] is False)
    require(type(r["coverage"]) is dict and set(r["coverage"]) == FALSE_COVERAGE and all(v is False for v in r["coverage"].values()))
    require(all(type(r[k]) is bool for k in ("approvalValidated", "nativeActionsAttempted", "platformDisposalRequired")))
    require(type(r["frames"]) is int and 0 <= r["frames"] <= 64)
    ready = validate_frame_progress(r["frameProgress"])
    require(r["frames"] == r["frameProgress"]["acceptedFrames"])
    require(r["nativeActionsAttempted"] or r["frameProgress"] == zero_frame_progress())
    require(which in NORMAL or r["frameProgress"] == zero_frame_progress())
    require(not r["nativeActionsAttempted"] or r["approvalValidated"])
    require(not r["platformDisposalRequired"] or r["nativeActionsAttempted"])
    if r["status"] == "blocked":
        require(not r["nativeActionsAttempted"] and r["frames"] == 0 and r["startup"] == "inspection_required" and not any(r["checks"].values()))
    if r["status"] == "passed_packaged_gui_subset":
        require(all(r["checks"].values()) and r["nativeActionsAttempted"] and r["platformDisposalRequired"] and r["stage"] == "completed" and r["reason"] == "none")
        require((r["startup"] == "absent" and r["frames"] >= 2 and ready and r["receiptProof"]["verified"]) if which in NORMAL else (r["startup"] == "disabled" and r["frames"] == 0))
    return r

def parse_controller(raw, source, which):
    require(type(raw) is bytes and len(raw) <= 32 << 10)
    rows = [line[len(b"current-setup-gui-report="):] for line in raw.splitlines() if line.startswith(b"current-setup-gui-report=")]
    require(len(rows) == 1)
    return validate_report(rows[0], source, which)

def bind_run(env, source, driver, setup, service, machine, deadline):
    require(authorize(env) == source and machine == env.get("COMPUTERNAME") and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", machine) and type(deadline) is int)
    # Native controller receives only explicit run scope and ordinary OS facts.
    child = {k: v for k, v in env.items() if k in {"TRACEBOLT_SETUP_SOURCE", "TRACEBOLT_SETUP_PROFILE", "TRACEBOLT_SETUP_CASE", *("TRACEBOLT_SETUP_APPROVE_" + a for a in APPROVALS)} or k in {"GITHUB_SHA", "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_ACTOR", "GITHUB_ACTOR_ID", "GITHUB_TRIGGERING_ACTOR", "GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "COMPUTERNAME", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP"}}
    child.update(TRACEBOLT_SETUP_MACHINE=machine, TRACEBOLT_SETUP_RUN_ID=env["GITHUB_RUN_ID"], TRACEBOLT_SETUP_EXPIRES_UNIX=str(deadline), TRACEBOLT_SETUP_DRIVER_SHA256=shared.binary_digest(driver), TRACEBOLT_SETUP_SETUP_SHA256=shared.binary_digest(setup), TRACEBOLT_SETUP_SERVICE_SHA256=shared.binary_digest(service), TRACEBOLT_SETUP_SETUP_ARTIFACT=str(setup), TRACEBOLT_SETUP_SERVICE_ARTIFACT=str(service), TRACEBOLT_SETUP_SOURCE_INPUTS_SHA256=shared.binary_digest(setup.parent / "source-inputs.json"), TRACEBOLT_SETUP_SOURCE_INPUTS_ARTIFACT=str(setup.parent / "source-inputs.json"), TRACEBOLT_SETUP_PUBLIC_INPUT=str(driver.parent / "public-bootstrap.json"), GOTRACEBACK="none")
    child.update(TRACEBOLT_SETUP_TREE=env["TRACEBOLT_SETUP_TREE"], TRACEBOLT_SETUP_MACHINE_ID_SHA256=env["TRACEBOLT_SETUP_MACHINE_ID_SHA256"])
    return child

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def regular_file(path, bound):
    require(not path.is_symlink() and not (hasattr(path, "is_junction") and path.is_junction()))
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= bound)
    with path.open("rb") as stream:
        raw = stream.read(bound + 1)
    require(len(raw) == info.st_size and len(raw) <= bound)
    return raw

def exact_directory(path, names):
    require(path.is_dir() and not path.is_symlink() and not (hasattr(path, "is_junction") and path.is_junction()))
    require({p.name for p in path.iterdir()} == set(names))

def read_public_package(path):
    # Never traverse the build stage: it also contains controller/public bootstrap.
    exact_directory(path, PUBLIC_FILES)
    bounds = {SETUP_NAME: 128 << 20, SERVICE_NAME: 128 << 20, "source-inputs.json": 4 << 20, "build-manifest.json": 64 << 10, "setup-package-amd64.json": 2048, "SHA256SUMS": 4096}
    return {name: regular_file(path / name, bounds[name]) for name in sorted(PUBLIC_FILES)}

def validate_public_package(files, source, report=None):
    require(type(files) is dict and set(files) == PUBLIC_FILES and shared.valid_source(source))
    hashes = {name: digest(raw) for name, raw in files.items()}
    manifest = shared.strict_json(files["build-manifest.json"], 64 << 10)
    expected_keys = {"schemaVersion", "repository", "version", "sourceCommit", "sourceKind", "sourceCommitRole", "sourceInputsSHA256", "goVersion", "architectures", "authenticode", "distributionStatus", "nativeExecution", "repeatBuildIdentical", "assets", "peChecks"}
    require(type(manifest) is dict and set(manifest) == expected_keys and files["build-manifest.json"] == canonical(manifest))
    for key, value in {"schemaVersion": "tracebolt.windows-setup-build.v1", "repository": "storminator89/Tracebolt", "version": VERSION, "sourceCommit": source, "sourceKind": "clean-git-commit", "sourceCommitRole": "exact", "sourceInputsSHA256": hashes["source-inputs.json"], "architectures": ["amd64"], "authenticode": "unsigned", "distributionStatus": "source-candidate-not-released", "nativeExecution": False, "repeatBuildIdentical": True}.items():
        require(manifest[key] == value and type(manifest[key]) is type(value))
    require(type(manifest["goVersion"]) is str and re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", manifest["goVersion"]))
    assets = PUBLIC_FILES - {"build-manifest.json", "SHA256SUMS"}
    require(type(manifest["assets"]) is dict and set(manifest["assets"]) == assets)
    for name in assets:
        require(manifest["assets"][name] == {"size": len(files[name]), "sha256": hashes[name]})
        require(type(manifest["assets"][name].get("size")) is int)
    package = shared.strict_json(files["setup-package-amd64.json"], 2048)
    require(package == {"schemaVersion": "tracebolt.windows-setup-package.v1", "version": VERSION, "sourceCommit": source, "architecture": "amd64", "sha256": hashes[SERVICE_NAME]} and files["setup-package-amd64.json"] == canonical(package))
    inputs = shared.strict_json(files["source-inputs.json"], 4 << 20)
    require(type(inputs) is dict and set(inputs) == {"schemaVersion", "files"} and inputs["schemaVersion"] == "tracebolt.windows-setup-source-inputs.v1" and type(inputs["files"]) is list and 1 <= len(inputs["files"]) <= 4096 and files["source-inputs.json"] == canonical(inputs))
    paths = []
    for item in inputs["files"]:
        require(type(item) is dict and set(item) == {"path", "size", "sha256"})
        path = item["path"]
        require(type(path) is str and 0 < len(path) <= 512 and "\\" not in path and all(p not in ("", ".", "..") for p in path.split("/")) and (path in {"go.mod", "go.sum"} or path.startswith(("cmd/", "internal/", "deploy/windows-setup/"))))
        require(type(item["size"]) is int and 0 <= item["size"] <= 128 << 20 and type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
        paths.append(path)
    require(len(paths) == len(set(paths)) == len({path.casefold() for path in paths}))
    require(sum(item["size"] for item in inputs["files"]) <= 128 << 20)
    require(type(manifest["peChecks"]) is dict and set(manifest["peChecks"]) == {SETUP_NAME, SERVICE_NAME})
    for name, setup in ((SETUP_NAME, True), (SERVICE_NAME, False)):
        actual = resources.verify_pe(files[name], VERSION, source, "amd64", setup=setup)
        actual["repeatBuildIdentical"] = True
        if not setup:
            actual["runtimeManifestValidated"] = True
        require(manifest["peChecks"][name] == actual)
    require(files[SERVICE_NAME] in files[SETUP_NAME] and files["setup-package-amd64.json"] in files[SETUP_NAME])
    sums = "".join(hashes[name] + "  " + name + "\n" for name in sorted(PUBLIC_FILES - {"SHA256SUMS"})).encode("ascii")
    require(files["SHA256SUMS"] == sums)
    if report is not None:
        require(report["status"] == "passed_packaged_gui_subset" and report["source"] == source)
        require(report["setupSHA256"] == hashes[SETUP_NAME] and report["serviceSHA256"] == hashes[SERVICE_NAME] and report["sourceInputsSHA256"] == hashes["source-inputs.json"])
    return hashes

def preserve_public_package(files, destination, source, report):
    validate_public_package(files, source, report)
    require(not destination.exists() and destination.parent.is_dir())
    destination.mkdir(mode=0o700)
    for name in sorted(PUBLIC_FILES):
        with (destination / name).open("xb") as stream:
            stream.write(files[name])
    copied = read_public_package(destination)
    require(copied == files)
    validate_public_package(copied, source, report)

def _validated_report_contents(reports, source, run_id):
    # Content checks alone establish neither case isolation nor acceptance.
    require(type(reports) is dict and set(reports) == set(CHECKS))
    accepted = {case: validate_report(raw, source, case) for case, raw in reports.items()}
    require(all(raw == canonical(accepted[case]) for case, raw in reports.items()))
    require(all(r["status"] == "passed_packaged_gui_subset" and r["runID"] == run_id for r in accepted.values()))
    for key in ("setupSHA256", "serviceSHA256", "driverSHA256", "sourceInputsSHA256", "sourceTree"):
        require(len({r[key] for r in accepted.values()}) == 1)
    return accepted

def _validated_reports(reports, source, run_id, execution_provenance=None, public_files=None):
    accepted = _validated_report_contents(reports, source, run_id)
    # MachineGuid and hostname may be cloned in a hosted Windows image. Keep
    # their original report values as descriptive evidence, not VM attestation.
    # Acceptance instead requires exact-source successful native reports (whose
    # controller first checks absent service/app directories) AND authenticated
    # distinct job/runner registrations bound to each original artifact's bytes.
    # The fresh-VM claim remains GitHub's standard Windows job-isolation contract;
    # neither self-reported IDs, random nonces nor a report-only check substitutes.
    try:
        provenance.validate_provenance(execution_provenance, source, run_id, reports, public_files)
    except Exception:
        raise shared.Rejected() from None
    return accepted

def aggregate_reports(reports, source, run_id, execution_provenance=None, public_files=None):
    return _validated_reports(reports, source, run_id, execution_provenance, public_files)

def run_aggregate(env, root=ROOT):
    source = authorize_aggregate(env)
    require_native_profile()  # Historical reports cannot satisfy the current schema.
    # The ephemeral API credential is confined to in-process provenance reads.
    child_env = {k: v for k, v in env.items() if k not in {provenance.TOKEN_ENV, "GITHUB_TOKEN", "GH_TOKEN"}}
    shared.verify_checkout(shared.child_environment(child_env), source, root)
    temp = Path(env.get("RUNNER_TEMP", ""))
    require(temp.is_absolute() and temp.is_dir())
    downloads = temp / "tracebolt-current-setup-reports"
    names = {case: "windows-current-setup-gui-" + case + "-" + source for case in CHECKS}
    exact_directory(downloads, names.values())
    raw_reports = {}
    for case, name in names.items():
        exact_directory(downloads / name, {REPORT_NAME})
        raw_reports[case] = regular_file(downloads / name / REPORT_NAME, 32 << 10)
    reports = _validated_report_contents(raw_reports, source, env["GITHUB_RUN_ID"])
    code, raw_tree = shared.command(["git", "rev-parse", "HEAD^{tree}"], shared.child_environment(child_env), root, 10, 128)
    tree = raw_tree.decode("ascii").strip()
    require(code == 0 and shared.valid_source(tree) and all(r["sourceTree"] == tree for r in reports.values()))
    package = read_public_package(temp / "tracebolt-current-setup-package-input")
    hashes = validate_public_package(package, source, reports["install-uninstall"])
    execution = provenance.verify_current_run(env, source, raw_reports, package)
    aggregate_reports(raw_reports, source, env["GITHUB_RUN_ID"], execution, package)
    preserve_public_package(package, temp / ACCEPTED_DIRECTORY, source, reports["install-uninstall"])
    evidence = {"schema": "tracebolt.windows-current-setup-native-subset.v1", "source": source, "runID": env["GITHUB_RUN_ID"], "status": "three_case_current_packaged_gui_subset", "distributionStatus": "unsigned-current-source-candidate-native-subset", "crossOSRebuildEquivalence": False, "coverage": dict.fromkeys(sorted(FALSE_COVERAGE), False), "reports": reports, "publicFilesSHA256": hashes, "executionProvenance": execution}
    with (temp / AGGREGATE_REPORT).open("xb") as stream:
        stream.write(canonical(evidence))
    require(env.get("GITHUB_OUTPUT", "") != "")
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as stream:
        stream.write("accepted_package_validated=true\n")
    return evidence

def run_native(env, root=ROOT):
    with pre_native_step("authorization"):
        source = authorize(env)  # Before staging/build/processes/native actions.
    with pre_native_step("native-profile"):
        require_native_profile()
    with pre_native_step("checkout"):
        child = shared.child_environment(env)
        shared.verify_checkout(child, source, root)
        code, raw_tree = shared.command(["git", "rev-parse", "HEAD^{tree}"], child, root, 10, 128)
        tree = raw_tree.decode("ascii").strip()
        require(code == 0 and shared.valid_source(tree))
    with pre_native_step("toolchain"):
        shared.verify_go(child, root)
    with pre_native_step("dependencies"):
        shared.successful(["go", "mod", "verify"], child, root, 180)
    with pre_native_step("staging"):
        temp = Path(env.get("RUNNER_TEMP", ""))
        require(temp.is_absolute() and temp.is_dir() and not (temp / REPORT_NAME).exists())
        # Retain the exact built artifacts and all app/private state for VM disposal.
        stage = Path(tempfile.mkdtemp(prefix="tracebolt-current-setup-gui-", dir=temp))
        package = stage / "package"
    with pre_native_step("package-build"):
        shared.successful([sys.executable, "-I", "-B", "deploy/windows-setup/build-setup.py", "--version", VERSION, "--source-commit", source, "--output", str(package), "--arch", "amd64"], child, root, 600)
    with pre_native_step("package-validation"):
        original_public = read_public_package(package)
        validate_public_package(original_public, source)
    with pre_native_step("driver-build"):
        setup = package / SETUP_NAME
        service = package / SERVICE_NAME
        driver = stage / "setup-gui.test.exe"
        shared.successful(["go", "test", "-c", "-mod=readonly", "-buildvcs=false", "-trimpath", "-tags", "tracebolt_setup_native", "-ldflags", "-X localrmm/cmd/windows-service.currentSetupCompiledSource=" + source + " -X localrmm/cmd/windows-service.currentSetupCompiledTree=" + tree, "-o", str(driver), "./cmd/windows-service"], child, root, 300)
    with pre_native_step("source-recheck"):
        shared.verify_checkout(child, source, root)
    with pre_native_step("run-binding"):
        machine_hash, build, revision = native_machine()
        bound = dict(env, TRACEBOLT_SETUP_TREE=tree, TRACEBOLT_SETUP_MACHINE_ID_SHA256=machine_hash)
        native_env = bind_run(bound, source, driver, setup, service, socket.gethostname(), int(time.time()) + 14 * 60)
    code, raw = shared.command([str(driver), "-test.run=^TestCurrentPackagedSetupGUINative$", "-test.count=1", "-test.timeout=15m"], native_env, root, 15 * 60, 32 << 10)
    report = parse_controller(raw, source, env["TRACEBOLT_SETUP_CASE"])
    for key, name in (("setupSHA256", "SETUP"), ("serviceSHA256", "SERVICE"), ("driverSHA256", "DRIVER"), ("sourceInputsSHA256", "SOURCE_INPUTS")):
        require(report[key] == native_env["TRACEBOLT_SETUP_" + name + "_SHA256"])
    require(report["runID"] == env["GITHUB_RUN_ID"] and report["machine"] == native_env["TRACEBOLT_SETUP_MACHINE"])
    require(report["sourceTree"] == tree and report["machineIDSHA256"] == machine_hash and report["osBuild"] == build and report["osRevision"] == revision)
    require(report["status"] != "passed_packaged_gui_subset" or code == 0)
    preserve = report["status"] == "passed_packaged_gui_subset" and report["case"] == "install-uninstall"
    if report["status"] == "passed_packaged_gui_subset":
        current_public = read_public_package(package)
        require(current_public == original_public)
        validate_public_package(current_public, source, report)
    if preserve:
        preserve_public_package(original_public, temp / PUBLIC_DIRECTORY, source, report)
    sanitized = canonical(report)
    validate_report(sanitized, source, env["TRACEBOLT_SETUP_CASE"])
    with (temp / REPORT_NAME).open("xb") as f:
        f.write(sanitized)
    require(env.get("GITHUB_OUTPUT", "") != "")
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as f:
        f.write("report_validated=true\n")
        if preserve:
            f.write("public_package_validated=true\n")
    return report

def main(argv=None, env=None):
    args = sys.argv[1:] if argv is None else argv
    values = dict(os.environ if env is None else env)
    try:
        require(args in (["--check-authorization"], ["--run-native"], ["--aggregate"]))
        if args == ["--check-authorization"]:
            source = authorize(values)
            shared.verify_checkout(shared.child_environment(values), source, ROOT)
            print("PASS: distinct current21 TLS-only approval syntax and exact clean source verified; no native work performed.")
            return 0
        if args == ["--aggregate"]:
            run_aggregate(values)
            print("PASS: three current same-run cases match exact tested public package bytes; unsigned source-candidate native subset only.")
            return 0
        r = run_native(values)
        print("Packaged Setup GUI subset: " + r["status"] + "; stage=" + r["stage"] + "; reason=" + r["reason"] + "; retained app/state requires platform VM disposal, unverified.")
        return 0 if r["status"] == "passed_packaged_gui_subset" else 1
    except PreNativeFailure as error:
        # Recheck the finite label at the output boundary; never stringify errors.
        stage = error.stage if type(error.stage) is str and error.stage in PRE_NATIVE_STAGES else "unknown"
        print("FAIL: packaged Setup gate; stage=" + stage + "; reason=pre_native_failed; private output withheld; inspect assigned VM/disposal status.")
        return 1
    except Exception:
        print("FAIL: packaged Setup gate or evidence rejected; private output withheld; inspect assigned VM/disposal status.")
        return 1
def native_machine():
    require(os.name == "nt")
    import ctypes
    import winreg
    class Version(ctypes.Structure):
        _fields_ = [("size", ctypes.c_ulong), ("major", ctypes.c_ulong), ("minor", ctypes.c_ulong), ("build", ctypes.c_ulong), ("platform", ctypes.c_ulong), ("csd", ctypes.c_wchar * 128), ("spmajor", ctypes.c_ushort), ("spminor", ctypes.c_ushort), ("suite", ctypes.c_ushort), ("product", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte)]
    value=Version(); value.size=ctypes.sizeof(value)
    fn=ctypes.WinDLL("ntdll").RtlGetVersion; fn.argtypes=[ctypes.POINTER(Version)]; fn.restype=ctypes.c_long
    require(fn(ctypes.byref(value)) == 0 and value.major == 10 and value.minor == 0 and value.build == 26100 and value.product == 3)
    access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Cryptography",0,access) as key:
        machine, kind=winreg.QueryValueEx(key,"MachineGuid")
    require(kind == winreg.REG_SZ and type(machine) is str and re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",machine))
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",0,access) as key:
        revision,kind=winreg.QueryValueEx(key,"UBR")
    require(kind == winreg.REG_DWORD and type(revision) is int and 0 < revision <= 2**32-1)
    return digest(("Tracebolt current hosted machine v1\n"+machine.lower()).encode("ascii")),value.build,revision

def validate_receipt_proof(value):
    keys={"verified","receiptSHA256","consentSHA256","senderBinding","manifestSHA256","credentialGeneration","grantDigests"}
    require(type(value) is dict and set(value)==keys and type(value["verified"]) is bool)
    if not value["verified"]:
        require(value == {"verified":False,"receiptSHA256":"","consentSHA256":"","senderBinding":"","manifestSHA256":"","credentialGeneration":0,"grantDigests":None})
        return
    require(all(type(value[k]) is str and re.fullmatch(r"[0-9a-f]{64}",value[k]) for k in ("receiptSHA256","consentSHA256","senderBinding","manifestSHA256")))
    require(type(value["credentialGeneration"]) is int and value["credentialGeneration"]==1)
    require(type(value["grantDigests"]) is list and len(value["grantDigests"])==20)
    for row,scope in zip(value["grantDigests"],current_frames.SCOPES[1:]):
        require(type(row) is dict and set(row)=={"scope","sha256"} and row["scope"]==scope and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",row["sha256"]))
    consent={"schemaVersion":"tracebolt.windows-capability-consent.v14","collectionProfile":"windows-inventory-v1","scopes":list(current_frames.SCOPES),"acknowledged":True,"insecureHTTPAcknowledged":False}
    require(value["consentSHA256"]==digest(json.dumps(consent,separators=(",",":"),ensure_ascii=False).encode("utf-8")))
    require(value["grantDigests"][6]["sha256"]==value["grantDigests"][18]["sha256"])

if __name__ == "__main__":
    raise SystemExit(main())
