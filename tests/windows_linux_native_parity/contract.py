"""Pure, fail-closed contract for the manually operated production-path gate.

Importing this module never starts a process, reads a host identity or opens a
network connection. A plan/approval reference is binding metadata, NOT evidence
that an authorized person granted permission. Obtain action-time approval first.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import time
from urllib.parse import urlsplit

SCHEMA = "tracebolt.windows-linux-native-parity.v1"
CURRENT_SCHEMA = "tracebolt.windows-linux-native-parity.v2"
CURRENT_PROFILE = {"schema": "tracebolt.windows-native-current-profile.v1", "setupContract": "fresh-twenty-one-read-admin-scopes-v1", "consentVersion": "tracebolt.windows-capability-consent.v14", "receiptVersion": 12, "renewal": True}
CURRENT_PHASES = ("manager-browser", "setup", "event-fixture", "own-restart", "remove")
PHASES = ("manager-browser", "setup", "event-fixture", "event-enable", "updates-enable", "event-disable", "updates-disable")
REASONS = frozenset(("contract_rejected", "target_mismatch", "artifact_mismatch", "source_mismatch", "private_path_rejected", "phase_replay", "deadline", "clock_changed", "secure_handoff_required", "native_operation_failed", "native_observation_unavailable", "manager_exited", "browser_incomplete", "cleanup_unverified", "read_admin_native_gate_unavailable", "complete"))
CHECKS = frozenset(("native_actions_attempted", "endpoint_binding", "fresh_host", "setup_launched", "installed_hash", "scm_running", "scm_stopped", "grant_enabled", "grant_disabled", "grant_independence", "synthetic_event_written", "real_manager_started", "real_browser_finished", "browser_cleanup", "manager_cleanup", "current_receipt", "current_grants", "current_credential", "same_identity", "own_restart", "receipt_owned_removal", "scm_absent", "retained_state_preserved", "browser_evidence_verified"))
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")

class Rejected(Exception):
    def __init__(self, reason="contract_rejected"):
        self.reason = reason if reason in REASONS else "contract_rejected"
        super().__init__(self.reason)

def need(ok, reason="contract_rejected"):
    if not ok:
        raise Rejected(reason)

def exact(obj, keys):
    need(type(obj) is dict and set(obj) == set(keys))

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def strict_json(raw, limit=1 << 20):
    need(type(raw) is bytes and 0 < len(raw) <= limit)
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out)
            out[k] = v
        return out
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected()))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected() from None

def sha(value, length=64):
    need(type(value) is str and (HEX64 if length == 64 else HEX40).fullmatch(value) is not None)
    need(len(set(value)) > 1)  # obvious placeholders cannot authorize a run

def ident(value):
    need(type(value) is str and IDENT.fullmatch(value) is not None)

def absolute(value, role):
    need(type(value) is str and 1 <= len(value) <= 1024 and not any(c in value for c in '\x00\r\n'))
    cls = PureWindowsPath if role == "windows" else PurePosixPath
    p = cls(value)
    need(p.is_absolute() and ".." not in p.parts and "." not in p.parts)
    if role == "windows":
        need(not value.startswith("\\\\") and re.fullmatch(r"[A-Z]:", p.drive) is not None and str(p) == value and "/" not in value and len(value) <= 240)
        for component in p.parts[1:]:
            need(re.fullmatch(r"[A-Za-z0-9_. -]{1,100}", component) is not None and component not in {".", ".."} and not component.startswith(" ") and not component.endswith((" ", ".")))
            base = component.split(".")[0].upper()
            need(base not in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"} and re.fullmatch(r"(COM|LPT)[0-9]", base) is None)
    else:
        need(str(p) == value)

def origin(value):
    need(type(value) is str and len(value) <= 256)
    try:
        u = urlsplit(value)
        need(u.scheme == "https" and u.hostname and u.path == "" and not u.query and not u.fragment and not u.username and not u.password)
        need(u.port is not None and 1024 <= u.port <= 65535)
        need(u.hostname not in {"localhost", "127.0.0.1", "::1"} and not u.hostname.endswith((".invalid", ".example")))
    except ValueError:
        raise Rejected() from None

def synthetic_message(run_id):
    ident(run_id)
    return "Tracebolt native parity synthetic Application event " + run_id

def is_current(p):
    return type(p) is dict and p.get("schema") == CURRENT_SCHEMA

def phases(p):
    return CURRENT_PHASES if is_current(p) else PHASES

def validate_current_profile(value):
    exact(value, CURRENT_PROFILE)
    need(value == CURRENT_PROFILE and type(value["receiptVersion"]) is int and type(value["renewal"]) is bool)
    return value

def validate_plan(p, now=None):
    current = is_current(p)
    keys = ("schema", "runId", "source", "notBeforeUnix", "expiresUnix", "targets", "tls", "artifacts", "phases", "syntheticEvent")
    exact(p, keys + (("currentProfile", "historyQuery") if current else ()))
    need(p["schema"] in {SCHEMA, CURRENT_SCHEMA})
    if current:
        validate_current_profile(p["currentProfile"])
    need(type(p["runId"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", p["runId"]) is not None)
    exact(p["source"], ("commit", "tree", "inventorySHA256"))
    sha(p["source"]["commit"], 40); sha(p["source"]["tree"], 40); sha(p["source"]["inventorySHA256"])
    need(type(p["notBeforeUnix"]) is int and type(p["expiresUnix"]) is int)
    need(60 <= p["expiresUnix"] - p["notBeforeUnix"] <= 7200)
    if now is not None:
        need(p["notBeforeUnix"] <= now < p["expiresUnix"], "deadline")
    exact(p["targets"], ("windows", "linux"))
    for role in ("windows", "linux"):
        t = p["targets"][role]
        keys = ("id", "machineIdSHA256", "workspace", "sourceRoot", "sourceInventory", "sourceCommitObject", "osBuild")
        if role == "windows":
            keys += ("publicBootstrap",)
            if current: keys += ("platform",)
        if role == "linux":
            keys += ("lanConfig", "enrollmentConfig", "webRoot", "webInventory", "browserRoot", "browserInventory")
        exact(t, keys)
        ident(t["id"]); sha(t["machineIdSHA256"])
        need(type(t["osBuild"]) is str and re.fullmatch(r"[0-9A-Za-z._-]{1,64}", t["osBuild"]) is not None)
        if role == "windows" and current:
            need(t["platform"] in {"windows-11-x64", "windows-server-2025-x64"})
            need(t["osBuild"].isdigit() and (int(t["osBuild"]) >= 22000 if t["platform"] == "windows-11-x64" else t["osBuild"] == "26100"))
        for key in set(keys) - {"id", "machineIdSHA256", "osBuild", "platform"}:
            absolute(t[key], role)
    need(p["targets"]["windows"]["id"] != p["targets"]["linux"]["id"])
    need(p["targets"]["windows"]["machineIdSHA256"] != p["targets"]["linux"]["machineIdSHA256"])
    exact(p["tls"], ("operatorOrigin", "agentOrigin", "custodian", "privateNetworkApprovalRef", "serverCertificateSHA256", "managerInstanceId", "issuerFingerprint", "bootstrapServerCASHA256", "bootstrapIssuerRootSHA256"))
    origin(p["tls"]["operatorOrigin"]); origin(p["tls"]["agentOrigin"])
    need(p["tls"]["operatorOrigin"] != p["tls"]["agentOrigin"])
    need(re.fullmatch(r"manager_[a-f0-9]{32}", p["tls"]["managerInstanceId"]) is not None)
    for key in ("issuerFingerprint", "bootstrapServerCASHA256", "bootstrapIssuerRootSHA256"):
        sha(p["tls"][key])
    need(PureWindowsPath(p["targets"]["windows"]["publicBootstrap"]).parent == PureWindowsPath(p["targets"]["windows"]["workspace"]))
    ident(p["tls"]["custodian"]); ident(p["tls"]["privateNetworkApprovalRef"]); sha(p["tls"]["serverCertificateSHA256"])
    exact(p["artifacts"], ("setup", "service", "setupManifest", "setupSourceInputs", "manager", "webInventory", "browserInventory", "node", "chromium"))
    for name, a in p["artifacts"].items():
        exact(a, ("path", "sha256"))
        sha(a["sha256"])
        absolute(a["path"], "windows" if name in {"setup", "service", "setupManifest", "setupSourceInputs"} else "linux")
    need(p["targets"]["linux"]["webInventory"] == p["artifacts"]["webInventory"]["path"])
    need(p["targets"]["linux"]["browserInventory"] == p["artifacts"]["browserInventory"]["path"])
    exact(p["phases"], phases(p))
    for phase, cfg in p["phases"].items():
        exact(cfg, ("approvalRef", "targetId")); ident(cfg["approvalRef"])
        need(cfg["targetId"] == p["targets"]["linux" if phase == "manager-browser" else "windows"]["id"])
    exact(p["syntheticEvent"], ("source", "eventId", "messageSHA256", "preparationApprovalRef", "messageResourcePath", "messageResourceSHA256"))
    e = p["syntheticEvent"]
    need(e["source"] == "TraceboltParity-" + p["runId"])
    need(type(e["eventId"]) is int and 1 <= e["eventId"] <= 1000)
    need(e["messageSHA256"] == digest(synthetic_message(p["runId"]).encode()))
    ident(e["preparationApprovalRef"])
    absolute(e["messageResourcePath"], "windows"); sha(e["messageResourceSHA256"])
    if current:
        # Exactly one bounded Application search and one selected-message request.
        # Approval references correlate an external human approval, never grant it.
        q = p["historyQuery"]
        exact(q, ("approvalRef", "messagesApprovalRef", "channel", "eventId", "startUnix", "endUnix", "maxRows", "maxMessages"))
        ident(q["approvalRef"]); ident(q["messagesApprovalRef"])
        need(q["approvalRef"] != q["messagesApprovalRef"])
        need(q["channel"] == "Application" and type(q["eventId"]) is int and q["eventId"] == e["eventId"])
        need(type(q["startUnix"]) is int and type(q["endUnix"]) is int and p["notBeforeUnix"] <= q["startUnix"] < q["endUnix"] < p["expiresUnix"] and q["startUnix"] % 60 == 0 and q["endUnix"] % 60 == 0)
        need(type(q["maxRows"]) is int and q["maxRows"] == 100 and type(q["maxMessages"]) is int and q["maxMessages"] == 1)
    return p

def no_links(path):
    p = Path(path)
    need(p.is_absolute(), "private_path_rejected")
    for x in (p, *p.parents):
        need(not x.is_symlink() and not (hasattr(x, "is_junction") and x.is_junction()), "private_path_rejected")
        if x.exists():
            need(not getattr(x.lstat(), "st_file_attributes", 0) & 0x400, "private_path_rejected")
    return p

def trusted_path(path, secret=False, trusted_sids=()):
    p = no_links(path)
    if os.name == "nt":
        from windows_native import require_safe_acl
        require_safe_acl(p, private=secret, trusted_sids=trusted_sids)
        for parent in p.parents:
            require_safe_acl(parent, ancestor=True, trusted_sids=trusted_sids)
    else:
        info = p.stat()
        need(info.st_uid in ({os.geteuid()} if secret else {0, os.geteuid()}), "private_path_rejected")
        need(not info.st_mode & (0o077 if secret else 0o022), "private_path_rejected")
        for parent in p.parents:
            info = parent.stat()
            need(info.st_uid in {0, os.geteuid()} and (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX), "private_path_rejected")
    return p

def read_regular(path, bound=1 << 20, trusted_sids=()):
    p = no_links(path)
    info = p.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= bound, "private_path_rejected")
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        opened = os.fstat(f.fileno())
        need((opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size), "private_path_rejected")
        raw = f.read(bound + 1)
        after = os.fstat(f.fileno())
        need((after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns), "private_path_rejected")
    need(len(raw) == info.st_size and len(raw) <= bound, "private_path_rejected")
    return raw

def verify_artifact(a, bound=512 << 20):
    trusted_path(a["path"])
    raw = read_regular(a["path"], bound)
    need(digest(raw) == a["sha256"], "artifact_mismatch")
    return raw

def verify_executable_header(a, bound=512 << 20):
    """Hash large direct executables incrementally; retain only the ELF header."""
    p = trusted_path(a["path"])
    before = p.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= bound, "artifact_mismatch")
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    h = hashlib.sha256(); header = b""; total = 0
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino, opened.st_size) == (before.st_dev, before.st_ino, before.st_size), "artifact_mismatch")
        while True:
            chunk = stream.read(1 << 20)
            if not chunk: break
            total += len(chunk); need(total <= bound, "artifact_mismatch")
            h.update(chunk)
            if not header: header = chunk[:64]
        after = os.fstat(stream.fileno())
        need((after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns), "artifact_mismatch")
    need(total == before.st_size and h.hexdigest() == a["sha256"], "artifact_mismatch")
    return header

def private_directory(path):
    p = no_links(path)
    need(p.is_dir(), "private_path_rejected")
    if os.name != "nt":
        need(p.stat().st_uid == os.geteuid() and stat.S_IMODE(p.stat().st_mode) == 0o700, "private_path_rejected")
        for parent in p.parents:
            s = parent.stat()
            need(s.st_uid in {0, os.geteuid()} and (not s.st_mode & 0o022 or s.st_uid == 0 and s.st_mode & stat.S_ISVTX), "private_path_rejected")
    else:
        # OS ACL verification lives in the Windows-only adapter; chmod is not an ACL.
        from windows_native import require_private_acl
        require_private_acl(p)
    return p

def local_input_path(path, windows=None):
    # Lexical guard runs before any stat/open: UNC must not initiate SMB and
    # Windows aliases/ADS must not select a different input than the displayed one.
    absolute(str(path), "windows" if (os.name == "nt" if windows is None else windows) else "linux")
    return path

def load_plan(path, expected_sha, now=None):
    local_input_path(path)
    sha(expected_sha)
    raw = read_regular(path, 32 << 10)
    need(digest(raw) == expected_sha)
    return validate_plan(strict_json(raw, 32 << 10), time.time() if now is None else now)

def git_object(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).digest()

def inventory_tree(rows):
    root = {}
    for r in rows:
        branch = root
        parts = r["path"].split("/")
        for part in parts[:-1]:
            need(part not in branch or type(branch[part]) is dict, "source_mismatch")
            branch = branch.setdefault(part, {})
        need(parts[-1] not in branch, "source_mismatch")
        branch[parts[-1]] = (r["mode"], bytes.fromhex(r["sha"]))
    def tree(node):
        data = b""
        for name in sorted(node, key=lambda n: (n + ("/" if type(node[n]) is dict else "")).encode()):
            value = node[name]
            mode, h = ("40000", tree(value)) if type(value) is dict else value
            data += mode.encode() + b" " + name.encode() + b"\0" + h
        return git_object("tree", data)
    return tree(root).hex()

def verify_commit(path, source):
    trusted_path(path)
    raw = read_regular(path, 2 << 20)
    need(git_object("commit", raw).hex() == source["commit"], "source_mismatch")
    need(raw.startswith(("tree " + source["tree"] + "\n").encode()) and b"\n\n" in raw, "source_mismatch")

def verify_inventory(root, inventory, expected_hash, expected_tree=None, dependencies=False, trusted=False):
    root = trusted_path(root) if trusted else no_links(root)
    if trusted: trusted_path(inventory)
    raw = read_regular(inventory, 8 << 20)
    need(digest(raw) == expected_hash, "source_mismatch")
    rows = strict_json(raw, 8 << 20)
    need(type(rows) is list and 1 <= len(rows) <= 20000, "source_mismatch")
    names, total = set(), 0
    for r in rows:
        exact(r, ("path", "sha", "sha256", "mode", "size"))
        rel = r["path"]
        need(type(rel) is str and 1 <= len(rel) <= 512 and "\\" not in rel and not rel.startswith("/") and all(x not in {"", ".", "..", ".git", "__pycache__"} for x in rel.split("/")), "source_mismatch")
        need(rel not in names and r["mode"] in {"100644", "100755"} and type(r["size"]) is int and 0 <= r["size"] <= 64 << 20, "source_mismatch")
        names.add(rel); total += r["size"]
        need(total <= 512 << 20, "source_mismatch")
        path = trusted_path(root / rel) if trusted else no_links(root / rel)
        s = path.stat(); need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size == r["size"], "source_mismatch")
        if os.name != "nt":
            need(bool(s.st_mode & 0o111) == (r["mode"] == "100755"), "source_mismatch")
        data = path.read_bytes()
        need(digest(data) == r["sha256"] and git_object("blob", data).hex() == r["sha"], "source_mismatch")
    actual = set()
    for parent, dirs, files in os.walk(root, followlinks=False):
        need("__pycache__" not in dirs, "source_mismatch")
        dirs[:] = [d for d in dirs if d != ".git"]
        for d in dirs:
            no_links(Path(parent) / d)
        for f in files:
            if f == ".git": continue
            need(not f.endswith((".pyc", ".pyo")), "source_mismatch")
            actual.add((Path(parent) / f).relative_to(root).as_posix())
    need(actual == names, "source_mismatch")
    if expected_tree:
        need(inventory_tree(rows) == expected_tree, "source_mismatch")
    return rows

def require_current_setup_gate(p=None):
    # Historical v1 cannot authorize expanded fresh Setup. Only the exact current
    # contract may proceed to ordinary native/action-time authorization checks.
    if not is_current(p):
        raise Rejected("read_admin_native_gate_unavailable")
    validate_plan(p)

def require_native_opt_in(args, role, p):
    need(__import__("sys").version_info >= (3, 12), "contract_rejected")
    need(__import__("sys").flags.isolated and __import__("sys").dont_write_bytecode, "contract_rejected")
    need(args.execute and args.target_id == p["targets"][role]["id"])
    need(args.phase in phases(p) and p["phases"][args.phase]["targetId"] == args.target_id)
    need(args.approval_reference == p["phases"][args.phase]["approvalRef"])
    browser_hash = getattr(args, "browser_report_sha256", None)
    if is_current(p) and args.phase == "remove":
        sha(browser_hash)
    else:
        need(browser_hash is None)
    need(not any(k in os.environ for k in ("CI", "GITHUB_ACTIONS", "TF_BUILD", "BUILD_BUILDID")))
    # The actual action-time authorization must be obtained OUTSIDE this harness.
    # Neither these flags nor this reference authenticate the approving person.
    need(__import__("sys").stdin.isatty(), "secure_handoff_required")
    require_current_setup_gate(p)  # Before native adapter import or host access.

REQUIRED_CHECKS = {
    "setup": {"native_actions_attempted", "fresh_host", "setup_launched", "installed_hash", "scm_running", "scm_stopped", "endpoint_binding"},
    "event-fixture": {"native_actions_attempted", "installed_hash", "scm_running", "synthetic_event_written"},
    "manager-browser": {"native_actions_attempted", "real_manager_started", "real_browser_finished", "browser_cleanup", "manager_cleanup"},
}
for _phase in ("event-enable", "updates-enable", "event-disable", "updates-disable"):
    REQUIRED_CHECKS[_phase] = {"native_actions_attempted", "installed_hash", "scm_running", "scm_stopped", "endpoint_binding", "grant_independence", "grant_enabled" if _phase.endswith("enable") else "grant_disabled"}

CURRENT_REQUIRED_CHECKS = {
    "setup": REQUIRED_CHECKS["setup"] | {"current_receipt", "current_grants", "current_credential"},
    "event-fixture": REQUIRED_CHECKS["event-fixture"] | {"endpoint_binding", "current_receipt", "current_grants", "current_credential"},
    "manager-browser": REQUIRED_CHECKS["manager-browser"],
    "own-restart": {"native_actions_attempted", "installed_hash", "scm_running", "scm_stopped", "endpoint_binding", "current_receipt", "current_grants", "current_credential", "same_identity", "own_restart"},
    "remove": {"native_actions_attempted", "installed_hash", "scm_running", "scm_stopped", "endpoint_binding", "current_receipt", "current_grants", "current_credential", "receipt_owned_removal", "scm_absent", "retained_state_preserved", "browser_evidence_verified"},
}

def required_checks(p, phase):
    need(phase in phases(p))
    return (CURRENT_REQUIRED_CHECKS if is_current(p) else REQUIRED_CHECKS)[phase]

_active_budget = None
class RunBudget:
    def __init__(self, expires):
        self.expires = expires; self.wall = time.time(); self.mono = time.monotonic()
        need(self.wall < expires, "deadline")
        self.end = self.mono + expires - self.wall
    def remaining(self):
        wall, mono = time.time(), time.monotonic()
        need(abs((wall - self.wall) - (mono - self.mono)) <= 1.5, "clock_changed")
        need(wall < self.expires and mono < self.end, "deadline")
        return min(self.expires - wall, self.end - mono)

def check_time(expires):
    if _active_budget is not None:
        need(_active_budget.expires == expires)
        return _active_budget.remaining()
    need(time.time() < expires, "deadline")
    return expires - time.time()

def report(p, plan_hash, phase, checks, status, reason, elapsed):
    need(phase in phases(p) and reason in REASONS and status in {"observed_phase", "blocked", "unknown"})
    need(type(checks) is dict and set(checks) <= CHECKS and all(type(v) is bool for v in checks.values()))
    need(type(elapsed) in {int, float} and 0 <= elapsed <= 7201)
    if status == "observed_phase":
        need(reason == "complete" and set(checks) == required_checks(p, phase) and all(checks.values()))
    else:
        need(reason != "complete")
    return {"schema": p["schema"] + ".evidence", "runId": p["runId"], "planSHA256": plan_hash, "source": p["source"], "phase": phase,
            "status": status, "reason": reason, "checks": checks, "elapsedSeconds": int(elapsed), "nativeExecution": checks.get("native_actions_attempted", False),
            "fullAcceptance": False, "manualStatementsAcceptedAsEvidence": False, "rawDataExported": False,
            "artifactSHA256": {k: a["sha256"] for k, a in p["artifacts"].items()}}

def validate_phase_report(r, p, plan_hash, phase):
    need(type(r) is dict)
    need(all(type(r.get(k)) is bool for k in ("nativeExecution", "fullAcceptance", "manualStatementsAcceptedAsEvidence", "rawDataExported")))
    need(type(r.get("elapsedSeconds")) is int)
    expected = report(p, plan_hash, phase, r.get("checks"), r.get("status"), r.get("reason"), r.get("elapsedSeconds"))
    need(r == expected and r["status"] == "observed_phase", "native_observation_unavailable")
    return r

def write_new(path, value):
    raw = canonical(value)
    need(len(raw) <= 32 << 10)
    path = no_links(Path(path))
    private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    if os.name == "nt":
        from windows_native import require_private_acl
        require_private_acl(path)

def begin_phase(p, role, phase, plan_hash):
    w = private_directory(p["targets"][role]["workspace"])
    marker = w / (p["runId"] + "-" + phase + ".started.json")
    try:
        write_new(marker, {"planSHA256": plan_hash, "phase": phase, "startedUnix": time.time(), "startedMonotonic": time.monotonic()})
    except FileExistsError:
        raise Rejected("phase_replay") from None
    return w
