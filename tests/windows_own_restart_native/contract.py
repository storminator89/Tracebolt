"""Independent own-restart contract. Importing this module performs no native work.
The low-level path and exact Git inventory checks are copied, without importing
or invoking the seven-phase parity harness. Plans are correlation, not permission.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
SCHEMA = "tracebolt.windows-own-restart-native.v1"
APP_COMMIT = "858d7846b4fa2f7b3cdaf672c067400d894369a4"
APP_TREE = "91999db7fcf6687795ba052b0029e670c01b01c7"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
OMISSIONS = ["graceful_worker_or_descendant_drain", "native_fault_or_cancellation_timing", "pending_body_signature_retry_retention", "memory_only_result_retention", "durable_local_consume_once_floors", "original_expiry_under_inflight_request", "bitwise_private_state_retention", "privileged_external_races", "other_service_actions", "repair_upgrade_reset_reenrollment", "reboot_or_os_persistence", "dashboard_rendering", "full_windows_parity"]
REASONS = {"contract_rejected", "target_mismatch", "artifact_mismatch", "source_mismatch", "private_path_rejected", "phase_replay", "deadline", "clock_changed", "secure_handoff_required", "native_observation_unavailable", "manager_changed", "browser_incomplete", "unknown_intervention_required", "complete"}
class Rejected(Exception):
    def __init__(self, reason="contract_rejected"):
        self.reason = reason if reason in REASONS else "contract_rejected"
        super().__init__(self.reason)
def need(ok, reason="contract_rejected"):
    if not ok: raise Rejected(reason)
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


SOURCE_NAMES = ('harness', 'application', 'manager', 'dashboard')
PUBLIC_NAMES = ('bootstrap', 'config', 'ready', 'certificate')
GRANT_NAMES = ('events', 'volumes', 'processMetrics', 'network', 'serviceStartup', 'updates')

def source(value):
    exact(value, ('commit', 'tree', 'inventorySHA256'))
    sha(value['commit'], 40); sha(value['tree'], 40); sha(value['inventorySHA256'])

def validate_plan(p, now=None):
    exact(p, ('schema', 'runId', 'notBeforeUnix', 'expiresUnix', 'targetService', 'sources', 'targets', 'artifacts', 'tls', 'selected', 'managerProcess', 'approvals', 'handoff'))
    need(p['schema'] == SCHEMA and p['targetService'] == 'TraceboltWindowsAgent')
    ident(p['runId']); need(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}', p['runId']) is not None and not p['runId'].startswith('REPLACE'))
    need(type(p['notBeforeUnix']) is int and type(p['expiresUnix']) is int and 240 <= p['expiresUnix'] - p['notBeforeUnix'] <= 3600)
    if now is not None: need(p['notBeforeUnix'] <= now < p['expiresUnix'], 'deadline')
    exact(p['sources'], SOURCE_NAMES)
    for value in p['sources'].values(): source(value)
    need(p['sources']['application']['commit'] == APP_COMMIT and p['sources']['application']['tree'] == APP_TREE, 'source_mismatch')
    exact(p['targets'], ('windows', 'linux'))
    for role, t in p['targets'].items():
        keys = ['id', 'machineIdSHA256', 'osBuild', 'workspace', 'sourcePaths']
        if role == 'linux': keys += ['lanConfig', 'enrollmentConfig', 'webRoot', 'browserRoot']
        exact(t, keys); ident(t['id']); sha(t['machineIdSHA256']); ident(t['osBuild'])
        for key in set(keys) - {'id','machineIdSHA256','osBuild','sourcePaths'}: absolute(t[key], role)
        expected = ('harness','application') if role == 'windows' else SOURCE_NAMES
        exact(t['sourcePaths'], expected)
        for s in t['sourcePaths'].values():
            exact(s, ('root','inventory','commitObject'))
            for v in s.values(): absolute(v, role)
    need(p['targets']['windows']['id'] != p['targets']['linux']['id'])
    need(p['targets']['windows']['machineIdSHA256'] != p['targets']['linux']['machineIdSHA256'])
    exact(p['artifacts'], ('controller','service','manager','node','chromium','webInventory','browserInventory'))
    for name, a in p['artifacts'].items():
        exact(a, ('path','sha256')); absolute(a['path'], 'windows' if name in {'controller','service'} else 'linux'); sha(a['sha256'])
    exact(p['tls'], ('operatorOrigin','agentOrigin','managerInstanceId','issuerFingerprint','serverCertificateSHA256','bootstrapServerCASHA256','bootstrapIssuerRootSHA256','custodian','networkApprovalRef'))
    for k in ('operatorOrigin','agentOrigin'): origin(p['tls'][k])
    need(p['tls']['operatorOrigin'] != p['tls']['agentOrigin'])
    need(re.fullmatch(r'manager_[a-f0-9]{32}', p['tls']['managerInstanceId']) is not None)
    for k in ('issuerFingerprint','serverCertificateSHA256','bootstrapServerCASHA256','bootstrapIssuerRootSHA256'): sha(p['tls'][k])
    ident(p['tls']['custodian']); ident(p['tls']['networkApprovalRef'])
    s = p['selected']; exact(s, ('deviceId','certificateSHA256','invitationIdSHA256','receiptSHA256','intentSHA256','publicSHA256','grantIds'))
    need(re.fullmatch(r'agent_[a-f0-9]{32}', s['deviceId']) is not None)
    for k in ('certificateSHA256','invitationIdSHA256','receiptSHA256','intentSHA256'): sha(s[k])
    exact(s['publicSHA256'], PUBLIC_NAMES)
    for v in s['publicSHA256'].values(): sha(v)
    need(type(s['grantIds']) is dict and {'events','volumes','processMetrics','network'} <= set(s['grantIds']) <= set(GRANT_NAMES))
    for v in s['grantIds'].values(): need(type(v) is str and re.fullmatch(r'[a-f0-9]{32}', v) is not None and len(set(v)) > 1)
    need(len(set(s['grantIds'].values())) == len(s['grantIds']))
    m = p['managerProcess']; exact(m, ('pid','startTicks','uid','executableSHA256','lanConfigSHA256','enrollmentConfigSHA256'))
    need(type(m['pid']) is int and 1 <= m['pid'] <= 2**31-1 and type(m['uid']) is int and 1 <= m['uid'] <= 2**32-2)
    decimal(m['startTicks']); need(int(m['startTicks']) > 0)
    for k in ('executableSHA256','lanConfigSHA256','enrollmentConfigSHA256'): sha(m[k])
    need(m['executableSHA256'] == p['artifacts']['manager']['sha256'])
    exact(p['approvals'], ('ownRestartTwoInvocations','linuxBrowserReadOnly','publicBoundaryTransfers'))
    for v in p['approvals'].values(): need(type(v) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{7,63}',v) is not None and not v.startswith('REPLACE'))
    need(len(set(p['approvals'].values())) == 3)
    exact(p['handoff'], ('windowsBaseline','linuxCompletion'))
    for key, role, suffix in [('windowsBaseline','windows','baseline'),('linuxCompletion','linux','completion')]:
        absolute(p['handoff'][key], role)
        cls = PureWindowsPath if role == 'windows' else PurePosixPath
        need(cls(p['handoff'][key]) == cls(p['targets'][role]['workspace']) / (p['runId'] + '-' + suffix + '.json'))
    return p

def decimal(value):
    need(type(value) is str and re.fullmatch(r'(0|[1-9][0-9]{0,19})', value) is not None)
    return int(value)

def nanos(value):
    """Lossless strict UTC RFC3339 through 9 fractional digits, never float."""
    need(type(value) is str)
    m = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z', value)
    need(m is not None)
    try: d = datetime.strptime(m[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    except ValueError: raise Rejected() from None
    delta = d - datetime(1970,1,1,tzinfo=timezone.utc)
    seconds = delta.days*86400 + delta.seconds
    need(seconds > 0)
    return seconds*10**9 + int((m[2] or '').ljust(9,'0'))

def filetime_nanos(value):
    ticks = decimal(value); need(ticks > 116444736000000000)
    return (ticks - 116444736000000000)*100

def binding_hash(p):
    return digest(canonical({'selected':p['selected'], 'windowsTarget':p['targets']['windows']['id'], 'windowsMachineIdSHA256':p['targets']['windows']['machineIdSHA256'], 'serviceSHA256':p['artifacts']['service']['sha256'], 'tls':p['tls']}))

def load_plan(path, expected, now=None):
    local_input_path(path); sha(expected)
    trusted_path(path); raw = read_regular(path, 32768)
    need(digest(raw) == expected)
    return validate_plan(strict_json(raw, 32768), time.time() if now is None else now)

class RunBudget:
    def __init__(self, expires):
        self.expires = expires; self.wall = time.time_ns(); self.mono = time.monotonic_ns()
        self.end = self.mono + expires*10**9 - self.wall
    def check(self):
        now, mono = time.time_ns(), time.monotonic_ns()
        need(abs((now-self.wall)-(mono-self.mono)) <= 1500000000, 'clock_changed')
        need(now < self.expires*10**9 and mono < self.end, 'deadline')

def write_new(path, value):
    raw = canonical(value); need(len(raw) <= 65536)
    path = no_links(Path(path)); private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
    if os.name == 'nt':
        from windows_native import require_private_acl
        require_private_acl(path)

def verify_sources(p, role):
    for name, s in p['targets'][role]['sourcePaths'].items():
        verify_commit(s['commitObject'], p['sources'][name])
        verify_inventory(s['root'], s['inventory'], p['sources'][name]['inventorySHA256'], p['sources'][name]['tree'], trusted=True)

NATIVE_KEYS = ('schema','runId','planSHA256','browserBaselineSHA256','status','phase','fullAcceptance','installerContentionRefused','oldProcessExited','newRunningProcess','receiptPublicIdentityRetained','commandInvocations','oldExitCode','newProcessCreationFiletime','newProcessCreationUTC','oldProcessGenerationSHA256','newProcessGenerationSHA256','deviceId','certificateSHA256','installedSHA256','controllerSHA256','windowStartFiletime','windowEndFiletime')
NATIVE_CHECKS = ('installerContentionRefused','oldProcessExited','newRunningProcess','receiptPublicIdentityRetained')

def validate_native_report(r,p,plan_hash,baseline_hash):
    exact(r, NATIVE_KEYS)
    need(r['schema'] == 'tracebolt.windows-own-restart-controller-result.v1' and r['runId'] == p['runId'] and r['planSHA256'] == plan_hash and r['browserBaselineSHA256'] == baseline_hash)
    need(r['fullAcceptance'] is False and r['status'] in {'passed-native-subset','blocked','unknown-intervention-required'})
    need(r['phase'] in {'authorization','baseline','contention','lease-release','restart','old-process-exit','new-process','retention','complete'})
    for k in NATIVE_CHECKS: need(type(r[k]) is bool)
    need(type(r['commandInvocations']) is int and 0 <= r['commandInvocations'] <= 2)
    need(r['oldExitCode'] is None or type(r['oldExitCode']) is int and 0 <= r['oldExitCode'] < 2**32)
    for k in ('newProcessCreationFiletime','windowStartFiletime','windowEndFiletime'):
        need(type(r[k]) is str)
        if r[k]: filetime_nanos(r[k])
    if r['newProcessCreationUTC']: need(nanos(r['newProcessCreationUTC']) == filetime_nanos(r['newProcessCreationFiletime']))
    for k in ('oldProcessGenerationSHA256','newProcessGenerationSHA256'):
        need(type(r[k]) is str)
        if r[k]: sha(r[k])
    need(r['deviceId'] == p['selected']['deviceId'] and r['certificateSHA256'] == p['selected']['certificateSHA256'])
    need(r['installedSHA256'] == p['artifacts']['service']['sha256'] and r['controllerSHA256'] == p['artifacts']['controller']['sha256'])
    if r['status'] == 'passed-native-subset':
        need(r['phase'] == 'complete' and all(r[k] for k in NATIVE_CHECKS) and r['commandInvocations'] == 2 and r['oldExitCode'] == 0)
        need(r['oldProcessGenerationSHA256'] and r['newProcessGenerationSHA256'] and r['oldProcessGenerationSHA256'] != r['newProcessGenerationSHA256'])
        need(r['newProcessCreationUTC'] and decimal(r['windowStartFiletime']) <= decimal(r['newProcessCreationFiletime']) <= decimal(r['windowEndFiletime']))
    return r

SAMPLE_KEYS = ('sequence','generationId','collectedAt','receivedAt','serverNow','observedAt','grantIds')
def validate_sample(s,p):
    exact(s, SAMPLE_KEYS)
    need(type(s['sequence']) is int and 1 <= s['sequence'] <= 2**53-1)
    need(type(s['generationId']) is str and re.fullmatch(r'sample_[a-f0-9]{32}',s['generationId']) is not None)
    need(s['grantIds'] == p['selected']['grantIds'])
    capture, receipt, server, observed = [nanos(s[k]) for k in ('collectedAt','receivedAt','serverNow','observedAt')]
    need(0 <= server-capture <= 120*10**9 and 0 <= server-receipt <= 120*10**9)
    need(capture-receipt <= 30*10**9 and abs(server-observed) <= 30*10**9)
    need(observed-capture <= 150*10**9)
    return s

def validate_baseline(b,p,plan_hash):
    exact(b, ('schema','runId','planSHA256','sources','bindingSHA256','managerProcess','sample','fullAcceptance'))
    need(b['schema'] == SCHEMA+'.baseline' and b['runId'] == p['runId'] and b['planSHA256'] == plan_hash and b['sources'] == p['sources'] and b['bindingSHA256'] == binding_hash(p) and b['managerProcess'] == p['managerProcess'] and b['fullAcceptance'] is False)
    validate_sample(b['sample'],p)
    need(p['notBeforeUnix']*10**9 <= nanos(b['sample']['observedAt']) < p['expiresUnix']*10**9)
    return b

def advancing(a,b,creation):
    return b['sequence'] > a['sequence'] and b['generationId'] != a['generationId'] and nanos(b['collectedAt']) > max(nanos(a['collectedAt']),filetime_nanos(creation)+1_000_000_000) and nanos(b['receivedAt']) > nanos(a['receivedAt'])

def completion(p,plan_hash,baseline_hash,native):
    validate_native_report(native,p,plan_hash,baseline_hash)
    need(native['status'] == 'passed-native-subset', 'unknown_intervention_required')
    return {'schema':SCHEMA+'.completion','runId':p['runId'],'planSHA256':plan_hash,'sources':p['sources'],'bindingSHA256':binding_hash(p),'browserBaselineSHA256':baseline_hash,'native':native,'fullAcceptance':False,'omissions':OMISSIONS}

def validate_browser_result(r,p,plan_hash,baseline_hash):
    exact(r, ('schema','runId','planSHA256','sources','bindingSHA256','browserBaselineSHA256','completionSHA256','status','reason','nativeExecution','fullAcceptance','dashboardRendered','checks','samples','omissions'))
    need(r['schema'] == SCHEMA+'.browser-result' and r['runId'] == p['runId'] and r['planSHA256'] == plan_hash and r['sources'] == p['sources'] and r['bindingSHA256'] == binding_hash(p) and r['browserBaselineSHA256'] == baseline_hash)
    need(r['fullAcceptance'] is False and r['dashboardRendered'] is False and r['omissions'] == OMISSIONS)
    need(type(r['nativeExecution']) is bool and r['status'] in {'passed-subset','blocked','unknown'})
    exact(r['checks'],('retainedManager','realBrowser','sameActivatedIdentity','baselineObserved','nativeCompletionObserved','twoAdvancingSamples','browserClosed'))
    for v in r['checks'].values(): need(type(v) is bool)
    need(type(r['samples']) is list and len(r['samples']) <= 3)
    for s in r['samples']: validate_sample(s,p)
    if r['status'] == 'passed-subset':
        sha(r['completionSHA256']); need(r['reason'] == 'complete' and r['nativeExecution'] and all(r['checks'].values()) and len(r['samples']) == 3)
    else: need(r['reason'] != 'complete')
    return r


def confirm_windows(p, cancelled, read=input, output=print):
    """Local accidental-invocation guard, never proof of external authorization.
    Native run binds read/output to the actual terminal; no command-line bypass.
    """
    target=p['targets']['windows']['id']
    phrase='RESTART TraceboltWindowsAgent ON '+target+' WITH TWO CLI INVOCATIONS'
    output('Selected Windows target: '+target+' (machine SHA256 '+p['targets']['windows']['machineIdSHA256']+').')
    output('Two exact installed CLI invocations: --restart --apply. First must refuse under the held installer lease without effect. Second may restart only after verified refusal and clean lease release. Existing agent interruption and loss of memory-only event results are possible.')
    output('Separate external action-time approval is required. This phrase is only an accidental-invocation guard. Type exactly: '+phrase)
    need(not cancelled(),'unknown_intervention_required')
    try:answer=read()
    except (EOFError,KeyboardInterrupt):raise Rejected('secure_handoff_required') from None
    need(not cancelled() and answer==phrase,'secure_handoff_required')

CI_KEYS={'CI','CONTINUOUS_INTEGRATION','BUILD_BUILDID','TF_BUILD','TEAMCITY_VERSION','JENKINS_URL','HUDSON_URL'}
CI_PREFIXES=('GITHUB_','GITLAB_','CIRCLE_','BUILDKITE_','TRAVIS_','RUNNER_')
def reject_ci(environment):
    need(not any(k.upper() in CI_KEYS or k.upper().startswith(CI_PREFIXES) for k in environment))
