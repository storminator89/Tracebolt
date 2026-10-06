#!/usr/bin/env python3
"""Create-only, fixed-path action setup adapter. Importing this module is inert.

The guide owns the explicit approval ceremony. This adapter rechecks its exact
facts under the existing installer lock. Tests inject an in-memory Effects;
source/fixture checks never authorize or exercise host provisioning.
"""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
import types

AGENT = "tracebolt-agent.service"
SERVICE = "tracebolt-action-helper.service"
SOCKET = "tracebolt-action-helper.socket"
UNIT_DIR = "/etc/systemd/system"
CONFIG_DIR = "/etc/tracebolt"
INSTALLER_DIR = "/var/lib/tracebolt-agent-installer"
BINARY = "/opt/tracebolt-agent/lan-agent"
CONFIG = "/var/lib/tracebolt-agent/enrollment/agent.json"
POLICY = CONFIG_DIR + "/action-helper.json"
PUBLIC_KEY = CONFIG_DIR + "/action-command.pub"
CLIENT = CONFIG_DIR + "/action-client.json"
INTENT = INSTALLER_DIR + "/action-setup-intent.json"
STARTED = INSTALLER_DIR + "/action-ledger-started.json"
COMPLETE = INSTALLER_DIR + "/action-setup-complete.json"
LEDGER = "/var/lib/tracebolt-action-helper"
RUNTIME = "/run/tracebolt-action-helper"
SOCKET_PATH = RUNTIME + "/action.sock"
WANTS = UNIT_DIR + "/sockets.target.wants/" + SOCKET
CREATED_FILES = frozenset((POLICY, PUBLIC_KEY, CLIENT, INTENT, COMPLETE,
                          UNIT_DIR + "/" + SERVICE, UNIT_DIR + "/" + SOCKET))
ACTION_PATHS = tuple(sorted(CREATED_FILES | {STARTED, LEDGER, RUNTIME, WANTS,
    UNIT_DIR + "/" + SERVICE + ".d", UNIT_DIR + "/" + SOCKET + ".d"}))
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
       "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"}
CAPABILITIES = dict(schemaVersion="tracebolt.action-setup-capabilities.v1",
    identityVersion="tracebolt.action-setup-identity.v1",
    readinessVersion="tracebolt.action-setup-readiness.v1",
    targetVersion="tracebolt.action-setup-target.v1",
    helperPolicyVersion="tracebolt.action-helper-policy.v1",
    clientPolicyVersion="tracebolt.action-client-policy.v1",
    helperCapabilitiesVersion="tracebolt.action-capabilities.v1",
    intentVersion="tracebolt.action-setup-intent.v1",
    startedVersion="tracebolt.action-ledger-started.v1", action="service.try-restart")
BUNDLE_FIELDS = ("schemaVersion", "managerId", "managerOrigin", "endpointId",
    "incarnationDigest", "transportProfile", "httpTestAcknowledged", "commandPublicKey",
    "keyId", "bundleDigest")
IDENTITY_FIELDS = ("schemaVersion", "senderBinding", "managerOrigin", "endpointId",
    "incarnationDigest", "transportProfile", "agentUid", "agentGid")


class Rejected(Exception):
    """Only fixed safe failure stages escape; never raw command diagnostics."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def canonical(value):
    # Runtime policy structs require field order; bundle hashing sorts explicitly.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).replace(
        "<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 131072, "bounded-json")
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, "duplicate-json-member")
            out[k] = v
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Rejected("invalid-json")))
    except (ValueError, UnicodeError):
        raise Rejected("invalid-json") from None
    require(type(value) is dict, "json-object")
    return value


def valid_digest(value):
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def pin(st):
    return {k: getattr(st, "st_" + k) for k in
        ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")}


def directory_pin(st):
    return {k: getattr(st, "st_" + k) for k in ("dev", "ino", "uid", "gid", "mode")}


def safe_path(value):
    return (type(value) is str and value.startswith("/") and str(Path(value)) == value and
        ".." not in Path(value).parts and len(value) <= 1024 and
        not any(c.isspace() or ord(c) < 32 or ord(c) > 126 for c in value))


def unit_fields(name):
    require(name in (AGENT, SERVICE, SOCKET), "fixed-unit")
    fields = ("LoadState", "ActiveState", "FragmentPath", "DropInPaths", "Transient",
              "Names", "MainPID", "UnitFileState")
    return tuple(k for k in fields if name != SOCKET or k != "MainPID")


def owned_unit(state, name, active=None):
    return (set(state) == set(unit_fields(name)) and state["LoadState"] == "loaded" and
        state["FragmentPath"] == UNIT_DIR + "/" + name and state["DropInPaths"] == "" and
        state["Transient"] == "no" and state["Names"] == name and
        state["UnitFileState"] in ("enabled", "disabled", "static") and
        state["ActiveState"] in ((active,) if active else ("active", "inactive")) and
        (name == SOCKET or (re.fullmatch(r"[0-9]+", state["MainPID"]) is not None and
        (state["MainPID"] == "0") == (state["ActiveState"] == "inactive"))))


def absent_unit(state, name):
    return (set(state) == set(unit_fields(name)) and state["LoadState"] == "not-found" and
        state["ActiveState"] == "inactive" and state["FragmentPath"] == state["DropInPaths"] == "" and
        state["Transient"] == "no" and state["Names"] in ("", name) and
        state["UnitFileState"] in ("", "not-found") and (name == SOCKET or state["MainPID"] == "0"))


class Effects:
    """Production adapter: fixed executables, no shell, no alternate host root."""
    def metadata(self, path):
        return os.lstat(path)

    def absent(self, path):
        try:
            os.lstat(path)
        except FileNotFoundError:
            return True
        return False

    def protected_dir(self, path):
        require(safe_path(path), "protected-path")
        for p in (Path(path), *Path(path).parents):
            st = os.lstat(p)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o6022 == 0,
                    "protected-directory")

    def read(self, path, limit=65536, mode=None):
        require(safe_path(path), "protected-path")
        self.protected_dir(str(Path(path).parent))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                before.st_mode & 0o6022 == 0 and 0 <= before.st_size <= limit and
                (mode is None or stat.S_IMODE(before.st_mode) == mode), "protected-file")
            out = bytearray()
            while len(out) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(out)))
                if not chunk:
                    break
                out.extend(chunk)
            require(len(out) == before.st_size and pin(before) == pin(os.fstat(fd)) == pin(os.lstat(path)),
                    "protected-file-changed")
            return bytes(out)
        finally:
            os.close(fd)

    def command(self, args, uid=None, gid=None, limit=16384, timeout=45, **_):
        require(args[0] in (BINARY, "/usr/bin/systemctl"), "fixed-command")
        self.read(args[0], 256 << 20)
        require((uid is None and gid is None) or
                (type(uid) is int and type(gid) is int and uid > 0 and gid > 0), "command-identity")
        kw = {} if uid is None else dict(user=uid, group=gid, extra_groups=[])
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=ENV, cwd="/", close_fds=True, start_new_session=True, **kw)
        out = bytearray()
        try:
            until = time.monotonic() + timeout
            with selectors.DefaultSelector() as sel:
                sel.register(child.stdout, selectors.EVENT_READ)
                while sel.get_map():
                    require(time.monotonic() < until, "command-timeout")
                    for key, _ in sel.select(min(.2, max(0, until - time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            sel.unregister(key.fileobj)
                        out.extend(chunk)
                        require(len(out) <= limit, "command-output-limit")
            require(child.wait(timeout=max(.01, until-time.monotonic())) == 0, "fixed-command-failed")
            return bytes(out)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            child.stdout.close()

    def status(self, name):
        fields = unit_fields(name)
        raw = self.command(["/usr/bin/systemctl", "show", name,
            "--property=" + ",".join(fields), "--all", "--no-pager"], timeout=5)
        out = {}
        for line in raw.decode("ascii").strip().splitlines():
            key, sep, value = line.partition("=")
            require(sep and key in fields and key not in out, "systemd-status")
            out[key] = value
        require(set(out) == set(fields), "systemd-status")
        return out

    def names(self, path):
        require(path == LEDGER, "fixed-directory-list")
        self.protected_dir(path)
        return sorted(os.listdir(path))

    def link(self, path):
        require(path == WANTS, "fixed-link")
        self.protected_dir(str(Path(path).parent))
        st = os.lstat(path)
        require(stat.S_ISLNK(st.st_mode) and st.st_uid == st.st_gid == 0, "socket-enablement-link")
        return os.readlink(path)

    @contextlib.contextmanager
    def lock(self):
        path = INSTALLER_DIR + "/install.lock"
        self.read(path, 4096, 0o600)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            require(pin(st) == pin(os.lstat(path)) and stat.S_ISREG(st.st_mode) and
                st.st_uid == st.st_gid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600,
                "installer-lock-changed")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def mkdir(self, path):
        require(path == CONFIG_DIR, "fixed-create-directory")
        self.protected_dir(str(Path(path).parent))
        parent = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(Path(path).name, 0o755, dir_fd=parent)
            fd = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o755)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        finally:
            os.close(parent)

    def create(self, path, raw, gid, mode):
        require(path in CREATED_FILES and len(raw) <= 131072 and mode in (0o600, 0o640, 0o644),
                "fixed-create-file")
        self.protected_dir(str(Path(path).parent))
        parent = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                os.fchown(fd, 0, gid)
                os.fchmod(fd, mode)
                remaining = memoryview(raw)
                while remaining:
                    n = os.write(fd, remaining)
                    require(n > 0, "file-write")
                    remaining = remaining[n:]
                os.fsync(fd)
            finally:
                os.close(fd)  # An uncertain partial file is deliberately retained.
            os.fsync(parent)
        finally:
            os.close(parent)


def snapshot(e, path, mode=None, gid=None, limit=131072):
    before = e.metadata(path)
    raw = e.read(path, limit, mode)
    require(pin(before) == pin(e.metadata(path)) and before.st_size == len(raw) and
        (gid is None or before.st_gid == gid), "snapshot-changed")
    return dict(digest=digest(raw), pin=pin(before)), raw


def bundle(raw, fingerprint):
    b = strict_json(raw)
    require(set(b) == set(BUNDLE_FIELDS) and b["schemaVersion"] == "tracebolt.action-setup-bundle.v1",
            "bundle-schema")
    unhashed = {k: v for k, v in b.items() if k != "bundleDigest"}
    hashed = json.dumps(unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    require(valid_digest(fingerprint) and fingerprint == b["bundleDigest"] == digest(hashed),
            "independent-bundle-fingerprint")
    require(type(b["managerId"]) is str and type(b["endpointId"]) is str and
        re.fullmatch(r"manager_[0-9a-f]{32}", b["managerId"]) and
        re.fullmatch(r"agent_[0-9a-f]{32}", b["endpointId"]) and valid_digest(b["incarnationDigest"]) and
        b["transportProfile"] in ("production-tls", "disposable-http-test") and
        b["httpTestAcknowledged"] is (b["transportProfile"] == "disposable-http-test"), "bundle-bindings")
    try:
        key = base64.b64decode(b["commandPublicKey"], validate=True)
    except (ValueError, TypeError):
        raise Rejected("bundle-public-key") from None
    require(len(key) == 32 and base64.b64encode(key).decode() == b["commandPublicKey"] and
            b["keyId"] == digest(key), "bundle-public-key")
    return b, key


class EndpointAdapter:
    def __init__(self, effects=None, setup_module=None, templates=None):
        self.e = effects if effects is not None else Effects()
        self.setup = setup_module
        self.templates = templates

    def _source(self):
        if self.setup is None:
            path = Path(__file__).resolve().parent.parent / "journal/setup.py"
            raw = self.e.read(str(path), 131072)
            module = types.ModuleType("action_setup_installation_reader")
            module.__file__ = str(path)
            exec(compile(raw, str(path), "exec"), module.__dict__)
            self.setup = module
        if self.templates is None:
            root = Path(__file__).resolve().parent.parent / "systemd"
            self.templates = {name + ".in": self.e.read(str(root / (name + ".in")), 16384)
                              for name in (AGENT, SERVICE, SOCKET)}

    def _identity(self, facts, readiness=False):
        mode = "--action-setup-readiness" if readiness else "--action-setup-identity"
        value = strict_json(self.e.command([BINARY, mode, "--config", CONFIG, "--service-identity",
            f"{facts['uid']}:{facts['gid']}"], uid=facts["uid"], gid=facts["gid"], limit=16384))
        identity = value.get("identity") if readiness else value
        require(type(identity) is dict and set(identity) == set(IDENTITY_FIELDS) and
            identity["schemaVersion"] == "tracebolt.action-setup-identity.v1" and
            identity["agentUid"] == facts["uid"] and identity["agentGid"] == facts["gid"] and
            type(identity["agentUid"]) is int and type(identity["agentGid"]) is int and
            identity["managerOrigin"] == facts["origin"] and
            identity["transportProfile"] == ("production-tls" if facts["profile"] == "tls" else "disposable-http-test") and
            type(identity["senderBinding"]) is str and re.fullmatch(r"[0-9a-f]{64}", identity["senderBinding"]) and
            type(identity["endpointId"]) is str and re.fullmatch(r"agent_[0-9a-f]{32}", identity["endpointId"]) and
            valid_digest(identity["incarnationDigest"]), "endpoint-identity")
        if readiness:
            require(set(value) == {"schemaVersion", "identity", "capabilities"} and
                value["schemaVersion"] == "tracebolt.action-setup-readiness.v1", "readiness-schema")
        return value

    def _target(self, request, raw):
        v = strict_json(self.e.command([BINARY, "--action-setup-check-target", "--review", request["reviewPath"]],
                                       limit=65536))
        require(set(v) == {"schemaVersion", "target", "unitPolicyDigest", "observedState"} and
            v["schemaVersion"] == "tracebolt.action-setup-target.v1" and type(v["target"]) is dict and
            v["target"] == strict_json(raw) and raw == canonical(v["target"]) and
            v["target"].get("unit") == request["allowUnit"] and
            v["unitPolicyDigest"] == digest(canonical(v["target"])) and
            v["observedState"] in ("active", "inactive", "failed", "unknown"), "reviewed-target")
        return dict(target=v["target"], unitPolicyDigest=v["unitPolicyDigest"])

    def _configuration_dir(self):
        if self.e.absent(CONFIG_DIR):
            return None
        self.e.protected_dir(CONFIG_DIR)
        st = self.e.metadata(CONFIG_DIR)
        require(st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o755, "shared-configuration-directory")
        return directory_pin(st)

    def inspect(self, request):
        self._source()
        e, s = self.e, self.setup
        require(type(request) is dict and set(request) == {"bundlePath", "bundleFingerprint", "reviewPath", "allowUnit", "httpAcknowledged"} and
            safe_path(request["bundlePath"]) and safe_path(request["reviewPath"]) and
            type(request["allowUnit"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.service", request["allowUnit"]),
            "endpoint-request")
        # Reuse the installer ownership/manifest/unit/account adapter, never config/key reads as root.
        try:
            installed = s.inspect_agent(e, self.templates)
        except s.Rejected:
            raise Rejected("installed-endpoint-validation") from None
        state = e.status(AGENT)
        require(owned_unit(state, AGENT) and state["UnitFileState"] in ("enabled", "disabled") and
                e.absent(UNIT_DIR + "/" + AGENT + ".d"), "owned-agent-service")
        require(strict_json(e.command([BINARY, "--action-setup-capabilities"], limit=8192)) == CAPABILITIES,
                "compatible-action-setup-binary")
        identity = self._identity(installed)
        pins, raw = {}, None
        pins[request["bundlePath"]], raw = snapshot(e, request["bundlePath"])
        public, key = bundle(raw, request["bundleFingerprint"])
        require(request["httpAcknowledged"] is (public["transportProfile"] == "disposable-http-test"),
                "local-http-action-risk-acknowledgement")
        require(all(public[k] == identity[k] for k in ("managerOrigin", "endpointId", "incarnationDigest", "transportProfile")),
                "bundle-endpoint-mismatch")
        pins[request["reviewPath"]], raw = snapshot(e, request["reviewPath"], 0o600, 0, limit=65536)
        target = self._target(request, raw)
        policy = dict(version="tracebolt.action-helper-policy.v1", enabled=True, managerId=public["managerId"],
            keyId=public["keyId"], endpointId=public["endpointId"], incarnationDigest=public["incarnationDigest"],
            transportProfile=public["transportProfile"], httpTestAcknowledged=public["httpTestAcknowledged"],
            agentUid=installed["uid"], agentGid=installed["gid"], maxLifetimeSeconds=60, maxFutureSkewSeconds=5,
            targets=[target["target"]])
        client = dict(version="tracebolt.action-client-policy.v1", enabled=True, senderBinding=identity["senderBinding"],
            managerOrigin=identity["managerOrigin"], managerId=public["managerId"], endpointId=public["endpointId"],
            incarnationDigest=public["incarnationDigest"], keyId=public["keyId"], rootPolicyDigest=digest(canonical(policy)),
            transportProfile=public["transportProfile"], httpTestAcknowledged=public["httpTestAcknowledged"],
            agentUid=installed["uid"], agentGid=installed["gid"])
        for path in (s.MANIFEST, s.INSTALLER_DIR + "/installation-owner.json", s.INSTALLER_DIR + "/ownership",
            s.INSTALLER_DIR + "/install.lock", s.BINARY, "/opt/tracebolt-agent/enroll-agent", s.BOOTSTRAP,
            UNIT_DIR + "/" + AGENT, "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/usr/bin/systemctl"):
            pins[path], _ = snapshot(e, path, limit=256 << 20)
        config_dir = self._configuration_dir()
        for path in ("/etc", "/run", "/var/lib", UNIT_DIR):
            e.protected_dir(path)
        if not e.absent(str(Path(WANTS).parent)):
            e.protected_dir(str(Path(WANTS).parent))
        facts = dict(schemaVersion="tracebolt.action-endpoint-plan.v1", request=dict(request), state="fresh",
            installation={k: installed[k] for k in ("manifest", "ownerHash", "uid", "gid", "profile", "origin")},
            identity=identity, publicBundle=public, target=target, rootPolicy=policy, clientPolicy=client,
            inputPins=pins, configurationDirectory=config_dir, agentActive=installed["active"],
            agentEnablement=state["UnitFileState"], templateHashes={k: digest(v) for k, v in self.templates.items()},
            createFiles=sorted(CREATED_FILES), socketPath=SOCKET_PATH)
        if all(e.absent(path) for path in ACTION_PATHS):
            require(all(absent_unit(e.status(name), name) for name in (SERVICE, SOCKET)), "foreign-action-unit")
        else:
            require(not e.absent(COMPLETE), "partial-or-foreign-action-setup")
            self._complete(facts)
            facts["state"] = "complete"
        return facts

    def _artifacts(self, facts):
        service = self.templates[SERVICE + ".in"]
        socket = self.templates[SOCKET + ".in"].replace(b"@AGENT_GID@", str(facts["installation"]["gid"]).encode())
        require(re.search(rb"@[A-Z_]+@", service + socket) is None, "template-placeholder")
        return {POLICY: (canonical(facts["rootPolicy"]), 0, 0o600),
            PUBLIC_KEY: (base64.b64decode(facts["publicBundle"]["commandPublicKey"], validate=True), 0, 0o600),
            CLIENT: (canonical(facts["clientPolicy"]), facts["installation"]["gid"], 0o640),
            UNIT_DIR + "/" + SERVICE: (service, 0, 0o644), UNIT_DIR + "/" + SOCKET: (socket, 0, 0o644)}

    def _intent(self, facts, plan_digest, version="tracebolt.action-setup-intent.v1"):
        p = facts["rootPolicy"]
        return dict(version=version, planDigest=plan_digest, rootPolicyDigest=digest(canonical(p)),
                    keyId=p["keyId"], endpointId=p["endpointId"], incarnationDigest=p["incarnationDigest"])

    def _ledger_metadata(self):
        e = self.e
        e.protected_dir(LEDGER)
        st = e.metadata(LEDGER)
        require(st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700, "root-ledger-directory")
        # Existing history is mutable. Validate protection without opening/repairing the store.
        for name in ("action-consumption.json", "action-consumption.lock"):
            st_file = e.metadata(LEDGER + "/" + name)
            require(stat.S_ISREG(st_file.st_mode) and st_file.st_uid == st_file.st_gid == 0 and
                stat.S_IMODE(st_file.st_mode) == 0o600 and st_file.st_nlink == 1 and
                (st_file.st_size > 0 if name.endswith("json") else st_file.st_size == 0), "root-ledger-file")
        require(e.names(LEDGER) == ["action-consumption.json", "action-consumption.lock"], "partial-ledger-state")
        return directory_pin(st)

    def _socket_metadata(self, facts):
        self.e.protected_dir(RUNTIME)
        st = self.e.metadata(RUNTIME)
        require(stat.S_IMODE(st.st_mode) == 0o755 and st.st_gid == 0, "action-runtime-directory")
        st = self.e.metadata(SOCKET_PATH)
        require(stat.S_ISSOCK(st.st_mode) and st.st_uid == 0 and
            st.st_gid == facts["installation"]["gid"] and stat.S_IMODE(st.st_mode) == 0o660 and
            st.st_nlink == 1, "action-socket-metadata")

    def _setup_binding(self, facts):
        # Mutable service activity and shared-directory timestamps are deliberately
        # excluded; authority, reviewed inputs and source templates must be exact.
        return digest(canonical({k: facts[k] for k in ("request", "installation", "identity", "publicBundle",
            "target", "rootPolicy", "clientPolicy", "inputPins", "agentEnablement", "templateHashes")}))

    def _complete(self, facts):
        e = self.e
        _, raw = snapshot(e, COMPLETE, 0o600, 0)
        receipt = strict_json(raw)
        require(set(receipt) == {"version", "intent", "bundleDigest", "senderBinding", "agentEnablement",
                "artifacts", "ledgerDirectory", "setupBinding", "configurationDirectory", "fences"} and receipt["version"] == "tracebolt.action-setup-complete.v1" and
                raw == canonical(receipt) and type(receipt["intent"]) is dict and
                valid_digest(receipt["intent"].get("planDigest")), "complete-receipt")
        intent = self._intent(facts, receipt["intent"]["planDigest"])
        require(receipt["intent"] == intent and receipt["bundleDigest"] == facts["publicBundle"]["bundleDigest"] and
            receipt["senderBinding"] == facts["identity"]["senderBinding"] and
            receipt["agentEnablement"] == facts["agentEnablement"] and
            receipt["setupBinding"] == self._setup_binding(facts) and
            receipt["configurationDirectory"] == self._configuration_dir(), "complete-binding")
        fences = {}
        for path, value in ((INTENT, intent), (STARTED, self._intent(facts, intent["planDigest"], "tracebolt.action-ledger-started.v1"))):
            fences[path], raw = snapshot(e, path, 0o600, 0)
            require(raw == canonical(value), "complete-fence")
        require(fences == receipt["fences"], "complete-fence-pins")
        actual = {}
        for path, (expected, gid, mode) in self._artifacts(facts).items():
            actual[path], raw = snapshot(e, path, mode, gid)
            require(raw == expected, "complete-artifact")
        require(receipt["artifacts"] == actual and receipt["ledgerDirectory"] == self._ledger_metadata(),
                "complete-artifact-pins")
        require(owned_unit(e.status(SERVICE), SERVICE, "active") and e.status(SERVICE)["UnitFileState"] == "static" and
            owned_unit(e.status(SOCKET), SOCKET, "active") and e.status(SOCKET)["UnitFileState"] == "enabled" and
            all(e.absent(UNIT_DIR + "/" + name + ".d") for name in (SERVICE, SOCKET)) and
            e.link(WANTS) == UNIT_DIR + "/" + SOCKET, "complete-helper-units")
        self._socket_metadata(facts)

    def _readiness(self, facts):
        value = self._identity(facts["installation"], readiness=True)
        require(value["identity"] == facts["identity"], "readiness-identity")
        c = value["capabilities"]
        p = facts["rootPolicy"]
        require(type(c) is dict and set(c) == {"version", "enabled", "managerId", "keyId", "endpointId",
            "incarnationDigest", "rootPolicyDigest", "transportProfile", "httpTestAcknowledged", "capturedAt",
            "maxLifetimeSeconds", "services"} and c["version"] == "tracebolt.action-capabilities.v1" and
            c["enabled"] is True and all(c[k] == p[k] for k in ("managerId", "keyId", "endpointId", "incarnationDigest",
                "transportProfile", "httpTestAcknowledged", "maxLifetimeSeconds")) and
            c["rootPolicyDigest"] == digest(canonical(p)) and type(c["capturedAt"]) is int and
            0 < c["capturedAt"] <= 253402300799 and
            c["services"] == [dict(unit=facts["request"]["allowUnit"], unitPolicyDigest=facts["target"]["unitPolicyDigest"])],
            "helper-readiness-bindings")

    def _status_result(self, result):
        result["unitStates"] = {}
        for name in (AGENT, SERVICE, SOCKET):
            observed = dict(activeState="unknown", enablement="unknown")
            try:
                state = self.e.status(name)
                if owned_unit(state, name) or absent_unit(state, name):
                    observed = dict(activeState=state["ActiveState"], enablement=state["UnitFileState"])
            except Exception:
                pass
            result["unitStates"][name] = observed
        activity = result["unitStates"][AGENT]["activeState"]
        result["agentStopped"] = (activity == "inactive") if activity != "unknown" else None
        return result

    def apply(self, plan, public_bundle):
        require(type(plan) is dict and set(plan) == {"schemaVersion", "endpoint", "planDigest"} and
            plan["schemaVersion"] == "tracebolt.action-setup-plan.v1" and valid_digest(plan["planDigest"]),
                "approved-endpoint-plan")
        expected = plan["endpoint"]
        require(public_bundle == expected["publicBundle"], "approved-public-bundle")
        e = self.e
        result = dict(configured=False, alreadyConfigured=False, retainedPartialState=False,
                      agentRestarted=False, agentStopped=None, targetActionExecuted=False)
        with e.lock():
            facts = self.inspect(expected["request"])
            require(facts == expected, "reviewed-endpoint-plan-changed")
            if facts["state"] == "complete":
                result.update(configured=True, alreadyConfigured=True, readinessProbed=False)
                return self._status_result(result)
            artifacts = self._artifacts(facts)
            created = {}
            touched_agent = False
            intent = self._intent(facts, plan["planDigest"])
            try:
                # First effect: exclusive durable root fence outside the action ledger.
                # Mark uncertainty before attempting creation, including fsync failure.
                result["retainedPartialState"] = True
                e.create(INTENT, canonical(intent), 0, 0o600)
                touched_agent = True
                e.command(["/usr/bin/systemctl", "stop", AGENT], timeout=60)
                require(owned_unit(e.status(AGENT), AGENT, "inactive"), "agent-drain")
                result["agentStopped"] = True
                validated = e.command([BINARY, "--validate-guided", "--config", CONFIG],
                    uid=facts["installation"]["uid"], gid=facts["installation"]["gid"], limit=4096)
                require(validated.strip() == b"Tracebolt guided handoff validated locally; no collection or network request performed.",
                        "stopped-sender-ledger-validation")
                current = dict(facts)
                current["agentActive"] = False
                # All plan inputs and identity are rechecked after stop, before grants.
                fresh = self._inspect_after_intent(facts)
                require(fresh == current, "endpoint-changed-after-drain")
                if facts["configurationDirectory"] is None:
                    e.mkdir(CONFIG_DIR)
                for path, (raw, gid, mode) in artifacts.items():
                    e.create(path, raw, gid, mode)
                    created[path], checked = snapshot(e, path, mode, gid)
                    require(checked == raw, "created-artifact-changed")
                initialized = strict_json(e.command([BINARY, "--action-setup-initialize"], limit=8192))
                require(initialized == dict(schemaVersion="tracebolt.action-setup-initialized.v1", initialized=True),
                        "root-ledger-initialization")
                ledger_pin = self._ledger_metadata()
                _, raw = snapshot(e, STARTED, 0o600, 0)
                require(raw == canonical(self._intent(facts, plan["planDigest"], "tracebolt.action-ledger-started.v1")),
                        "initialization-fence")
                e.command(["/usr/bin/systemctl", "daemon-reload"])
                require(owned_unit(e.status(SERVICE), SERVICE, "inactive") and
                    e.status(SERVICE)["UnitFileState"] == "static" and
                    owned_unit(e.status(SOCKET), SOCKET, "inactive") and
                    e.status(SOCKET)["UnitFileState"] == "disabled", "published-action-units")
                e.command(["/usr/bin/systemctl", "enable", "--now", SOCKET])
                require(owned_unit(e.status(SOCKET), SOCKET, "active") and
                    e.status(SOCKET)["UnitFileState"] == "enabled" and e.link(WANTS) == UNIT_DIR + "/" + SOCKET,
                    "action-socket-activation")
                self._socket_metadata(facts)
                self._readiness(facts)  # Only capabilities IPC. Never a target action.
                require(owned_unit(e.status(SERVICE), SERVICE, "active") and
                    e.status(SERVICE)["UnitFileState"] == "static", "ready-helper-service")
                # Recheck content, installation and identity immediately before restoring.
                self._recheck_installed(facts)
                require(owned_unit(e.status(AGENT), AGENT, "inactive"), "agent-restarted-before-readiness")
                for path, (raw, gid, mode) in artifacts.items():
                    current_pin, current_raw = snapshot(e, path, mode, gid)
                    require(current_pin == created[path] and current_raw == raw, "grant-changed-before-restore")
                if facts["agentActive"]:
                    e.command(["/usr/bin/systemctl", "start", AGENT])
                    require(owned_unit(e.status(AGENT), AGENT, "active"), "agent-restore-status")
                    result.update(agentRestarted=True, agentStopped=False)
                require(e.status(AGENT)["UnitFileState"] == facts["agentEnablement"], "agent-enablement-changed")
                receipt = dict(version="tracebolt.action-setup-complete.v1", intent=intent,
                    bundleDigest=facts["publicBundle"]["bundleDigest"], senderBinding=facts["identity"]["senderBinding"],
                    agentEnablement=facts["agentEnablement"], artifacts=created, ledgerDirectory=ledger_pin,
                    setupBinding=self._setup_binding(facts), configurationDirectory=self._configuration_dir(),
                    fences={path: snapshot(e, path, 0o600, 0)[0] for path in (INTENT, STARTED)})
                e.create(COMPLETE, canonical(receipt), 0, 0o600)
                self._complete(facts)
                result.update(configured=True, retainedPartialState=False, readinessProbed=True)
            except (Exception, KeyboardInterrupt) as exc:
                result["failureStage"] = str(exc) if isinstance(exc, Rejected) else "endpoint-operation-failed"
                # Never delete, reset or automatically resume partial state. Stop only
                # exact newly-owned helper files and the existing authorized agent.
                if touched_agent:
                    try:
                        self._recheck_installed(facts)
                        e.command(["/usr/bin/systemctl", "stop", AGENT], timeout=60)
                        result["agentStopped"] = owned_unit(e.status(AGENT), AGENT, "inactive")
                        result["agentRestarted"] = False
                    except (Rejected, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                        result["agentStopped"] = False
                for name in (SOCKET, SERVICE):
                    path = UNIT_DIR + "/" + name
                    try:
                        if path in created and snapshot(e, path, 0o644, 0)[0] == created[path]:
                            args = ["/usr/bin/systemctl", "disable", "--now", name] if name == SOCKET else ["/usr/bin/systemctl", "stop", name]
                            e.command(args, timeout=60)
                    except (Rejected, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                        result["cleanupIncomplete"] = True
            return self._status_result(result)

    def _recheck_installed(self, facts):
        try:
            installed = self.setup.inspect_agent(self.e, self.templates)
        except self.setup.Rejected:
            raise Rejected("installed-endpoint-changed") from None
        require({k: installed[k] for k in facts["installation"]} == facts["installation"] and
            self.e.status(AGENT)["UnitFileState"] == facts["agentEnablement"] and
            self._identity(installed) == facts["identity"], "installed-endpoint-changed")
        for path, previous in facts["inputPins"].items():
            require(snapshot(self.e, path, limit=256 << 20)[0] == previous, "pinned-input-changed")
        _, raw = snapshot(self.e, facts["request"]["reviewPath"], limit=65536)
        require(self._target(facts["request"], raw) == facts["target"], "target-changed")

    def _inspect_after_intent(self, facts):
        # Intent now exists, so ordinary inspect deliberately refuses the partial
        # setup. Explicitly recheck every original read-only fact instead.
        self._recheck_installed(facts)
        require(self._configuration_dir() == facts["configurationDirectory"] and
            all(self.e.absent(p) for p in ACTION_PATHS if p != INTENT) and
            all(absent_unit(self.e.status(n), n) for n in (SERVICE, SOCKET)), "partial-state-changed")
        current = dict(facts)
        current["agentActive"] = self.e.status(AGENT)["ActiveState"] == "active"
        return current
