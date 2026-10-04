#!/usr/bin/env python3
"""Fixed-purpose Linux journal helper setup. Default: read-only plan.

No import-time host access. Tests inject Effects and never run real host commands.
This is a create-only operation, not an installer recovery or policy editor.
"""
import argparse
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
import sys
import time
from urllib.parse import urlsplit

AGENT = "tracebolt-agent"
HELPER = "tracebolt-journal-reader"
AGENT_UNIT = AGENT + ".service"
SERVICE = HELPER + ".service"
SOCKET = HELPER + ".socket"
UNIT_DIR = "/etc/systemd/system"
CONFIG_DIR = "/etc/tracebolt"
STATE_DIR = "/var/lib/tracebolt-agent"
INSTALLER_DIR = "/var/lib/tracebolt-agent-installer"
BINARY = "/opt/tracebolt-agent/lan-agent"
CONFIG = STATE_DIR + "/enrollment/agent.json"
MANIFEST = "/opt/tracebolt-agent/installation.json"
BOOTSTRAP = "/etc/tracebolt-agent/bootstrap.json"
RUNTIME_DIR = "/run/tracebolt-journal-reader"
SOCKET_PATH = RUNTIME_DIR + "/reader.sock"
POLICY = CONFIG_DIR + "/journal-content-policy.json"
CLIENT_POLICY = CONFIG_DIR + "/journal-client-policy.json"
DEPLOYMENT = CONFIG_DIR + "/journal-helper.json"
CLIENT_DEPLOYMENT = CONFIG_DIR + "/journal-client-helper.json"
ATTEMPT = CONFIG_DIR + "/journal-setup-attempt.json"
# Frozen direct-write allowlist. Account database and socket/enablement effects
# belong only to the fixed useradd/systemctl calls below; no arbitrary commands.
CREATED_FILES = frozenset((ATTEMPT, POLICY, CLIENT_POLICY, DEPLOYMENT,
                          CLIENT_DEPLOYMENT, UNIT_DIR + "/" + SERVICE,
                          UNIT_DIR + "/" + SOCKET))
CREATE_DIRS = frozenset((CONFIG_DIR,))
SCOPE = "on-demand-allowlisted-system-service-log-content"
PROFILE = "managed-operations-v3"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
       "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"}
TEMPLATES = Path(__file__).resolve().parent.parent / "systemd"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class Rejected(Exception):
    """Only fixed safe stage names escape to the operator."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def canonical(value):
    # All accepted strings are ASCII. Field order matches the Go wire structs.
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode())


def same_file(a, b):
    return all(getattr(a, k) == getattr(b, k) for k in
               ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns"))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw, fields=None):
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, "duplicate-json-member")
            out[k] = v
        return out
    try:
        out = json.loads(raw, object_pairs_hook=pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Rejected("invalid-json")))
    except (ValueError, UnicodeError):
        raise Rejected("invalid-json") from None
    require(type(out) is dict and (fields is None or set(out) == set(fields)), "json-members")
    return out


def valid_id(value):
    return type(value) is int and 0 < value < 2**32 - 1


def valid_digest(value):
    return type(value) is str and DIGEST.fullmatch(value) is not None and value != "0" * 64


def valid_unit(unit):
    if not isinstance(unit, str) or len(unit) > 255 or not unit.endswith(".service"):
        return False
    stem = unit[:-8]
    return bool(stem and stem[0] not in ".-@" and ".." not in stem and
                not stem.endswith("@") and stem.count("@") <= 1 and
                re.fullmatch(r"[a-zA-Z0-9_.@-]+", stem))


def selected_units(units):
    require(1 <= len(units) <= 32 and len(units) == len(set(units)) and
            all(valid_unit(u) for u in units), "explicit-service-allowlist")
    return sorted(units)


def valid_origin(origin, profile):
    if not isinstance(origin, str) or not 1 <= len(origin) <= 512 or not origin.isascii():
        return False
    if any(c in origin for c in "\\%\r\n\t "):
        return False
    try:
        u = urlsplit(origin)
        return (u.scheme == ("https" if profile == "tls" else "http") and
                u.netloc and u.netloc == u.netloc.lower() and not u.username and
                not u.password and not u.path and not u.query and not u.fragment and
                origin == u.scheme + "://" + u.netloc)
    except ValueError:
        return False


def account_tables(passwd, group):
    users, groups = {}, {}
    for raw, count, output in ((passwd, 7, users), (group, 4, groups)):
        for line in raw.decode("ascii").splitlines():
            if not line:
                continue
            row = line.split(":")
            require(len(row) == count and row[0] not in output and
                    re.fullmatch(r"0|[1-9][0-9]*", row[2]), "local-account-database")
            output[row[0]] = row
    return users, groups


def account(users, groups, name, home):
    require(name in users and name in groups, "dedicated-account")
    u, g = users[name], groups[name]
    require(re.fullmatch(r"[1-9][0-9]*", u[3]) is not None, "dedicated-account")
    uid, gid = int(u[2]), int(u[3])
    require(valid_id(uid) and valid_id(gid) and g[2] == str(gid) and not g[3] and
            u[5] == home and u[6] == "/usr/sbin/nologin", "dedicated-account")
    require(sum(int(row[2]) == uid for row in users.values()) == 1 and
            sum(int(row[2]) == gid for row in groups.values()) == 1 and
            all(row[0] == name or row[3] != str(gid) for row in users.values()) and
            all(name not in row[3].split(",") for row in groups.values()), "account-membership")
    return uid, gid


def agent_unit(template, m):
    raw = template.decode("ascii")
    identity = f" --service-identity {m['uid']}:{m['gid']}"
    raw = raw.replace("User=tracebolt-agent\n", f"User={m['uid']}\n", 1)
    raw = raw.replace("Group=tracebolt-agent\n", f"Group={m['gid']}\n", 1)
    raw = raw.replace(" --interval 30s\n", " --interval 30s" + identity + "\n", 1)
    if m["version"] == "tracebolt.agent-installation.v2":
        raw = raw.replace("ConditionPathExists=/var/lib/tracebolt-agent/enrollment/ready.json\n", "", 1)
        args = " --enrollment-bootstrap /etc/tracebolt-agent/bootstrap.json --enrollment-state-directory /var/lib/tracebolt-agent/enrollment"
        if m["profile"] == "http-test":
            args += " --insecure-http-test"
        raw = raw.replace(identity + "\n", identity + args + "\n", 1)
    return raw.encode()


def unit_state(raw):
    fields = ("LoadState", "ActiveState", "FragmentPath", "DropInPaths", "Transient", "Names", "MainPID", "UnitFileState")
    out = {}
    for line in raw.decode("ascii").strip().splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in fields and key not in out, "systemd-unit-status")
        out[key] = value
    require(set(out) == set(fields) and re.fullmatch(r"[0-9]+", out["MainPID"]), "systemd-unit-status")
    return out


def absent_unit(s, name):
    return (s["LoadState"] == "not-found" and s["ActiveState"] == "inactive" and
            s["FragmentPath"] == s["DropInPaths"] == "" and s["Transient"] == "no" and
            s["Names"] in ("", name) and s["MainPID"] == "0" and
            s["UnitFileState"] in ("", "not-found"))


def owned_unit(s, name, active=None):
    return (s["LoadState"] == "loaded" and s["FragmentPath"] == UNIT_DIR + "/" + name and
            s["DropInPaths"] == "" and s["Transient"] == "no" and s["Names"] == name and
            s["UnitFileState"] in ("enabled", "disabled", "static") and
            s["ActiveState"] in ((active,) if active else ("active", "inactive", "failed")))


def preview(raw, expected, mode="preview"):
    fields = ("schemaVersion", "mode", "scope", "senderBinding", "managerOrigin", "transportProfile",
              "collectionProfile", "deviceId", "certificateHash", "agentUid", "agentGid",
              "initialized", "existingStatePreserved")
    p = strict_json(raw, fields)
    require(p["schemaVersion"] == "tracebolt.journal-consent-result.v1" and p["mode"] == mode and
            p["scope"] == SCOPE and p["collectionProfile"] == PROFILE and
            p["transportProfile"] == expected["profile"] and p["managerOrigin"] == expected["origin"] and
            p["agentUid"] == expected["uid"] and p["agentGid"] == expected["gid"] and
            type(p["agentUid"]) is int and type(p["agentGid"]) is int and
            p["initialized"] is (mode == "initialize") and p["existingStatePreserved"] is True and
            valid_digest(p["senderBinding"]) and valid_digest(p["certificateHash"]) and
            isinstance(p["deviceId"], str) and re.fullmatch(r"agent_[0-9a-f]{32}", p["deviceId"]),
            "stopped-agent-preview")
    return p


def declarations(p, helper_uid, helper_gid, journal_gid, units):
    require(all(valid_id(n) for n in (helper_uid, helper_gid, journal_gid)) and
            helper_uid != p["agentUid"] and len({helper_gid, journal_gid, p["agentGid"]}) == 3,
            "helper-numeric-identity")
    d = dict(schemaVersion="tracebolt.journal-helper-deployment.v1", helperUid=helper_uid,
             helperGid=helper_gid, journalGid=journal_gid, agentUid=p["agentUid"], agentGid=p["agentGid"])
    policy = dict(schemaVersion="tracebolt.journal-content-policy.v1", scope=SCOPE,
                  collectionProfile=PROFILE, senderBinding=p["senderBinding"], managerOrigin=p["managerOrigin"],
                  transportProfile=p["transportProfile"], agentUid=p["agentUid"], helperUid=helper_uid,
                  allowedUnits=selected_units(units), maxWindowSeconds=3600, maxLookbackSeconds=86400,
                  maxPriority=7, enabled=True, contentAcknowledged=True,
                  plaintextAcknowledged=p["transportProfile"] == "http-test")
    return canonical(d), canonical(policy)


class Effects:
    """Real effects; no alternate root, executable, destination or shell options."""
    def protected_dir(self, path):
        for p in (Path(path), *Path(path).parents):
            st = os.lstat(p)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
                    st.st_mode & 0o6022 == 0, "protected-directory")

    def metadata(self, path):
        return os.lstat(path)

    def absent(self, path):
        try:
            os.lstat(path)
        except FileNotFoundError:
            return True
        return False

    def read(self, path, limit=65536, mode=None):
        self.protected_dir(str(Path(path).parent))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                    before.st_mode & 0o6022 == 0 and 0 <= before.st_size <= limit and
                    (mode is None or stat.S_IMODE(before.st_mode) == mode), "protected-file")
            raw = b""
            while len(raw) <= limit:
                part = os.read(fd, min(65536, limit + 1 - len(raw)))
                if not part:
                    break
                raw += part
            require(len(raw) == before.st_size and same_file(before, os.fstat(fd)) and
                    same_file(before, os.lstat(path)), "changed-protected-file")
            return raw
        finally:
            os.close(fd)

    def command(self, args, uid=None, gid=None, limit=16384, timeout=45):
        # Every caller below supplies a fixed executable and a bounded argument set.
        require(args[0] in ("/usr/bin/systemctl", "/usr/sbin/useradd", BINARY), "fixed-command")
        self.read(args[0], 256 << 20)
        kw = {} if uid is None else dict(user=uid, group=gid, extra_groups=[])
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=ENV, cwd="/", close_fds=True,
                                 start_new_session=True, **kw)
        out = bytearray()
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(child.stdout, selectors.EVENT_READ)
                until = time.monotonic() + timeout
                while sel.get_map():
                    require(time.monotonic() < until, "command-timeout")
                    for key, _ in sel.select(min(0.2, max(0, until - time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            sel.unregister(key.fileobj)
                        out.extend(chunk)
                        require(len(out) <= limit, "command-output-limit")
            require(child.wait(timeout=max(0.01, until - time.monotonic())) == 0, "fixed-command-failed")
            return bytes(out)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            child.stdout.close()

    def status(self, name):
        require(name in (AGENT_UNIT, SERVICE, SOCKET), "fixed-unit")
        return unit_state(self.command(["/usr/bin/systemctl", "show", name,
            "--property=LoadState,ActiveState,FragmentPath,DropInPaths,Transient,Names,MainPID,UnitFileState", "--no-pager"], timeout=5))

    @contextlib.contextmanager
    def lock(self):
        path = INSTALLER_DIR + "/install.lock"
        self.read(path, 4096, 0o600)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            require(same_file(st, os.lstat(path)) and stat.S_ISREG(st.st_mode) and
                    st.st_uid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600,
                    "installer-lock-changed")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def mkdir(self, path):
        require(path in CREATE_DIRS, "fixed-create-directory")
        self.protected_dir(str(Path(path).parent))
        os.mkdir(path, 0o755)  # Existing paths are never adopted/chmodded.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fchmod(fd, 0o755)  # Exact mode on this newly created directory only.
            os.fsync(fd)
        finally:
            os.close(fd)

    def create(self, path, raw, gid, mode):
        require(path in CREATED_FILES and len(raw) <= 16384 and mode in (0o600, 0o640, 0o644), "fixed-create-file")
        self.protected_dir(str(Path(path).parent))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, mode)
            view = memoryview(raw)
            while view:
                n = os.write(fd, view)
                require(n > 0, "file-write")
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)  # An uncertain partial file is deliberately retained.
        d = os.open(str(Path(path).parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(d)
        finally:
            os.close(d)


def read_templates(e):
    return {name: e.read(str(TEMPLATES / name), 16384) for name in
            (AGENT_UNIT + ".in", SERVICE + ".in", SOCKET + ".in")}


def inspect_agent(e, templates):
    # Exact source-version adapter for agentinstall ownership. No key/config/ledger reads.
    fields = ("version", "profile", "uid", "gid", "agentHash", "enrollHash", "sourceHash", "bootstrapHash", "unitHash")
    raw = e.read(MANIFEST, 8192)
    m = strict_json(raw, fields)
    require(m["version"] in ("tracebolt.agent-installation.v1", "tracebolt.agent-installation.v2") and
            m["profile"] in ("tls", "http-test") and valid_id(m["uid"]) and valid_id(m["gid"]) and
            all(valid_digest(m[k]) for k in fields[4:]), "installed-manifest")
    e.protected_dir(INSTALLER_DIR)
    require(stat.S_IMODE(e.metadata(INSTALLER_DIR).st_mode) == 0o700 and
            e.read(INSTALLER_DIR + "/ownership", 128, 0o600) == b"tracebolt.agent-installer-owned.v1\n" and
            e.absent(INSTALLER_DIR + "/transaction.json") and e.absent(INSTALLER_DIR + "/transaction.json.new"),
            "unresolved-installer-ownership")
    e.read(INSTALLER_DIR + "/install.lock", 4096, 0o600)
    owner_raw = e.read(INSTALLER_DIR + "/installation-owner.json", 16384, 0o600)
    owner = strict_json(owner_raw, ("version", "status", "installation", "stateDevice", "stateInode"))
    expected_version = "tracebolt.agent-install-owner." + m["version"].rsplit(".", 1)[1]
    canonical_owner = dict(version=owner["version"], status=owner["status"],
                           installation={k: m[k] for k in fields},
                           stateDevice=owner["stateDevice"], stateInode=owner["stateInode"])
    require(owner_raw.strip() == canonical(canonical_owner) and owner["version"] == expected_version and
            owner["status"] == "installed" and owner["installation"] == m, "installed-owner-record")
    state = e.metadata(STATE_DIR)
    require(stat.S_ISDIR(state.st_mode) and stat.S_IMODE(state.st_mode) == 0o700 and
            state.st_uid == m["uid"] and state.st_gid == m["gid"] and
            type(owner["stateDevice"]) is int and type(owner["stateInode"]) is int and
            owner["stateDevice"] == state.st_dev and owner["stateInode"] == state.st_ino and state.st_ino > 0,
            "existing-state-domain")
    users, groups = account_tables(e.read("/etc/passwd", 1 << 20), e.read("/etc/group", 1 << 20))
    require(account(users, groups, AGENT, STATE_DIR) == (m["uid"], m["gid"]), "unchanged-agent-identity")
    # Fail closed for non-local NSS providers, where local files cannot prove absence/membership.
    nss = e.read("/etc/nsswitch.conf", 65536).decode("ascii")
    for kind in ("passwd", "group"):
        rows = [x.partition(":")[2].split("#", 1)[0].split() for x in nss.splitlines()
                if x.partition(":")[0].strip() == kind]
        require(len(rows) == 1 and rows[0] and rows[0][0] == "files" and
                all(x in ("files", "systemd") for x in rows[0]), "local-nss-only")
    for path, key, max_size in ((BINARY, "agentHash", 256 << 20),
                               ("/opt/tracebolt-agent/enroll-agent", "enrollHash", 256 << 20),
                               (BOOTSTRAP, "bootstrapHash", 65536),
                               (UNIT_DIR + "/" + AGENT_UNIT, "unitHash", 65536)):
        require(digest(e.read(path, max_size)) == m[key], "owned-artifact-hash")
    require(digest(agent_unit(templates[AGENT_UNIT + ".in"], m)) == m["unitHash"], "fixed-agent-unit")
    s = e.status(AGENT_UNIT)
    require(owned_unit(s, AGENT_UNIT) and s["UnitFileState"] in ("enabled", "disabled"), "owned-agent-systemd-unit")
    bootstrap = strict_json(e.read(BOOTSTRAP, 65536))
    require(bootstrap.get("profile") == m["profile"] and bootstrap.get("collectionProfile") == PROFILE and
            valid_origin(bootstrap.get("agentOrigin"), m["profile"]), "public-bootstrap-scope")
    return dict(manifest=m, uid=m["uid"], gid=m["gid"], profile=m["profile"],
                origin=bootstrap["agentOrigin"], ownerHash=digest(owner_raw),
                active=s["ActiveState"] == "active", users=users, groups=groups)


def preflight(e, units, templates):
    existing = inspect_agent(e, templates)
    require(HELPER not in existing["users"] and HELPER not in existing["groups"], "existing-helper-account")
    groups = existing["groups"]
    require("systemd-journal" in groups, "existing-systemd-journal-group")
    journal_gid = int(groups["systemd-journal"][2])
    require(valid_id(journal_gid) and journal_gid != existing["gid"] and
            sum(int(g[2]) == journal_gid for g in groups.values()) == 1, "journal-group-identity")
    for p in (CONFIG_DIR, RUNTIME_DIR, UNIT_DIR + "/" + SERVICE, UNIT_DIR + "/" + SOCKET,
              UNIT_DIR + "/" + SERVICE + ".d", UNIT_DIR + "/" + SOCKET + ".d",
              UNIT_DIR + "/sockets.target.wants/" + SOCKET):
        require(e.absent(p), "existing-helper-path")
    for name in (SERVICE, SOCKET):
        require(absent_unit(e.status(name), name), "foreign-helper-systemd-unit")
    for path in ("/etc", "/run", UNIT_DIR):
        e.protected_dir(path)
    # systemctl enable may create only this fixed wants directory and link.
    wants = UNIT_DIR + "/sockets.target.wants"
    if not e.absent(wants):
        e.protected_dir(wants)
    for path in ("/usr/bin/systemctl", "/usr/sbin/useradd", "/usr/sbin/nologin"):
        e.read(path, 256 << 20)
    plan = dict(schemaVersion="tracebolt.journal-helper-plan.v1", managerOrigin=existing["origin"],
                transportProfile=existing["profile"], agentUid=existing["uid"], agentGid=existing["gid"],
                agentManifest=existing["manifest"], ownerHash=existing["ownerHash"],
                allowUnits=selected_units(units), maxWindowSeconds=3600, maxLookbackSeconds=86400,
                maxPriority=7, helperAccount=HELPER, helperIds="allocated-by-system-useradd",
                journalGid=journal_gid, senderBinding="resolved-from-stopped-nonroot-preview-during-apply",
                templateHashes={k: digest(v) for k, v in templates.items()},
                createFiles=sorted(CREATED_FILES), socket=SOCKET_PATH, socketMode="0660",
                enableSocket=True, restorePreviouslyActiveAgent=True,
                warning="Log messages may contain credentials and personal data. Masking is best effort, never secret-free.",
                plaintextWarning=("HTTP log content is observable and the manager can be impersonated."
                                  if existing["profile"] == "http-test" else ""))
    return existing, plan


def consent_command(e, mode, facts):
    args = [BINARY, "--config", CONFIG, "--service-identity", f"{facts['uid']}:{facts['gid']}",
            "--journal-content-consent", mode]
    if mode == "initialize":
        args.append("--ack-journal-content")
        if facts["profile"] == "http-test":
            args.append("--ack-journal-http-plaintext")
    return preview(e.command(args, uid=facts["uid"], gid=facts["gid"], limit=8192), facts, mode)


def same_agent(a, b):
    return all(a[k] == b[k] for k in ("manifest", "ownerHash", "uid", "gid", "profile", "origin"))


def apply(e, units, templates, expected_plan, content_ack, plaintext_ack):
    require(content_ack, "content-acknowledgement-required")
    with e.lock():
        facts, plan = preflight(e, units, templates)
        require(valid_digest(expected_plan) and digest(canonical(plan)) == expected_plan, "reviewed-plan-changed")
        require(plaintext_ack == (facts["profile"] == "http-test"), "transport-specific-acknowledgement")
        stopped = False
        result = dict(configured=False, sourceVerified=False, contentRead=False,
                      retainedPartialState=False, agentRestarted=False)
        error = None
        try:
            # Remember before attempting: even an uncertain stop must be reconciled.
            stopped = True
            e.command(["/usr/bin/systemctl", "stop", AGENT_UNIT])
            require(owned_unit(e.status(AGENT_UNIT), AGENT_UNIT, "inactive") and
                    e.status(AGENT_UNIT)["MainPID"] == "0", "stopped-agent")
            require(same_agent(facts, inspect_agent(e, templates)), "agent-changed-after-stop")
            p = consent_command(e, "preview", facts)
            e.mkdir(CONFIG_DIR)
            result["retainedPartialState"] = True
            e.create(ATTEMPT, canonical(dict(schemaVersion="tracebolt.journal-setup-attempt.v1",
                     planSHA256=expected_plan, senderBinding=p["senderBinding"], deviceId=p["deviceId"],
                     certificateHash=p["certificateHash"])), 0, 0o600)
            e.command(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home",
                       "--no-log-init", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
                       "-K", "CREATE_MAIL_SPOOL=no", HELPER])
            users, groups = account_tables(e.read("/etc/passwd", 1 << 20), e.read("/etc/group", 1 << 20))
            hu, hg = account(users, groups, HELPER, "/nonexistent")
            require(account(users, groups, AGENT, STATE_DIR) == (facts["uid"], facts["gid"]) and
                    groups["systemd-journal"] == facts["groups"]["systemd-journal"], "unchanged-existing-accounts")
            deployment, policy = declarations(p, hu, hg, plan["journalGid"], units)
            for path, raw, gid in ((DEPLOYMENT, deployment, hg), (CLIENT_DEPLOYMENT, deployment, facts["gid"]),
                                   (POLICY, policy, hg), (CLIENT_POLICY, policy, facts["gid"])):
                e.create(path, raw, gid, 0o640)
            service = templates[SERVICE + ".in"].replace(b"@HELPER_UID@", str(hu).encode()).replace(
                b"@HELPER_GID@", str(hg).encode()).replace(b"@JOURNAL_GID@", str(plan["journalGid"]).encode())
            socket = templates[SOCKET + ".in"].replace(b"@AGENT_GID@", str(facts["gid"]).encode())
            require(not re.search(rb"@[A-Z_]+@", service + socket), "unresolved-template-placeholder")
            # '@system-service' syscall groups are literal systemd syntax.
            e.create(UNIT_DIR + "/" + SERVICE, service, 0, 0o644)
            e.create(UNIT_DIR + "/" + SOCKET, socket, 0, 0o644)
            initialized = consent_command(e, "initialize", facts)
            require(all(initialized[k] == p[k] for k in ("senderBinding", "deviceId", "certificateHash")), "consent-identity-changed")
            e.command(["/usr/bin/systemctl", "daemon-reload"])
            require(owned_unit(e.status(SERVICE), SERVICE, "inactive") and
                    owned_unit(e.status(SOCKET), SOCKET, "inactive"), "published-helper-units")
            e.command(["/usr/bin/systemctl", "enable", "--now", SOCKET])
            require(owned_unit(e.status(SOCKET), SOCKET, "active"), "socket-activation")
            e.protected_dir(RUNTIME_DIR)
            st = e.metadata(SOCKET_PATH)
            require(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660 and
                    st.st_uid == 0 and st.st_gid == facts["gid"] and st.st_nlink == 1, "socket-ownership")
            result.update(configured=True, retainedPartialState=False, policySHA256=digest(policy),
                          deploymentSHA256=digest(deployment), helperUid=hu, helperGid=hg)
        except (Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError) as exc:
            error = exc if isinstance(exc, Rejected) else Rejected("local-operation-failed")
        finally:
            if stopped and facts["active"]:
                try:
                    # Never start over a new/uncertain installer transaction, changed
                    # ownership/identity or foreign unit. Do not bypass failed checks.
                    require(same_agent(facts, inspect_agent(e, templates)), "agent-restart-ownership")
                    e.command(["/usr/bin/systemctl", "start", AGENT_UNIT])
                    require(owned_unit(e.status(AGENT_UNIT), AGENT_UNIT, "active"), "agent-restart-status")
                    result["agentRestarted"] = True
                except (Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError):
                    error = Rejected("agent-restart-blocked-retain-state")
        if error:
            result["failureStage"] = str(error)
        return result


def interrupted(_signum, _frame):
    raise Rejected("interrupted")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-unit", action="append", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--ack-journal-content", action="store_true")
    parser.add_argument("--ack-journal-http-plaintext", action="store_true")
    args = parser.parse_args(argv)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        require(sys.platform == "linux" and os.geteuid() == 0, "root-linux-local-administration")
        units = selected_units(args.allow_unit)
        e = Effects()
        # Apply only a reviewed root-owned script/templates in protected ancestors.
        # Plan also needs root to inspect existing installer ownership, never keys.
        e.read(str(Path(__file__).resolve()), 65536)
        templates = read_templates(e)
        if args.apply:
            result = apply(e, units, templates, args.expected_plan_sha256,
                           args.ack_journal_content, args.ack_journal_http_plaintext)
            print(json.dumps(result, indent=2))
            return 0 if result["configured"] and "failureStage" not in result else 1
        require(not args.expected_plan_sha256 and not args.ack_journal_content and
                not args.ack_journal_http_plaintext, "plan-does-not-accept-apply-flags")
        _, plan = preflight(e, units, templates)
        print(json.dumps(dict(plan=plan, planSHA256=digest(canonical(plan))), indent=2))
        return 0
    except (Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError) as exc:
        stage = str(exc) if isinstance(exc, Rejected) else "local-preflight-failed"
        print(json.dumps(dict(configured=False, failureStage=stage,
                              warning="Retain any partial state. No automatic adoption, cleanup or identity reset.")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
