#!/usr/bin/env python3
"""Verified-release, same-identity read-admin v2 update. Inert on import.

The coordinator holds the existing installer lock across the native subprocess.
No enrollment, grant, policy epoch, private state, or original receipt is written.
Uncertain transactions remain stopped and require inspection, never replay.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys

CONTROL = "/var/lib/tracebolt-agent-installer"
TRANSACTION = CONTROL + "/read-admin-upgrade-transaction.json"
CURRENT = CONTROL + "/read-admin-upgrade-current.json"
OWNER = CONTROL + "/installation-owner.json"
MANIFEST = "/opt/tracebolt-agent/installation.json"
AGENT = "/opt/tracebolt-agent/lan-agent"
ENROLL = "/opt/tracebolt-agent/enroll-agent"
HELPER = "/opt/tracebolt-agent/socket-owner-reader"
DEPLOYMENT = "/etc/tracebolt/socket-owner-deployment.json"
PUBLIC = {AGENT: (0o555, 0), ENROLL: (0o555, 0), MANIFEST: (0o644, 0), OWNER: (0o600, 0), HELPER: (0o755, 0), CURRENT: (0o600, 0)}
VERSION = "tracebolt.read-admin-upgrade-transaction.v1"
RESTORE_STEPS = frozenset(("reset-restart-state", "enablement", "helpers", "socket-proof", "journal-proof",
                           "agent-validation", "agent-start", "final-enablement"))


class Rejected(Exception):
    pass


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def canonical(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def same_identity(before, after):
    keys = ("configHash", "deviceId", "origin", "profile", "uid", "gid")
    return all(before[k] == after[k] for k in keys) and all(before["manifest"][k] == after["manifest"][k]
        for k in ("version", "profile", "uid", "gid", "bootstrapHash", "unitHash"))


def run(adapter, confirm, emit):
    result = dict(schemaVersion="tracebolt.read-admin-upgrade-result.v1", completed=False, canceled=False,
                  identityRetained=True, scopesChanged=False, participantsStopped=False, rollbackConfirmed=False,
                  restartBookkeepingReset=False, nativeAcceptance="not-established")
    attempted = False
    phase = "preflight"
    try:
        original = adapter.inspect()
        emit(adapter.disclosure(original))
        if not confirm("UPGRADE READ ADMIN" + (" OVER HTTP" if original["profile"] == "http-test" else "")):
            result["canceled"] = True
            return result
        with adapter.lock():
            require(adapter.inspect() == original, "reviewed-installation-changed")
            phase = "prepare"
            attempted = True
            try:
                adapter.prepare(original)
                phase = "drain"
                adapter.quiesce(original)
                result["participantsStopped"] = True
                phase = "retained-state"
                retained = adapter.retained(original)
                phase = "native-upgrade"
                adapter.native_upgrade(original)
                phase = "helper-rebind"
                adapter.rebind(original)
                phase = "same-scope-validation"
                current = adapter.inspect(updating=True)
                require(same_identity(original, current) and original["users"] == current["users"] and original["groups"] == current["groups"], "updated-identity-changed")
                require(adapter.retained(current) == retained, "retained-state-changed")
                phase = "restore-runtime"
                result["restartBookkeepingReset"] = True
                adapter.restore(original, current)
                phase = "commit"
                adapter.commit()
                result["participantsStopped"] = False
                result["agentActivityRestored"] = True
                result["agentActive"] = original["active"]
            except BaseException:
                restore_step = getattr(adapter, "restore_step", None)
                if phase == "restore-runtime" and type(restore_step) is str and restore_step in RESTORE_STEPS:
                    result["restoreStep"] = restore_step
                # Any uncertain child/replace/start is contained before rollback.
                # Restoration never starts participants after a failed update.
                try:
                    result["participantsStopped"] = adapter.contain(original)
                except BaseException:
                    result["participantsStopped"] = False
                if result["participantsStopped"]:
                    try:
                        result["rollbackConfirmed"] = adapter.rollback(original)
                    except BaseException:
                        result["rollbackConfirmed"] = False
                raise
            phase = "lock-release"
        # The context's named-lock recheck and descriptor close are part of
        # success. A late exit failure must never produce a successful result.
        result["completed"] = True
    except BaseException as exc:
        result["completed"] = False
        result["failureStage"] = phase
        result["failureReason"] = str(exc) if isinstance(exc, adapter.rejection_types) and re.fullmatch(r"[a-z0-9-]{1,96}", str(exc)) else "upgrade-step-unconfirmed"
        if attempted:
            result["recovery"] = "Keep the upgrade transaction, original receipts, public backups and all private state. Inspect the reported phase. Do not reinstall, repeat an uncertain upgrade, remove evidence or create a new identity."
    return result


# Run only as the dedicated nonroot account, with no supplementary groups. The
# bounded digest includes every private file, including future transport state.
# Only the aggregate digest is returned; no private bytes or paths are printed.
STATE_DIGEST = r'''
import hashlib, os, stat, struct
root="/var/lib/tracebolt-agent"
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
h=hashlib.sha256(); count=0; total=0
uid,gid=os.geteuid(),os.getegid()
assert uid>0 and gid>0 and os.getgroups()==[]
def stamp(s):
 return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def bounded_names(fd, limit):
 names=[]
 with os.scandir(fd) as entries:
  for entry in entries:
   if len(names)>=limit: raise ValueError('state-entry-limit')
   names.append(entry.name)
 return sorted(names)
def visit(fd, prefix):
 global count,total
 before=os.fstat(fd)
 assert stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode)==0o700 and before.st_uid==uid and before.st_gid==gid
 names=bounded_names(fd,10000-count)
 count+=len(names)
 for name in names:
  st=os.stat(name,dir_fd=fd,follow_symlinks=False)
  b=(prefix+name).encode(); h.update(struct.pack('>Q',len(b))); h.update(b)
  if stat.S_ISDIR(st.st_mode):
   h.update(b'D'); child=os.open(name,flags,dir_fd=fd)
   try: visit(child,prefix+name+'/')
   finally: os.close(child)
  else:
   assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) in (0o400,0o600) and st.st_uid==uid and st.st_gid==gid and st.st_nlink==1
   total+=st.st_size; assert total<=1<<30
   h.update(b'F'); h.update(struct.pack('>Q',st.st_size)); f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
   try:
    assert stamp(os.fstat(f))==stamp(st)
    n=0
    while True:
     part=os.read(f,65536)
     if not part: break
     n+=len(part); assert n<=st.st_size; h.update(part)
    assert n==st.st_size and stamp(os.fstat(f))==stamp(st)
   finally: os.close(f)
  assert stamp(os.stat(name,dir_fd=fd,follow_symlinks=False))==stamp(st)
 assert bounded_names(fd,len(names))==names and stamp(os.fstat(fd))==stamp(before)
fd=os.open(root,flags)
try:
 before=os.fstat(fd); visit(fd,''); assert stamp(os.lstat(root))==stamp(before)
finally: os.close(fd)
print(h.hexdigest())
'''


def real_adapter(w, s, inventory, amendment, socket, templates, release, directory, command, *, arch):
    require(arch in ("amd64", "arm64"), "supported-upgrade-architecture")
    ie = inventory.real_effects(s)
    je = amendment.real_effects(s, {})
    se = socket.real_effects(s)
    roles = ("agent-service", "lan-agent", "enroll-agent", "socket-owner-reader")
    assets = {role: dict(release["assets"][f"tracebolt-{release['version']}-linux-{arch}-{role}"],
                        path=str(directory / f"tracebolt-{release['version']}-linux-{arch}-{role}")) for role in roles}
    source = release["assets"][f"tracebolt-{release['version']}-source.tar"]["sha256"]
    release_hash = digest((directory / "manifest.json").read_bytes())
    participants = (s.AGENT_UNIT, s.SOCKET, s.SERVICE, socket.SOCKET, socket.SERVICE)

    class Adapter:
        rejection_types = (Rejected, w.Rejected, s.Rejected, inventory.Rejected, amendment.Rejected, socket.Rejected)
        fd = None
        archive = None
        marker = None
        old = None
        expected = None
        native_attempted = False
        native_complete = False

        def inspect(self, updating=False):
            require(updating or ie.absent(TRANSACTION), "unresolved-read-admin-upgrade")
            require(all(ie.absent(p) for p in (socket.REVOKE_STARTED, socket.REVOKE_COMPLETE, socket.DISABLE_STAGE)), "revoked-or-uncertain-socket-scope")
            se.platform()
            require(socket.native_architecture() == arch, "upgrade-architecture-mismatch")
            facts = inventory.inspect(s, ie, templates, inventory.selected_scopes(True))
            require((facts["profile"] == "http-test") == ("--insecure-http-test" in command), "upgrade-transport-acknowledgement")
            raw = ie.read(w.RECEIPT, 16384, 0o600)
            bound = inventory.strict_json(raw, 16384)
            require(type(bound) is dict and set(bound) == {"schemaVersion", "planSHA256", "readProfile", "ownerHash", "configHash", "deviceId", "managerOrigin", "agentUid", "agentGid", "installation"} and
                    bound["schemaVersion"] == "tracebolt.read-admin-intent.v2" and bound["readProfile"] == w.PROFILE and raw == w.canonical(bound), "completed-read-admin-v2-required")
            require(all(bound[k] == facts[v] for k, v in (("configHash", "configHash"), ("deviceId", "deviceId"), ("managerOrigin", "origin"), ("agentUid", "uid"), ("agentGid", "gid"))), "original-identity-changed")
            for phase in w.PHASES:
                for state in ("started", "complete"):
                    require(ie.read(w.phase_path(phase, state), 16384, 0o600) == w.phase_record(bound, phase, state), "incomplete-read-admin-phase")
            receipt = socket.proof(s, se, templates, facts, digest(raw))
            j = amendment.inspect(s, je, templates)
            require(j["policy"]["schemaVersion"] == amendment.V3 and j["policy"]["serviceAuthorization"] == amendment.ALL_SERVICES and j["policy"]["enabled"] is True, "existing-broad-journal-required")
            require(all(facts[k] == j[k] for k in ("manifest", "uid", "gid", "origin", "profile")), "journal-installation-changed")
            if not updating:
                require(j["enablement"][s.SOCKET] == "enabled" and j["activity"][s.SOCKET], "journal-admission-not-enabled")
                socket.runtime_configuration(se, facts, receipt)
            facts.update(parent=bound, receipt=receipt,
                         journalPolicy=j["policy"], journalIdentity=j["identity"],
                         journalHelperUid=j["helperUid"], journalHelperGid=j["helperGid"], journalGid=j["journalGid"],
                         unitHashes={name: digest(socket.exact_file(ie, s.UNIT_DIR + "/" + name, 0o644, 0)) for name in participants},
                         enablement={name: (se.status(name) if name in (socket.SOCKET, socket.SERVICE) else je.status(name))["UnitFileState"] for name in participants},
                         activity={name: (se.status(name) if name in (socket.SOCKET, socket.SERVICE) else je.status(name))["ActiveState"] == "active" for name in participants})
            self.journal_loaded(facts)
            return facts

        def disclosure(self, facts):
            return ("Upgrade the existing Tracebolt read-admin device " + facts["deviceId"] + " at " + facts["origin"] +
                    " to " + release["version"] + " (" + release["sourceCommit"] + ").\n" +
                    "Preserve its device identity, private history, counters, inventory consent, journal policy and socket-owner grant epoch. Replace verified agent/enrollment/helper binaries and explicitly rebind the same approved executable contract. No scope or capability is added.\n" +
                    "The owned agent and both helper/socket pairs will stop and drain. Startup enablement is restored after validation. Their systemd failed/start-limit bookkeeping is reset before restarting; historical journal entries and sender counters remain.\n" +
                    "Original approval receipts remain immutable. Public artifact backups and explicit upgrade history are retained. An uncertain failure leaves participants stopped for inspection. Existing socket-tagged pending bytes may be discarded by the ordinary runtime when the helper runtime changes, preserving the monotonic floor.\n" +
                    ("WARNING: Existing HTTP-test reporting remains unencrypted and unauthenticated, including inventory and requested journal content.\n" if facts["profile"] == "http-test" else "") +
                    "No invitation, re-enrollment or new device approval is needed.")

        @contextlib.contextmanager
        def lock(self):
            path = CONTROL + "/install.lock"
            old = ie.read(path, 4096, 0o600)
            self.fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                require(s.same_file(os.fstat(self.fd), os.lstat(path)), "installer-lock-changed")
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                require(ie.read(path, 4096, 0o600) == old, "installer-lock-changed")
                yield
                require(s.same_file(os.fstat(self.fd), os.lstat(path)), "installer-lock-changed")
            finally:
                os.close(self.fd)
                self.fd = None

        def write(self, path, raw, mode=0o600, gid=0, previous=None):
            # Only fixed public bindings and this transaction's own archive.
            allowed = path in PUBLIC or path in (DEPLOYMENT, TRANSACTION) or bool(re.fullmatch(re.escape(CONTROL) + r"/read-admin-upgrade-[0-9a-f]{64}\.complete\.json", path)) or self.archive and str(Path(path).parent) == self.archive
            require(allowed and type(raw) is bytes and 0 < len(raw) <= 128 << 20, "fixed-upgrade-write")
            parent = str(Path(path).parent)
            ie.protected_dir(parent)
            d = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            name = Path(path).name
            temp = name + ".upgrade-stage"
            try:
                require(s.same_file(os.fstat(d), os.lstat(parent)), "upgrade-parent-changed")
                if previous is None:
                    require(ie.absent(path), "upgrade-write-collision")
                else:
                    require(socket.exact_file(ie, path, mode, gid, limit=128 << 20) == previous, "upgrade-original-changed")
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=d)
                try:
                    os.fchown(fd, 0, gid); os.fchmod(fd, mode)
                    view = memoryview(raw)
                    while view:
                        n = os.write(fd, view); require(n > 0, "upgrade-write-failed"); view = view[n:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                if previous is None:
                    # link is exclusive; never overwrite an immutable archive.
                    os.link(temp, name, src_dir_fd=d, dst_dir_fd=d, follow_symlinks=False)
                    os.unlink(temp, dir_fd=d)
                else:
                    require(socket.exact_file(ie, path, mode, gid, limit=128 << 20) == previous, "upgrade-original-changed")
                    os.replace(temp, name, src_dir_fd=d, dst_dir_fd=d)
                os.fsync(d)
                require(socket.exact_file(ie, path, mode, gid, limit=128 << 20) == raw, "upgrade-write-readback")
            finally:
                os.close(d)

        def artifact(self, role):
            spec = assets[role]
            name = spec["path"]
            require(re.fullmatch(r"/tmp/tracebolt-release-[a-z0-9_]{8}/tracebolt-v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?-linux-" + re.escape(arch) + "-" + re.escape(role), name), "verified-upgrade-artifact-path")
            # The verified bootstrap staging directory is the only sticky-parent exception.
            parent = Path(name).parent
            pst = os.lstat(parent); tst = os.lstat("/tmp")
            require(stat.S_ISDIR(pst.st_mode) and pst.st_uid == pst.st_gid == 0 and stat.S_IMODE(pst.st_mode) == 0o700 and stat.S_ISDIR(tst.st_mode) and tst.st_uid == tst.st_gid == 0 and stat.S_IMODE(tst.st_mode) == 0o1777, "upgrade-staging-metadata")
            d = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                require(s.same_file(os.fstat(d), pst), "upgrade-staging-changed")
                fd = os.open(Path(name).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=d)
                try:
                    st = os.fstat(fd)
                    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o500 and st.st_size == spec["size"] and 0 < st.st_size <= 128 << 20, "upgrade-artifact-metadata")
                    chunks = []; size = 0
                    while size <= st.st_size:
                        chunk = os.read(fd, min(65536, st.st_size + 1 - size))
                        if not chunk: break
                        chunks.append(chunk); size += len(chunk)
                    raw = b"".join(chunks)
                    require(size == st.st_size and digest(raw) == spec["sha256"] and s.same_file(st, os.fstat(fd)) and s.same_file(st, os.stat(Path(name).name, dir_fd=d, follow_symlinks=False)) and s.same_file(pst, os.lstat(parent)), "upgrade-artifact-changed")
                    return raw
                finally:
                    os.close(fd)
            finally:
                os.close(d)

        def prepare(self, facts):
            require(self.fd is not None and ie.absent(TRANSACTION), "upgrade-lock-or-intent")
            new = {role: self.artifact(role) for role in roles}
            self.old = {}
            for path, (mode, gid) in dict(PUBLIC, **{DEPLOYMENT: (0o640, facts["receipt"]["helperGid"])}).items():
                self.old[path] = None if path == CURRENT and ie.absent(path) else socket.exact_file(ie, path, mode, gid, limit=128 << 20)
            updated = dict(facts["manifest"], agentHash=assets["lan-agent"]["sha256"], enrollHash=assets["enroll-agent"]["sha256"], sourceHash=source)
            owner = s.strict_json(self.old[OWNER]); owner["installation"] = updated
            self.expected = {AGENT: new["lan-agent"], ENROLL: new["enroll-agent"], HELPER: new["socket-owner-reader"],
                             MANIFEST: canonical(updated) + b"\n", OWNER: canonical(owner) + b"\n"}
            archive = CONTROL + "/read-admin-upgrade-" + secrets.token_hex(32) + ".prepared"
            os.mkdir(archive, 0o700)
            d = os.open(archive, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fchmod(d, 0o700); os.fsync(d)
                require(s.same_file(os.fstat(d), os.lstat(archive)), "upgrade-archive-changed")
                self.archive = archive
            finally: os.close(d)
            plan = canonical(dict(schemaVersion="tracebolt.read-admin-upgrade-prepared.v1", releaseManifestSHA256=release_hash,
                                  previous={p: None if raw is None else digest(raw) for p, raw in self.old.items()},
                                  expected={p: digest(raw) for p, raw in self.expected.items()}, enablement=facts["enablement"], activity=facts["activity"]))
            self.write(self.archive + "/plan.json", plan)
            for index, (path, raw) in enumerate(self.old.items()):
                if raw is not None: self.write(self.archive + "/before-" + str(index), raw)
            self.marker = canonical(dict(version=VERSION, phase="prepared", agentSHA256=assets["lan-agent"]["sha256"], enrollSHA256=assets["enroll-agent"]["sha256"], sourceSHA256=source, previousOwnerSHA256=digest(self.old[OWNER]), historySHA256=digest(plan)))
            self.write(TRANSACTION, self.marker)

        def systemctl(self, verb, unit):
            require(verb in ("stop", "start", "enable", "disable", "reset-failed") and unit in participants and (verb not in ("enable", "disable") or unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET)), "fixed-upgrade-command")
            return s.Effects.command(je, ["/usr/bin/systemctl", verb, unit])

        def drain(self, unit):
            if unit in (s.AGENT_UNIT, socket.SERVICE):
                se.drain(unit)
                return
            require(unit == s.SERVICE, "fixed-upgrade-drain")
            # Same descendant-aware cgroup.events contract as the socket helper.
            parent = "/sys/fs/cgroup/system.slice"
            d = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                try: fd = os.open(unit, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=d)
                except FileNotFoundError: return
                try:
                    event = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try: raw = os.read(event, 4097)
                    finally: os.close(event)
                    rows = [line.split() for line in raw.decode("ascii").splitlines()]
                    require(len(raw) <= 4096 and all(len(row) == 2 for row in rows) and len({r[0] for r in rows}) == len(rows) and dict(rows).get("populated") == "0" and s.same_file(os.fstat(fd), os.stat(unit, dir_fd=d, follow_symlinks=False)), "journal-cgroup-not-drained")
                finally: os.close(fd)
            finally: os.close(d)

        def journal_loaded(self, facts, allow_failed=False, only=None):
            names = (s.SERVICE, s.SOCKET) if only is None else (only,)
            require(all(name in (s.SERVICE, s.SOCKET) for name in names), "fixed-journal-proof")
            for root in socket.ROOTS:
                for name in names:
                    require(ie.absent(root + "/" + name + ".d") and (root == s.UNIT_DIR or ie.absent(root + "/" + name)), "journal-unit-override")
                for name in ("tracebolt-journal-.service.d", "tracebolt-journal-.socket.d", "tracebolt-journal-reader-.service.d", "tracebolt-journal-reader-.socket.d"):
                    require(ie.absent(root + "/" + name), "journal-unit-override")
            for name in names:
                selected = socket.BASIC_FIELDS + (socket.SOCKET_FIELDS if name == s.SOCKET else socket.SERVICE_FIELDS)
                raw = s.Effects.command(je, ["/usr/bin/systemctl", "show", name, "--property=" + ",".join(selected), "--all", "--no-pager"], timeout=5)
                fields = {}
                for line in raw.decode("ascii").splitlines():
                    key, sep, value = line.partition("=")
                    require(sep and key in selected and key not in fields, "journal-loaded-fields")
                    fields[key] = value
                require(set(selected) - set(fields) <= {"PrivatePIDs"}, "journal-loaded-fields")
                require(socket.owned(fields, name) or allow_failed and fields["ActiveState"] == "failed" and socket.owned(dict(fields, ActiveState="inactive"), name), "journal-loaded-ownership")
                if name == s.SOCKET:
                    expected = dict(Listen=s.SOCKET_PATH + " (Stream)", SocketUser="root", SocketGroup=str(facts["gid"]), SocketMode="0660", DirectoryMode="0755", FileDescriptorName="journal-reader", Accept="no", Triggers=s.SERVICE, RemoveOnStop="yes")
                else:
                    expected = dict(User=str(facts["journalHelperUid"]), Group=str(facts["journalHelperGid"]), SupplementaryGroups=str(facts["journalGid"]), CapabilityBoundingSet="", AmbientCapabilities="", NoNewPrivileges="yes", KillMode="control-group", Delegate="no", PrivateNetwork="yes", PrivateUsers="no", NetworkNamespacePath="", JoinsNamespaceOf="", RootDirectory="", RootImage="", ProtectProc="invisible", ProcSubset="pid", RuntimeDirectory="")
                    require(fields.get("PrivatePIDs", "no") == "no" and re.fullmatch(r"[0-9]+", fields["MainPID"]) and fields["ControlGroup"] in ("", "/system.slice/" + name), "journal-loaded-process")
                    argv = [AGENT, "--journal-reader"]
                    expression = r"\{ path=" + re.escape(argv[0]) + r" ; argv\[\]=" + re.escape(" ".join(argv)) + r" ; ignore_errors=no ; start_time=[^;{}]* ; stop_time=[^;{}]* ; pid=[0-9]+ ; code=[^;{}]* ; status=[^;{}]* \}"
                    require(re.fullmatch(expression, fields["ExecStart"]), "journal-loaded-executable")
                require(all(fields.get(k) == v for k, v in expected.items()), "journal-loaded-security-contract")

        def prove_unit_ownership(self, facts, unit):
            require(unit in participants and digest(socket.exact_file(ie, s.UNIT_DIR + "/" + unit, 0o644, 0)) == facts["unitHashes"][unit], "upgrade-unit-artifact-changed")
            if unit in (s.AGENT_UNIT, s.SERVICE):
                require(digest(socket.exact_file(ie, AGENT, 0o555, 0, limit=128 << 20)) in (facts["manifest"]["agentHash"], assets["lan-agent"]["sha256"]), "upgrade-agent-artifact-unproven")
            elif unit == socket.SERVICE:
                require(digest(socket.exact_file(ie, HELPER, 0o755, 0, limit=128 << 20)) in (facts["receipt"]["artifactSHA256"][HELPER], assets["socket-owner-reader"]["sha256"]), "upgrade-helper-artifact-unproven")
            if unit == s.AGENT_UNIT:
                socket.loaded(se, unit, facts["uid"], facts["gid"], socket.agent_argv(s, templates, facts), allow_failed=True)
            elif unit == socket.SERVICE:
                socket.loaded(se, unit, facts["receipt"]["helperUid"], facts["receipt"]["helperGid"], [HELPER], allow_failed=True)
            elif unit == socket.SOCKET:
                socket.loaded(se, unit, 0, facts["gid"], [], allow_failed=True)
            else:
                self.journal_loaded(facts, allow_failed=True, only=unit)

        def prove_stop_ownership(self, facts):
            for unit in participants:
                self.prove_unit_ownership(facts, unit)

        def contain(self, facts):
            # Best effort across independently proven participants. One foreign
            # unit or failed stop must not suppress containment of the others.
            confirmed = True
            for unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET, s.SERVICE, socket.SERVICE):
                try:
                    self.prove_unit_ownership(facts, unit)
                except BaseException:
                    confirmed = False
                    continue
                if unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET):
                    try:
                        self.systemctl("disable", unit)
                    except BaseException:
                        pass  # The final readback decides whether it took effect.
                try:
                    self.prove_unit_ownership(facts, unit)
                    self.systemctl("stop", unit)
                except BaseException:
                    pass
                try:
                    self.prove_unit_ownership(facts, unit)
                    state = se.status(unit) if unit in (socket.SERVICE, socket.SOCKET) else je.status(unit)
                    require(s.owned_unit(state, unit) and state["ActiveState"] in ("inactive", "failed") and (unit in (s.SOCKET, socket.SOCKET) or state["MainPID"] == "0"), "upgrade-unit-not-stopped")
                    if unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET):
                        require(state["UnitFileState"] == "disabled", "upgrade-startup-not-disabled")
                    if unit not in (s.SOCKET, socket.SOCKET):
                        self.drain(unit)
                    else:
                        require((se if unit == socket.SOCKET else je).absent(socket.SOCKET_PATH if unit == socket.SOCKET else s.SOCKET_PATH), "upgrade-socket-admission-remains")
                except BaseException:
                    confirmed = False
            return confirmed

        def quiesce(self, facts):
            self.prove_stop_ownership(facts)
            # Disable admission/startup first. No capabilities or policy change.
            # Retain enablement in the durable prepared record for exact restore.
            for unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET):
                self.systemctl("disable", unit)
            for unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET, s.SERVICE, socket.SERVICE):
                self.systemctl("stop", unit)
                state = se.status(unit) if unit in (socket.SERVICE, socket.SOCKET) else je.status(unit)
                require(s.owned_unit(state, unit) and state["ActiveState"] in ("inactive", "failed") and (unit in (s.SOCKET, socket.SOCKET) or state["MainPID"] == "0"), "upgrade-unit-not-stopped")
                if unit not in (s.SOCKET, socket.SOCKET): self.drain(unit)
            require(se.absent(socket.SOCKET_PATH) and je.absent(s.SOCKET_PATH), "upgrade-socket-admission-remains")
            for unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET):
                state = se.status(unit) if unit == socket.SOCKET else je.status(unit)
                require(state["UnitFileState"] == "disabled", "upgrade-startup-not-disabled")

        def retained(self, facts):
            previews = {key: inventory.configure(s, ie, facts, key, "preview") for key in inventory.selected_scopes(True)}
            require(all(p["enabled"] for p in previews.values()), "existing-inventory-consent-disabled")
            for key in previews: inventory.check_shape(ie.scope_shape(facts["uid"], facts["gid"], key), key, True)
            j = amendment.inspect(s, je, templates)
            journal = amendment.command(s, je, j, "preview", j["policy"])
            consent = socket.cli(s, se, facts, "preview")
            require(consent["state"] == "enabled" and consent["identity"] == facts["receipt"]["identity"] and consent["policy"] == facts["receipt"]["policy"], "existing-socket-consent-changed")
            se.validate(facts)
            # Use the same checked interpreter as the verified release bootstrap.
            python = str(Path(sys.executable).resolve())
            ie.read(python, 128 << 20)
            proc = subprocess.run([python, "-I", "-c", STATE_DIGEST], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env=s.ENV, cwd="/", close_fds=True, user=facts["uid"], group=facts["gid"], extra_groups=[], timeout=45)
            require(proc.returncode == 0 and re.fullmatch(b"[0-9a-f]{64}\n", proc.stdout), "private-state-digest-unconfirmed")
            return dict(inventory=previews, journal=journal, socket=consent, privateStateSHA256=proc.stdout.decode().strip(), journalFiles=socket.journal_snapshot(se))

        def native_upgrade(self, facts):
            record = s.strict_json(self.marker); record["phase"] = "native-ready"
            updated = canonical(record)
            self.write(TRANSACTION, updated, previous=self.marker); self.marker = updated
            # Recheck selected release executables immediately before execution.
            for role in roles: self.artifact(role)
            require(self.fd is not None and command[0] == assets["agent-service"]["path"], "fixed-native-upgrade-command")
            self.native_attempted = True
            args = command + ["--read-admin-upgrade-lock-fd", str(self.fd)]
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=s.ENV, cwd="/", close_fds=True, pass_fds=(self.fd,), start_new_session=True)
            try:
                raw, _ = child.communicate(timeout=180)
                require(len(raw) <= 65536 and child.returncode == 0, "native-upgrade-unconfirmed")
                result = s.strict_json(raw)
                require(result.get("committed") is True and result.get("serviceLeftStopped") is True and result.get("identityRetained") is True, "native-left-stopped-unconfirmed")
                self.native_complete = True
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try: child.wait(timeout=45)
                    except subprocess.TimeoutExpired: os.killpg(child.pid, signal.SIGKILL); child.wait()
            for path in (AGENT, ENROLL, MANIFEST, OWNER):
                mode, gid = PUBLIC[path]
                require(socket.exact_file(ie, path, mode, gid, limit=128 << 20) == self.expected[path], "native-upgrade-artifact-mismatch")

        def rebind(self, facts):
            helper = self.artifact("socket-owner-reader")
            self.write(HELPER, helper, 0o755, previous=self.old[HELPER])
            hashes = dict(facts["receipt"]["artifactSHA256"], **{AGENT: assets["lan-agent"]["sha256"], HELPER: assets["socket-owner-reader"]["sha256"]})
            deployment = socket.deployment(facts["receipt"]["policy"], hashes)
            raw = socket.canonical(deployment)
            self.expected[DEPLOYMENT] = raw
            self.write(DEPLOYMENT, raw, 0o640, facts["receipt"]["helperGid"], previous=self.old[DEPLOYMENT])
            record = dict(schemaVersion="tracebolt.read-admin-upgrade-binding.v1", originalParentSHA256=digest(ie.read(w.RECEIPT, 16384, 0o600)),
                          originalSocketSHA256=digest(ie.read(socket.COMPLETE, 16384, 0o600)), previousBindingSHA256="" if self.old[CURRENT] is None else digest(self.old[CURRENT]),
                          installation=s.strict_json(self.expected[MANIFEST]), ownerHash=digest(self.expected[OWNER]), deployment=deployment,
                          artifactSHA256=hashes, releaseManifestSHA256=release_hash)
            current = socket.canonical(record)
            self.expected[CURRENT] = current
            self.write(CONTROL + "/read-admin-upgrade-" + digest(current) + ".complete.json", current)
            self.write(CURRENT, current, previous=self.old[CURRENT])

        def reset_restart_state(self, facts, unit):
            require(unit in (s.AGENT_UNIT, s.SERVICE, socket.SERVICE), "fixed-upgrade-reset-unit")
            self.prove_unit_ownership(facts, unit)
            try:
                self.systemctl("reset-failed", unit)
            except s.Rejected as exc:
                if str(exc) != "fixed-command-failed":
                    raise
                # ResetFailedUnit does not load units. An inactive unit may have
                # been garbage-collected after the ownership proof, discarding
                # its counters. Unlike show, this exact-name enumeration never
                # loads it. A listed unit still requires a successful reset,
                # even when inactive with Result=success and NRestarts=0.
                listed = s.Effects.command(je, ["/usr/bin/systemctl", "list-units", "--all", "--full",
                                               "--plain", "--no-legend", unit], limit=4096, timeout=5)
                require(listed == b"", "upgrade-reset-loaded-unit-unconfirmed")
                self.prove_unit_ownership(facts, unit)
                state = se.status(unit) if unit == socket.SERVICE else je.status(unit)
                require(s.owned_unit(state, unit) and state["ActiveState"] == "inactive" and
                        state["MainPID"] == "0", "upgrade-reset-stopped-unit-unconfirmed")
                self.drain(unit)

        def restore(self, original, current):
            self.restore_step = "reset-restart-state"
            for unit in (s.AGENT_UNIT, s.SERVICE, socket.SERVICE): self.reset_restart_state(current, unit)
            self.restore_step = "enablement"
            for unit in (s.AGENT_UNIT, s.SOCKET, socket.SOCKET):
                if original["enablement"][unit] == "enabled": self.systemctl("enable", unit)
            self.restore_step = "helpers"
            for unit in (s.SOCKET, socket.SOCKET, s.SERVICE, socket.SERVICE):
                if original["activity"][unit]: self.systemctl("start", unit)
            self.restore_step = "socket-proof"
            socket.runtime_configuration(se, current, current["receipt"])
            self.restore_step = "journal-proof"
            j = amendment.inspect(s, je, templates)
            require(j["policy"] == original["journalPolicy"] and j["identity"] == original["journalIdentity"] and j["activity"][s.SOCKET], "journal-runtime-handoff-unconfirmed")
            self.restore_step = "agent-validation"
            se.validate(current)
            self.restore_step = "agent-start"
            if original["active"]:
                self.systemctl("start", s.AGENT_UNIT)
                socket.loaded(se, s.AGENT_UNIT, current["uid"], current["gid"], socket.agent_argv(s, templates, current), active="active")
            self.restore_step = "final-enablement"
            for unit in participants:
                state = se.status(unit) if unit in (socket.SERVICE, socket.SOCKET) else je.status(unit)
                require(state["UnitFileState"] == original["enablement"][unit], "startup-enablement-changed")

        def commit(self):
            require(ie.read(TRANSACTION, 4096, 0o600) == self.marker, "upgrade-intent-changed")
            # Preserve the completed coordinator marker in the private archive.
            require(ie.absent(self.archive + "/transaction.complete.json"), "upgrade-completion-collision")
            os.rename(TRANSACTION, self.archive + "/transaction.complete.json")
            for parent in (CONTROL, self.archive):
                fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try: os.fsync(fd)
                finally: os.close(fd)

        def rollback(self, original):
            if self.archive is None or self.marker is None:
                return False
            # Unknown native commit/rollback status must never be guessed around.
            if self.native_attempted and not self.native_complete: return False
            if not ie.absent(CONTROL + "/transaction.json"): return False
            if self.native_complete:
                for path in (CURRENT, DEPLOYMENT, HELPER, OWNER, MANIFEST, ENROLL, AGENT):
                    old = self.old[path]
                    mode, gid = (0o640, original["receipt"]["helperGid"]) if path == DEPLOYMENT else PUBLIC[path]
                    now = None if ie.absent(path) else socket.exact_file(ie, path, mode, gid, limit=128 << 20)
                    if now == old: continue
                    require(now == self.expected.get(path), "rollback-foreign-artifact")
                    if old is None:
                        require(path == CURRENT, "rollback-fixed-absence")
                        os.unlink(path)
                        fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        try: os.fsync(fd)
                        finally: os.close(fd)
                    else: self.write(path, old, mode, gid, previous=now)
            # Marker/backups/history remain, even after proven rollback. Startup
            # remains disabled until a separately reviewed recovery decision.
            evidence = canonical(dict(schemaVersion="tracebolt.read-admin-upgrade-rollback.v1", stopped=True, privateStateRestored=False, originalReceiptPreserved=True))
            self.write(self.archive + "/rollback.complete.json", evidence)
            return True

    return Adapter()
