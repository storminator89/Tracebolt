#!/usr/bin/env python3
"""Archive only an exact marker-only failed account-creation attempt.

Default is a read-only plan. Archive and fresh setup are separate operations.
No account creation, policy adoption, deletion, repair or journal collection.
"""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location("journal_setup", Path(__file__).with_name("setup.py"))
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)
BACKUP = "/etc/tracebolt-journal-account-attempt-backup"
ARCHIVE = BACKUP + "/tracebolt"
# Fixed trusted nonroot code; it reads no keys or ledgers and returns one boolean.
ABSENCE_PROBE = r'''
import os
import sys
import stat
import json
import re

_SUCCESS = b'{"journalStateAbsent":true}\n'
_FIELDS = frozenset(("schemaVersion", "profile", "managerOrigin", "agentId",
                     "certificateFile", "privateKeyFile", "serverCAFile",
                     "stateDirectory", "insecureHTTPAcknowledged",
                     "collectionProfile"))
_BASE = "/var/lib/tracebolt-agent/enrollment"
_LIMIT = 16384


def _require(value):
    if not value:
        raise ValueError()


def _signature(st):
    # atime intentionally excluded: our own bounded read may change it.
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _pairs(items):
    out = {}
    for key, value in items:
        _require(key not in out)
        out[key] = value
    return out


def _config(raw):
    _require(0 < len(raw) <= _LIMIT)
    text = raw.decode("utf-8", "strict")
    _require("\ufffd" not in text)
    c = json.loads(text, object_pairs_hook=_pairs)
    _require(type(c) is dict and set(c) == _FIELDS)
    _require(type(c["insecureHTTPAcknowledged"]) is bool)
    for key in _FIELDS - {"insecureHTTPAcknowledged"}:
        _require(type(c[key]) is str and c[key].isascii())
    _require(c["schemaVersion"] == "tracebolt.lan-agent.v5" and
             c["collectionProfile"] == "managed-operations-v3")
    _require(c["stateDirectory"] == _BASE + "/telemetry")
    _require(c["certificateFile"] == _BASE + "/agent-cert.pem" and
             c["privateKeyFile"] == _BASE + "/agent-key.pem")
    _require(re.fullmatch(r"agent_[0-9a-f]{32}", c["agentId"]))
    if c["profile"] == "tls":
        _require(c["insecureHTTPAcknowledged"] is False and
                 c["serverCAFile"] == _BASE + "/server-ca.pem")
    else:
        _require(c["profile"] == "http-test" and
                 c["insecureHTTPAcknowledged"] is True and c["serverCAFile"] == "")
    # The prior fresh consent preview validates origin/handoff against the plan.
    # This recovery probe deliberately does not duplicate Go routing policy.
    _require(1 <= len(c["managerOrigin"]) <= 512)


def _probe(fs, uid, gid):
    # fs is an injection-only unit-test seam. Production passes only stdlib os.
    _require(type(uid) is int and type(gid) is int and 0 < uid < 2**32 - 1 and
             0 < gid < 2**32 - 1)
    _require(fs.getresuid() == (uid, uid, uid) and
             fs.getresgid() == (gid, gid, gid) and fs.getgroups() == [])
    directory_flags = fs.O_RDONLY | fs.O_DIRECTORY | fs.O_NOFOLLOW | fs.O_CLOEXEC
    file_flags = fs.O_RDONLY | fs.O_NOFOLLOW | fs.O_CLOEXEC | fs.O_NONBLOCK
    opened = []
    snapshots = []

    def remember(fd, parent, name, before):
        opened.append(fd)
        after = fs.fstat(fd)
        _require(_signature(before) == _signature(after))
        snapshots.append((fd, parent, name, before))
        return fd

    def directory(parent, name, private):
        before = fs.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(stat.S_ISDIR(before.st_mode))
        if private:
            _require(before.st_uid == uid and before.st_gid == gid and
                     stat.S_IMODE(before.st_mode) == 0o700)
        else:
            _require(before.st_uid == 0 and before.st_gid == 0 and
                     stat.S_IMODE(before.st_mode) & 0o7022 == 0)
        return remember(fs.open(name, directory_flags, dir_fd=parent), parent, name, before)

    def check_stable():
        for fd, parent, name, before in reversed(snapshots):
            _require(_signature(fs.fstat(fd)) == _signature(before))
            _require(_signature(fs.stat(name, dir_fd=parent, follow_symlinks=False)) ==
                     _signature(before))

    def journal_absent(telemetry):
        try:
            fs.stat("journal", dir_fd=telemetry, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError()

    try:
        root = directory(None, "/", False)
        var = directory(root, "var", False)
        lib = directory(var, "lib", False)
        agent = directory(lib, "tracebolt-agent", True)
        enrollment = directory(agent, "enrollment", True)
        before = fs.stat("agent.json", dir_fd=enrollment, follow_symlinks=False)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and
                 before.st_gid == gid and stat.S_IMODE(before.st_mode) == 0o600 and
                 before.st_nlink == 1 and 0 < before.st_size <= _LIMIT)
        config_fd = remember(fs.open("agent.json", file_flags, dir_fd=enrollment),
                             enrollment, "agent.json", before)
        raw = bytearray()
        while len(raw) <= _LIMIT:
            part = fs.read(config_fd, _LIMIT + 1 - len(raw))
            if not part:
                break
            raw.extend(part)
        _require(len(raw) == before.st_size)
        _config(bytes(raw))
        telemetry = directory(enrollment, "telemetry", True)
        journal_absent(telemetry)
        check_stable()
        journal_absent(telemetry)
        check_stable()
    finally:
        for fd in reversed(opened):
            fs.close(fd)


def _main(fs, argv):
    try:
        _require(len(argv) == 3)
        _require(all(re.fullmatch(r"[1-9][0-9]{0,9}", value) for value in argv[1:]))
        _probe(fs, int(argv[1]), int(argv[2]))
        _require(fs.write(1, _SUCCESS) == len(_SUCCESS))
        return 0
    except BaseException:
        return 1


if __name__ == "__main__":
    sys.exit(_main(os, sys.argv))
'''


def identity(st):
    return {k: getattr(st, k) for k in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                                       "st_size", "st_mtime_ns", "st_ctime_ns")}


def same_object(a, b):
    return all(getattr(a, k) == getattr(b, k) for k in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode"))


class Effects(s.Effects):
    def marker(self):
        self.protected_dir(s.CONFIG_DIR)
        fd = os.open(s.CONFIG_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            s.require(before.st_uid == before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o755,
                      "marker-directory-ownership")
            with os.scandir(fd) as entries:
                names = []
                for item in entries:
                    names.append(item.name)
                    s.require(len(names) <= 1, "marker-directory-not-singleton")
            s.require(names == [Path(s.ATTEMPT).name], "marker-directory-not-singleton")
            marker_before = os.stat(Path(s.ATTEMPT).name, dir_fd=fd, follow_symlinks=False)
            raw = self.read(s.ATTEMPT, 4096, 0o600)
            marker = os.stat(Path(s.ATTEMPT).name, dir_fd=fd, follow_symlinks=False)
            s.require(marker.st_gid == 0 and s.same_file(marker_before, marker) and
                      s.same_file(marker, os.lstat(s.ATTEMPT)) and
                      s.same_file(before, os.fstat(fd)) and s.same_file(before, os.lstat(s.CONFIG_DIR)),
                      "marker-identity-changed")
            return raw, before, marker
        finally:
            os.close(fd)

    def journal_absent(self, facts):
        # Use the current trusted system interpreter; it may be a root-owned symlink.
        interpreter = str(Path(sys.executable).resolve())
        s.require(s.re.fullmatch(r"/usr/bin/python3(?:\.[0-9]+)?", interpreter),
                  "fixed-recovery-interpreter")
        self.read(interpreter, 256 << 20)
        s.require(ABSENCE_PROBE, "missing-recovery-probe")
        child = subprocess.Popen([interpreter, "-I", "-S", "-c", ABSENCE_PROBE, str(facts["uid"]), str(facts["gid"])],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=s.ENV, cwd="/", close_fds=True, user=facts["uid"], group=facts["gid"],
            extra_groups=[], start_new_session=True)
        output = bytearray()
        try:
            with s.selectors.DefaultSelector() as selected:
                selected.register(child.stdout, s.selectors.EVENT_READ)
                until = s.time.monotonic() + 5
                while selected.get_map():
                    s.require(s.time.monotonic() < until, "journal-state-probe-timeout")
                    for key, _ in selected.select(min(0.2, max(0, until - s.time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65)
                        if not chunk:
                            selected.unregister(key.fileobj)
                        output.extend(chunk)
                        s.require(len(output) <= 64, "journal-state-probe-output-limit")
            s.require(child.wait(timeout=max(0.01, until - s.time.monotonic())) == 0 and
                      output == b'{"journalStateAbsent":true}\n', "journal-state-absence-not-confirmed")
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            child.stdout.close()

    def archive(self, snapshot):
        # Kernel RENAME_NOREPLACE is required; no unsafe overwrite or copy fallback.
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        s.require(rename is not None, "no-clobber-rename-unavailable")
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        self.protected_dir("/etc")
        parent = os.open("/etc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        backup_fd = source_fd = None
        try:
            parent_id = os.fstat(parent)
            s.require(s.same_file(parent_id, os.lstat("/etc")) and self.absent(BACKUP), "archive-parent-changed")
            source_fd = os.open("tracebolt", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            s.require(self.marker_snapshot() == snapshot and identity(os.fstat(source_fd)) == snapshot["directory"],
                      "marker-identity-changed")
            os.mkdir(Path(BACKUP).name, 0o700, dir_fd=parent)
            backup_fd = os.open(Path(BACKUP).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.fchown(backup_fd, 0, 0)
            os.fchmod(backup_fd, 0o700)
            backup_id = os.fstat(backup_fd)
            s.require(backup_id.st_uid == backup_id.st_gid == 0 and stat.S_IMODE(backup_id.st_mode) == 0o700 and
                      s.same_file(backup_id, os.stat(Path(BACKUP).name, dir_fd=parent, follow_symlinks=False)),
                      "archive-parent-changed")
            os.fsync(backup_fd)
            os.fsync(parent)
            s.require(self.marker_snapshot() == snapshot and same_object(parent_id, os.lstat("/etc")),
                      "marker-identity-changed")
            s.require(rename(parent, b"tracebolt", backup_fd, b"tracebolt", 1) == 0, "archive-no-clobber-rename-failed")
            moved = os.stat("tracebolt", dir_fd=backup_fd, follow_symlinks=False)
            s.require(same_object(os.fstat(source_fd), moved) and
                      moved.st_dev == snapshot["directory"]["st_dev"] and moved.st_ino == snapshot["directory"]["st_ino"] and
                      self.absent(s.CONFIG_DIR), "archive-identity-not-confirmed")
            marker = os.stat(Path(s.ATTEMPT).name, dir_fd=source_fd, follow_symlinks=False)
            s.require(identity(marker) == snapshot["marker"], "archive-marker-changed")
            marker_fd = os.open(Path(s.ATTEMPT).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                dir_fd=source_fd)
            try:
                preserved = os.read(marker_fd, 4097)
                s.require(identity(os.fstat(marker_fd)) == snapshot["marker"] and
                          s.digest(preserved) == snapshot["sha256"], "archive-marker-changed")
            finally:
                os.close(marker_fd)
            s.require(same_object(backup_id, os.stat(Path(BACKUP).name, dir_fd=parent, follow_symlinks=False)) and
                      same_object(parent_id, os.lstat("/etc")), "archive-parent-changed")
            os.fsync(source_fd)
            os.fsync(backup_fd)
            os.fsync(parent)
        finally:
            for fd in (source_fd, backup_fd, parent):
                if fd is not None:
                    os.close(fd)

    def marker_snapshot(self):
        raw, directory, marker = self.marker()
        return dict(sha256=s.digest(raw), directory=identity(directory), marker=identity(marker))


class MarkerOnlyPreflight:
    """Replace only the absent config directory check AFTER singleton validation."""
    def __init__(self, effects):
        self.effects = effects

    def __getattr__(self, name):
        return getattr(self.effects, name)

    def absent(self, path):
        return True if path == s.CONFIG_DIR else self.effects.absent(path)


def plan(e, units, templates, expected_original):
    s.require(s.valid_digest(expected_original), "original-plan-required")
    raw, directory, metadata = e.marker()
    marker = s.strict_json(raw, ("schemaVersion", "planSHA256", "senderBinding", "deviceId", "certificateHash"))
    s.require(raw == s.canonical(marker) and marker["schemaVersion"] == "tracebolt.journal-setup-attempt.v1" and
              marker["planSHA256"] == expected_original and s.valid_digest(marker["senderBinding"]) and
              s.valid_digest(marker["certificateHash"]) and isinstance(marker["deviceId"], str) and
              s.re.fullmatch(r"agent_[0-9a-f]{32}", marker["deviceId"]), "exact-attempt-marker")
    s.require(e.absent(BACKUP), "archive-destination-exists")
    facts, original = s.preflight(MarkerOnlyPreflight(e), units, templates)
    s.require(s.digest(s.canonical(original)) == expected_original, "original-plan-changed")
    snapshot = dict(sha256=s.digest(raw), directory=identity(directory), marker=identity(metadata))
    out = dict(schemaVersion="tracebolt.journal-account-attempt-archive-plan.v1", originalPlan=original,
               originalPlanSHA256=expected_original, attempt=snapshot, archiveDirectory=ARCHIVE,
               backupParentMode="0700", stoppedIdentityAndStateAbsenceRequired=True,
               restorePreviouslyActiveAgent=True, archiveOnly=True, setupApplySeparate=True)
    return facts, marker, snapshot, out


def archive(e, units, templates, expected_original, expected_archive):
    with e.lock():
        facts, marker, snapshot, reviewed = plan(e, units, templates, expected_original)
        s.require(s.valid_digest(expected_archive) and s.digest(s.canonical(reviewed)) == expected_archive,
                  "archive-reviewed-plan-changed")
        stopped = False
        out = dict(archived=False, sourceVerified=False, contentRead=False, agentRestarted=False,
                   retainedPartialState=True, setupApplySeparate=True)
        error = None
        try:
            stopped = True
            e.command(["/usr/bin/systemctl", "stop", s.AGENT_UNIT], failure_stage="agent-stop-command-failed")
            current = e.status(s.AGENT_UNIT)
            s.require(s.owned_unit(current, s.AGENT_UNIT, "inactive") and current["MainPID"] == "0", "stopped-agent")
            s.require(s.same_agent(facts, s.inspect_agent(e, templates)), "agent-changed-after-stop")
            preview = s.consent_command(e, "preview", facts)
            s.require(all(preview[k] == marker[k] for k in ("senderBinding", "deviceId", "certificateHash")),
                      "attempt-identity-changed")
            again, _, actual, fresh = plan(e, units, templates, expected_original)
            s.require(s.same_agent(facts, again) and actual == snapshot and fresh == reviewed,
                      "archive-reviewed-plan-changed")
            e.journal_absent(facts)
            e.archive(snapshot)
            out.update(archived=True, attemptPreserved=True, archiveDirectory=ARCHIVE)
        except (s.Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError) as exc:
            # Exceptions carry no stderr, path or config data.
            error = exc if isinstance(exc, s.Rejected) else s.Rejected("archive-operation-failed-retain-state")
        finally:
            if stopped and facts["active"]:
                try:
                    s.require(s.same_agent(facts, s.inspect_agent(e, templates)), "agent-restart-ownership")
                    e.command(["/usr/bin/systemctl", "start", s.AGENT_UNIT], failure_stage="agent-restart-command-failed")
                    s.require(s.owned_unit(e.status(s.AGENT_UNIT), s.AGENT_UNIT, "active"), "agent-restart-status")
                    out["agentRestarted"] = True
                except (s.Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError):
                    error = s.Rejected("agent-restart-blocked-retain-state")
        if error:
            out["failureStage"] = str(error)
        return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-unit", action="append", required=True)
    parser.add_argument("--original-plan-sha256", required=True)
    parser.add_argument("--archive", action="store_true")
    parser.add_argument("--expected-archive-plan-sha256")
    args = parser.parse_args(argv)
    signal.signal(signal.SIGINT, s.interrupted)
    signal.signal(signal.SIGTERM, s.interrupted)
    try:
        s.require(sys.platform == "linux" and os.geteuid() == 0, "root-linux-local-administration")
        e = Effects()
        e.read(str(Path(__file__).resolve()), 65536)
        e.read(str(Path(__file__).with_name("setup.py").resolve()), 65536)
        templates = s.read_templates(e)
        units = s.selected_units(args.allow_unit)
        if args.archive:
            result = archive(e, units, templates, args.original_plan_sha256, args.expected_archive_plan_sha256)
            print(json.dumps(result, indent=2))
            return 0 if result["archived"] and "failureStage" not in result else 1
        s.require(not args.expected_archive_plan_sha256, "plan-does-not-accept-archive-flags")
        _, _, _, result = plan(e, units, templates, args.original_plan_sha256)
        print(json.dumps(dict(plan=result, archivePlanSHA256=s.digest(s.canonical(result))), indent=2))
        return 0
    except (s.Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError) as exc:
        print(json.dumps(dict(archived=False, failureStage=str(exc) if isinstance(exc, s.Rejected) else "archive-preflight-failed",
                              warning="Preserve all existing and partial state. No automatic cleanup or retry.")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
