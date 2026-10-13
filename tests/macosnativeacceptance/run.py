#!/usr/bin/env python3
"""Default-inert, manually admitted macOS evidence supervisor. No product setup."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import types

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 1
REPORT_LIMIT = 64 * 1024
SOURCE_LIMIT = 128 * 1024 * 1024
SOURCE_FILE_LIMIT = 8 * 1024 * 1024
BINARY_LIMIT = 32 * 1024 * 1024
COMPILER_LIMIT = 256 * 1024 * 1024
MANUAL_LIMIT = 1024 * 1024
MANUAL_SHA256 = "d89cb620dbcab9e849161d2f3c63c4be62c5bd8240bba851d395a09fc7504c08"
RUNNERS = {"macos-15": ("ARM64", "arm64"), "macos-15-intel": ("X64", "x86_64")}
BASE_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
SOURCE_FIXED = ("go.mod", "go.sum", ".github/workflows/macos-native-acceptance.yml", "docs/macos-native-acceptance.md")
HARNESS_REQUIRED = ("run.py", "test_run.py", "log_probe.py", "test_log_probe.py", "emitter.c")
TOOL_PATHS = {"sysctl": "/usr/sbin/sysctl", "pkgutil": "/usr/sbin/pkgutil", "ps": "/bin/ps", "ifconfig": "/sbin/ifconfig", "log": "/usr/bin/log"}
VERSION_COMMANDS = {
    "productVersion": (("/usr/bin/sw_vers", "-productVersion"), r"15(?:\.[0-9]{1,3}){1,2}"),
    "productBuild": (("/usr/bin/sw_vers", "-buildVersion"), r"[0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?"),
    "darwinRelease": (("/usr/bin/uname", "-r"), r"[0-9]{1,3}(?:\.[0-9]{1,3}){2}"),
    "machine": (("/usr/bin/uname", "-m"), r"arm64|x86_64"),
}
REASONS = {"ok", "not_selected", "dispatch_not_admitted", "source_mismatch", "source_invalid", "preparation_failed", "metadata_unavailable", "identity_unavailable", "configuration_present_or_unknown", "manual_changed_or_unavailable", "probe_failed", "probe_schema_rejected", "native_deadline", "cancelled", "cleanup_failed", "internal_failure"}
PROCESS_REASONS = {"ok", "spawn_failed", "timeout", "output_limit", "read_failed", "nonzero_exit", "stderr_output", "reap_failed"}


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "internal_failure"


class Cancelled(BaseException):
    pass


class NativeDeadline(BaseException):
    pass


def strict_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def strict_json(data):
    if len(data) > REPORT_LIMIT:
        raise ValueError("oversize")
    return json.loads(data.decode("utf-8"), object_pairs_hook=strict_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))


def bounded_hash(path, maximum=BINARY_LIMIT, seconds=5):
    """Read one regular, stable file without following its final symlink."""
    start = time.monotonic()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise Refused("metadata_unavailable")
        digest = hashlib.sha256()
        count = 0
        while True:
            if time.monotonic() - start >= seconds:
                raise Refused("metadata_unavailable")
            chunk = os.read(fd, min(65536, maximum + 1 - count))
            if time.monotonic() - start >= seconds:
                raise Refused("metadata_unavailable")
            if not chunk:
                break
            count += len(chunk)
            if count > maximum:
                raise Refused("metadata_unavailable")
            digest.update(chunk)
        after = os.fstat(fd)
        if count != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise Refused("metadata_unavailable")
        if time.monotonic() - start >= seconds:
            raise Refused("metadata_unavailable")
        return digest.hexdigest(), count
    finally:
        os.close(fd)


def installed_manual_hash():
    """Same fixed uncompressed manual path/custody/128KiB/256KiB/5s boundary."""
    deadline = time.monotonic() + 5
    descriptors = []
    def remaining():
        if time.monotonic() >= deadline:
            raise Refused("manual_changed_or_unavailable")
    def checked_open(part, parent=None, directory=False):
        remaining()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(part, flags, **({"dir_fd": parent} if parent is not None else {}))
        descriptors.append(fd)
        info = os.fstat(fd)
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refused("manual_changed_or_unavailable")
        return fd, info
    try:
        parent, _ = checked_open("/", directory=True)
        for part in ("usr", "share", "man", "man1"):
            parent, _ = checked_open(part, parent, directory=True)
        fd, before = checked_open("log.1", parent)
        if not 0 < before.st_size <= 128 * 1024:
            raise Refused("manual_changed_or_unavailable")
        raw = bytearray()
        while True:
            remaining()
            data = os.read(fd, min(4096, 128 * 1024 + 1 - len(raw)))
            if not data:
                break
            raw.extend(data)
            if len(raw) > 128 * 1024:
                raise Refused("manual_changed_or_unavailable")
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise Refused("manual_changed_or_unavailable")
        # This exact installed source is uncompressed; no alternate path/decoder.
        remaining()
        if not raw or len(raw) > 256 * 1024:
            raise Refused("manual_changed_or_unavailable")
        text = bytes(raw).decode("utf-8", errors="strict")
        if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} and c not in "\t\r\n" for c in text) or not re.search(r'^\.Dt\s+"?log"?\s+1(?:\s|$)', text, re.M | re.I) or not re.search(r'^\.Sh\s+"?NAME"?\s*$', text, re.M | re.I) or not re.search(r'^\.Sh\s+"?SYNOPSIS"?\s*$', text, re.M | re.I):
            raise Refused("manual_changed_or_unavailable")
        remaining()
        return hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError):
        raise Refused("manual_changed_or_unavailable") from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def verify_source_unchanged(manifest):
    if source_manifest(ROOT) != manifest:
        raise Refused("source_mismatch")


def verify_binary_custody(tree, name, expected):
    if name not in ("inventory-probe", "tracebolt-native-log-probe") or not _hash(expected):
        raise Refused("source_mismatch")
    # Recheck protected task components and inode immediately before execution.
    root = tree.path
    if root.resolve(strict=True) != root or (root.stat().st_dev, root.stat().st_ino) != tree.identity:
        raise Refused("source_mismatch")
    rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        rootinfo = os.fstat(rootfd)
        if (rootinfo.st_dev, rootinfo.st_ino) != tree.identity or rootinfo.st_uid != tree.uid or stat.S_IMODE(rootinfo.st_mode) != 0o700:
            raise Refused("source_mismatch")
        bindir = os.open("bin", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
        try:
            bindir_info = os.fstat(bindir)
            if bindir_info.st_uid != tree.uid or stat.S_IMODE(bindir_info.st_mode) != 0o700:
                raise Refused("source_mismatch")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=bindir)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_uid != tree.uid or before.st_mode & 0o022 or not before.st_mode & 0o100 or before.st_nlink != 1 or not 0 < before.st_size <= BINARY_LIMIT:
                    raise Refused("source_mismatch")
                deadline = time.monotonic() + 5
                digest, count = hashlib.sha256(), 0
                while True:
                    if time.monotonic() >= deadline:
                        raise Refused("source_mismatch")
                    data = os.read(fd, min(65536, BINARY_LIMIT + 1 - count))
                    if time.monotonic() >= deadline:
                        raise Refused("source_mismatch")
                    if not data:
                        break
                    count += len(data)
                    if count > BINARY_LIMIT:
                        raise Refused("source_mismatch")
                    digest.update(data)
                after = os.fstat(fd)
                fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
                if time.monotonic() >= deadline or count != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields) or digest.hexdigest() != expected:
                    raise Refused("source_mismatch")
            finally:
                os.close(fd)
        finally:
            os.close(bindir)
    finally:
        os.close(rootfd)

def source_manifest(root=ROOT):
    """No process, platform/identity lookup, provider or compiler. Public source only."""
    root = Path(root)
    paths = set(SOURCE_FIXED)
    for prefix in ("internal", "tests/macosnativeacceptance"):
        base = root / prefix
        if base.is_symlink() or not base.is_dir():
            raise Refused("source_invalid")
        for directory, dirs, files in os.walk(base, followlinks=False):
            dirs.sort()
            if any((Path(directory) / name).is_symlink() for name in dirs):
                raise Refused("source_invalid")
            dirs[:] = [name for name in dirs if name != "__pycache__"]
            for name in sorted(files):
                if name.endswith(".pyc"):
                    continue
                paths.add((Path(directory) / name).relative_to(root).as_posix())
    if len(paths) > 8192 or not all("tests/macosnativeacceptance/" + p in paths for p in HARNESS_REQUIRED):
        raise Refused("source_invalid")
    if not any(p.startswith("tests/macosnativeacceptance/inventoryprobe/") and p.endswith(".go") for p in paths):
        raise Refused("source_invalid")
    digest = hashlib.sha256(b"tracebolt-macos-native-source-v1\n")
    total = 0
    harness = {}
    for relative in sorted(paths):
        path = root / relative
        # Reject aliased parents as well as symlink files.
        if path.resolve() != path.absolute():
            raise Refused("source_invalid")
        value, size = bounded_hash(path, SOURCE_FILE_LIMIT)
        total += size
        if total > SOURCE_LIMIT:
            raise Refused("source_invalid")
        mode = stat.S_IMODE(path.stat().st_mode)
        digest.update((relative + "\0" + ("x" if mode & 0o111 else "-") + "\0" + str(size) + "\0" + value + "\n").encode())
        if relative in SOURCE_FIXED or relative in {"tests/macosnativeacceptance/" + n for n in HARNESS_REQUIRED} or relative in {"tests/macosnativeacceptance/inventoryprobe/" + n for n in ("main.go", "main_test.go", "probe.go", "probe_test.go", "README.md")}:
            harness[relative] = value
    return {"sha256": digest.hexdigest(), "fileCount": len(paths), "bytes": total, "files": harness}


def hosted_admission(env, platform, manifest):
    label = env.get("TRACEBOLT_RUNNER_LABEL")
    if platform != "darwin" or label not in RUNNERS:
        raise Refused("dispatch_not_admitted")
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "storminator89/Tracebolt", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": RUNNERS[label][0], "TRACEBOLT_REPOSITORY_VISIBILITY": "public", "GITHUB_RUN_ATTEMPT": "1"}
    if any(env.get(k) != v for k, v in expected.items()):
        raise Refused("dispatch_not_admitted")
    sha = env.get("TRACEBOLT_REVIEWED_COMMIT", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or sha != env.get("GITHUB_SHA") or sha != env.get("GITHUB_WORKFLOW_SHA"):
        raise Refused("source_mismatch")
    review = env.get("TRACEBOLT_REVIEWED_SOURCE_SHA256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", review) or review != manifest["sha256"]:
        raise Refused("source_mismatch")
    a, b = env.get("TRACEBOLT_SELECT_GATE_A"), env.get("TRACEBOLT_SELECT_GATE_B")
    if a not in ("true", "false") or b not in ("true", "false") or (a, b) == ("false", "false"):
        raise Refused("dispatch_not_admitted")
    return {"runnerLabel": label, "runnerArch": RUNNERS[label][0], "commit": sha, "gateASelected": a == "true", "gateBSelected": b == "true"}


def elapsed_milliseconds(started, maximum=1200000):
    value = int((time.monotonic() - started) * 1000)
    return value if 0 <= value <= maximum else None


@dataclass
class Capture:
    data: bytes
    metadata: dict


class Processes:
    """Own direct children; do not invent visibility into collector-internal children."""
    def __init__(self):
        self.started = 0
        self.reaped = 0
        self.active = set()
        self.completed = set()
        self.registering = False
        self.pending = None

    def interrupt(self, exception):
        # Queue asynchronous cancellation until a returned child handle is owned.
        # No OS signal mask is inherited by a child.
        if self.registering:
            if self.pending is None:
                self.pending = exception
            return
        raise exception

    def deliver_pending(self):
        self.registering = False
        pending, self.pending = self.pending, None
        if pending is not None:
            raise pending

    def record_reap(self, process):
        # Called only within cancellation-deferred bookkeeping.
        if process not in self.completed:
            self.completed.add(process)
            self.reaped += 1
        self.active.discard(process)

    def capture(self, argv, *, env, cwd, seconds, stdout_limit, stderr_limit, retain=True, allow_failed_projection=False, allow_stderr=False):
        start = time.monotonic()
        meta = {"reason": "spawn_failed", "started": False, "reaped": False, "exitCode": None, "stdoutBytes": 0, "stderrBytes": 0, "elapsedMilliseconds": 0}
        chunks = bytearray()
        self.registering = True
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env=env, cwd=cwd, start_new_session=True, close_fds=True)
        except (OSError, ValueError):
            self.deliver_pending()
            return Capture(b"", meta)
        self.started += 1
        self.active.add(process)
        meta["started"] = True
        reason = "ok"
        finished = False
        try:
            self.deliver_pending()
            with selectors.DefaultSelector() as selector:
                for stream, name in ((process.stdout, "stdoutBytes"), (process.stderr, "stderrBytes")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = seconds - (time.monotonic() - start)
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    events = selector.select(min(0.1, remaining))
                    if time.monotonic() - start >= seconds:
                        reason = "timeout"
                        break
                    for key, _ in events:
                        name = key.data
                        maximum = stdout_limit if name == "stdoutBytes" else stderr_limit
                        data = os.read(key.fd, min(16384, maximum + 1 - meta[name]))
                        if time.monotonic() - start >= seconds:
                            reason = "timeout"
                            break
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        meta[name] += len(data)
                        if meta[name] > maximum:
                            reason = "output_limit"
                            break
                        if retain and name == "stdoutBytes":
                            chunks.extend(data)
                    if reason != "ok":
                        break
                if reason == "ok":
                    try:
                        remaining = seconds - (time.monotonic() - start)
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(argv, seconds)
                        process.wait(timeout=remaining)
                        finished = True
                        if time.monotonic() - start >= seconds:
                            reason = "timeout"
                    except subprocess.TimeoutExpired:
                        reason = "timeout"
        except (OSError, ValueError):
            reason = "read_failed"
        finally:
            # Defer asynchronous cancellation through final wait/accounting.
            # Never signal a PID whose child has already been reaped by Popen.
            self.registering = True
            try:
                if not finished and process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError:
                        reason = "reap_failed"
                try:
                    process.wait(timeout=2)
                    meta["reaped"] = True
                    self.record_reap(process)
                except (subprocess.TimeoutExpired, OSError):
                    reason = "reap_failed"
                process.stdout.close()
                process.stderr.close()
            finally:
                self.deliver_pending()
        meta["exitCode"] = process.returncode
        meta["elapsedMilliseconds"] = elapsed_milliseconds(start)
        if meta["elapsedMilliseconds"] is None or time.monotonic() - start >= seconds:
            reason = "timeout"
        if reason == "ok" and process.returncode != 0:
            reason = "nonzero_exit"
        if reason == "ok" and meta["stderrBytes"] and not allow_stderr:
            reason = "stderr_output"
        meta["reason"] = reason
        return Capture(bytes(chunks) if reason == "ok" or (allow_failed_projection and reason == "nonzero_exit" and process.returncode == 1 and not meta["stderrBytes"]) else b"", meta)

    def stop(self):
        self.registering = True
        try:
            for process in tuple(self.active):
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                try:
                    process.wait(timeout=2)
                    self.record_reap(process)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            return not self.active and self.started == self.reaped
        finally:
            # Terminal cleanup does not start another operation after cancellation.
            self.registering = False
            self.pending = None


class TaskTree:
    def __init__(self, parent, uid):
        # No new filesystem state until execute has assigned this owner object.
        self.parent = Path(parent).resolve(strict=True)
        if not self.parent.is_dir():
            raise Refused("preparation_failed")
        self.path = None
        self.uid = uid
        self.identity = None

    def create(self):
        # Defer cancellation only while registering the newly created directory.
        # Once unmasked, the caller already owns self and can clean partial setup.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            self.path = Path(tempfile.mkdtemp(prefix="tracebolt-native-", dir=self.parent))
            info = self.path.stat()
            self.identity = info.st_dev, info.st_ino
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        for name in ("home", "tmp", "bin", "cache", "modules", "gopath"):
            (self.path / name).mkdir(mode=0o700)
        return self

    def remove(self):
        """Descriptor-relative no-follow deletion, only this recorded new tree."""
        def clear(fd):
            for entry in os.scandir(fd):
                info = entry.stat(follow_symlinks=False)
                if info.st_uid != self.uid:
                    raise OSError("owner")
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        actual = os.fstat(child)
                        if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                            raise OSError("changed")
                        os.fchmod(child, 0o700)
                        clear(child)
                    finally:
                        os.close(child)
                    os.rmdir(entry.name, dir_fd=fd)
                else:
                    os.unlink(entry.name, dir_fd=fd)
        if self.path is None:
            return True
        if self.identity is None:
            return False
        try:
            parentfd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                try:
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) != self.identity or info.st_uid != self.uid:
                        return False
                    clear(fd)
                finally:
                    os.close(fd)
                os.rmdir(self.path.name, dir_fd=parentfd)
                try:
                    os.stat(self.path.name, dir_fd=parentfd, follow_symlinks=False)
                    return False
                except FileNotFoundError:
                    return True
            finally:
                os.close(parentfd)
        except OSError:
            return False


def clean_environment(tree):
    return dict(BASE_ENV, HOME=str(tree.path / "home"), TMPDIR=str(tree.path / "tmp"))


def logrc_absent(homes):
    if len(homes) != 3:
        return False
    try:
        for home in homes:
            if not isinstance(home, str) or not home or not os.path.isabs(home):
                return False
            # lstat config only; never open/read any .logrc, even a symlink.
            canonical = Path(home).resolve(strict=True)
            if not canonical.is_dir():
                return False
            try:
                os.lstat(canonical / ".logrc")
            except FileNotFoundError:
                continue
            return False
    except (OSError, RuntimeError):
        return False
    return True


def current_identity():
    # No account/group enumeration, id subprocess, username or public home.
    import pwd
    uid, euid, gid, egid = os.getuid(), os.geteuid(), os.getgid(), os.getegid()
    groups = os.getgroups()
    if len(groups) > 64 or any(type(x) is not int or not 0 <= x <= 4294967295 for x in [uid, euid, gid, egid] + groups):
        raise Refused("identity_unavailable")
    home = pwd.getpwuid(uid).pw_dir
    if uid != euid or gid != egid or uid == 0 or not home or not os.path.isabs(home):
        raise Refused("identity_unavailable")
    return {"uid": uid, "euid": euid, "gid": gid, "egid": egid, "groups": sorted(set(groups)), "adminMembership": None, "adminMembershipReason": "not_queried"}, home


def require_capture(processes, argv, env, cwd, seconds=5, maximum=128):
    result = processes.capture(argv, env=env, cwd=cwd, seconds=seconds, stdout_limit=maximum, stderr_limit=maximum)
    if result.metadata["reason"] != "ok" or not result.metadata["reaped"]:
        raise Refused("metadata_unavailable")
    return result.data.decode("utf-8", errors="strict").strip()


def source_identity(processes, env, context):
    git_env = dict(BASE_ENV, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    commit = require_capture(processes, ("/usr/bin/git", "rev-parse", "--verify", "HEAD"), git_env, ROOT)
    tree = require_capture(processes, ("/usr/bin/git", "rev-parse", "--verify", "HEAD^{tree}"), git_env, ROOT)
    if commit != context["commit"] or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise Refused("source_mismatch")
    return tree


def selected_go(ambient, context):
    """setup-go selects PATH, not GOROOT for current Go; ignore stale GOROOT."""
    raw_cache, raw_path = ambient.get("RUNNER_TOOL_CACHE", ""), ambient.get("PATH", "")
    if not raw_cache or not os.path.isabs(raw_cache) or not raw_path or len(raw_path) > 16384:
        raise Refused("preparation_failed")
    cache = Path(raw_cache).resolve(strict=True)
    arch = "arm64" if context["runnerArch"] == "ARM64" else "x64"
    root = cache / "go" / "1.27.1" / arch
    go = root / "bin/go"
    selected = shutil.which("go", path=raw_path)
    if selected is None or root.resolve(strict=True) != root or go.resolve(strict=True) != go or Path(selected).resolve(strict=True) != go or not go.is_file():
        raise Refused("preparation_failed")
    # No other caller path or ambient GOROOT may select the compiler.
    return root, go


def prepare(processes, tree, context, ambient):
    env = clean_environment(tree)
    metadata = {"goVersion": None, "goSHA256": None, "inventorySHA256": None, "emitterSHA256": None, "clangSHA256": None, "clangVersion": None, "sdkVersion": None, "sdkSettingsSHA256": None}
    if context["gateASelected"]:
        go_root, go = selected_go(ambient, context)
        env.update(GOROOT=str(go_root), GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly", CGO_ENABLED="0", GOPROXY="https://proxy.golang.org", GOSUMDB="sum.golang.org", GOPRIVATE="", GONOPROXY="", GONOSUMDB="", GOVCS="*:off", GOPATH=str(tree.path / "gopath"), GOCACHE=str(tree.path / "cache"), GOMODCACHE=str(tree.path / "modules"))
        version = require_capture(processes, (str(go), "version"), env, ROOT, maximum=128)
        expected_arch = "arm64" if context["runnerArch"] == "ARM64" else "amd64"
        if version != "go version go1.27.1 darwin/" + expected_arch:
            raise Refused("preparation_failed")
        metadata.update(goVersion="go1.27.1", goSHA256=bounded_hash(go, COMPILER_LIMIT)[0])
        for argv in ((str(go), "mod", "download"), (str(go), "mod", "verify")):
            capture = processes.capture(argv, env=env, cwd=ROOT, seconds=240, stdout_limit=1024 * 1024, stderr_limit=1024 * 1024, retain=False, allow_stderr=True)
            if capture.metadata["reason"] != "ok":
                raise Refused("preparation_failed")
        env.update(GOPROXY="off", GOSUMDB="off")
        binary = tree.path / "bin/inventory-probe"
        capture = processes.capture((str(go), "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./tests/macosnativeacceptance/inventoryprobe"), env=env, cwd=ROOT, seconds=240, stdout_limit=65536, stderr_limit=65536, retain=False)
        if capture.metadata["reason"] != "ok":
            raise Refused("preparation_failed")
        metadata["inventorySHA256"] = bounded_hash(binary)[0]
    if context["gateBSelected"]:
        # Only the already installed Apple compiler/SDK, with no install fallback.
        clang = Path(require_capture(processes, ("/usr/bin/xcrun", "--find", "clang"), clean_environment(tree), tree.path / "home", maximum=1024)).resolve(strict=True)
        sdk = Path(require_capture(processes, ("/usr/bin/xcrun", "--show-sdk-path"), clean_environment(tree), tree.path / "home", maximum=1024)).resolve(strict=True)
        if not clang.is_absolute() or not sdk.is_absolute():
            raise Refused("preparation_failed")
        metadata["clangSHA256"] = bounded_hash(clang, COMPILER_LIMIT)[0]
        raw = require_capture(processes, (str(clang), "--version"), clean_environment(tree), tree.path / "home", maximum=4096)
        match = re.match(r"Apple clang version ([0-9]+(?:\.[0-9]+){1,3})\b", raw)
        if not match:
            raise Refused("preparation_failed")
        metadata["clangVersion"] = match[1]
        sdk_version = require_capture(processes, ("/usr/bin/xcrun", "--show-sdk-version"), clean_environment(tree), tree.path / "home")
        if not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}", sdk_version):
            raise Refused("preparation_failed")
        metadata["sdkVersion"] = sdk_version
        metadata["sdkSettingsSHA256"] = bounded_hash(sdk / "SDKSettings.json", MANUAL_LIMIT)[0]
        emitter = tree.path / "bin/tracebolt-native-log-probe"
        capture = processes.capture((str(clang), "-O0", "-Wall", "-Wextra", "-Werror", "-isysroot", str(sdk), "-o", str(emitter), str(ROOT / "tests/macosnativeacceptance/emitter.c")), env=clean_environment(tree), cwd=tree.path / "home", seconds=60, stdout_limit=65536, stderr_limit=65536, retain=False)
        if capture.metadata["reason"] != "ok":
            raise Refused("preparation_failed")
        metadata["emitterSHA256"] = bounded_hash(emitter)[0]
    return metadata


def load_log_probe(expected_sha):
    # -B suppresses cache writes, not cache reads. Execute reviewed source bytes
    # directly, so unreviewed timestamp-valid .pyc files cannot replace them.
    path = ROOT / "tests/macosnativeacceptance/log_probe.py"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= SOURCE_FILE_LIMIT:
            raise Refused("source_mismatch")
        raw = bytearray()
        deadline = time.monotonic() + 5
        while True:
            if time.monotonic() >= deadline:
                raise Refused("source_mismatch")
            data = os.read(fd, min(65536, SOURCE_FILE_LIMIT + 1 - len(raw)))
            if time.monotonic() >= deadline:
                raise Refused("source_mismatch")
            if not data:
                break
            raw.extend(data)
            if len(raw) > SOURCE_FILE_LIMIT:
                raise Refused("source_mismatch")
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if time.monotonic() >= deadline or len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields) or hashlib.sha256(raw).hexdigest() != expected_sha:
            raise Refused("source_mismatch")
    finally:
        os.close(fd)
    module = types.ModuleType("tracebolt_log_probe")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    code = compile(bytes(raw), "reviewed_synthetic_log_probe", "exec", dont_inherit=True)
    exec(code, module.__dict__)
    return module


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _hash(value, size=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None


def _keys(value, keys):
    return type(value) is dict and set(value) == set(keys)


def valid_inventory(v):
    try:
        keys = {"schemaVersion", "gate", "mode", "status", "reason", "collector", "snapshotSchema", "collectionCalls", "collectionReturned", "collectionElapsedMilliseconds", "snapshotValidated", "snapshotRoundTripValidated", "snapshotBytes", "sourcesObserved", "commandMetricsAvailable", "limits", "sources"}
        if not _keys(v, keys) or v["schemaVersion"] != "tracebolt.macos-native-inventory-evidence.v1" or v["gate"] != "A" or v["mode"] != "native" or v["status"] not in ("passed", "failed") or v["collector"] != "macosinventory.CollectNative" or v["snapshotSchema"] != "tracebolt.macos-read-inventory.v1":
            return False
        if v["reason"] not in {"none", "not_run", "invalid_input", "unsupported_platform", "host_context_rejected", "selector_required", "toolchain_rejected", "provider_panic", "collection_failed", "snapshot_invalid", "provider_outcome", "access_denied", "source_unavailable", "invalid_metadata", "bounds_exceeded", "budget_exhausted"}:
            return False
        if not all(type(v[k]) is bool for k in ("collectionReturned", "snapshotValidated", "snapshotRoundTripValidated", "commandMetricsAvailable")) or v["commandMetricsAvailable"]:
            return False
        if not _integer(v["collectionCalls"], 0, 1) or not _integer(v["sourcesObserved"], 0, 5) or (v["collectionReturned"] and v["collectionCalls"] != 1):
            return False
        if v["collectionElapsedMilliseconds"] is not None and not _integer(v["collectionElapsedMilliseconds"], 0, 120000):
            return False
        if v["snapshotBytes"] is not None and not _integer(v["snapshotBytes"], 1, 512 * 1024):
            return False
        limits = {"commandMilliseconds": 1000, "pipeWaitMilliseconds": 200, "providerMilliseconds": 2000, "collectionMilliseconds": 8000, "snapshotMaxBytes": 512 * 1024, "reportMaxBytes": REPORT_LIMIT}
        if v["limits"] != limits or any(type(x) is not int for x in v["limits"].values()):
            return False
        if type(v["sources"]) is not list or len(v["sources"]) != 5:
            return False
        ids = ("hardware_sysctl_v1", "receipts_pkgutil_v1", "processes_ps_ucomm_v1", "interfaces_ipv4_ifconfig_v1", "interfaces_ipv6_ifconfig_v1")
        counts = (1, 2048, 4096, 128, 128)
        source_keys = {"id", "availability", "reason", "parserPassed", "validationPassed", "passed", "rows", "addresses", "maxOutputBytes", "maxRows", "maxAddressesPerRow", "stdoutBytes", "stderrBytes", "elapsedMilliseconds", "exitCode", "childStarted", "childReaped"}
        observed = 0
        for i, row in enumerate(v["sources"]):
            if not _keys(row, source_keys) or row["id"] != ids[i] or row["availability"] not in ("not_run", "observed", "denied", "unavailable") or row["reason"] not in ("none", "not_run", "access_denied", "source_unavailable", "unsupported_platform", "invalid_metadata", "bounds_exceeded", "budget_exhausted"):
                return False
            expected = {"maxOutputBytes": 4096 if i == 0 else 256 * 1024, "maxRows": counts[i], "maxAddressesPerRow": 16 if i >= 3 else 0}
            if any(type(row[k]) is not int or row[k] != val for k, val in expected.items()) or any(row[k] is not None for k in ("stdoutBytes", "stderrBytes", "elapsedMilliseconds", "exitCode", "childStarted", "childReaped")) or any(type(row[k]) is not bool for k in ("parserPassed", "validationPassed", "passed")):
                return False
            if row["availability"] == "observed":
                if not all(row[k] for k in ("parserPassed", "validationPassed", "passed")) or row["reason"] != "none" or not _integer(row["rows"], 0 if i == 1 else 1, counts[i]):
                    return False
                if (i < 3 and row["addresses"] is not None) or (i >= 3 and not _integer(row["addresses"], 0, row["rows"] * 16)):
                    return False
                observed += 1
            elif row["passed"] or row["parserPassed"] or row["rows"] is not None or row["addresses"] is not None or row["reason"] == "none":
                return False
        return observed == v["sourcesObserved"] and (v["status"] != "passed" or (v["collectionCalls"] == 1 and v["collectionReturned"] and v["snapshotValidated"] and v["snapshotRoundTripValidated"] and observed == 5 and v["reason"] == "none"))
    except (TypeError, ValueError, KeyError):
        return False


def valid_process(value):
    return (_keys(value, {"reason", "started", "reaped", "exitCode", "stdoutBytes", "stderrBytes", "elapsedMilliseconds"}) and value["reason"] in PROCESS_REASONS and all(type(value[k]) is bool for k in ("started", "reaped")) and (value["exitCode"] is None or _integer(value["exitCode"], -255, 255)) and _integer(value["stdoutBytes"], 0, REPORT_LIMIT + 1) and _integer(value["stderrBytes"], 0, 1025) and (value["elapsedMilliseconds"] is None or _integer(value["elapsedMilliseconds"], 0, 1200000)) and (value["elapsedMilliseconds"] is not None or value["reason"] != "ok") and (not value["reaped"] or value["started"]))


def validate_report(value, log_module=None):
    """Exact closed projection. Never publish arbitrary strings or source content."""
    try:
        if not _keys(value, report_template({}, {})) or type(value["schemaVersion"]) is not int or value["schemaVersion"] != SCHEMA or value["scope"] != "macos-native-evidence-v1" or value["status"] not in ("passed", "failed", "blocked") or value["reason"] not in REASONS:
            return False
        c = value["context"]
        if not _keys(c, {"runnerLabel", "runnerArch", "commit", "gateASelected", "gateBSelected"}) or c["runnerLabel"] not in RUNNERS or c["runnerArch"] != RUNNERS[c["runnerLabel"]][0] or not _hash(c["commit"], 40) or any(type(c[k]) is not bool for k in ("gateASelected", "gateBSelected")) or not (c["gateASelected"] or c["gateBSelected"]):
            return False
        source = value["source"]
        expected_files = set(SOURCE_FIXED) | {"tests/macosnativeacceptance/" + name for name in HARNESS_REQUIRED} | {"tests/macosnativeacceptance/inventoryprobe/" + name for name in ("main.go", "main_test.go", "probe.go", "probe_test.go", "README.md")}
        if not _keys(source, {"sha256", "fileCount", "bytes", "files"}) or not _hash(source["sha256"]) or not _integer(source["fileCount"], len(expected_files), 8192) or not _integer(source["bytes"], 1, SOURCE_LIMIT) or not _keys(source["files"], expected_files) or not all(_hash(x) for x in source["files"].values()):
            return False
        for key, size in (("sourceTree", 40), ("installedLogManualSHA256", 64)):
            if value[key] is not None and not _hash(value[key], size):
                return False
        for key, pattern in (("imageOS", r"macos15(?:-arm64)?"), ("imageVersion", r"[0-9]{8}\.[0-9]{1,4}\.[0-9]{1,4}")):
            if value[key] is not None and (type(value[key]) is not str or not re.fullmatch(pattern, value[key])):
                return False
        if value["versions"] is not None:
            versions = value["versions"]
            if not _keys(versions, VERSION_COMMANDS) or any(type(versions[k]) is not str or not re.fullmatch(VERSION_COMMANDS[k][1], versions[k]) for k in versions) or versions["machine"] != RUNNERS[c["runnerLabel"]][1]:
                return False
        if value["identity"] is not None:
            ident = value["identity"]
            if not _keys(ident, {"uid", "euid", "gid", "egid", "groups", "adminMembership", "adminMembershipReason"}) or any(not _integer(ident[k], 0, 4294967295) for k in ("uid", "euid", "gid", "egid")) or type(ident["groups"]) is not list or len(ident["groups"]) > 64 or any(not _integer(x, 0, 4294967295) for x in ident["groups"]) or ident["groups"] != sorted(set(ident["groups"])) or ident["adminMembership"] is not None or ident["adminMembershipReason"] != "not_queried":
                return False
        if value["tools"] is not None and (not _keys(value["tools"], TOOL_PATHS) or not all(_hash(x) for x in value["tools"].values())):
            return False
        if value["build"] is not None:
            b = value["build"]
            if not _keys(b, {"goVersion", "goSHA256", "inventorySHA256", "emitterSHA256", "clangSHA256", "clangVersion", "sdkVersion", "sdkSettingsSHA256"}) or b["goVersion"] not in (None, "go1.27.1"):
                return False
            if any(b[k] is not None and not _hash(b[k]) for k in ("goSHA256", "inventorySHA256", "emitterSHA256", "clangSHA256", "sdkSettingsSHA256")) or any(b[k] is not None and (type(b[k]) is not str or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", b[k])) for k in ("clangVersion", "sdkVersion")):
                return False
        if value["inventory"] is not None and not valid_inventory(value["inventory"]):
            return False
        if value["inventoryProcess"] is not None and not valid_process(value["inventoryProcess"]):
            return False
        if value["syntheticLog"] is not None and (log_module is None or not log_module.validate_result(value["syntheticLog"])):
            return False
        if type(value["logrcAbsenceChecked"]) is not bool or (value["nativeElapsedMilliseconds"] is not None and not _integer(value["nativeElapsedMilliseconds"], 0, 1200000)):
            return False
        clean = value["cleanup"]
        if not _keys(clean, {"directChildrenStarted", "directChildrenReaped", "allDirectChildrenReaped", "syntheticChildrenReaped", "taskTreeRemoved", "hostLogsErased"}) or not _integer(clean["directChildrenStarted"], 0, 32) or not _integer(clean["directChildrenReaped"], 0, clean["directChildrenStarted"]) or type(clean["allDirectChildrenReaped"]) is not bool or clean["allDirectChildrenReaped"] != (clean["directChildrenStarted"] == clean["directChildrenReaped"]) or any(clean[k] is not None and type(clean[k]) is not bool for k in ("syntheticChildrenReaped", "taskTreeRemoved")) or clean["hostLogsErased"] is not False:
            return False
        if any(value[k] is not False for k in ("ordinaryNonAdminEstablished", "installedAgentEstablished", "nativeReleaseAccepted")):
            return False
        if not c["gateASelected"] and (value["inventory"] is not None or value["inventoryProcess"] is not None):
            return False
        if not c["gateBSelected"] and (value["syntheticLog"] is not None or value["installedLogManualSHA256"] is not None or value["logrcAbsenceChecked"]):
            return False
        if value["status"] == "passed":
            if value["reason"] != "ok" or value["nativeElapsedMilliseconds"] is None or not all(value[k] is not None for k in ("sourceTree", "imageOS", "imageVersion", "versions", "identity", "tools", "build")) or not clean["allDirectChildrenReaped"] or clean["taskTreeRemoved"] is not True:
                return False
            if c["gateASelected"] and (value["inventory"] is None or value["inventory"]["status"] != "passed" or value["inventoryProcess"] is None or value["inventoryProcess"]["reason"] != "ok" or not value["inventoryProcess"]["reaped"]):
                return False
            if c["gateBSelected"] and (value["syntheticLog"] is None or value["syntheticLog"]["status"] != "passed" or clean["syntheticChildrenReaped"] is not True or not value["logrcAbsenceChecked"] or value["installedLogManualSHA256"] != MANUAL_SHA256):
                return False
        return len(json.dumps(value, allow_nan=False).encode("utf-8")) <= REPORT_LIMIT
    except (KeyError, TypeError, ValueError):
        return False

def report_template(context, manifest):
    return {"schemaVersion": SCHEMA, "scope": "macos-native-evidence-v1", "status": "blocked", "reason": "dispatch_not_admitted", "context": context, "source": manifest, "sourceTree": None, "imageOS": None, "imageVersion": None, "versions": None, "identity": None, "tools": None, "build": None, "installedLogManualSHA256": None, "logrcAbsenceChecked": False, "inventory": None, "inventoryProcess": None, "syntheticLog": None, "nativeElapsedMilliseconds": 0, "cleanup": {"directChildrenStarted": 0, "directChildrenReaped": 0, "allDirectChildrenReaped": True, "syntheticChildrenReaped": None, "taskTreeRemoved": None, "hostLogsErased": False}, "ordinaryNonAdminEstablished": False, "installedAgentEstablished": False, "nativeReleaseAccepted": False}


def execute(context, manifest, ambient):
    report = report_template(context, manifest)
    processes = Processes()
    tree = None
    native_start = None
    old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    signal.signal(signal.SIGTERM, lambda *_: processes.interrupt(Cancelled()))
    signal.signal(signal.SIGINT, lambda *_: processes.interrupt(Cancelled()))
    signal.signal(signal.SIGALRM, lambda *_: processes.interrupt(NativeDeadline()))
    log_module = None
    try:
        report["sourceTree"] = source_identity(processes, ambient, context)
        tree = TaskTree(ambient["RUNNER_TEMP"], os.getuid())
        tree.create()
        report["build"] = prepare(processes, tree, context, ambient)
        verify_source_unchanged(manifest)
        # A build is preparation; the separate native 120-second budget starts here.
        native_start = time.monotonic()
        signal.setitimer(signal.ITIMER_REAL, 120)
        child_env = clean_environment(tree)
        for key, pattern in (("ImageOS", r"macos15(?:-arm64)?"), ("ImageVersion", r"[0-9]{8}\.[0-9]{1,4}\.[0-9]{1,4}")):
            val = ambient.get(key, "")
            if not re.fullmatch(pattern, val):
                raise Refused("metadata_unavailable")
            report["imageOS" if key == "ImageOS" else "imageVersion"] = val
        versions = {}
        for key, (argv, pattern) in VERSION_COMMANDS.items():
            value = require_capture(processes, argv, child_env, tree.path / "home")
            if not re.fullmatch(pattern, value):
                raise Refused("metadata_unavailable")
            versions[key] = value
        if versions["machine"] != RUNNERS[context["runnerLabel"]][1]:
            raise Refused("metadata_unavailable")
        report["versions"] = versions
        identity, passwd_home = current_identity()
        report["identity"] = identity
        report["tools"] = {name: bounded_hash(path)[0] for name, path in TOOL_PATHS.items()}
        if context["gateASelected"]:
            verify_source_unchanged(manifest)
            verify_binary_custody(tree, "inventory-probe", report["build"]["inventorySHA256"])
            native_env = dict(child_env, GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY="storminator89/Tracebolt", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="macOS", RUNNER_ARCH=context["runnerArch"], TRACEBOLT_RUNNER_LABEL=context["runnerLabel"], TRACEBOLT_NATIVE_GATE_A="enabled", TRACEBOLT_REPOSITORY_VISIBILITY="public", GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly")
            result = processes.capture((str(tree.path / "bin/inventory-probe"), "--native-inventory-once"), env=native_env, cwd=tree.path / "home", seconds=12, stdout_limit=REPORT_LIMIT, stderr_limit=1024, allow_failed_projection=True)
            report["inventoryProcess"] = result.metadata
            if result.data:
                try:
                    parsed = strict_json(result.data)
                    coherent_exit = result.metadata["exitCode"] == (0 if parsed.get("status") == "passed" else 1)
                    if valid_inventory(parsed) and coherent_exit:
                        report["inventory"] = parsed
                except (ValueError, TypeError, AttributeError):
                    pass  # Discard an invalid projection; independently selected B remains eligible.
        if context["gateBSelected"]:
            verify_source_unchanged(manifest)
            verify_binary_custody(tree, "tracebolt-native-log-probe", report["build"]["emitterSHA256"])
            manual = installed_manual_hash()
            report["installedLogManualSHA256"] = manual
            if manual != MANUAL_SHA256:
                raise Refused("manual_changed_or_unavailable")
            homes = (str(tree.path / "home"), ambient.get("HOME", ""), passwd_home)
            if not logrc_absent(homes):
                raise Refused("configuration_present_or_unknown")
            report["logrcAbsenceChecked"] = True
            log_module = load_log_probe(manifest["files"]["tests/macosnativeacceptance/log_probe.py"])
            report["cleanup"]["syntheticChildrenReaped"] = False
            with log_module.configure_admission(tree.path, before_query=lambda: logrc_absent(homes), clean_env=child_env, current_platform=sys.platform):
                result = log_module.run_log_gate(tree.path, tree.path / "bin/tracebolt-native-log-probe")
            if not log_module.validate_result(result):
                raise Refused("probe_schema_rejected")
            report["syntheticLog"] = result
            report["cleanup"]["syntheticChildrenReaped"] = (not result["emitter"]["started"] or result["emitter"]["reaped"]) and all(not q["started"] or q["reaped"] for q in result["queries"])
        passed_a = not context["gateASelected"] or (report["inventory"] is not None and report["inventory"]["status"] == "passed")
        passed_b = not context["gateBSelected"] or report["syntheticLog"]["status"] == "passed"
        report["status"], report["reason"] = ("passed", "ok") if passed_a and passed_b else ("failed", "probe_failed")
    except Refused as exc:
        report["reason"] = exc.reason
    except NativeDeadline:
        report["status"], report["reason"] = "failed", "native_deadline"
    except Cancelled:
        report["status"], report["reason"] = "failed", "cancelled"
    except (Exception, KeyboardInterrupt):
        # Never print repr/str of errors, paths, raw child output or traceback.
        report["status"], report["reason"] = "failed", "internal_failure"
    finally:
        # Parent-only cleanup mask: no new process is started while it is held.
        # Protect the whole close/handler-restoration phase rather than gradually
        # installing SIG_IGN handlers, which leaves a repeated-cancellation gap.
        masked = False
        transition_cancelled = False
        for _ in range(3):
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, set(old_handlers))
                masked = True
                break
            except (Cancelled, NativeDeadline, KeyboardInterrupt):
                transition_cancelled = True
            except Exception:
                break
        cleanup = report["cleanup"]
        if tree is not None:
            cleanup["taskTreeRemoved"] = False
        finalization_failed = not masked
        try:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
            except BaseException:
                finalization_failed = True
            reaped = False
            for _ in range(3):
                try:
                    reaped = processes.stop()
                    break
                except (Cancelled, NativeDeadline, KeyboardInterrupt):
                    transition_cancelled = True
                except Exception:
                    break
            cleanup.update(directChildrenStarted=processes.started, directChildrenReaped=processes.reaped, allDirectChildrenReaped=reaped)
            if tree is not None and reaped and cleanup["syntheticChildrenReaped"] is not False:
                try:
                    cleanup["taskTreeRemoved"] = tree.remove()
                except BaseException:
                    finalization_failed = True
        except BaseException:
            # Repeated cancellation/cleanup failure never becomes a successful
            # cleanup claim, and must not skip restoration of other handlers.
            finalization_failed = True
        finally:
            cleanup.update(directChildrenStarted=processes.started, directChildrenReaped=processes.reaped, allDirectChildrenReaped=not processes.active and processes.started == processes.reaped)
            for sig, handler in old_handlers.items():
                restored = False
                for _ in range(3):
                    try:
                        signal.signal(sig, handler)
                        restored = True
                        break
                    except (Cancelled, NativeDeadline, KeyboardInterrupt):
                        transition_cancelled = True
                    except Exception:
                        break
                finalization_failed = finalization_failed or not restored
            restored_mask = False
            for _ in range(3):
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, entry_mask)
                    restored_mask = True
                    break
                except (Cancelled, NativeDeadline, KeyboardInterrupt):
                    # A pending signal may run only after all handlers/children
                    # have been restored/closed. Catch that final delivery too.
                    transition_cancelled = True
                except Exception:
                    break
            finalization_failed = finalization_failed or not restored_mask
        if transition_cancelled and report["reason"] not in ("cancelled", "native_deadline"):
            report["status"], report["reason"] = "failed", "cancelled"
        if finalization_failed or not cleanup["allDirectChildrenReaped"] or cleanup["taskTreeRemoved"] is False or cleanup["syntheticChildrenReaped"] is False:
            report["status"], report["reason"] = "failed", "cleanup_failed"
        if native_start is not None:
            report["nativeElapsedMilliseconds"] = elapsed_milliseconds(native_start)
            if report["nativeElapsedMilliseconds"] is None and report["reason"] != "cleanup_failed":
                report["status"], report["reason"] = "failed", "native_deadline"
    return report, log_module


def write_report(report, log_module=None):
    if not validate_report(report, log_module):
        raise Refused("probe_schema_rejected")
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode()
    if len(raw) > REPORT_LIMIT:
        raise Refused("probe_schema_rejected")
    # Fixed public content-free artifact; never upload the task tree or raw output.
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors = [fd]
    try:
        for component in ("artifacts", "review"):
            try:
                os.mkdir(component, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise Refused("source_invalid")
        output = os.open("macos-native-acceptance.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(output, "wb") as stream:
            stream.write(raw)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def mark_report_ready():
    # Static runner plumbing only, after this invocation wrote validated evidence.
    # A refused/existing/stale report never enables artifact upload.
    path = os.environ.get("GITHUB_OUTPUT", "")
    if not path or not os.path.isabs(path):
        raise Refused("source_invalid")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > REPORT_LIMIT:
            raise Refused("source_invalid")
        data = b"report_ready=true\n"
        if os.write(fd, data) != len(data):
            raise Refused("source_invalid")
    finally:
        os.close(fd)


def main(argv=None):
    # Reject arbitrary CLI text without argparse echo or generic traceback.
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ["--check"], ["--verify-dispatch"], ["--execute"]):
        print("Native evidence refused: invalid invocation.")
        return 2
    manifest = source_manifest()
    if args in ([], ["--check"]):
        print(json.dumps({"schemaVersion": SCHEMA, "inertCheck": True, "sourceSHA256": manifest["sha256"], "sourceFileCount": manifest["fileCount"]}, separators=(",", ":")))
        return 0
    context = hosted_admission(os.environ, sys.platform, manifest)
    if args == ["--verify-dispatch"]:
        print("Manual source selection verified; no native probe executed.")
        return 0
    report, log_module = execute(context, manifest, os.environ)
    write_report(report, log_module)
    mark_report_ready()
    print("Content-free native evidence recorded: " + report["status"] + ".")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt):
        print("Native evidence refused or failed; no raw diagnostics retained.")
        sys.exit(1)
