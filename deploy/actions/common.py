"""Small shared, inert helpers for the explicit action setup guide."""
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import time
import stat
import subprocess

class Rejected(Exception):
    """Fixed safe stage names only; never include subprocess output or secrets."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def valid_digest(value):
    return type(value) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None


def strict_json(raw, limit=1048576):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "json-bounds")
    def pairs(items):
        value = {}
        for k, v in items:
            require(k not in value, "duplicate-json-member")
            value[k] = v
        return value
    try:
        return json.loads(raw.decode(), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("json-number")))
    except (ValueError, UnicodeError) as exc:
        raise Rejected("json-invalid") from exc


@contextlib.contextmanager
def parent(path):
    require(type(path) is str and path.startswith("/") and str(Path(path)) == path and
            ".." not in Path(path).parts, "protected-path")
    opened = []
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened.append(("/", fd))
        for name in ("", *Path(path).parent.parts[1:]):
            if name:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                opened.append((str(Path(opened[-1][0]) / name), fd))
            st = os.fstat(fd)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o6022 == 0,
                    "protected-parent")
        yield fd
        for name, handle in opened:
            a, b = os.fstat(handle), os.lstat(name)
            require((a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode) ==
                    (b.st_dev, b.st_ino, b.st_uid, b.st_gid, b.st_mode), "parent-changed")
    finally:
        for _, handle in reversed(opened):
            os.close(handle)


def protected_read(path, limit=1048576):
    with parent(path) as directory:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            a = os.fstat(fd)
            require(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_nlink == 1 and
                    a.st_mode & 0o6022 == 0 and 0 < a.st_size <= limit, "protected-file")
            raw = os.read(fd, limit + 1)
            b = os.fstat(fd)
            c = os.stat(Path(path).name, dir_fd=directory, follow_symlinks=False)
            pin = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            require(len(raw) == a.st_size and pin(a) == pin(b) == pin(c), "file-changed")
            return raw
        finally:
            os.close(fd)


def create_file(path, raw):
    with parent(path) as directory:
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            st = os.fstat(fd)
            require(st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1,
                    "created-file-protection")
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
            os.fsync(fd)
            os.fsync(directory)
        finally:
            os.close(fd)


def valid_lan_ip(value):
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, TypeError, ipaddress.AddressValueError):
        return False
    return str(ip) == value and any(ip in ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def run(args, data=None, timeout=30, lan_ip=None):
    # Bound both input and output, use no shell/PATH search/inherited Docker or
    # proxy/loader variables, and never expose raw subprocess diagnostics.
    require(args and args[0].startswith("/"), "absolute-command")
    require(data is None or type(data) is bytes and len(data) <= 32768, "command-input-bounds")
    require(lan_ip is None or valid_lan_ip(lan_ip), "explicit-private-lan-ip")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if lan_ip is not None:
        environment["TRACEBOLT_HTTP_TEST_BIND_IP"] = lan_ip
    child = None
    try:
        child = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/", close_fds=True,
                                 start_new_session=True,
                                 env=environment)
        output = bytearray()
        remaining = memoryview(data or b"")
        until = time.monotonic() + timeout
        with selectors.DefaultSelector() as selected:
            os.set_blocking(child.stdout.fileno(), False)
            selected.register(child.stdout, selectors.EVENT_READ)
            if child.stdin is not None:
                if remaining:
                    os.set_blocking(child.stdin.fileno(), False)
                    selected.register(child.stdin, selectors.EVENT_WRITE)
                else:
                    child.stdin.close()
            while selected.get_map():
                require(time.monotonic() < until, "command-timeout-unconfirmed")
                for key, event in selected.select(min(.2, max(0, until - time.monotonic()))):
                    if event & selectors.EVENT_WRITE:
                        count = os.write(key.fileobj.fileno(), remaining[:4096])
                        require(count > 0, "command-input-failed")
                        remaining = remaining[count:]
                        if not remaining:
                            selected.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selected.unregister(key.fileobj)
                        output.extend(chunk)
                        require(len(output) <= 1048576, "command-output-bounds")
        require(child.wait(timeout=max(.01, until-time.monotonic())) == 0, "command-failed-unconfirmed")
        return bytes(output)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Rejected("command-unconfirmed") from exc
    finally:
        if child is not None:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()
            child.stdout.close()
