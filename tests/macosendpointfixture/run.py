#!/usr/bin/env python3
"""SOURCE-ONLY native endpoint fixture supervisor; runtime gate is NOT available.

Invoking this file always emits a closed boolean-only blocked result. No flag,
environment variable, imported approval token or stdin message can enable it.
The adapters below are proposed mechanics for a later exact reviewed Darwin gate,
not permission to execute them. They must not be called by source/unit checks.

The peer is a simulated manager. It owns all TLS sockets and keeps fixture issuer
keys in memory. The endpoint keeps its disposable identity in one new private
tree. Invitation bytes travel only peer stdout -> supervisor memory -> hidden
controlling PTY. Python cannot promise erasure of immutable JSON decoder copies;
mutable buffers are cleared best-effort and nothing private is printed or saved.

Full Stage 1 cannot pass here: the unchanged macos-agent CLI masks lock failures
with a generic message, so a recognized exclusive-custody case is still missing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from typing import Callable

CONTROL_LIMIT = 64 * 1024
FRAME_LIMIT = 72 * 1024
OUTPUT_LIMIT = 256 * 1024
FILE_LIMIT = 256 * 1024
MAX_TREE_ENTRIES = 64
MAX_TREE_DEPTH = 3
OWNED_LAYOUT = {
    "bootstrap.json": False, "state": True, "state/telemetry": True,
    "state/enrollment.lock": False, "state/.enrollment.tmp": False,
    "state/ledger.json": False, "state/agent-key.pem": False,
    "state/agent-cert.pem": False, "state/server-ca.pem": False,
    "state/agent.json": False, "state/ready.json": False,
    "state/telemetry/state.lock": False, "state/telemetry/state.json": False,
    "state/telemetry/.state.tmp": False,
}
HIDDEN_PROMPT = b"then enter the invitation (hidden): "
PENDING_PROMPT = b"Waiting for approval in the manager."
FP_PATTERN = rb"(?:^|\n)Local device SPKI SHA-256: ([0-9a-f]{64})\r?\n"
COMPARISON_PATTERN = rb"(?:^|\n)Local 128-bit comparison: ([0-9a-f]{32})\r?\n"
STATUS_BOOLS = frozenset((
    "activated", "tls13", "currentLeaf", "missingClientRejected", "basicOnly",
    "sourceSemantics", "exactRetry", "originalReceiptTime", "nextSequence",
))
STATUS_COUNTS = frozenset(("acceptedReports", "duplicateReports", "lossCount"))
RESULT_FIELDS = (
    "blocked", "simulated_manager", "runtime_started", "hidden_prompt", "cancel_echo_restored",
    "same_key_and_requests", "fingerprint_compared", "comparison_compared",
    "enrolled", "validated_existing", "first_report", "pending_retained",
    "exact_retry", "original_receipt_time", "fresh_sequence", "tls13",
    "current_leaf", "missing_client_rejected", "basic_only", "source_semantics",
    "children_reaped", "listeners_stopped", "owned_tree_removed",
    "custody_mismatch", "supervisor_failure", "endpoint_cases_passed",
    "custody_case_implemented", "stage1_passed",
)
REQUIRED_ENDPOINT = tuple(x for x in RESULT_FIELDS if x not in {
    "blocked", "simulated_manager", "runtime_started", "custody_mismatch", "supervisor_failure",
    "endpoint_cases_passed", "custody_case_implemented", "stage1_passed",
})


class FixtureFailure(Exception):
    """Never attach raw errors, paths or values to an exception crossing a boundary."""
    def __str__(self):
        return "fixture stopped"


class CustodyFailure(FixtureFailure):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise FixtureFailure()


def closed_result() -> dict[str, bool]:
    result = dict.fromkeys(RESULT_FIELDS, False)
    result["blocked"] = True
    result["simulated_manager"] = True
    return result


def result_json(result: dict[str, bool]) -> str:
    # No permissive object serialization: only exact, literal boolean fields.
    require(type(result) is dict and set(result) == set(RESULT_FIELDS))
    require(all(type(value) is bool for value in result.values()))
    return json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n"


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def strict_json(raw: bytes, limit: int = CONTROL_LIMIT) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(FixtureFailure()))
    except (ValueError, UnicodeError, RecursionError):
        raise FixtureFailure() from None
    require(type(value) is dict)
    return value


def bool_reply(value: dict, names: tuple[str, ...]) -> dict:
    require(type(value) is dict and set(value) == set(names))
    require(all(type(x) is bool for x in value.values()))
    return value


def status_reply(value: dict) -> dict:
    require(type(value) is dict and set(value) == STATUS_BOOLS | STATUS_COUNTS)
    require(all(type(value[k]) is bool for k in STATUS_BOOLS))
    require(all(type(value[k]) is int and 0 <= value[k] <= 16 for k in STATUS_COUNTS))
    return value


def public_bootstrap(value: dict) -> bytes:
    names = {"schemaVersion", "managerInstanceId", "profile", "enrollmentOrigin",
             "agentOrigin", "collectionProfile", "invitationId", "serverCaPem",
             "issuerRootPem", "issuerPem"}
    require(type(value) is dict and set(value) == names)
    require(all(type(x) is str and 0 < len(x) <= 32768 for x in value.values()))
    require(value["schemaVersion"] == "tracebolt.enrollment-bootstrap.v2")
    require(value["profile"] == "tls" and value["collectionProfile"] == "basic-readonly-v1")
    ports = []
    for name in ("enrollmentOrigin", "agentOrigin"):
        match = re.fullmatch(r"https://127\.0\.0\.1:([1-9][0-9]{0,4})", value[name])
        require(match is not None)
        port = int(match.group(1))
        require(port <= 65535)
        ports.append(port)
    require(ports[0] != ports[1])
    for name in ("managerInstanceId", "invitationId"):
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value[name]) is not None)
    for name in ("serverCaPem", "issuerRootPem", "issuerPem"):
        # Public certificates only. Product bootstrap parsing remains authoritative.
        require(re.fullmatch(r"(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+"
                             r"-----END CERTIFICATE-----\n?)+", value[name]) is not None)
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    require(len(raw) <= CONTROL_LIMIT)
    return raw


def start_reply(value: dict) -> tuple[bytes, bytearray]:
    require(type(value) is dict and set(value) == {"bootstrap", "invitation"})
    require(type(value["invitation"]) is str)
    require(re.fullmatch(r"[A-Za-z0-9_-]{43}", value["invitation"]) is not None)
    bootstrap = public_bootstrap(value["bootstrap"])
    secret = bytearray(value.pop("invitation"), "ascii")
    value.clear()
    require(bytes(secret) not in bootstrap)
    return bootstrap, secret


def displayed_identity(raw: bytes) -> tuple[str, str]:
    require(len(raw) <= OUTPUT_LIMIT)
    fingerprints = re.findall(FP_PATTERN, raw)
    comparisons = re.findall(COMPARISON_PATTERN, raw)
    require(len(fingerprints) == 1 and len(comparisons) == 1)
    return fingerprints[0].decode("ascii"), comparisons[0].decode("ascii")


def ledger_identity(raw: bytes) -> tuple[str, ...]:
    value = strict_json(raw)
    names = ("seed", "csr", "claimId", "claimRequestId", "statusRequestId",
             "credentialRequestId", "activationRequestId")
    require(all(type(value.get(k)) is str and 0 < len(value[k]) <= 4096 for k in names))
    require(len(set(value[k] for k in names[2:])) == len(names[2:]))
    # Comparing seed AND CSR also proves same public key without generating a key.
    return tuple(value[k] for k in names)


def pending_state(raw: bytes, expected_pending: bool) -> tuple[int, bytes]:
    value = strict_json(raw, FILE_LIMIT)
    require(set(value) == {"version", "binding", "lastSequence", "pending"})
    sequence = value["lastSequence"]
    require(type(sequence) is int and 0 < sequence <= 9007199254740991)
    if not expected_pending:
        require(value["pending"] is None)
        return sequence, b""
    pending = value["pending"]
    require(type(pending) is dict and set(pending) == {"sequence", "digest", "body"})
    require(type(pending["sequence"]) is int and pending["sequence"] == sequence)
    require(type(pending["body"]) is str and type(pending["digest"]) is str)
    try:
        body = base64.b64decode(pending["body"], validate=True)
    except (ValueError, TypeError):
        raise FixtureFailure() from None
    require(0 < len(body) <= FRAME_LIMIT)
    require(base64.b64encode(body).decode("ascii") == pending["body"])
    require(hashlib.sha256(body).hexdigest() == pending["digest"])
    return sequence, body


class BoundedBuffer:
    def __init__(self, limit: int = OUTPUT_LIMIT):
        self.limit = limit
        self.data = bytearray()
        self.total = 0

    def append(self, data: bytes) -> None:
        require(self.total + len(data) <= self.limit)
        self.total += len(data)
        self.data.extend(data)

    def clear(self) -> None:
        self.data[:] = b"\0" * len(self.data)
        self.data.clear()


def _record(metadata) -> tuple[int, int, int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid,
            stat.S_IMODE(metadata.st_mode), stat.S_IFMT(metadata.st_mode), metadata.st_nlink)


def private_metadata(metadata, uid: int, directory: bool) -> bool:
    expected_mode = 0o700 if directory else 0o600
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    return (metadata.st_uid == uid and stat.S_IMODE(metadata.st_mode) == expected_mode
            and expected_type(metadata.st_mode) and (directory or metadata.st_nlink == 1))


@dataclass(frozen=True)
class FutureInputs:
    """Not an authorization object; a future gate must pin/review these values."""
    approved_parent: str
    peer_binary: str
    peer_sha256: str
    enroll_binary: str
    enroll_sha256: str
    sender_binary: str
    sender_sha256: str


def _open_canonical_directory(path: str) -> int:
    require(type(path) is str and os.path.isabs(path) and os.path.normpath(path) == path)
    require(path != "/" and os.path.realpath(path) == path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in path.split("/")[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check_binary(path: str, digest: str) -> None:
    # Hashes bind the inspected file only. Pathname execution has a remaining
    # same-owner swap window; this is not immutable-artifact execution evidence.
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None)
    parent, name = os.path.split(path)
    fd = _open_canonical_directory(parent)
    file_fd = -1
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        before = os.fstat(file_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        require(before.st_uid in (0, os.getuid()) and before.st_mode & 0o022 == 0)
        require(before.st_mode & 0o111 != 0 and 0 < before.st_size <= 128 * 1024 * 1024)
        hasher = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(file_fd, min(65536, remaining))
            require(bool(block))
            hasher.update(block)
            remaining -= len(block)
        require(not os.read(file_fd, 1))
        after = os.fstat(file_fd)
        require(_record(before) == _record(after) and before.st_mtime_ns == after.st_mtime_ns)
        require(hasher.hexdigest() == digest)
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(fd)


def _directory_names(fd: int) -> list[str]:
    # scandir is consumed only up to the limit; listdir would allocate an
    # unbounded hostile directory before checking its length.
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= MAX_TREE_ENTRIES:
                raise CustodyFailure()
            names.append(entry.name)
    return names


class OwnedTree:
    """One newly created tree, descriptor-relative no-follow custody and cleanup.

    No shutil/rmtree, realpath repair, glob cleanup or permissions repair. A
    complete validated inventory is recorded after all children are reaped; any
    mismatch preserves the remaining tree. Same-UID hostile races are not claimed
    to be atomic compare-and-unlink protection: Darwin has no such Python API.
    """
    def __init__(self, parent: str):
        import tempfile
        self.parent = parent
        self.parent_fd = self.fd = -1
        try:
            self.parent_fd = _open_canonical_directory(parent)
            self.parent_record = _record(os.fstat(self.parent_fd))
            self.path = tempfile.mkdtemp(prefix="tracebolt-endpoint-", dir=parent)
            self.name = os.path.basename(self.path)
            self.fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                              os.O_CLOEXEC, dir_fd=self.parent_fd)
            self.root_record = _record(os.fstat(self.fd))
            self.uid = os.getuid()
            require(private_metadata(os.fstat(self.fd), self.uid, True))
            self.state = os.path.join(self.path, "state")
            self.config = os.path.join(self.state, "agent.json")
            self.bootstrap = os.path.join(self.path, "bootstrap.json")
        except BaseException:
            # Construction did not establish custody. Preserve any created tree;
            # never guess-delete it or chmod a strict-umask result. The caller
            # cannot own self until construction returns, so release every known
            # descriptor here and replace raw acquisition errors with a fixed one.
            for fd in (self.fd, self.parent_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except (Exception, KeyboardInterrupt):
                        pass
            self.parent_fd = self.fd = -1
            raise CustodyFailure() from None

    def _root(self):
        if (_record(os.fstat(self.parent_fd))[:5] != self.parent_record[:5] or
                _record(os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False))[:5] != self.root_record[:5] or
                _record(os.fstat(self.fd))[:5] != self.root_record[:5]):
            raise CustodyFailure()

    def write_bootstrap(self, raw: bytes):
        self._root()
        public_bootstrap(strict_json(raw))
        fd = os.open("bootstrap.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            require(private_metadata(os.fstat(fd), self.uid, False))
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                require(count > 0)
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)

    def read(self, relative: str) -> bytes:
        self._root()
        require(relative in {"state/ledger.json", "state/agent.json", "state/agent-key.pem",
                             "state/telemetry/state.json"})
        parts = relative.split("/")
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                  os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                if not private_metadata(os.fstat(fd), self.uid, True):
                    raise CustodyFailure()
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                              os.O_CLOEXEC, dir_fd=fd)
            try:
                before = os.fstat(file_fd)
                if not private_metadata(before, self.uid, False):
                    raise CustodyFailure()
                require(0 < before.st_size <= FILE_LIMIT)
                chunks = bytearray()
                while len(chunks) <= FILE_LIMIT:
                    block = os.read(file_fd, min(65536, FILE_LIMIT + 1 - len(chunks)))
                    if not block:
                        break
                    chunks.extend(block)
                after = os.fstat(file_fd)
                require(len(chunks) <= FILE_LIMIT)
                if (_record(before) != _record(after) or before.st_mtime_ns != after.st_mtime_ns or
                        _record(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)) != _record(after)):
                    raise CustodyFailure()
                return bytes(chunks)
            finally:
                os.close(file_fd)
        finally:
            os.close(fd)

    def _inventory(self, fd: int, prefix: str = "", depth: int = 0) -> dict:
        if depth > MAX_TREE_DEPTH:
            raise CustodyFailure()
        result = {}
        names = _directory_names(fd)
        if len(names) > MAX_TREE_ENTRIES:
            raise CustodyFailure()
        for name in names:
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            directory = stat.S_ISDIR(entry.st_mode)
            if not private_metadata(entry, self.uid, directory):
                raise CustodyFailure()
            key = prefix + name
            if key not in OWNED_LAYOUT or OWNED_LAYOUT[key] != directory:
                raise CustodyFailure()
            if not directory and entry.st_size > FILE_LIMIT:
                raise CustodyFailure()
            result[key] = _record(entry)
            if directory:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC, dir_fd=fd)
                try:
                    if _record(os.fstat(child)) != _record(entry):
                        raise CustodyFailure()
                    result.update(self._inventory(child, key + "/", depth + 1))
                finally:
                    os.close(child)
            if len(result) > MAX_TREE_ENTRIES:
                raise CustodyFailure()
        return result

    def cleanup(self) -> bool:
        self._root()
        records = self._inventory(self.fd)
        self._root()
        if self._inventory(self.fd) != records:
            raise CustodyFailure()
        for relative in sorted(records, key=lambda p: p.count("/"), reverse=True):
            parts = relative.split("/")
            fd = os.dup(self.fd)
            try:
                prefix = ""
                for part in parts[:-1]:
                    prefix += part
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                    os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd)
                    fd = child
                    # Directory nlink changes as owned children are removed.
                    if _record(os.fstat(fd))[:5] != records[prefix][:5]:
                        raise CustodyFailure()
                    prefix += "/"
                current = _record(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False))
                expected = records[relative]
                if current[:5] != expected[:5] or (current[4] == stat.S_IFREG and current[5] != 1):
                    raise CustodyFailure()
                if current[4] == stat.S_IFDIR:
                    os.rmdir(parts[-1], dir_fd=fd)
                else:
                    os.unlink(parts[-1], dir_fd=fd)
            finally:
                os.close(fd)
        # Root nlink changes when its owned state directory is removed.
        if (_record(os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False))[:5]
                != self.root_record[:5] or _directory_names(self.fd)):
            raise CustodyFailure()
        os.rmdir(self.name, dir_fd=self.parent_fd)
        return True

    def close(self):
        failed = False
        for fd in (self.fd, self.parent_fd):
            try:
                os.close(fd)
            except (Exception, KeyboardInterrupt):
                failed = True
        self.fd = self.parent_fd = -1
        require(not failed)


class Child:
    """One directly owned subprocess; all output remains bounded in memory."""
    def __init__(self, process, streams, master=None, slave=None, original=None):
        self.process = process
        self.streams = dict(streams)
        self.output = BoundedBuffer()
        self.stdout = BoundedBuffer()
        self.master, self.slave, self.original = master, slave, original
        self.closed = False

    def pump(self, timeout: float):
        import select
        if not self.streams:
            time.sleep(min(timeout, 0.02))
            return
        ready, _, _ = select.select(list(self.streams), [], [], timeout)
        for fd in ready:
            try:
                block = os.read(fd, 8192)
            except BlockingIOError:
                continue
            except OSError:
                # A held slave avoids treating Darwin/Linux PTY EIO as success.
                raise FixtureFailure() from None
            if not block:
                self.streams.pop(fd)
                continue
            self.output.append(block)
            if self.streams[fd] == "stdout":
                self.stdout.append(block)

    def until(self, predicate: Callable[[], bool], deadline: float):
        while not predicate():
            require(time.monotonic() < deadline)
            self.pump(min(0.05, max(0, deadline - time.monotonic())))
            require(predicate() or self.process.poll() is None)

    def wait(self, seconds: float) -> int:
        deadline = time.monotonic() + seconds
        while self.process.poll() is None:
            require(time.monotonic() < deadline)
            self.pump(min(0.05, max(0, deadline - time.monotonic())))
        # Drain available bytes without waiting on the retained PTY slave.
        import select
        while self.streams and select.select(list(self.streams), [], [], 0)[0]:
            self.pump(0)
        return self.process.wait(timeout=0)

    def echo_hidden(self) -> bool:
        import termios
        require(self.slave is not None)
        flags = termios.tcgetattr(self.slave)[3]
        return flags & (termios.ECHO | termios.ECHONL | termios.ICANON) == 0

    def echo_restored(self) -> bool:
        import termios
        require(self.slave is not None and self.original is not None)
        return termios.tcgetattr(self.slave) == self.original

    def send_invitation(self, secret: bytearray):
        require(self.echo_hidden() and self.process.poll() is None)
        payload = bytearray(secret)
        payload.append(10)
        try:
            _bounded_write(self.master, payload, time.monotonic() + 2)
        finally:
            payload[:] = b"\0" * len(payload)

    def stop(self) -> bool:
        import signal
        for sig, grace in ((signal.SIGINT, 3), (signal.SIGTERM, 3), (signal.SIGKILL, 2)):
            if self.process.poll() is not None:
                self.process.wait(timeout=0)
                return True
            self.process.send_signal(sig)
            deadline = time.monotonic() + grace
            while self.process.poll() is None and time.monotonic() < deadline:
                try:
                    self.pump(0.05)
                except Exception:
                    # Reaping must still happen on a bound/read failure. Discard
                    # further bytes without writing them anywhere.
                    self.streams.clear()
            if self.process.poll() is not None:
                self.process.wait(timeout=0)
                return True
        return False

    def close(self):
        if self.closed:
            return
        self.closed = True
        failed = False
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (Exception, KeyboardInterrupt):
                    failed = True
        for fd in (self.master, self.slave):
            if fd is not None:
                try:
                    os.close(fd)
                except (Exception, KeyboardInterrupt):
                    # Do not retry close after an uncertain close outcome.
                    failed = True
        self.output.clear()
        self.stdout.clear()
        require(not failed)


def _bounded_write(fd: int, data, deadline: float):
    import select
    view = memoryview(data)
    while view:
        require(time.monotonic() < deadline)
        if not select.select([], [fd], [], min(0.05, deadline - time.monotonic()))[1]:
            continue
        try:
            count = os.write(fd, view)
        except BlockingIOError:
            continue
        require(count > 0)
        view = view[count:]


class NativeRuntime:
    """Not constructed by any entry point in this source-only revision."""
    def __init__(self, inputs: FutureInputs):
        require(sys.platform == "darwin" and os.getuid() != 0 and os.getuid() == os.geteuid())
        for path, digest in ((inputs.peer_binary, inputs.peer_sha256),
                             (inputs.enroll_binary, inputs.enroll_sha256),
                             (inputs.sender_binary, inputs.sender_sha256)):
            _check_binary(path, digest)
        self.inputs = inputs
        self.children = []
        self.tree = OwnedTree(inputs.approved_parent)
        self.peer = None
        self.peer_stopped = False

    def _spawn(self, argv: list[str], terminal: bool = False) -> Child:
        import subprocess
        # No inherited credentials, proxies, config search paths or user shell.
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
        master = slave = None
        original = None
        try:
            if terminal:
                import fcntl
                import pty
                import termios
                master, slave = pty.openpty()
                original = termios.tcgetattr(slave)
                require(original[3] & termios.ECHO != 0)
                os.set_blocking(master, False)
                def controlling_terminal():
                    os.setsid()
                    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=slave,
                                           stderr=slave, env=env, cwd=self.tree.path,
                                           close_fds=True, pass_fds=(slave,),
                                           preexec_fn=controlling_terminal)
                child = Child(process, {master: "pty"}, master, slave, original)
            else:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, env=env, cwd=self.tree.path,
                                           close_fds=True, start_new_session=True)
                child = Child(process, {process.stdout.fileno(): "stdout",
                                        process.stderr.fileno(): "stderr"})
            self.children.append(child)
            if not terminal:
                for stream in (process.stdin, process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
            return child
        except BaseException:
            # Successful Popen is registered before nonblocking setup. A later
            # failure is handled by cleanup; do not close its owned PTY twice.
            if "child" not in locals():
                for fd in (master, slave):
                    if fd is not None:
                        os.close(fd)
            raise

    def rpc(self, command: str, **fields) -> dict:
        require(command in {"start", "approve", "arm_loss", "status", "stop"})
        if command == "start":
            require(self.peer is None)
            self.peer = self._spawn([self.inputs.peer_binary])
        require(self.peer is not None and self.peer.process.poll() is None)
        payload = json.dumps({"command": command, **fields}, separators=(",", ":")).encode("ascii") + b"\n"
        require(len(payload) <= 4096)
        _bounded_write(self.peer.process.stdin.fileno(), payload, time.monotonic() + 2)
        self.peer.until(lambda: b"\n" in self.peer.stdout.data, time.monotonic() + 15)
        raw, trailing = bytes(self.peer.stdout.data).split(b"\n", 1)
        require(not trailing and len(raw) <= CONTROL_LIMIT)
        self.peer.stdout.clear()
        self.peer.output.clear()
        result = strict_json(raw)
        # start raw contains invitation: drop references promptly. Copies in
        # Python's decoder/allocator cannot be guaranteed erased.
        raw = b""
        if command == "stop":
            bool_reply(result, ("stopped",))
            require(result["stopped"])
            require(self.peer.wait(5) == 0)
            self.peer_stopped = True
        return result

    def enroll(self) -> Child:
        return self._spawn([self.inputs.enroll_binary, "--bootstrap", self.tree.bootstrap,
                            "--state-directory", self.tree.state, "--timeout", "2m"], True)

    def sender(self, validate: bool = False) -> int:
        args = [self.inputs.sender_binary, "--config", self.tree.config]
        if validate:
            args.append("--validate-guided")
        child = self._spawn(args)
        # Agent stdin receives EOF, never the invitation or a control command.
        child.process.stdin.close()
        return child.wait(10 if validate else 35)

    def read(self, name: str) -> bytes:
        return self.tree.read(name)

    def write_bootstrap(self, raw: bytes):
        self.tree.write_bootstrap(raw)

    def cleanup(self, preserve_tree: bool = False) -> tuple[bool, bool, bool, bool]:
        import signal
        reaped, stopped, removed, mismatch = True, self.peer_stopped, False, preserve_tree
        interrupted = [False]
        failed = False
        previous_handler = None
        handler_attempted = False

        def defer_interrupt(_signum, _frame):
            interrupted[0] = True

        # Repeated Ctrl-C must not abandon owned children. No global permissions
        # change: defer SIGINT only in this supervisor during its bounded teardown,
        # then restore the exact previous handler even if an operation fails.
        try:
            previous_handler = signal.getsignal(signal.SIGINT)
            handler_attempted = True
            signal.signal(signal.SIGINT, defer_interrupt)
        except (Exception, KeyboardInterrupt):
            failed = True
        try:
            if self.peer is not None:
                try:
                    if self.peer.process.poll() is None:
                        self.rpc("stop")
                        stopped = True
                except (Exception, KeyboardInterrupt):
                    failed = True
                    stopped = False
            for child in reversed(self.children):
                child_reaped = False
                # A synthetic/explicit KeyboardInterrupt can still be raised by
                # an adapter. Retry this owned reap once, then continue others;
                # both attempts retain Child.stop's fixed maximum grace periods.
                for attempt in range(2):
                    try:
                        child_reaped = child.stop()
                        break
                    except KeyboardInterrupt:
                        interrupted[0] = True
                        if attempt == 1:
                            failed = True
                    except Exception:
                        failed = True
                        break
                reaped = child_reaped and reaped
            # Never remove state while any owned child remains unreaped. A peer
            # killed/reaped without its explicit joined stop cannot earn a pass.
            if reaped and not preserve_tree:
                try:
                    removed = self.tree.cleanup()
                except CustodyFailure:
                    mismatch = True
                except (Exception, KeyboardInterrupt):
                    failed = True
            for child in self.children:
                try:
                    child.close()
                except (Exception, KeyboardInterrupt):
                    failed = True
            try:
                self.tree.close()
            except (Exception, KeyboardInterrupt):
                failed = True
        finally:
            if handler_attempted:
                for attempt in range(2):
                    try:
                        signal.signal(signal.SIGINT, previous_handler)
                        break
                    except (Exception, KeyboardInterrupt):
                        failed = True
        require(not failed and not interrupted[0])
        return reaped, stopped, removed, mismatch


def _exercise(runtime, clock: Callable[[], float] = time.monotonic,
              pause: Callable[[float], None] = time.sleep) -> dict[str, bool]:
    """Future orchestration. Unit tests pass fake adapters; NEVER native today."""
    import signal
    result = closed_result()
    result["runtime_started"] = True
    secret = bytearray()
    try:
        bootstrap, secret = start_reply(runtime.rpc("start"))
        runtime.write_bootstrap(bootstrap)
        first = runtime.enroll()
        first.until(lambda: HIDDEN_PROMPT in first.output.data, clock() + 15)
        require(first.echo_hidden())
        original_display = displayed_identity(bytes(first.output.data))
        result["hidden_prompt"] = True
        first.process.send_signal(signal.SIGINT)
        require(first.wait(5) != 0 and first.echo_restored())
        result["cancel_echo_restored"] = True
        original_identity = ledger_identity(runtime.read("state/ledger.json"))
        resumed = runtime.enroll()
        resumed.until(lambda: HIDDEN_PROMPT in resumed.output.data, clock() + 15)
        require(resumed.echo_hidden())
        display = displayed_identity(bytes(resumed.output.data))
        require(display == original_display)
        require(ledger_identity(runtime.read("state/ledger.json")) == original_identity)
        resumed.send_invitation(secret)
        resumed.until(lambda: PENDING_PROMPT in resumed.output.data, clock() + 20)
        require(bytes(secret) not in resumed.output.data)
        deadline = clock() + 20
        while True:
            reply = bool_reply(runtime.rpc("approve", fingerprint=display[0], comparison=display[1]),
                               ("fingerprintMatched", "comparisonMatched", "approved"))
            if reply["approved"]:
                require(reply["fingerprintMatched"] and reply["comparisonMatched"])
                break
            require(not reply["fingerprintMatched"] and not reply["comparisonMatched"])
            require(clock() < deadline)
            resumed.pump(0.05)
            pause(0.05)
        result["fingerprint_compared"] = reply["fingerprintMatched"]
        result["comparison_compared"] = reply["comparisonMatched"]
        require(resumed.wait(120) == 0 and resumed.echo_restored())
        require(bytes(secret) not in first.output.data and bytes(secret) not in resumed.output.data)
        secret[:] = b"\0" * len(secret)
        require(ledger_identity(runtime.read("state/ledger.json")) == original_identity)
        result["same_key_and_requests"] = True
        original_key = runtime.read("state/agent-key.pem")
        config = strict_json(runtime.read("state/agent.json"))
        require(config.get("profile") == "tls" and not config.get("renewalManifestFile"))
        # The actual generated path is fixed by handoff.go. Never scrape a shell
        # command from CLI output or infer a path from another profile.
        result["enrolled"] = True
        require(runtime.sender(validate=True) == 0)
        result["validated_existing"] = True
        require(runtime.sender() == 0)
        before_sequence, _ = pending_state(runtime.read("state/telemetry/state.json"), False)
        first_status = status_reply(runtime.rpc("status"))
        require(first_status["acceptedReports"] == 1 and first_status["duplicateReports"] == 0)
        require(first_status["lossCount"] == 0)
        result["first_report"] = True
        require(bool_reply(runtime.rpc("arm_loss"), ("armed",))["armed"])
        retry_started = clock()
        require(runtime.sender() != 0)
        pending_raw = runtime.read("state/telemetry/state.json")
        pending_sequence, _ = pending_state(pending_raw, True)
        require(pending_sequence == before_sequence + 1)
        lost_status = status_reply(runtime.rpc("status"))
        require(lost_status["acceptedReports"] == 2 and lost_status["lossCount"] == 1)
        require(lost_status["duplicateReports"] == 0)
        result["pending_retained"] = True
        require(runtime.read("state/telemetry/state.json") == pending_raw)
        require(runtime.sender() == 0 and clock() - retry_started < 120)
        sequence, _ = pending_state(runtime.read("state/telemetry/state.json"), False)
        require(sequence == pending_sequence)
        retried = status_reply(runtime.rpc("status"))
        require(retried["exactRetry"] and retried["originalReceiptTime"])
        require(retried["acceptedReports"] == 2 and retried["duplicateReports"] == 1)
        result["exact_retry"], result["original_receipt_time"] = True, True
        require(runtime.sender() == 0)
        sequence, _ = pending_state(runtime.read("state/telemetry/state.json"), False)
        require(sequence == pending_sequence + 1)
        final = status_reply(runtime.rpc("status"))
        require(all(final[k] for k in STATUS_BOOLS))
        require(final["acceptedReports"] == 3 and final["duplicateReports"] == 1 and final["lossCount"] == 1)
        require(runtime.read("state/agent-key.pem") == original_key)
        require(ledger_identity(runtime.read("state/ledger.json")) == original_identity)
        for source, destination in (("nextSequence", "fresh_sequence"), ("tls13", "tls13"),
                                    ("currentLeaf", "current_leaf"), ("missingClientRejected", "missing_client_rejected"),
                                    ("basicOnly", "basic_only"), ("sourceSemantics", "source_semantics")):
            result[destination] = final[source]
    except CustodyFailure:
        result["custody_mismatch"] = True
        result["supervisor_failure"] = True
    except (Exception, KeyboardInterrupt):
        result["supervisor_failure"] = True
    finally:
        secret[:] = b"\0" * len(secret)
        try:
            reaped, stopped, removed, mismatch = runtime.cleanup(preserve_tree=result["custody_mismatch"])
            require(all(type(v) is bool for v in (reaped, stopped, removed, mismatch)))
            result["children_reaped"], result["listeners_stopped"] = reaped, stopped
            result["owned_tree_removed"] = removed
            result["custody_mismatch"] = result["custody_mismatch"] or mismatch
        except (Exception, KeyboardInterrupt):
            result["supervisor_failure"] = True
    result["endpoint_cases_passed"] = (all(result[k] for k in REQUIRED_ENDPOINT)
                                        and not result["supervisor_failure"] and not result["custody_mismatch"])
    # Unconditionally false until the separately reviewed custody case exists.
    result["stage1_passed"] = False
    return result


def run_after_exact_review(*_args, **_kwargs):
    """There is deliberately no implemented runtime approval gate in this revision."""
    raise FixtureFailure()


def main(argv=None, output=None) -> int:
    # Intentionally do not parse argv/env/stdin, inspect platform/state/binaries,
    # construct adapters, open PTYs, spawn children, generate keys or bind sockets.
    (output if output is not None else sys.stdout).write(result_json(closed_result()))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
