"""Source-only, separately admitted synthetic OSLog evidence gate.

Not a product provider, grant, stable Apple schema, or authorization mechanism.
The supervisor must verify the frozen source/manual, native platform, exact
approved host scope and task-tree custody before configure_admission is entered.
No execution occurs on import. No raw bytes, messages or exception text leave
run_log_gate; validate_result is the public, closed output-schema boundary.

Native flags/framing: acquired Apple log(1), text SHA256
  d89cb620dbcab9e849161d2f3c63c4be62c5bd8240bba851d395a09fc7504c08.
Event keys below are ONLY a conservative hypothesis, based on the native CLI
example in https://docs.nxlog.co/userguide/os/macos.html (Example 2; exclude
NXLog-added fields), plus Apple log(1)'s documented predicate keys. That example
is not Apple's schema guarantee, nor evidence from this runner. Unknown actual
keys/types/terminal shapes fail unsupported without recording their names/values.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
import time

MAX_BYTES = 1024 * 1024
MAX_OBJECT = 64 * 1024
MAX_EVENTS = 64
MAX_DEPTH = 8
MAX_KEYS = 64
QUERY_SECONDS = 15
EMITTER_SECONDS = 90
READ_SIZE = 4096
# Report measured elapsed milliseconds through the 20-minute outer job budget;
# a longer/non-finite/regressed measurement is unknown, never silently clipped.
MAX_ELAPSED_MILLISECONDS = 1200000
SUBSYSTEM_PREFIX = "org.tracebolt.nativeacceptance."
PUBLIC_MESSAGE = "tracebolt-native-public"
SPECIAL_MESSAGE = 'tracebolt-native-special line1\nline2 "quoted" café'
PRIVATE_PREFIX = "tracebolt-native-private PUBLIC_CANARY "
# This is a reviewed nonsecret synthetic source constant. Never output its value.
_PRIVATE_CANARY = "PRIVATE_CANARY"
FIELD_TYPES = {
    "traceID": "integer", "eventMessage": "string", "eventType": "string",
    "source": "null", "formatString": "string", "activityIdentifier": "integer",
    "subsystem": "string", "category": "string", "threadID": "integer",
    "senderImageUUID": "string", "backtrace": "object", "bootUUID": "string",
    "processImagePath": "string", "timestamp": "string", "senderImagePath": "string",
    "machTimestamp": "integer", "messageType": "string", "processImageUUID": "string",
    "processID": "integer", "senderProgramCounter": "integer",
    "parentActivityIdentifier": "integer", "timezoneName": "string",
}
REQUIRED_FIELDS = frozenset(("subsystem", "category", "processID", "eventMessage",
                             "timestamp", "eventType", "messageType"))
OBSERVATION_KEYS = ("publicMarker", "specialMarker", "privateMarker",
                    "multilinePreserved", "unicodePreserved", "privateCanaryVisible",
                    "privateCanaryAbsent", "timestampShape", "insideWindow")
QUERY_IDS = ("json_positive", "ndjson_positive", "json_negative")
STATUSES = frozenset(("not_run", "passed", "blocked", "failed", "unsupported",
                      "inconclusive_not_observed"))
REASONS = frozenset(("not_admitted", "not_run", "accepted", "not_observed",
    "invalid_admission", "unsupported_platform", "configuration_present_or_unknown",
    "spawn_failed", "source_unavailable", "stderr_present", "timeout", "byte_limit",
    "object_limit", "event_limit", "depth_limit", "key_limit", "malformed_framing",
    "invalid_json", "unsupported_schema", "unrelated_event", "duplicate_event",
    "incomplete_markers", "timestamp_shape", "outside_window", "clock_regression",
    "window_limit", "emitter_unavailable", "emitter_protocol", "emitter_timeout",
    "reap_failed", "cancelled", "internal_error"))
_ADMISSION = ContextVar("synthetic_oslog_admission", default=None)


class _Failure(Exception):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "internal_error"
        super().__init__(self.reason)


class _Cancelled(BaseException):
    pass


def _integer(value, maximum, minimum=0):
    return type(value) is int and minimum <= value <= maximum


def _query_template(index):
    return dict(id=QUERY_IDS[index], status="not_run", reason="not_run", exitCode=None,
                stdoutBytes=0, stderrBytes=0, elapsedMilliseconds=0, eventCount=0,
                started=False, reaped=False, timedOut=False, bounded=True, framingComplete=False,
                terminalFinished=False, fields={},
                observations={name: None for name in OBSERVATION_KEYS})


def result_template(reason="not_admitted"):
    """Closed failure result; caller text can never be copied into it."""
    if reason not in REASONS:
        reason = "internal_error"
    return dict(schemaVersion=1, gate="synthetic_oslog_schema", status="blocked",
                reason=reason, emitter=dict(started=False, reaped=False,
                deadlineExceeded=False, stdoutBytes=0, stderrBytes=0),
                queries=[_query_template(i) for i in range(3)])


def validate_result(value):
    """Accept only the finite content-free result schema, without throwing."""
    try:
        if type(value) is not dict or set(value) != set(result_template()):
            return False
        if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1:
            return False
        if value["gate"] != "synthetic_oslog_schema" or value["status"] not in STATUSES - {"not_run"} or value["reason"] not in REASONS:
            return False
        e = value["emitter"]
        if type(e) is not dict or set(e) != set(result_template()["emitter"]):
            return False
        if any(type(e[k]) is not bool for k in ("started", "reaped", "deadlineExceeded")):
            return False
        if any(not _integer(e[k], 65) for k in ("stdoutBytes", "stderrBytes")):
            return False
        if type(value["queries"]) is not list or len(value["queries"]) != 3:
            return False
        for i, q in enumerate(value["queries"]):
            if type(q) is not dict or set(q) != set(_query_template(i)) or q["id"] != QUERY_IDS[i]:
                return False
            if q["status"] not in STATUSES or q["reason"] not in REASONS:
                return False
            if q["exitCode"] is not None and not _integer(q["exitCode"], 255, -255):
                return False
            for name, cap in (("stdoutBytes", MAX_BYTES + 1), ("stderrBytes", MAX_BYTES + 1), ("eventCount", MAX_EVENTS)):
                if not _integer(q[name], cap):
                    return False
            if q["elapsedMilliseconds"] is not None and not _integer(q["elapsedMilliseconds"], MAX_ELAPSED_MILLISECONDS):
                return False
            if q["stdoutBytes"] + q["stderrBytes"] > MAX_BYTES + 1:
                return False
            if any(type(q[k]) is not bool for k in ("started", "reaped", "timedOut", "bounded", "framingComplete", "terminalFinished")):
                return False
            if type(q["observations"]) is not dict or set(q["observations"]) != set(OBSERVATION_KEYS):
                return False
            if any(v is not None and type(v) is not bool for v in q["observations"].values()):
                return False
            if type(q["fields"]) is not dict or (q["fields"] and set(q["fields"]) != set(FIELD_TYPES)):
                return False
            if q["status"] not in ("passed", "inconclusive_not_observed") and (q["fields"] or any(v is not None for v in q["observations"].values())):
                return False
            if q["reaped"] and not q["started"]:
                return False
            if not q["started"] and (q["exitCode"] is not None or q["stdoutBytes"] or q["stderrBytes"] or q["eventCount"] or q["framingComplete"] or q["terminalFinished"] or q["timedOut"]):
                return False
            if q["status"] == "not_run" and q != _query_template(i):
                return False
            for name, row in q["fields"].items():
                if type(row) is not dict or set(row) != {"present", "null", "empty", "types"}:
                    return False
                if any(not _integer(row[k], q["eventCount"]) for k in ("present", "null", "empty")):
                    return False
                if row["null"] + row["empty"] > row["present"]:
                    return False
                if type(row["types"]) is not list or len(row["types"]) > 2:
                    return False
                if row["types"] != sorted(set(row["types"])) or not set(row["types"]) <= {FIELD_TYPES[name], "null"}:
                    return False
            if q["status"] in {"passed", "inconclusive_not_observed"}:
                if not (q["started"] and q["reaped"] and q["exitCode"] == 0 and q["bounded"] and q["framingComplete"]):
                    return False
                if q["stderrBytes"] or q["timedOut"] or q["elapsedMilliseconds"] is None or q["elapsedMilliseconds"] >= QUERY_SECONDS * 1000 or q["terminalFinished"] != (i == 1):
                    return False
                if q["status"] == "inconclusive_not_observed":
                    if i == 2 or q["reason"] != "not_observed" or q["eventCount"] or q["fields"] or any(v is not None for v in q["observations"].values()):
                        return False
                elif q["reason"] != "accepted":
                    return False
                elif i == 2:
                    if q["eventCount"] or q["fields"] or any(v is not None for v in q["observations"].values()):
                        return False
                else:
                    if q["eventCount"] != 3 or set(q["fields"]) != set(FIELD_TYPES):
                        return False
                    if any(q["observations"][k] is not True for k in ("publicMarker", "specialMarker", "privateMarker", "multilinePreserved", "unicodePreserved", "timestampShape", "insideWindow")):
                        return False
                    if type(q["observations"]["privateCanaryVisible"]) is not bool or q["observations"]["privateCanaryAbsent"] is not (not q["observations"]["privateCanaryVisible"]):
                        return False
                    for name in REQUIRED_FIELDS:
                        if q["fields"][name] != dict(present=3, null=0, empty=0, types=[FIELD_TYPES[name]]):
                            return False
        if e["reaped"] and not e["started"]:
            return False
        if not e["started"] and (e["stdoutBytes"] or e["stderrBytes"] or e["deadlineExceeded"] or any(q["started"] for q in value["queries"])):
            return False
        if value["status"] in {"passed", "inconclusive_not_observed"}:
            if e != dict(started=True, reaped=True, deadlineExceeded=False, stdoutBytes=1, stderrBytes=0):
                return False
            statuses = [q["status"] for q in value["queries"]]
            if value["status"] == "passed":
                if value["reason"] != "accepted" or statuses != ["passed"] * 3:
                    return False
            elif value["reason"] != "not_observed" or statuses[2] != "passed" or not all(s in {"passed", "inconclusive_not_observed"} for s in statuses) or "inconclusive_not_observed" not in statuses:
                return False
        # Artifact budget is a final defense, independent from native input bounds.
        return len(json.dumps(value, ensure_ascii=True).encode("ascii")) <= 65536
    except BaseException:
        return False


@contextmanager
def configure_admission(task_root, *, before_query, clean_env, current_platform="darwin"):
    """Supervisor-only scope. It asserts reviewed approval, not a new host grant.

    before_query() must return literal True after lstat-only definite-absence
    checks at isolated HOME, original runner HOME and current passwd home.
    The context is one-shot: even failed native attempts cannot be rerun in it.
    """
    token = _ADMISSION.set(dict(root=task_root, before_query=before_query,
                               env=clean_env, platform=current_platform, used=False))
    try:
        yield
    finally:
        _ADMISSION.reset(token)


def _check_admission(task_root, emitter_path):
    a = _ADMISSION.get()
    if a is None or a["used"]:
        raise _Failure("not_admitted")
    a["used"] = True
    if a["platform"] != "darwin" or sys.platform != "darwin":
        raise _Failure("unsupported_platform")
    root = Path(task_root)
    if not root.is_absolute() or str(root) != os.path.realpath(root) or str(root) != str(a["root"]):
        raise _Failure("invalid_admission")
    if str(emitter_path) != str(root / "bin" / "tracebolt-native-log-probe"):
        raise _Failure("invalid_admission")
    expected_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
                    "TZ": "UTC", "HOME": str(root / "home"), "TMPDIR": str(root / "tmp")}
    if type(a["env"]) is not dict or a["env"] != expected_env or not callable(a["before_query"]):
        raise _Failure("invalid_admission")
    # Custody/no-follow inode checks are the supervisor's prior responsibility.
    # Copy the environment, so no mutable ambient mapping reaches subprocesses.
    a["env"] = expected_env
    return a


def _guard_config(a):
    try:
        accepted = a["before_query"]()
    except BaseException:
        raise _Failure("configuration_present_or_unknown") from None
    if accepted is not True:
        raise _Failure("configuration_present_or_unknown")


def _signal_cancel(_signum, _frame):
    raise _Cancelled()


@contextmanager
def _defer_spawn_cancellation():
    """Queue cancellation across Popen return -> owned-handle registration.

    Never mask signals across Popen: the executable must not inherit a blocked
    mask that defeats the emitter's independent alarm. After Popen returns, a
    brief parent-only mask makes handler restoration atomic with cancellation.
    A queued parent ALRM handler is invoked only after ownership registration.
    """
    saved = {}
    pending = []
    def defer(signum, _frame):
        if signum not in pending:
            pending.append(signum)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            saved[sig] = signal.getsignal(sig)
            signal.signal(sig, defer)
        yield
    finally:
        # No process creation occurs in this post-spawn restoration section.
        # Unmasking may deliver cancellation; every handle is already owned and
        # every previous handler has then been restored.
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, tuple(saved))
        try:
            for sig, handler in saved.items():
                signal.signal(sig, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    if pending:
        sig = pending[0]
        previous = saved[sig]
        if callable(previous):
            previous(sig, None)
        raise _Cancelled()


def _type_name(value):
    if value is None:
        return "null"
    return {str: "string", int: "integer", dict: "object"}.get(type(value), "unsupported")


def _pairs(pairs):
    if len(pairs) > MAX_KEYS:
        raise _Failure("key_limit")
    out = {}
    for key, value in pairs:
        if key in out:
            raise _Failure("invalid_json")
        out[key] = value
    return out


def _reject_number(_value):
    raise _Failure("unsupported_schema")


def _elapsed_milliseconds(begun):
    elapsed = time.monotonic() - begun
    if not math.isfinite(elapsed) or not 0 <= elapsed <= MAX_ELAPSED_MILLISECONDS / 1000:
        return None
    return int(elapsed * 1000)


class _ObjectScanner:
    """Bound bytes, nesting and each object's keys before allocating JSON values."""
    def __init__(self):
        self.raw = bytearray()
        self.stack = []
        self.string = False
        self.escape = False
        self.done = False

    def feed_byte(self, byte):
        if self.done or len(self.raw) >= MAX_OBJECT:
            raise _Failure("object_limit")
        if self.string:
            if self.escape:
                self.escape = False
            elif byte == 92:
                self.escape = True
            elif byte == 34:
                self.string = False
        elif byte == 34:
            self.string = True
        elif byte in (123, 91):
            if len(self.stack) >= MAX_DEPTH:
                raise _Failure("depth_limit")
            self.stack.append([byte, 0])
        elif byte == 58:
            if not self.stack or self.stack[-1][0] != 123:
                raise _Failure("invalid_json")
            if self.stack[-1][1] >= MAX_KEYS:
                raise _Failure("key_limit")
            self.stack[-1][1] += 1
        elif byte in (125, 93):
            if not self.stack or self.stack[-1][0] != (123 if byte == 125 else 91):
                raise _Failure("invalid_json")
            self.stack.pop()
            self.done = not self.stack
        self.raw.append(byte)

    def decode(self):
        if not self.done or self.string or self.stack:
            raise _Failure("malformed_framing")
        try:
            value = json.loads(self.raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                               parse_float=_reject_number, parse_constant=_reject_number)
            self._unicode(value)
            if type(value) is not dict:
                raise _Failure("unsupported_schema")
            return value
        except _Failure:
            raise
        except (ValueError, UnicodeError, RecursionError):
            raise _Failure("invalid_json") from None
        finally:
            self.raw.clear()

    @staticmethod
    def _unicode(value):
        if type(value) is str:
            value.encode("utf-8", "strict")
        elif type(value) is dict:
            for k, v in value.items():
                k.encode("utf-8", "strict")
                _ObjectScanner._unicode(v)
        elif type(value) is list:
            for v in value:
                _ObjectScanner._unicode(v)


class _Events:
    def __init__(self, subsystem, pid, start, end, negative):
        self.subsystem, self.pid = subsystem, pid
        self.start, self.end, self.negative = start, end, negative
        self.count = 0
        self.markers = set()
        self.private_visible = None
        self.fields = {k: dict(present=0, null=0, empty=0, types=set()) for k in FIELD_TYPES}

    def accept(self, value):
        if self.count >= MAX_EVENTS:
            raise _Failure("event_limit")
        self.count += 1
        if self.negative:
            raise _Failure("unrelated_event")
        # Do not derive/output any field-name/type observations until attribution.
        if not REQUIRED_FIELDS <= value.keys():
            raise _Failure("unsupported_schema")
        if (value["subsystem"] != self.subsystem or value["category"] != "schema"
                or type(value["processID"]) is not int or value["processID"] != self.pid):
            raise _Failure("unrelated_event")
        message = value["eventMessage"]
        if message == PUBLIC_MESSAGE:
            marker = "public"
        elif message == SPECIAL_MESSAGE:
            marker = "special"
        elif message in (PRIVATE_PREFIX + _PRIVATE_CANARY, PRIVATE_PREFIX + "<private>"):
            marker = "private"
            self.private_visible = message == PRIVATE_PREFIX + _PRIVATE_CANARY
        else:
            raise _Failure("unrelated_event")
        if marker in self.markers:
            raise _Failure("duplicate_event")
        if not value.keys() <= FIELD_TYPES.keys():
            raise _Failure("unsupported_schema")
        if value["eventType"] != "logEvent" or value["messageType"] != "Default":
            raise _Failure("unsupported_schema")
        for name, field in value.items():
            kind = _type_name(field)
            if kind != FIELD_TYPES[name] and not (field is None and name not in REQUIRED_FIELDS):
                raise _Failure("unsupported_schema")
            if name == "backtrace" and field is not None:
                if set(field) != {"frames"} or type(field["frames"]) is not list or len(field["frames"]) > 64:
                    raise _Failure("unsupported_schema")
                for frame in field["frames"]:
                    if type(frame) is not dict or set(frame) != {"imageOffset", "imageUUID"} or type(frame["imageOffset"]) is not int or type(frame["imageUUID"]) is not str:
                        raise _Failure("unsupported_schema")
        stamp = value["timestamp"]
        if type(stamp) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{4}", stamp):
            raise _Failure("timestamp_shape")
        try:
            instant = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f%z").timestamp()
        except ValueError:
            raise _Failure("timestamp_shape") from None
        # Observation only; no claim about the utility's boundary inclusivity.
        if not self.start <= instant < self.end:
            raise _Failure("outside_window")
        self.markers.add(marker)
        for name, field in value.items():
            row = self.fields[name]
            row["present"] += 1
            row["null"] += field is None
            row["empty"] += type(field) is str and field == ""
            row["types"].add(_type_name(field))

    def observations(self):
        return dict(publicMarker="public" in self.markers, specialMarker="special" in self.markers,
                    privateMarker="private" in self.markers, multilinePreserved="special" in self.markers,
                    unicodePreserved="special" in self.markers, privateCanaryVisible=self.private_visible,
                    privateCanaryAbsent=None if self.private_visible is None else not self.private_visible,
                    timestampShape=self.count > 0, insideWindow=self.count > 0)


class _Decoder:
    """Streaming array/NDJSON framing; never retains a full raw query result."""
    def __init__(self, style, events):
        self.style, self.events = style, events
        self.state = "start"
        self.object = None
        self.finished = False
        self.line_bytes = 0
        self.line_complete = False

    def feed(self, chunk):
        if self.style == "ndjson":
            for byte in chunk:
                if byte == 10:
                    self._line()
                else:
                    if self.line_bytes >= MAX_OBJECT:
                        raise _Failure("object_limit")
                    self.line_bytes += 1
                    if self.finished:
                        raise _Failure("malformed_framing")
                    if self.object is None:
                        if byte in b" \t\r":
                            continue
                        if byte != 123:
                            raise _Failure("malformed_framing")
                        self.object = _ObjectScanner()
                    elif self.line_complete:
                        if byte in b" \t\r":
                            continue
                        raise _Failure("malformed_framing")
                    self.object.feed_byte(byte)
                    self.line_complete = self.object.done
            return
        for byte in chunk:
            if self.object is not None:
                self.object.feed_byte(byte)
                if self.object.done:
                    self.events.accept(self.object.decode())
                    self.object = None
                    self.state = "after"
                continue
            if byte in b" \t\r\n":
                continue
            if self.state == "start" and byte == 91:
                self.state = "first"
            elif self.state in ("first", "after") and byte == 93:
                self.state = "done"
            elif self.state == "after" and byte == 44:
                self.state = "next"
            elif self.state in ("first", "next") and byte == 123:
                if self.events.count >= MAX_EVENTS:
                    raise _Failure("event_limit")
                self.object = _ObjectScanner()
                self.object.feed_byte(byte)
            else:
                raise _Failure("malformed_framing")

    def _line(self):
        if not self.line_bytes or self.finished or self.object is None:
            raise _Failure("malformed_framing")
        value = self.object.decode()
        self.object = None
        self.line_bytes = 0
        self.line_complete = False
        if "finished" in value:
            # The manual specifies presence, not a terminal value/type schema.
            # This deliberately narrow hypothesis fails unsupported if different.
            if set(value) != {"finished"} or value["finished"] is not True:
                raise _Failure("unsupported_schema")
            self.finished = True
        else:
            self.events.accept(value)

    def finish(self):
        if self.style == "ndjson":
            if self.line_bytes:
                self._line()
            if not self.finished:
                raise _Failure("malformed_framing")
        elif self.state != "done" or self.object is not None:
            raise _Failure("malformed_framing")


def _argv(style, subsystem, pid, start, end, negative=False):
    if style not in ("json", "ndjson") or not re.fullmatch(r"org\.tracebolt\.nativeacceptance\.[0-9a-f]{32}", subsystem) or type(pid) is not int or pid <= 0:
        raise _Failure("invalid_admission")
    category = "never-emitted" if negative else "schema"
    predicate = f'subsystem == "{subsystem}" AND category == "{category}"'
    fmt = lambda value: datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S+0000")
    return ["/usr/bin/log", "show", "--style", style, "--start", fmt(start), "--end", fmt(end),
            "--timezone", "UTC", "--predicate", predicate, "--process", str(pid),
            "--no-info", "--no-debug", "--no-signpost", "--no-pager", "--color", "none"]


class _Runtime:
    def __init__(self, admission, result):
        self.a, self.result = admission, result
        self.children = []
        self.emitter = None
        self.emitter_start = None
        self.ready = False
        self.selector = selectors.DefaultSelector()
        self.last_wall = None
        self.active_query = None
        self.active_deadline = None

    def wall(self):
        now = time.time()
        if not math.isfinite(now) or (self.last_wall is not None and now < self.last_wall):
            raise _Failure("clock_regression")
        self.last_wall = now
        return now

    def spawn(self, argv, kind, decoder=None, query=None):
        with _defer_spawn_cancellation():
            try:
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, env=self.a["env"], cwd=self.a["env"]["HOME"],
                    close_fds=True, start_new_session=True, bufsize=0)
            except Exception:
                raise _Failure("spawn_failed") from None
            child = dict(proc=proc, kind=kind, decoder=decoder, query=query,
                         out=0, err=0, begin=None, open=2, reaped=False)
            # Register before queued cancellation can escape this short scope.
            self.children.append(child)
            if query is not None:
                query["started"] = True
            if kind == "emitter":
                self.emitter = child
                self.result["emitter"]["started"] = True
        child["begin"] = time.monotonic()
        if kind == "emitter":
            self.emitter_start = child["begin"]
        if type(proc.pid) is not int or proc.pid <= 0:
            raise _Failure("spawn_failed")
        for pipe, stream in ((proc.stdout, "out"), (proc.stderr, "err")):
            os.set_blocking(pipe.fileno(), False)
            self.selector.register(pipe, selectors.EVENT_READ, (child, stream))
        return child

    def check_emitter(self):
        if self.emitter is None:
            return
        if time.monotonic() - self.emitter_start >= EMITTER_SECONDS:
            self.result["emitter"]["deadlineExceeded"] = True
            raise _Failure("emitter_timeout")
        if self.emitter["proc"].poll() is not None:
            raise _Failure("emitter_unavailable")

    def check_query_deadline(self):
        if self.active_deadline is not None and time.monotonic() >= self.active_deadline:
            self.active_query["timedOut"] = self.active_query["started"]
            raise _Failure("timeout")

    def pump(self, timeout):
        self.check_emitter()
        self.check_query_deadline()
        self.wall()
        ready = self.selector.select(max(0, min(timeout, 0.05)))
        # A scheduler-delayed wake must not trigger any post-deadline read/parse.
        self.check_query_deadline()
        self.check_emitter()
        for key, _mask in ready:
            self.check_query_deadline()
            child, stream = key.data
            cap = 64 if child["kind"] == "emitter" else MAX_BYTES
            remaining = cap - child["out"] - child["err"]
            try:
                chunk = os.read(key.fileobj.fileno(), min(READ_SIZE, max(1, remaining + 1)))
            except BlockingIOError:
                continue
            if not chunk:
                self.selector.unregister(key.fileobj)
                child["open"] -= 1
                continue
            child[stream] += len(chunk)
            if child["kind"] == "emitter":
                e = self.result["emitter"]
                e["stdoutBytes"], e["stderrBytes"] = child["out"], child["err"]
            if child["out"] + child["err"] > cap:
                raise _Failure("byte_limit")
            self.check_query_deadline()
            if stream == "err":
                # Count only; never retain or decode stderr text.
                raise _Failure("stderr_present")
            if child["kind"] == "emitter":
                if chunk != b"R" or self.ready:
                    raise _Failure("emitter_protocol")
                self.ready = True
            else:
                self.check_query_deadline()
                child["decoder"].feed(chunk)
                self.check_query_deadline()
        self.check_emitter()

    def delay(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.pump(deadline - time.monotonic())

    def stop(self, child):
        proc = child["proc"]
        reaped = False
        try:
            if proc.poll() is None:
                # No global kill or name lookup; target only this owned process.
                proc.kill()
            code = proc.wait(timeout=1)
            reaped = True
            if child["query"] is not None and _integer(code, 255, -255):
                child["query"]["exitCode"] = code
        except BaseException as interruption:
            if not isinstance(interruption, Exception):
                self.result["status"], self.result["reason"] = "failed", "cancelled"
                if child["query"] is not None:
                    child["query"]["status"], child["query"]["reason"] = "failed", "cancelled"
                    child["query"]["fields"] = {}
                    child["query"]["observations"] = {k: None for k in OBSERVATION_KEYS}
            # Bounded last retry is cleanup only, never a query/emission retry.
            try:
                if proc.poll() is None:
                    proc.kill()
                code = proc.wait(timeout=1)
                reaped = True
                if child["query"] is not None and _integer(code, 255, -255):
                    child["query"]["exitCode"] = code
            except BaseException:
                pass
        finally:
            child["reaped"] = reaped
            for pipe in (proc.stdout, proc.stderr):
                try:
                    self.selector.unregister(pipe)
                except BaseException:
                    pass
                try:
                    pipe.close()
                except BaseException:
                    pass
        if child["kind"] == "emitter":
            self.result["emitter"]["reaped"] = reaped
        elif child["query"] is not None:
            child["query"]["reaped"] = reaped
        return reaped

    def query(self, index, subsystem, start, end):
        q = self.result["queries"][index]
        child = None
        events = _Events(subsystem, self.emitter["proc"].pid, start, end, index == 2)
        decoder = _Decoder("ndjson" if index == 1 else "json", events)
        begun = time.monotonic()
        deadline = begun + QUERY_SECONDS
        self.active_query, self.active_deadline = q, deadline
        def check_deadline():
            if time.monotonic() >= deadline:
                q["timedOut"] = child is not None
                raise _Failure("timeout")
        try:
            _guard_config(self.a)
            self.check_emitter()
            check_deadline()
            child = self.spawn(_argv(decoder.style, subsystem, self.emitter["proc"].pid,
                                    start, end, index == 2), "query", decoder, q)
            while child["open"] or child["proc"].poll() is None:
                check_deadline()
                self.pump(deadline - time.monotonic())
                # select/read/decoding may cross the deadline on the final EOF.
                check_deadline()
            code = child["proc"].wait(timeout=0)
            child["reaped"] = q["reaped"] = True
            q["exitCode"] = code if _integer(code, 255, -255) else None
            if code != 0:
                raise _Failure("source_unavailable")
            check_deadline()
            decoder.finish()
            check_deadline()
            q["framingComplete"] = True
            q["terminalFinished"] = decoder.finished
            if index == 2:
                q["status"], q["reason"] = "passed", "accepted"
            elif events.count == 0:
                q["status"], q["reason"] = "inconclusive_not_observed", "not_observed"
            elif events.markers != {"public", "special", "private"}:
                raise _Failure("incomplete_markers")
            else:
                q["status"], q["reason"] = "passed", "accepted"
                q["fields"] = {k: dict(present=v["present"], null=v["null"], empty=v["empty"],
                                    types=sorted(v["types"])) for k, v in events.fields.items()}
                q["observations"] = events.observations()
        except _Failure as failure:
            q["status"] = "unsupported" if failure.reason == "unsupported_schema" else "failed"
            q["reason"] = failure.reason
            q["bounded"] = failure.reason not in {"timeout", "byte_limit", "object_limit", "event_limit", "depth_limit", "key_limit", "emitter_timeout"}
            raise
        except _Cancelled:
            q["status"], q["reason"] = "failed", "cancelled"
            raise
        except BaseException:
            q["status"], q["reason"] = "failed", "internal_error"
            raise _Failure("internal_error") from None
        finally:
            self.active_query, self.active_deadline = None, None
            q["eventCount"] = min(events.count, MAX_EVENTS)
            q["elapsedMilliseconds"] = _elapsed_milliseconds(begun)
            if child is not None:
                q["stdoutBytes"], q["stderrBytes"] = child["out"], child["err"]
                if not self.stop(child):
                    q["status"], q["reason"] = "failed", "reap_failed"
                    q["fields"] = {}
                    q["observations"] = {k: None for k in OBSERVATION_KEYS}

    def close(self):
        ok = True
        for child in reversed(self.children):
            if not child["reaped"]:
                try:
                    ok = self.stop(child) and ok
                except BaseException:
                    # A parent cancellation must not skip other owned children.
                    ok = False
        try:
            self.selector.close()
        except BaseException:
            ok = False
        return ok


def run_log_gate(task_root, emitter_path):
    """One admitted emitter and up to three exact narrow queries; closed result.

    On any safety/parser failure stop without later queries or fallback. Empty
    positive results are inconclusive and do not authorize a repeat. Parent must
    apply its own 120-second supervisor and validated, content-free publication.
    """
    result = result_template()
    runtime = None
    previous_handlers = {}
    try:
        a = _check_admission(task_root, emitter_path)
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.signal(sig, _signal_cancel)
        _guard_config(a)
        runtime = _Runtime(a, result)
        nonce = secrets.token_hex(16)
        if not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise _Failure("internal_error")
        start = math.floor(runtime.wall()) - 1
        runtime.spawn([str(emitter_path), nonce], "emitter")
        ready_deadline = time.monotonic() + 5
        while not runtime.ready:
            if time.monotonic() >= ready_deadline:
                raise _Failure("emitter_unavailable")
            runtime.pump(ready_deadline - time.monotonic())
        runtime.delay(5)
        end = math.floor(runtime.wall()) + 1
        if not 0 < end - start <= 30:
            raise _Failure("window_limit")
        # Fixed endpoints never change after this point; only wait for END.
        while runtime.wall() <= end:
            runtime.pump(min(0.05, end - runtime.last_wall + 0.001))
        for index in range(3):
            runtime.query(index, SUBSYSTEM_PREFIX + nonce, start, end)
            if result["queries"][index]["status"] == "failed":
                raise _Failure(result["queries"][index]["reason"])
        if any(q["status"] == "inconclusive_not_observed" for q in result["queries"]):
            result["status"], result["reason"] = "inconclusive_not_observed", "not_observed"
        else:
            result["status"], result["reason"] = "passed", "accepted"
    except _Failure as failure:
        result["reason"] = failure.reason
        result["status"] = ("unsupported" if failure.reason == "unsupported_schema" else
                            "blocked" if failure.reason in {"not_admitted", "invalid_admission", "unsupported_platform", "configuration_present_or_unknown"} else "failed")
    except (_Cancelled, KeyboardInterrupt):
        result["status"], result["reason"] = "failed", "cancelled"
    except BaseException:
        result["status"], result["reason"] = "failed", "internal_error"
    finally:
        # Parent-only post-spawn shield: a second cancellation must not escape
        # between entering finally and synchronously stopping owned children.
        # No process can be created after this point. Keep the original mask.
        cleanup_mask = None
        if previous_handlers:
            for _attempt in range(3):
                try:
                    cleanup_mask = signal.pthread_sigmask(
                        signal.SIG_BLOCK, (signal.SIGINT, signal.SIGTERM, signal.SIGALRM))
                    break
                except BaseException as interruption:
                    result["status"], result["reason"] = "failed", "cancelled"
                    if isinstance(interruption, Exception):
                        # Unsupported masking is a safety failure, never a pass.
                        result["reason"] = "internal_error"
                        break
        try:
            if runtime is not None:
                try:
                    if not runtime.close():
                        result["status"], result["reason"] = "failed", "reap_failed"
                except BaseException:
                    result["status"], result["reason"] = "failed", "reap_failed"
            for sig, handler in previous_handlers.items():
                for _attempt in range(3):
                    try:
                        signal.signal(sig, handler)
                        break
                    except BaseException as interruption:
                        result["status"], result["reason"] = "failed", "cancelled"
                        if isinstance(interruption, Exception):
                            result["reason"] = "internal_error"
                            break
        finally:
            # All owned children have had their reap attempt before cancellation
            # can be delivered to restored parent handlers. A parent's raising
            # handler cannot turn this boundary into a raw exception report.
            if cleanup_mask is not None:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
                except BaseException:
                    result["status"], result["reason"] = "failed", "cancelled"
    if not validate_result(result):
        # Never stringify the rejected result or a caught exception.
        fallback = result_template("internal_error")
        fallback["status"] = "failed"
        # Retain ownership/reap truth even if another output field is invalid.
        # The supervisor must never infer safe cleanup from a lost failure report.
        if runtime is not None:
            for child in runtime.children:
                if child["kind"] == "emitter":
                    fallback["emitter"]["started"] = True
                    fallback["emitter"]["reaped"] = child["reaped"] is True
                else:
                    for index, query in enumerate(result["queries"]):
                        if child["query"] is query:
                            fallback["queries"][index]["started"] = True
                            fallback["queries"][index]["reaped"] = child["reaped"] is True
                            fallback["queries"][index]["status"] = "failed"
                            fallback["queries"][index]["reason"] = "internal_error"
                            fallback["queries"][index]["elapsedMilliseconds"] = None
        return fallback
    return result
