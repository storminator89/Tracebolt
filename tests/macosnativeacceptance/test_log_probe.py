"""Inert synthetic fixtures only: never execute compiler/emitter/log/network."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import unittest
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location("log_probe", Path(__file__).with_name("log_probe.py"))
p = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p)

NONCE = "a" * 32
SUBSYSTEM = p.SUBSYSTEM_PREFIX + NONCE
ROOT = "/tmp/tracebolt-synthetic-inert-task"
EMITTER = ROOT + "/bin/tracebolt-native-log-probe"
ENV = dict(PATH="/usr/bin:/bin:/usr/sbin:/sbin", LANG="C", LC_ALL="C", TZ="UTC",
           HOME=ROOT + "/home", TMPDIR=ROOT + "/tmp")


def rows(pid=4100, stamp=1700000002, private=False):
    base = dict(subsystem=SUBSYSTEM, category="schema", processID=pid,
                eventType="logEvent", messageType="Default",
                timestamp=datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f%z"),
                processImagePath="/synthetic/path", source=None, timezoneName="",
                backtrace={"frames": [{"imageOffset": 123, "imageUUID": "SYNTHETIC_UUID"}]})
    messages = (p.PUBLIC_MESSAGE, p.SPECIAL_MESSAGE,
                p.PRIVATE_PREFIX + (p._PRIVATE_CANARY if private else "<private>"))
    return [dict(base, eventMessage=m) for m in messages]


def encode(style, values, terminal=True):
    if style == "json":
        return json.dumps(values, ensure_ascii=False).encode()
    raw = b"".join(json.dumps(v, ensure_ascii=False).encode() + b"\n" for v in values)
    return raw + (b'{"finished":true}\n' if terminal else b"")


class Counter:
    def __init__(self):
        self.count = 0

    def accept(self, value):
        self.count += 1
        if self.count > p.MAX_EVENTS:
            raise p._Failure("event_limit")


class Clock:
    def __init__(self):
        self.value = 0.0
        self.wall_calls = 0
        self.regress_at = None
        self.jump = 0

    def monotonic(self):
        return self.value

    def wall(self):
        self.wall_calls += 1
        if self.regress_at and self.wall_calls >= self.regress_at:
            return 1700000000 + self.value - 100
        return 1700000000 + self.value + self.jump


class Pipe:
    def __init__(self, owner, number, data, stream):
        self.owner, self.number, self.data, self.stream = owner, number, bytearray(data), stream
        self.closed = False

    def fileno(self):
        return self.number

    def close(self):
        self.closed = True


class Child:
    def __init__(self, world, pid, kind, out, err, hung=False, code=0, fail_reap=False):
        self.pid, self.kind, self.hung, self.code, self.fail_reap = pid, kind, hung, code, fail_reap
        self.killed = False
        self.waited = False
        self.kill_calls = 0
        self.stdout = Pipe(self, pid * 2, out, "out")
        self.stderr = Pipe(self, pid * 2 + 1, err, "err")
        world.pipes[self.stdout.number] = self.stdout
        world.pipes[self.stderr.number] = self.stderr

    def poll(self):
        if self.killed and not self.fail_reap:
            return -9
        if self.kind == "emitter" or self.hung:
            return None
        if not self.stdout.data and not self.stderr.data:
            return self.code
        return None

    def kill(self):
        self.kill_calls += 1
        self.killed = True

    def wait(self, timeout):
        if self.fail_reap or self.poll() is None:
            raise subprocess.TimeoutExpired("SENSITIVE_EXCEPTION_COMMAND", timeout)
        self.waited = True
        return self.poll()


class Selector:
    def __init__(self, world):
        self.world = world
        self.registered = {}
        self.closed = False

    def register(self, pipe, event, data):
        self.registered[pipe.number] = type("Key", (), dict(fileobj=pipe, data=data))()

    def unregister(self, pipe):
        self.registered.pop(pipe.number, None)

    def select(self, timeout):
        self.world.clock.value += max(0.0001, timeout)
        if self.world.cancel:
            self.world.cancel = False
            raise p._Cancelled()
        ready = []
        for key in list(self.registered.values()):
            pipe = key.fileobj
            if pipe.data or pipe.owner.kind != "emitter":
                ready.append((key, 1))
        return ready

    def close(self):
        self.closed = True


class World:
    def __init__(self, modify=None):
        self.clock = Clock()
        self.pipes = {}
        self.children = []
        self.calls = []
        self.modify = modify
        self.cancel = False
        self.cancel_on_spawn = None
        self.handlers = {signal.SIGINT: signal.SIG_DFL, signal.SIGTERM: signal.SIG_DFL,
                         signal.SIGALRM: self.parent_deadline}
        self.mask = set()
        self.inherited_masks = []
        self.cancel_on_unmask = None
        self.selector = Selector(self)

    @staticmethod
    def parent_deadline(_sig, _frame):
        raise BaseException("SENSITIVE PARENT DEADLINE")

    def set_signal(self, sig, handler):
        prior = self.handlers[sig]
        self.handlers[sig] = handler
        return prior

    def set_mask(self, how, signals):
        old = set(self.mask)
        if how == signal.SIG_BLOCK:
            self.mask.update(signals)
        elif how == signal.SIG_SETMASK:
            self.mask = set(signals)
        else:
            raise AssertionError("unsupported inert mask operation")
        if how == signal.SIG_SETMASK and not self.mask and self.cancel_on_unmask is not None:
            sig = self.cancel_on_unmask
            self.cancel_on_unmask = None
            self.handlers[sig](sig, None)
        return old

    def popen(self, argv, **kwargs):
        self.inherited_masks.append(set(self.mask))
        index = len(self.calls)
        self.calls.append((argv, kwargs))
        kind = "emitter" if index == 0 else "query"
        options = dict(hung=False, code=0, fail_reap=False)
        if index == 0:
            out, err = b"R", b""
        else:
            values = rows(pid=self.children[0].pid)
            if index == 3:
                values = []
            out, err = encode("ndjson" if index == 2 else "json", values), b""
        if self.modify:
            out, err, options = self.modify(index, out, err, options)
        child = Child(self, 4100 + index, kind, out, err, **options)
        self.children.append(child)
        if self.cancel_on_spawn and self.cancel_on_spawn[0] == index:
            sig = self.cancel_on_spawn[1]
            self.handlers[sig](sig, None)
        return child

    def read(self, number, count):
        pipe = self.pipes[number]
        data = bytes(pipe.data[:count])
        del pipe.data[:count]
        return data

    def execute(self, before_query=lambda: True, env=None):
        with patch.object(p.sys, "platform", "darwin"), patch.object(p.subprocess, "Popen", self.popen), \
             patch.object(p.selectors, "DefaultSelector", lambda: self.selector), \
             patch.object(p.os, "read", self.read), patch.object(p.os, "set_blocking"), \
             patch.object(p.time, "monotonic", self.clock.monotonic), patch.object(p.time, "time", self.clock.wall), \
             patch.object(p.secrets, "token_hex", lambda size: NONCE), \
             patch.object(p.signal, "signal", self.set_signal), patch.object(p.signal, "getsignal", lambda sig: self.handlers[sig]), \
             patch.object(p.signal, "pthread_sigmask", self.set_mask):
            with p.configure_admission(ROOT, before_query=before_query, clean_env=ENV if env is None else env):
                return p.run_log_gate(ROOT, EMITTER)


class GateTests(unittest.TestCase):
    def setUp(self):
        # An accidental unmocked native process in any test is a hard inert failure.
        self.block_process = patch.object(p.subprocess, "Popen", side_effect=AssertionError("native execution forbidden"))
        self.block_process.start()
        self.addCleanup(self.block_process.stop)

    def assert_closed(self, result):
        self.assertTrue(p.validate_result(result))
        raw = json.dumps(result)
        for forbidden in (NONCE, ROOT, "SENSITIVE", "synthetic/path", "SYNTHETIC_UUID", p.PUBLIC_MESSAGE,
                          p.SPECIAL_MESSAGE, p._PRIVATE_CANARY, "1700000000", '"processID": 4100'):
            self.assertNotIn(forbidden, raw)

    def test_import_and_no_admission_never_spawn(self):
        result = p.run_log_gate(ROOT, EMITTER)
        self.assertEqual(result["reason"], "not_admitted")
        self.assert_closed(result)

    def test_success_exact_queries_clean_environment_and_reap(self):
        world = World()
        result = world.execute()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(world.calls), 4)
        self.assertTrue(all(c.waited and c.stdout.closed and c.stderr.closed for c in world.children))
        self.assertTrue(world.children[0].killed)
        self.assertTrue(result["emitter"]["reaped"])
        self.assertLess(world.clock.value, 90)
        positive = world.calls[1][0]
        ndjson = world.calls[2][0]
        negative = world.calls[3][0]
        self.assertEqual(positive[:4], ["/usr/bin/log", "show", "--style", "json"])
        self.assertEqual(ndjson, positive[:3] + ["ndjson"] + positive[4:])
        self.assertEqual(negative, [x.replace('category == "schema"', 'category == "never-emitted"') for x in positive])
        self.assertEqual(positive[-8:], ["--process", "4100", "--no-info", "--no-debug", "--no-signpost", "--no-pager", "--color", "none"])
        self.assertEqual(positive[5], "2023-11-14 22:13:19+0000")
        self.assertEqual(positive[7], "2023-11-14 22:13:26+0000")
        for argv, kwargs in world.calls:
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["env"], ENV)
            self.assertEqual(kwargs["cwd"], ENV["HOME"])
            self.assertTrue(kwargs["start_new_session"])
            self.assertTrue(kwargs["close_fds"])
            self.assertNotIn("shell", kwargs)
        for q in result["queries"][:2]:
            self.assertEqual(q["eventCount"], 3)
            self.assertTrue(q["started"] and q["reaped"])
            self.assertEqual(q["fields"]["source"], dict(present=3, null=3, empty=0, types=["null"]))
            self.assertEqual(q["fields"]["timezoneName"]["empty"], 3)
            self.assertTrue(q["observations"]["privateCanaryAbsent"])
            self.assertTrue(q["observations"]["multilinePreserved"])
        self.assertTrue(result["queries"][1]["terminalFinished"])
        self.assert_closed(result)

    def test_empty_positive_remains_inconclusive_negative_empty_passes(self):
        def modify(index, out, err, options):
            return (encode("ndjson" if index == 2 else "json", []) if index else out), err, options
        result = World(modify).execute()
        self.assertEqual(result["status"], "inconclusive_not_observed")
        self.assertEqual([q["status"] for q in result["queries"]], ["inconclusive_not_observed", "inconclusive_not_observed", "passed"])
        self.assert_closed(result)

    def test_private_visible_is_boolean_only(self):
        def modify(index, out, err, options):
            if index in (1, 2):
                out = encode("ndjson" if index == 2 else "json", rows(private=True))
            return out, err, options
        result = World(modify).execute()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["queries"][0]["observations"]["privateCanaryVisible"])
        self.assert_closed(result)

    def test_stderr_discards_payload_and_stops(self):
        def modify(index, out, err, options):
            return out, (b"SENSITIVE RAW DIAGNOSTIC" if index == 1 else err), options
        world = World(modify)
        result = world.execute()
        self.assertEqual(result["reason"], "stderr_present")
        self.assertEqual(len(world.calls), 2)
        self.assertGreater(result["queries"][0]["stderrBytes"], 0)
        self.assertEqual(result["queries"][0]["fields"], {})
        self.assert_closed(result)

    def test_nonzero_exit_not_denial_and_no_fallback(self):
        def modify(index, out, err, options):
            if index == 1:
                options["code"] = 77
            return out, err, options
        world = World(modify)
        result = world.execute()
        self.assertEqual(result["reason"], "source_unavailable")
        self.assertEqual(result["queries"][0]["exitCode"], 77)
        self.assertEqual(len(world.calls), 2)
        self.assert_closed(result)

    def test_query_deadline_kills_and_reaps(self):
        def modify(index, out, err, options):
            if index == 1:
                options["hung"] = True
            return out, err, options
        world = World(modify)
        result = world.execute()
        q = result["queries"][0]
        self.assertEqual(result["reason"], "timeout")
        self.assertTrue(q["timedOut"] and q["reaped"])
        self.assertFalse(q["bounded"])
        self.assertTrue(world.children[1].killed)
        self.assertLess(q["elapsedMilliseconds"], 15100)
        self.assert_closed(result)

    def test_final_eof_crossing_deadline_cannot_pass(self):
        world = World()
        original = world.selector.select
        crossed = []
        def select(timeout):
            if len(world.children) == 2 and not crossed:
                child = world.children[1]
                if not child.stdout.data and not child.stderr.data:
                    world.clock.value += 16
                    crossed.append(True)
            return original(timeout)
        world.selector.select = select
        result = world.execute()
        self.assertEqual(result["reason"], "timeout")
        self.assertEqual(len(world.calls), 2)
        self.assertTrue(result["queries"][0]["timedOut"])
        self.assertFalse(result["queries"][0]["bounded"])
        self.assertEqual(result["queries"][0]["fields"], {})
        self.assertTrue(world.children[1].waited)
        self.assert_closed(result)

    def test_final_decode_crossing_deadline_cannot_pass(self):
        world = World()
        original = p._Decoder.finish
        def finish(decoder):
            original(decoder)
            world.clock.value += 16
        with patch.object(p._Decoder, "finish", finish):
            result = world.execute()
        self.assertEqual(result["reason"], "timeout")
        self.assertEqual(len(world.calls), 2)
        self.assertTrue(result["queries"][0]["timedOut"])
        self.assert_closed(result)

    def test_delayed_select_does_not_read_or_feed_late_payload(self):
        world = World()
        original_select = world.selector.select
        original_feed = p._Decoder.feed
        feeds = []
        crossed = []
        def select(timeout):
            if len(world.children) == 2 and not crossed:
                world.clock.value += 16
                crossed.append(True)
            return original_select(timeout)
        def feed(decoder, payload):
            feeds.append(True)
            return original_feed(decoder, payload)
        world.selector.select = select
        with patch.object(p._Decoder, "feed", feed):
            result = world.execute()
        self.assertEqual(result["reason"], "timeout")
        self.assertEqual(feeds, [])
        self.assertEqual(result["queries"][0]["stdoutBytes"], 0)
        self.assertEqual(result["queries"][0]["eventCount"], 0)
        self.assertTrue(result["queries"][0]["reaped"])
        self.assertEqual(len(world.calls), 2)
        self.assert_closed(result)

    def test_failed_elapsed_is_measured_or_null_never_saturated(self):
        for delay in (125, 1250):
            world = World()
            original = world.selector.select
            delayed = []
            def select(timeout):
                if len(world.children) == 2 and not delayed:
                    world.clock.value += delay
                    delayed.append(True)
                return original(timeout)
            world.selector.select = select
            result = world.execute()
            self.assertEqual(result["reason"], "timeout")
            elapsed = result["queries"][0]["elapsedMilliseconds"]
            if delay == 125:
                self.assertGreaterEqual(elapsed, 125000)
                self.assertLess(elapsed, 125100)
            else:
                self.assertIsNone(elapsed)
            self.assertTrue(result["queries"][0]["reaped"])
            self.assertEqual(len(world.calls), 2)
            self.assert_closed(result)

    def test_combined_byte_limit_during_read(self):
        def modify(index, out, err, options):
            return (b" " * (p.MAX_BYTES + 1000) if index == 1 else out), err, options
        world = World(modify)
        result = world.execute()
        self.assertEqual(result["reason"], "byte_limit")
        self.assertEqual(result["queries"][0]["stdoutBytes"], p.MAX_BYTES + 1)
        self.assertTrue(world.children[1].waited)
        self.assert_closed(result)

    def test_emitter_ready_ack_required_before_queries(self):
        def modify(index, out, err, options):
            return (b"" if index == 0 else out), err, options
        world = World(modify)
        result = world.execute()
        self.assertEqual(result["reason"], "emitter_unavailable")
        self.assertEqual(len(world.calls), 1)
        self.assertTrue(world.children[0].waited)
        self.assert_closed(result)

    def test_emitter_bad_ack_is_failure(self):
        def modify(index, out, err, options):
            return (b"SENSITIVE" if index == 0 else out), err, options
        result = World(modify).execute()
        self.assertEqual(result["reason"], "emitter_protocol")
        self.assert_closed(result)

    def test_configuration_guard_initial_and_each_query(self):
        calls = []
        def guard():
            calls.append(True)
            return len(calls) < 4
        world = World()
        result = world.execute(before_query=guard)
        self.assertEqual(len(calls), 4)
        self.assertEqual(len(world.calls), 3)
        self.assertEqual(result["reason"], "configuration_present_or_unknown")
        self.assertFalse(result["queries"][2]["started"])
        self.assert_closed(result)

    def test_config_exceptions_not_output(self):
        def guard():
            raise RuntimeError("SENSITIVE HOME")
        world = World()
        result = world.execute(before_query=guard)
        self.assertEqual(len(world.calls), 0)
        self.assertEqual(result["reason"], "configuration_present_or_unknown")
        self.assert_closed(result)

    def test_dirty_environment_rejected_before_spawn(self):
        world = World()
        result = world.execute(env=dict(ENV, OS_ACTIVITY_MODE="debug"))
        self.assertEqual(result["reason"], "invalid_admission")
        self.assertEqual(len(world.calls), 0)
        self.assert_closed(result)

    def test_platform_not_accepted_from_caller_string_alone(self):
        with patch.object(p.sys, "platform", "linux"), p.configure_admission(ROOT, before_query=lambda: True, clean_env=ENV):
            result = p.run_log_gate(ROOT, EMITTER)
        self.assertEqual(result["reason"], "unsupported_platform")
        self.assert_closed(result)

    def test_admission_is_one_shot_even_after_failure(self):
        with patch.object(p.sys, "platform", "linux"), p.configure_admission(ROOT, before_query=lambda: True, clean_env=ENV):
            p.run_log_gate(ROOT, EMITTER)
            result = p.run_log_gate(ROOT, EMITTER)
        self.assertEqual(result["reason"], "not_admitted")
        self.assert_closed(result)

    def test_cancellation_reaps_owned_emitter(self):
        world = World()
        world.cancel = True
        result = world.execute()
        self.assertEqual(result["reason"], "cancelled")
        self.assertTrue(world.children[0].waited)
        self.assert_closed(result)

    def test_cancellation_at_popen_return_keeps_child_owned_and_reaped(self):
        for index in (0, 1):
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
                with self.subTest(index=index, signal=sig):
                    world = World()
                    original_handlers = dict(world.handlers)
                    world.cancel_on_spawn = (index, sig)
                    result = world.execute()
                    self.assertEqual(result["status"], "failed")
                    self.assertEqual(len(world.calls), index + 1)
                    self.assertTrue(all(c.waited and c.stdout.closed and c.stderr.closed for c in world.children))
                    self.assertTrue(result["emitter"]["started"] and result["emitter"]["reaped"])
                    if index:
                        self.assertTrue(result["queries"][0]["started"] and result["queries"][0]["reaped"])
                    self.assertEqual(world.handlers, original_handlers)
                    self.assertEqual(world.mask, set())
                    self.assertTrue(all(not mask for mask in world.inherited_masks))
                    self.assert_closed(result)

    def test_cancellation_during_handler_restoration_reaps_and_restores(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            world = World()
            original_handlers = dict(world.handlers)
            world.cancel_on_unmask = sig
            result = world.execute()
            self.assertEqual(result["status"], "failed")
            self.assertEqual(len(world.calls), 1)
            self.assertTrue(world.children[0].waited)
            self.assertEqual(world.handlers, original_handlers)
            self.assertEqual(world.mask, set())
            self.assertEqual(world.inherited_masks, [set()])
            self.assert_closed(result)

    def test_second_cancellation_cannot_interrupt_cleanup_entry(self):
        world = World()
        world.cancel_on_spawn = (0, signal.SIGINT)
        original = world.set_signal
        interrupted = []
        def set_signal(sig, handler):
            if handler == signal.SIG_IGN and not interrupted:
                interrupted.append(True)
                world.handlers[signal.SIGTERM](signal.SIGTERM, None)
            return original(sig, handler)
        world.set_signal = set_signal
        result = world.execute()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(world.children[0].killed and world.children[0].waited)
        self.assertTrue(result["emitter"]["reaped"])
        self.assertEqual(world.mask, set())
        self.assertEqual(interrupted, [])  # There is no interruptible SIG_IGN loop.
        self.assert_closed(result)

    def test_cancellation_before_cleanup_mask_retries_then_reaps(self):
        world = World()
        world.cancel_on_spawn = (0, signal.SIGINT)
        original = world.set_mask
        blocked_calls = []
        def set_mask(how, signals):
            if how == signal.SIG_BLOCK:
                blocked_calls.append(True)
                # First block is spawn restoration; second is final cleanup.
                if len(blocked_calls) == 2:
                    world.handlers[signal.SIGTERM](signal.SIGTERM, None)
            return original(how, signals)
        world.set_mask = set_mask
        result = world.execute()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(blocked_calls), 3)
        self.assertTrue(world.children[0].waited)
        self.assertTrue(result["emitter"]["reaped"])
        self.assertEqual(world.mask, set())
        self.assert_closed(result)

    def test_final_cleanup_mask_covers_reap_and_handler_restoration(self):
        world = World()
        original_wait = Child.wait
        original_set_signal = world.set_signal
        original_handlers = dict(world.handlers)
        checks = []
        def wait(child, timeout):
            if child.kind == "emitter" and child.killed:
                self.assertTrue({signal.SIGINT, signal.SIGTERM, signal.SIGALRM} <= world.mask)
                checks.append(True)
            return original_wait(child, timeout)
        world.set_signal = original_set_signal
        with patch.object(Child, "wait", wait):
            result = world.execute()
        self.assertTrue(checks)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(world.handlers, original_handlers)
        self.assertEqual(world.mask, set())
        self.assertTrue(all(not mask for mask in world.inherited_masks))
        self.assert_closed(result)

    def test_pending_final_cancellation_is_delivered_only_after_reap(self):
        original_wait = Child.wait
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            world = World()
            world.handlers[signal.SIGINT] = world.parent_deadline
            world.handlers[signal.SIGTERM] = world.parent_deadline
            original_handlers = dict(world.handlers)
            def wait(child, timeout):
                result = original_wait(child, timeout)
                if child.kind == "emitter" and child.killed:
                    self.assertTrue(child.waited)
                    self.assertTrue(sig in world.mask)
                    world.cancel_on_unmask = sig
                return result
            with patch.object(Child, "wait", wait):
                result = world.execute()
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["reason"], "cancelled")
            self.assertTrue(result["emitter"]["reaped"])
            self.assertEqual(world.handlers, original_handlers)
            self.assertEqual(world.mask, set())
            self.assert_closed(result)

    def test_baseexception_from_supervisor_reaps_without_text(self):
        class SupervisorDeadline(BaseException):
            pass
        world = World()
        def select(_timeout):
            raise SupervisorDeadline("SENSITIVE")
        world.selector.select = select
        result = world.execute()
        self.assertEqual(result["reason"], "internal_error")
        self.assertTrue(world.children[0].waited)
        self.assert_closed(result)

    def test_cleanup_failure_never_invents_reap(self):
        def modify(index, out, err, options):
            if index == 0:
                options["fail_reap"] = True
            return out, err, options
        result = World(modify).execute()
        self.assertEqual(result["reason"], "reap_failed")
        self.assertFalse(result["emitter"]["reaped"])
        self.assert_closed(result)

    def test_cancellation_during_cleanup_retries_reap_and_is_not_pass(self):
        world = World()
        original = Child.wait
        interrupted = []
        def wait(child, timeout):
            if child.kind == "emitter" and not interrupted:
                interrupted.append(True)
                raise p._Cancelled()
            return original(child, timeout)
        with patch.object(Child, "wait", wait):
            result = world.execute()
        self.assertEqual(result["reason"], "cancelled")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["emitter"]["reaped"])
        self.assert_closed(result)

    def test_spawn_failure_is_closed_and_stops(self):
        def modify(index, out, err, options):
            if index == 1:
                raise OSError("SENSITIVE EXECUTABLE PATH")
            return out, err, options
        world = World(modify)
        result = world.execute()
        self.assertEqual(result["reason"], "spawn_failed")
        self.assertFalse(result["queries"][0]["started"])
        self.assertTrue(result["emitter"]["reaped"])
        self.assert_closed(result)

    def test_registration_failure_still_records_and_reaps_owned_query(self):
        world = World()
        original = world.selector.register
        def register(pipe, event, data):
            if pipe.owner.kind == "query":
                raise RuntimeError("SENSITIVE")
            return original(pipe, event, data)
        world.selector.register = register
        result = world.execute()
        self.assertEqual(result["reason"], "internal_error")
        self.assertTrue(result["queries"][0]["started"])
        self.assertTrue(result["queries"][0]["reaped"])
        self.assertTrue(world.children[1].waited)
        self.assert_closed(result)

    def test_schema_fallback_preserves_reap_failure_truth(self):
        def modify(index, out, err, options):
            if index == 0:
                options["fail_reap"] = True
            return out, err, options
        world = World(modify)
        with patch.object(p, "validate_result", return_value=False):
            result = world.execute()
        self.assertEqual(result["reason"], "internal_error")
        self.assertTrue(result["emitter"]["started"])
        self.assertFalse(result["emitter"]["reaped"])
        self.assertTrue(all(q["started"] and q["reaped"] for q in result["queries"]))
        self.assert_closed(result)

    def test_window_limit_never_widens_or_queries(self):
        world = World()
        original = world.selector.select
        def select(timeout):
            if world.clock.value >= 4:
                world.clock.jump = 31
            return original(timeout)
        world.selector.select = select
        result = world.execute()
        self.assertEqual(result["reason"], "window_limit")
        self.assertEqual(len(world.calls), 1)
        self.assertTrue(result["emitter"]["reaped"])
        self.assert_closed(result)

    def test_missing_one_marker_fails_without_output_summary(self):
        def modify(index, out, err, options):
            return (encode("json", rows()[:2]) if index == 1 else out), err, options
        result = World(modify).execute()
        self.assertEqual(result["reason"], "incomplete_markers")
        self.assertEqual(result["queries"][0]["fields"], {})
        self.assert_closed(result)

    def test_clock_regression_before_queries_stops(self):
        world = World()
        world.clock.regress_at = 4
        result = world.execute()
        self.assertEqual(result["reason"], "clock_regression")
        self.assertEqual(len(world.calls), 1)
        self.assertTrue(world.children[0].waited)
        self.assert_closed(result)

    def test_unknown_schema_does_not_output_unknown_key(self):
        def modify(index, out, err, options):
            if index == 1:
                values = rows()
                values[0]["SENSITIVE_DYNAMIC_KEY"] = "SENSITIVE_DYNAMIC_VALUE"
                out = encode("json", values)
            return out, err, options
        result = World(modify).execute()
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["queries"][0]["fields"], {})
        self.assert_closed(result)

    def test_negative_any_event_fails_without_schema(self):
        def modify(index, out, err, options):
            return (encode("json", rows()) if index == 3 else out), err, options
        result = World(modify).execute()
        self.assertEqual(result["reason"], "unrelated_event")
        self.assertEqual(result["queries"][2]["fields"], {})
        self.assert_closed(result)

    def test_source_contract_emitter_only_three_fixed_calls_and_ceiling(self):
        source = Path(__file__).with_name("emitter.c").read_text()
        self.assertEqual(source.count("os_log_with_type(log, OS_LOG_TYPE_DEFAULT"), 3)
        self.assertIn('alarm(89)', source)
        self.assertIn('"%{public}s"', source)
        self.assertIn('"tracebolt-native-private %{public}s %{private}s"', source)
        self.assertNotIn("getenv", source)
        self.assertNotIn("system(", source)


class DecoderTests(unittest.TestCase):
    def decode(self, style, raw, chunk=17, negative=False):
        events = p._Events(SUBSYSTEM, 4100, 1700000000, 1700000010, negative)
        decoder = p._Decoder(style, events)
        for offset in range(0, len(raw), chunk):
            decoder.feed(raw[offset:offset + chunk])
        decoder.finish()
        return events, decoder

    def assert_reason(self, reason, style, raw):
        with self.assertRaises(p._Failure) as raised:
            self.decode(style, raw)
        self.assertEqual(raised.exception.reason, reason)

    def test_utf8_newline_quote_split_at_every_byte(self):
        for style in ("json", "ndjson"):
            events, decoder = self.decode(style, encode(style, rows()), chunk=1)
            self.assertEqual(events.markers, {"public", "special", "private"})
            self.assertEqual(decoder.finished, style == "ndjson")

    def test_array_framing_malformed_and_extra_documents(self):
        for raw in (b"", b"{}", b"[", b"[,{}]", b"[{},]", b"[]{}", b"[] []", b"[42]", b"[null]"):
            with self.subTest(raw=raw):
                with self.assertRaises(p._Failure):
                    self.decode("json", raw)

    def test_duplicate_keys_rejected_before_attribution(self):
        self.assert_reason("invalid_json", "json", b'[{"a":1,"a":2}]')

    def test_invalid_utf8_and_surrogates_rejected(self):
        self.assert_reason("invalid_json", "json", b'[{"x":"\xff"}]')
        self.assert_reason("invalid_json", "json", b'[{"x":"\\ud800"}]')

    def test_nonfinite_and_float_rejected(self):
        for number in (b"NaN", b"Infinity", b"1.25"):
            self.assert_reason("unsupported_schema", "json", b'[{"x":' + number + b'}]')

    def test_ndjson_terminal_required_final_and_exact(self):
        self.assert_reason("malformed_framing", "ndjson", encode("ndjson", rows(), terminal=False))
        self.assert_reason("malformed_framing", "ndjson", b'{"finished":true}\n{"finished":true}\n')
        self.assert_reason("unsupported_schema", "ndjson", b'{"finished":false}\n')
        self.assert_reason("unsupported_schema", "ndjson", b'{"finished":true,"SENSITIVE":1}\n')
        self.assert_reason("malformed_framing", "ndjson", b'{"finished":true}\n\n')
        self.assert_reason("malformed_framing", "ndjson", b'{"finished":true} {}\n')
        self.decode("ndjson", b'{"finished":true}')

    def test_object_and_line_bound_preallocation(self):
        for style in ("json", "ndjson"):
            raw = b'{"x":"' + b"a" * p.MAX_OBJECT + b'"}'
            self.assert_reason("object_limit", style, b"[" + raw + b"]" if style == "json" else raw + b"\n")
        self.assert_reason("object_limit", "ndjson", b" " * (p.MAX_OBJECT + 1))

    def test_depth_and_key_limits_incremental(self):
        for style in ("json", "ndjson"):
            deep = b'{"x":' * 9 + b"0" + b"}" * 9
            many = json.dumps({"k" + str(i): i for i in range(65)}).encode()
            for raw, reason in ((deep, "depth_limit"), (many, "key_limit")):
                self.assert_reason(reason, style, b"[" + raw + b"]" if style == "json" else raw + b"\n")

    def test_sixty_four_events_then_cutoff_before_extra_buffer(self):
        counter = Counter()
        decoder = p._Decoder("json", counter)
        decoder.feed(b"[" + b",".join([b"{}"] * 64))
        self.assertEqual(counter.count, 64)
        with self.assertRaises(p._Failure) as raised:
            decoder.feed(b",{")
        self.assertEqual(raised.exception.reason, "event_limit")
        self.assertIsNone(decoder.object)

    def test_provenance_pid_category_subsystem_and_markers(self):
        for key, value in (("processID", 1), ("processID", True), ("category", "different"),
                           ("subsystem", "different"), ("eventMessage", "SENSITIVE")):
            values = rows()
            values[0][key] = value
            self.assert_reason("unrelated_event", "json", encode("json", values))

    def test_missing_required_unknown_nested_and_wrong_type_unsupported(self):
        variants = []
        row = rows()[0]
        del row["timestamp"]
        variants.append(row)
        row = rows()[0]
        row["processImagePath"] = 1
        variants.append(row)
        row = rows()[0]
        row["backtrace"]["frames"][0]["SENSITIVE"] = "value"
        variants.append(row)
        for row in variants:
            self.assert_reason("unsupported_schema", "json", encode("json", [row]))

    def test_duplicate_markers_rejected(self):
        self.assert_reason("duplicate_event", "json", encode("json", [rows()[0], rows()[0]]))

    def test_timestamp_shape_and_window(self):
        values = rows()
        values[0]["timestamp"] = "not-a-timestamp"
        self.assert_reason("timestamp_shape", "json", encode("json", values))
        self.assert_reason("outside_window", "json", encode("json", rows(stamp=1700000020)))
        self.assert_reason("outside_window", "json", encode("json", rows(stamp=1700000010)))
        self.decode("json", encode("json", rows(stamp=1700000000)))

    def test_negative_empty_is_valid_only_empty(self):
        events, _ = self.decode("json", b"[]", negative=True)
        self.assertEqual(events.count, 0)
        with self.assertRaises(p._Failure):
            self.decode("json", encode("json", rows()), negative=True)

    def test_result_schema_rejects_content_unknown_fields_wrong_types(self):
        base = p.result_template()
        self.assertTrue(p.validate_result(base))
        mutations = []
        value = copy.deepcopy(base); value["raw"] = "SENSITIVE"; mutations.append(value)
        value = copy.deepcopy(base); value["reason"] = "SENSITIVE"; mutations.append(value)
        value = copy.deepcopy(base); value["emitter"]["reaped"] = 1; mutations.append(value)
        value = copy.deepcopy(base); value["queries"][0]["observations"]["publicMarker"] = "SENSITIVE"; mutations.append(value)
        value = copy.deepcopy(base); value["queries"][0]["fields"] = {"SENSITIVE": {}}; mutations.append(value)
        value = copy.deepcopy(base); value["queries"][0]["stdoutBytes"] = p.MAX_BYTES + 2; mutations.append(value)
        value = copy.deepcopy(base); value["status"] = "passed"; value["reason"] = "accepted"; mutations.append(value)
        value = copy.deepcopy(base); value["queries"][0]["status"] = "passed"; value["queries"][0]["reason"] = "accepted"; mutations.append(value)
        value = copy.deepcopy(base); value["emitter"]["reaped"] = True; mutations.append(value)
        for value in mutations:
            self.assertFalse(p.validate_result(value))
        self.assertEqual(p.result_template("SENSITIVE")["reason"], "internal_error")

    def test_valid_pass_mutations_fail_semantic_validation(self):
        base = World().execute()
        self.assertTrue(p.validate_result(base))
        changes = (("started", False), ("reaped", False), ("exitCode", None),
                   ("timedOut", True), ("bounded", False), ("framingComplete", False),
                   ("eventCount", 2), ("elapsedMilliseconds", 15000), ("elapsedMilliseconds", None))
        for key, value in changes:
            altered = copy.deepcopy(base)
            altered["queries"][0][key] = value
            self.assertFalse(p.validate_result(altered))
        altered = copy.deepcopy(base)
        altered["queries"][1]["terminalFinished"] = False
        self.assertFalse(p.validate_result(altered))

    def test_elapsed_range_and_invalid_measurements(self):
        for now, expected in ((100.0, 0), (221.25, 121250), (1300.0, 1200000),
                              (1300.001, None), (99.0, None), (float("inf"), None),
                              (float("nan"), None)):
            with patch.object(p.time, "monotonic", return_value=now):
                self.assertEqual(p._elapsed_milliseconds(100.0), expected)
        failed = p.result_template()
        failed["queries"][0].update(status="failed", reason="timeout", elapsedMilliseconds=None)
        self.assertTrue(p.validate_result(failed))
        failed["queries"][0]["elapsedMilliseconds"] = p.MAX_ELAPSED_MILLISECONDS + 1
        self.assertFalse(p.validate_result(failed))


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.block_process = patch.object(p.subprocess, "Popen", side_effect=AssertionError("native execution forbidden"))
        self.block_process.start()
        self.addCleanup(self.block_process.stop)

    assert_closed = GateTests.assert_closed

    def failure(self, row=None, *, raw=None, index=1):
        def modify(which, out, err, options):
            if which == index:
                out = raw if raw is not None else encode("ndjson" if index == 2 else "json", [row])
            return out, err, options
        world = World(modify)
        result = world.execute()
        self.assert_closed(result)
        self.assertEqual(len(world.calls), index + 1)
        self.assertTrue(all(child.waited for child in world.children))
        query = result["queries"][index - 1]
        self.assertEqual(query["fields"], {})
        self.assertTrue(all(v is None for v in query["observations"].values()))
        return result, query["diagnostic"]

    def assert_no_metadata(self, diagnostic, code):
        self.assertEqual(diagnostic, dict(p._diagnostic_template(), code=code))

    def test_schema_version_is_explicit_and_old_shape_not_reinterpreted(self):
        result = p.result_template()
        self.assertEqual(result["schemaVersion"], 2)
        result["schemaVersion"] = 1
        self.assertFalse(p.validate_result(result))
        for q in result["queries"]:
            del q["diagnostic"]
        self.assertFalse(p.validate_result(result))

    def test_pass_and_inconclusive_do_not_use_failure_metadata(self):
        passed = World().execute()
        self.assertEqual(passed["status"], "passed")
        for q in passed["queries"]:
            self.assert_no_metadata(q["diagnostic"], "none")
        def modify(index, out, err, options):
            return (encode("ndjson" if index == 2 else "json", []) if index else out), err, options
        result = World(modify).execute()
        self.assertEqual(result["status"], "inconclusive_not_observed")
        for q in result["queries"]:
            self.assert_no_metadata(q["diagnostic"], "none")

    def test_extra_keys_count_but_never_name_value_or_path(self):
        for index in (1, 2):
            row = rows()[0]
            row["SENSITIVE_DYNAMIC_KEY /private/path"] = {"SENSITIVE_NESTED_NAME": "SENSITIVE_VALUE"}
            row["SENSITIVE_SECOND_KEY"] = 17
            result, d = self.failure(row, index=index)
            self.assertEqual(result["reason"], "unsupported_schema")
            self.assertEqual(d["code"], "extra_event_keys")
            self.assertTrue(d["syntheticAttributionVerified"])
            self.assertEqual(d["unknownKeyCount"], 2)
            self.assertEqual(set(d["knownFieldTypes"]), set(rows()[0]))
            self.assertEqual(d["knownFieldTypes"]["processImagePath"], "string")
            self.assertEqual(d["knownFieldTypes"]["backtrace"], "object")

    def test_all_exact_synthetic_messages_can_anchor_metadata(self):
        for private in (False, True):
            for row in rows(private=private):
                row["SENSITIVE_UNKNOWN"] = None
                _, d = self.failure(row)
                self.assertTrue(d["syntheticAttributionVerified"])
                self.assertEqual(d["unknownKeyCount"], 1)

    def test_top_level_unknown_count_is_bounded_and_not_nested_count(self):
        row = rows()[0]
        for number in range(p.MAX_KEYS - len(row)):
            row["SENSITIVE_KEY_" + str(number)] = {"SENSITIVE_NESTED": 1}
        _, d = self.failure(row)
        self.assertEqual(d["unknownKeyCount"], p.MAX_KEYS - len(rows()[0]))
        self.assertEqual(len(d["knownFieldTypes"]) + d["unknownKeyCount"], p.MAX_KEYS)
        row["SENSITIVE_OVERFLOW"] = 1
        result, d = self.failure(row)
        self.assertEqual(result["reason"], "key_limit")
        self.assert_no_metadata(d, "none")

    def test_missing_any_required_key_discloses_only_fixed_code(self):
        for name in p.REQUIRED_FIELDS:
            row = rows()[0]
            del row[name]
            row["SENSITIVE_UNKNOWN"] = "SENSITIVE_VALUE"
            result, d = self.failure(row)
            self.assertEqual(result["reason"], "unsupported_schema")
            self.assert_no_metadata(d, "missing_required")

    def test_inexact_attribution_cannot_disclose_metadata(self):
        for name, value in (("subsystem", "SENSITIVE"), ("subsystem", None),
                            ("category", "SENSITIVE"), ("processID", True), ("processID", 4101),
                            ("eventMessage", p.PUBLIC_MESSAGE + "SENSITIVE"),
                            ("eventMessage", []), ("eventMessage", None)):
            row = rows()[0]
            row[name] = value
            row["SENSITIVE_UNKNOWN"] = "SENSITIVE_VALUE"
            result, d = self.failure(row)
            self.assertEqual(result["reason"], "unrelated_event")
            self.assert_no_metadata(d, "attribution")

    def test_invalid_or_out_of_window_timestamp_suppresses_metadata(self):
        stamps = ("SENSITIVE", "2023-11-31 22:13:22.000000+0000", None, 17,
                  rows(stamp=1700000007)[0]["timestamp"], rows(stamp=1699999998)[0]["timestamp"])
        for stamp in stamps:
            row = rows()[0]
            row["timestamp"] = stamp
            row["SENSITIVE_UNKNOWN"] = "SENSITIVE_VALUE"
            result, d = self.failure(row)
            self.assertEqual(result["reason"], "unsupported_schema")
            self.assert_no_metadata(d, "extra_event_keys")

    def test_types_are_closed_and_do_not_relax_acceptance(self):
        for value, kind in ((False, "boolean"), ([], "array"), ({}, "object"), (17, "integer")):
            row = rows()[0]
            row["processImagePath"] = value
            result, d = self.failure(row)
            self.assertEqual(result["reason"], "unsupported_schema")
            self.assertEqual(d["code"], "known_field_type")
            self.assertTrue(d["syntheticAttributionVerified"])
            self.assertEqual(d["unknownKeyCount"], 0)
            self.assertEqual(d["knownFieldTypes"]["processImagePath"], kind)

    def test_event_type_and_message_type_have_separate_fixed_codes(self):
        for name, code in (("eventType", "event_type"), ("messageType", "message_type")):
            for value, kind in (("SENSITIVE_LITERAL", "string"), (False, "boolean"), (None, "null")):
                row = rows()[0]
                row[name] = value
                result, d = self.failure(row)
                self.assertEqual(result["status"], "unsupported")
                self.assertEqual(d["code"], code)
                self.assertTrue(d["syntheticAttributionVerified"])
                self.assertEqual(d["knownFieldTypes"][name], kind)

    def test_backtrace_shapes_share_code_without_nested_names_or_values(self):
        variants = ({"SENSITIVE_NESTED": []}, {"frames": False}, {"frames": [False]},
                    {"frames": [{"imageOffset": 1, "imageUUID": "SENSITIVE", "SENSITIVE": 2}]},
                    {"frames": [{"imageOffset": True, "imageUUID": "SENSITIVE"}]},
                    {"frames": [{"imageOffset": 1, "imageUUID": None}]},
                    {"frames": [] , "SENSITIVE": 1}, {"frames": [{}] * 65})
        for backtrace in variants:
            row = rows()[0]
            row["backtrace"] = backtrace
            result, d = self.failure(row)
            self.assertEqual(result["reason"], "unsupported_schema")
            self.assertEqual(d["code"], "backtrace_shape")
            self.assertTrue(d["syntheticAttributionVerified"])
            self.assertEqual(d["knownFieldTypes"]["backtrace"], "object")
            self.assertEqual(d["unknownKeyCount"], 0)
        # A later bad field must not erase the first backtrace branch's evidence.
        row = rows()[0]
        row["backtrace"] = {"SENSITIVE": []}
        row["formatString"] = False
        result, d = self.failure(row)
        self.assertEqual(d["code"], "backtrace_shape")
        self.assertEqual(d["knownFieldTypes"]["formatString"], "boolean")

    def test_decoding_rejects_only_with_fixed_codes_before_attribution(self):
        cases = ((b'[{"SENSITIVE":1,"SENSITIVE":2}]', "duplicate_keys"),
                 (b'[{"SENSITIVE":"\\ud800"}]', "decode_json"),
                 (b'[{"SENSITIVE":\xff}]', "decode_json"),
                 (b'[{"SENSITIVE":NaN}]', "numeric_encoding"),
                 (b'[{"SENSITIVE":1.5}]', "numeric_encoding"),
                 (b'[{"SENSITIVE":]}]', "structural_json"),
                 (b'[] SENSITIVE', "framing"))
        for raw, code in cases:
            _, d = self.failure(raw=raw)
            self.assert_no_metadata(d, code)
        row = rows()[0]
        row["SENSITIVE_UNKNOWN"] = 1.5
        _, d = self.failure(row)
        self.assert_no_metadata(d, "numeric_encoding")

    def test_empty_stdout_retains_framing_failure_without_event_metadata(self):
        for index in (1, 2, 3):
            result, d = self.failure(raw=b"", index=index)
            self.assertEqual(result["reason"], "malformed_framing")
            self.assertEqual(result["queries"][index - 1]["eventCount"], 0)
            self.assert_no_metadata(d, "framing")

    def test_projector_rechecks_attribution_independently(self):
        events = p._Events(SUBSYSTEM, 4100, 1700000000, 1700000010, False)
        for key in p.ATTRIBUTION_FIELDS:
            row = rows()[0]
            row[key] = "SENSITIVE_INEXACT"
            row["SENSITIVE_UNKNOWN"] = 17
            with self.assertRaises(p._Failure) as caught:
                events.reject_schema(row, "extra_event_keys")
            self.assert_no_metadata(caught.exception.diagnostic, "extra_event_keys")
        events.negative = True
        with self.assertRaises(p._Failure) as caught:
            events.reject_schema(dict(rows()[0], SENSITIVE_UNKNOWN=17), "extra_event_keys")
        self.assert_no_metadata(caught.exception.diagnostic, "extra_event_keys")

    def test_terminal_failure_never_reuses_prior_event_metadata(self):
        raw = encode("ndjson", rows(), terminal=False) + b'{"finished":false,"SENSITIVE":17}\n'
        _, d = self.failure(raw=raw, index=2)
        self.assert_no_metadata(d, "terminal_shape")

    def test_later_unrelated_event_cannot_reuse_prior_attribution(self):
        values = rows()
        values[1]["eventMessage"] = "SENSITIVE_MESSAGE"
        values[1]["SENSITIVE_UNKNOWN"] = 17
        _, d = self.failure(raw=encode("json", values))
        self.assert_no_metadata(d, "attribution")

    def test_negative_query_has_no_event_metadata_even_for_exact_synthetic_row(self):
        row = rows()[0]
        row["SENSITIVE_UNKNOWN"] = 17
        _, d = self.failure(row, index=3)
        self.assert_no_metadata(d, "negative_event")

    def test_timestamp_and_duplicate_failures_remain_fixed_only(self):
        row = rows()[0]
        row["timestamp"] = "SENSITIVE_TIME"
        _, d = self.failure(row)
        self.assert_no_metadata(d, "timestamp_shape")
        _, d = self.failure(rows(stamp=1700000010)[0])
        self.assert_no_metadata(d, "outside_window")
        _, d = self.failure(raw=encode("json", [rows()[0], rows()[0]]))
        self.assert_no_metadata(d, "duplicate_marker")

    def test_cleanup_failure_clears_diagnostic_and_preserves_reap_truth(self):
        def modify(index, out, err, options):
            if index == 1:
                row = rows()[0]
                row["SENSITIVE_UNKNOWN"] = 17
                out = encode("json", [row])
                options["fail_reap"] = True
            return out, err, options
        result = World(modify).execute()
        self.assert_closed(result)
        q = result["queries"][0]
        self.assertEqual(q["reason"], "reap_failed")
        self.assertFalse(q["reaped"])
        self.assert_no_metadata(q["diagnostic"], "none")

    def test_cleanup_cancellation_clears_diagnostic(self):
        original = Child.wait
        interrupted = []
        def wait(child, timeout):
            if child.kind == "query" and not interrupted:
                interrupted.append(True)
                raise p._Cancelled()
            return original(child, timeout)
        row = rows()[0]
        row["SENSITIVE_UNKNOWN"] = 17
        with patch.object(Child, "wait", wait):
            result, d = self.failure(row)
        self.assertNotEqual(result["status"], "passed")
        self.assertEqual(result["queries"][0]["reason"], "cancelled")
        self.assert_no_metadata(d, "none")

    def test_diagnostic_validator_rejects_arbitrary_shape_types_and_inferences(self):
        row = rows()[0]
        row["SENSITIVE_UNKNOWN"] = 17
        base, _ = self.failure(row)
        changes = (("code", "SENSITIVE_CODE"), ("code", []), ("code", "none"),
                   ("code", "missing_required"), ("syntheticAttributionVerified", 1),
                   ("syntheticAttributionVerified", False), ("unknownKeyCount", True),
                   ("unknownKeyCount", -1), ("unknownKeyCount", p.MAX_KEYS + 1),
                   ("unknownKeyCount", p.MAX_KEYS), ("unknownKeyCount", None),
                   ("unknownKeyCount", 0), ("knownFieldTypes", {"SENSITIVE": "string"}))
        for key, value in changes:
            altered = copy.deepcopy(base)
            altered["queries"][0]["diagnostic"][key] = value
            self.assertFalse(p.validate_result(altered), key)
        for key, value in (("SENSITIVE_FIELD", "string"), ("source", "SENSITIVE_TYPE"),
                           ("processID", "boolean"), ("timestamp", "integer")):
            altered = copy.deepcopy(base)
            altered["queries"][0]["diagnostic"]["knownFieldTypes"][key] = value
            self.assertFalse(p.validate_result(altered), key)
        for key in p.REQUIRED_FIELDS:
            altered = copy.deepcopy(base)
            del altered["queries"][0]["diagnostic"]["knownFieldTypes"][key]
            self.assertFalse(p.validate_result(altered), key)
        altered = copy.deepcopy(base)
        altered["queries"][0]["diagnostic"]["raw"] = "SENSITIVE"
        self.assertFalse(p.validate_result(altered))
        altered = copy.deepcopy(base)
        altered["queries"][0]["status"] = "passed"
        self.assertFalse(p.validate_result(altered))
        altered = copy.deepcopy(base)
        altered["queries"][0]["eventCount"] = 0
        self.assertFalse(p.validate_result(altered))
        passed = World().execute()
        passed["queries"][0]["diagnostic"] = base["queries"][0]["diagnostic"]
        self.assertFalse(p.validate_result(passed))

    def test_failure_metadata_cannot_be_attached_to_fixed_only_codes(self):
        row = rows()[0]
        row["SENSITIVE_UNKNOWN"] = 17
        base, _ = self.failure(row)
        for code, reason in p.DIAGNOSTIC_REASONS.items():
            if code in p.ATTRIBUTED_SCHEMA_CODES:
                continue
            altered = copy.deepcopy(base)
            q = altered["queries"][0]
            q["diagnostic"]["code"] = code
            q["reason"] = reason
            q["status"] = "unsupported" if reason == "unsupported_schema" else "failed"
            self.assertFalse(p.validate_result(altered), code)

    def test_diagnostic_report_remains_below_export_budget(self):
        row = rows()[0]
        for name, kind in p.FIELD_TYPES.items():
            if name not in row:
                row[name] = 1 if kind == "integer" else "SENSITIVE_KNOWN_VALUE"
        for number in range(p.MAX_KEYS - len(row)):
            row["SENSITIVE_UNKNOWN_" + str(number)] = "SENSITIVE_VALUE"
        result, _ = self.failure(row)
        self.assertLess(len(json.dumps(result, ensure_ascii=True).encode("ascii")), 65536)
        self.assertEqual(set(result["queries"][0]["diagnostic"]["knownFieldTypes"]), set(p.FIELD_TYPES))


if __name__ == "__main__":
    unittest.main()
