"""Inert supervisor checks: fake adapters only, no process, PTY, socket or keys."""
import base64
import copy
import contextlib
import hashlib
import io
import json
import stat
import types
import unittest
from unittest import mock

import run


def bootstrap():
    # Syntactic inert markers, not a parseable X.509 certificate or usable key.
    pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
    return {
        "schemaVersion": "tracebolt.enrollment-bootstrap.v2",
        "managerInstanceId": "manager_fixture", "profile": "tls",
        "enrollmentOrigin": "https://127.0.0.1:41001",
        "agentOrigin": "https://127.0.0.1:41002",
        "collectionProfile": "basic-readonly-v1", "invitationId": "invitation_fixture",
        "serverCaPem": pem, "issuerRootPem": pem, "issuerPem": pem,
    }


def identity():
    return {"seed": "inert seed marker", "csr": "inert CSR marker", "claimId": "claim_fixture",
            "claimRequestId": "request_claim", "statusRequestId": "request_status",
            "credentialRequestId": "request_credential", "activationRequestId": "request_activation"}


def state(sequence, pending=False):
    body = b'{"inert":"private report marker"}'
    return json.dumps({"version": 1, "binding": "inert binding", "lastSequence": sequence,
                       "pending": {"sequence": sequence, "digest": hashlib.sha256(body).hexdigest(),
                                   "body": base64.b64encode(body).decode("ascii")} if pending else None}).encode()


def display():
    return (b"Local device SPKI SHA-256: " + b"a" * 64 + b"\r\n"
            b"Local 128-bit comparison: " + b"b" * 32 + b"\r\n" + run.HIDDEN_PROMPT)


class FakeProcess:
    def __init__(self):
        self.signals = []

    def send_signal(self, value):
        self.signals.append(value)

    def poll(self):
        return None


class FakeChild:
    def __init__(self, runtime):
        self.runtime = runtime
        self.output = run.BoundedBuffer()
        self.output.append(display())
        self.process = FakeProcess()
        self.invitation_received = False

    def until(self, predicate, deadline):
        run.require(predicate())

    def echo_hidden(self):
        return not self.runtime.fault == "echo_on"

    def echo_restored(self):
        return not self.runtime.fault == "echo_unrestored"

    def send_invitation(self, secret):
        run.require(self.echo_hidden())
        self.invitation_received = True
        self.output.append(run.PENDING_PROMPT)
        if self.runtime.fault == "secret_echo":
            self.output.append(bytes(secret))

    def pump(self, seconds):
        pass

    def wait(self, seconds):
        return 1 if self.process.signals else 0


class FakeRuntime:
    def __init__(self, fault=""):
        self.fault = fault
        self.children = []
        self.commands = []
        self.sender_calls = []
        self.calls = 0
        self.accepted = 0
        self.duplicates = 0
        self.loss = 0
        self.cleaned = False
        self.preserved = False
        self.bootstrap_raw = b""
        self.ledger_reads = 0
        self.approval_calls = 0
        self.state_raw = state(1)

    def rpc(self, command, **fields):
        self.commands.append((command, fields))
        if command == "start":
            return {"bootstrap": bootstrap(), "invitation": "A" * 43}
        if command == "approve":
            self.approval_calls += 1
            if self.fault == "approval_pending" and self.approval_calls < 3:
                return dict(fingerprintMatched=False, comparisonMatched=False, approved=False)
            return dict(fingerprintMatched=True, comparisonMatched=self.fault != "comparison",
                        approved=True)
        if command == "arm_loss":
            return {"armed": True}
        if command == "status":
            result = dict.fromkeys(run.STATUS_BOOLS, True)
            result.update(acceptedReports=self.accepted, duplicateReports=self.duplicates,
                          lossCount=self.loss)
            if self.fault == "receipt" and self.duplicates:
                result["originalReceiptTime"] = False
            if self.fault == "no_client" and self.accepted == 3:
                result["missingClientRejected"] = False
            if self.fault == "status_extra":
                result["unsafe_payload"] = "/private/path secret"
            return result
        raise AssertionError("unexpected control command")

    def write_bootstrap(self, raw):
        self.bootstrap_raw = raw

    def enroll(self):
        child = FakeChild(self)
        if self.fault == "display_change" and self.children:
            child.output.data[:] = display().replace(b"a" * 64, b"c" * 64)
        self.children.append(child)
        return child

    def read(self, name):
        if name == "state/ledger.json":
            self.ledger_reads += 1
            if self.fault == "custody":
                raise run.CustodyFailure()
            data = identity()
            if self.fault == "key_change" and self.ledger_reads > 1:
                data["seed"] = "different inert marker"
            return json.dumps(data).encode()
        if name == "state/agent-key.pem":
            return b"inert private key marker, never a real key"
        if name == "state/agent.json":
            return b'{"profile":"tls"}'
        if name == "state/telemetry/state.json":
            return self.state_raw
        raise AssertionError("unexpected state read")

    def sender(self, validate=False):
        self.sender_calls.append(validate)
        if validate:
            if self.fault == "unexpected_error":
                raise RuntimeError("SECRET raw exception /private/user/path")
            return 0
        self.calls += 1
        if self.calls == 1:
            self.accepted = 1
            self.state_raw = state(1)
            return 0
        if self.calls == 2:
            self.accepted = 2
            self.loss = 1
            self.state_raw = state(2, pending=self.fault != "missing_pending")
            return 1
        if self.calls == 3:
            self.duplicates = 1
            self.state_raw = state(2)
            return 0
        if self.calls == 4:
            self.accepted = 3
            self.state_raw = state(3)
            return 0
        raise AssertionError("unexpected sender call")

    def cleanup(self, preserve_tree=False):
        self.cleaned = True
        self.preserved = preserve_tree
        if self.fault == "cleanup_error":
            raise RuntimeError("SECRET cleanup exception")
        return (self.fault != "unreaped", True,
                not preserve_tree and self.fault != "not_removed", preserve_tree)


class ClosedEntryTests(unittest.TestCase):
    def test_main_always_blocked_without_native_adapter_or_input(self):
        output = io.StringIO()
        with mock.patch.object(run, "NativeRuntime", side_effect=AssertionError("native adapter called")), \
             mock.patch.object(run, "_exercise", side_effect=AssertionError("runtime called")), \
             mock.patch.object(run, "_open_canonical_directory", side_effect=AssertionError("path read")):
            self.assertEqual(run.main(["--run", "--approved", "--host=darwin"], output), 2)
        parsed = json.loads(output.getvalue())
        self.assertEqual(parsed, run.closed_result())
        self.assertTrue(parsed["blocked"])
        self.assertFalse(parsed["runtime_started"])

    def test_exact_review_function_is_always_blocked(self):
        with self.assertRaises(run.FixtureFailure):
            run.run_after_exact_review(object(), approved=True)

    def test_result_rejects_unbounded_or_unsafe_fields(self):
        result = run.closed_result()
        for changed in ({**result, "error": "secret"}, {**result, "blocked": 1},
                        {**result, "owned_tree_removed": "/private/path"}):
            with self.assertRaises(run.FixtureFailure):
                run.result_json(changed)
        self.assertLess(len(run.result_json(result)), 4096)
        self.assertTrue(all(type(v) is bool for v in result.values()))


class WireTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_nonfinite_array_and_bad_utf8(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'[]',
                    b'{}{}', b'{"x":"\xff"}', b''):
            with self.subTest(raw=raw), self.assertRaises(run.FixtureFailure):
                run.strict_json(raw)

    def test_strict_json_bound(self):
        with self.assertRaises(run.FixtureFailure):
            run.strict_json(b'{"x":"' + b"A" * run.CONTROL_LIMIT + b'"}')

    def test_start_secret_separated_and_decoder_object_cleared(self):
        source = {"bootstrap": bootstrap(), "invitation": "A" * 43}
        raw, secret = run.start_reply(source)
        self.assertNotIn(bytes(secret), raw)
        self.assertEqual(source, {})
        self.assertEqual(secret, bytearray(b"A" * 43))
        self.assertEqual(set(json.loads(raw)), set(bootstrap()))

    def test_public_bootstrap_closed_scope_and_loopback_only(self):
        mutations = [dict(profile="http"), dict(renewalPolicy="enabled"),
                     dict(collectionProfile="macos-read-inventory"),
                     dict(agentOrigin="https://localhost:41002"),
                     dict(agentOrigin="https://127.0.0.1:65536"),
                     dict(agentOrigin="https://127.0.0.1:41001"),
                     dict(agentOrigin="https://127.0.0.1:41002/path"),
                     dict(agentOrigin="https://user@127.0.0.1:41002"),
                     dict(serverCaPem="-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"),
                     dict(invitation="A" * 43)]
        for mutation in mutations:
            with self.subTest(mutation=list(mutation)), self.assertRaises(run.FixtureFailure):
                run.public_bootstrap({**bootstrap(), **mutation})

    def test_start_rejects_invitation_wrong_shape_and_extra_fields(self):
        for token in ("A" * 42, "A" * 44, "A" * 42 + "\n", 123, None):
            with self.assertRaises(run.FixtureFailure):
                run.start_reply({"bootstrap": bootstrap(), "invitation": token})
        with self.assertRaises(run.FixtureFailure):
            run.start_reply({"bootstrap": bootstrap(), "invitation": "A" * 43, "key": "SECRET"})

    def test_status_exact_booleans_and_bounded_integer_counts(self):
        status = dict.fromkeys(run.STATUS_BOOLS, True)
        status.update(dict.fromkeys(run.STATUS_COUNTS, 0))
        self.assertEqual(run.status_reply(status), status)
        for value in (True, -1, 17, "1", 1.0):
            with self.assertRaises(run.FixtureFailure):
                run.status_reply({**status, "acceptedReports": value})
        with self.assertRaises(run.FixtureFailure):
            run.status_reply({**status, "tls13": 1})
        with self.assertRaises(run.FixtureFailure):
            run.status_reply({**status, "report": {"private": True}})

    def test_approval_requires_exact_boolean_fields(self):
        names = ("fingerprintMatched", "comparisonMatched", "approved")
        with self.assertRaises(run.FixtureFailure):
            run.bool_reply(dict.fromkeys(names, 1), names)
        with self.assertRaises(run.FixtureFailure):
            run.bool_reply({"approved": True}, names)

    def test_display_requires_complete_single_fingerprint_and_comparison(self):
        self.assertEqual(run.displayed_identity(display()), ("a" * 64, "b" * 32))
        for raw in (display() + display(), display().replace(b"a" * 64, b"a" * 63),
                    display().replace(b"b" * 32, b"b" * 31),
                    display().replace(b"a" * 64, b"g" * 64)):
            with self.assertRaises(run.FixtureFailure):
                run.displayed_identity(raw)

    def test_ledger_identity_ignores_later_phase_but_retains_all_operation_ids(self):
        initial = identity()
        before = run.ledger_identity(json.dumps(initial).encode())
        self.assertEqual(before, run.ledger_identity(json.dumps({**initial, "activated": True}).encode()))
        for key in initial:
            changed = {**initial, key: initial[key] + "different"}
            self.assertNotEqual(before, run.ledger_identity(json.dumps(changed).encode()))

    def test_pending_integrity_and_exact_body(self):
        self.assertEqual(run.pending_state(state(2, True), True),
                         (2, b'{"inert":"private report marker"}'))
        self.assertEqual(run.pending_state(state(2), False), (2, b""))
        broken = json.loads(state(2, True))
        for key, value in (("sequence", 3), ("digest", "0" * 64), ("body", "!bad!")):
            bad = copy.deepcopy(broken)
            bad["pending"][key] = value
            with self.assertRaises(run.FixtureFailure):
                run.pending_state(json.dumps(bad).encode(), True)
        with self.assertRaises(run.FixtureFailure):
            run.pending_state(state(2), True)
        with self.assertRaises(run.FixtureFailure):
            run.pending_state(state(2, True), False)

    def test_output_bound_is_cumulative_even_after_clear(self):
        buffer = run.BoundedBuffer(5)
        buffer.append(b"1234")
        buffer.clear()
        self.assertEqual(buffer.data, b"")
        with self.assertRaises(run.FixtureFailure):
            buffer.append(b"67")
        buffer.append(b"5")


class CustodyTests(unittest.TestCase):
    def metadata(self, mode=stat.S_IFREG | 0o600, uid=501, nlink=1):
        return types.SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=nlink)

    def test_private_file_requires_exact_mode_owner_type_single_link(self):
        self.assertTrue(run.private_metadata(self.metadata(), 501, False))
        for m in (self.metadata(mode=stat.S_IFREG | 0o644), self.metadata(uid=0),
                  self.metadata(nlink=2), self.metadata(mode=stat.S_IFLNK | 0o600),
                  self.metadata(mode=stat.S_IFIFO | 0o600)):
            self.assertFalse(run.private_metadata(m, 501, False))

    def test_directory_does_not_require_single_link(self):
        self.assertTrue(run.private_metadata(self.metadata(mode=stat.S_IFDIR | 0o700, nlink=3), 501, True))
        self.assertFalse(run.private_metadata(self.metadata(mode=stat.S_IFDIR | 0o750), 501, True))


class AdapterBoundaryTests(unittest.TestCase):
    def setUp(self):
        # Native cleanup is tested only with mocked signal APIs as well as fake
        # process/filesystem adapters. Unit tests never change a real handler.
        self.saved_handler = object()
        self.signal_get = mock.patch("signal.getsignal", return_value=self.saved_handler)
        self.signal_set = mock.patch("signal.signal")
        self.getsignal = self.signal_get.start()
        self.setsignal = self.signal_set.start()
        self.addCleanup(self.signal_get.stop)
        self.addCleanup(self.signal_set.stop)

    def constructor_failure(self, mkdtemp_error=False, open_error=False, strict_umask=False):
        parent = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=501,
                                       st_nlink=2, st_dev=1, st_ino=11)
        root = types.SimpleNamespace(st_mode=stat.S_IFDIR | (0 if strict_umask else 0o700),
                                     st_uid=501, st_nlink=2, st_dev=1, st_ino=12)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(run, "_open_canonical_directory", return_value=11))
            stack.enter_context(mock.patch.object(run.os, "fstat", side_effect=[parent, root, root]))
            stack.enter_context(mock.patch.object(run.os, "getuid", return_value=501))
            created = stack.enter_context(mock.patch("tempfile.mkdtemp", return_value="/approved/new-tree"))
            opened = stack.enter_context(mock.patch.object(run.os, "open", return_value=12))
            closed = stack.enter_context(mock.patch.object(run.os, "close"))
            unlink = stack.enter_context(mock.patch.object(run.os, "unlink"))
            rmdir = stack.enter_context(mock.patch.object(run.os, "rmdir"))
            chmod = stack.enter_context(mock.patch.object(run.os, "chmod"))
            if mkdtemp_error:
                created.side_effect = OSError("SECRET private path from mkdir")
            if open_error:
                opened.side_effect = OSError(24, "SECRET EMFILE private path")
            with self.assertRaises(run.CustodyFailure) as caught:
                run.OwnedTree("/approved")
            self.assertEqual(str(caught.exception), "fixture stopped")
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertEqual([c.args[0] for c in closed.call_args_list],
                             [12, 11] if strict_umask else [11])
            unlink.assert_not_called()
            rmdir.assert_not_called()
            chmod.assert_not_called()
            return opened.call_count

    def test_constructor_mkdtemp_failure_closes_parent(self):
        self.assertEqual(self.constructor_failure(mkdtemp_error=True), 0)

    def test_constructor_open_emfile_preserves_created_tree_and_closes_parent(self):
        self.assertEqual(self.constructor_failure(open_error=True), 1)

    def test_constructor_strict_umask_preserves_tree_without_repair(self):
        self.assertEqual(self.constructor_failure(strict_umask=True), 1)

    def fake_cleanup_runtime(self):
        runtime = object.__new__(run.NativeRuntime)
        runtime.peer = None
        runtime.peer_stopped = True
        runtime.tree = mock.Mock()
        runtime.tree.cleanup.return_value = True
        runtime.children = [mock.Mock(), mock.Mock()]
        for child in runtime.children:
            child.stop.return_value = True
        return runtime

    def test_cleanup_interrupt_during_peer_stop_continues_all_owned_teardown(self):
        runtime = self.fake_cleanup_runtime()
        runtime.peer = mock.Mock()
        runtime.peer.process.poll.return_value = None
        runtime.rpc = mock.Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(run.FixtureFailure):
            runtime.cleanup()
        for child in runtime.children:
            child.stop.assert_called_once()
            child.close.assert_called_once()
        runtime.tree.close.assert_called_once()
        self.assertIs(self.setsignal.call_args_list[-1].args[1], self.saved_handler)

    def test_cleanup_interrupt_during_reap_retries_owned_child_then_continues(self):
        runtime = self.fake_cleanup_runtime()
        runtime.children[1].stop.side_effect = [KeyboardInterrupt(), True]
        with self.assertRaises(run.FixtureFailure):
            runtime.cleanup()
        self.assertEqual(runtime.children[1].stop.call_count, 2)
        runtime.children[0].stop.assert_called_once()
        for child in runtime.children:
            child.close.assert_called_once()
        runtime.tree.close.assert_called_once()
        self.assertIs(self.setsignal.call_args_list[-1].args[1], self.saved_handler)

    def test_cleanup_repeated_reap_interrupt_preserves_tree_and_reaps_others(self):
        runtime = self.fake_cleanup_runtime()
        runtime.children[1].stop.side_effect = KeyboardInterrupt()
        with self.assertRaises(run.FixtureFailure):
            runtime.cleanup()
        self.assertEqual(runtime.children[1].stop.call_count, 2)
        runtime.children[0].stop.assert_called_once()
        runtime.tree.cleanup.assert_not_called()
        runtime.tree.close.assert_called_once()

    def test_cleanup_interrupt_during_close_continues_all_closes(self):
        runtime = self.fake_cleanup_runtime()
        runtime.children[0].close.side_effect = KeyboardInterrupt()
        with self.assertRaises(run.FixtureFailure):
            runtime.cleanup()
        runtime.children[1].close.assert_called_once()
        runtime.tree.close.assert_called_once()
        self.assertIs(self.setsignal.call_args_list[-1].args[1], self.saved_handler)

    def test_cleanup_defers_received_sigint_and_restores_handler(self):
        runtime = self.fake_cleanup_runtime()
        def stop():
            handler = self.setsignal.call_args_list[0].args[1]
            handler(2, None)
            handler(2, None)
            return True
        runtime.children[1].stop.side_effect = stop
        with self.assertRaises(run.FixtureFailure):
            runtime.cleanup()
        runtime.children[0].stop.assert_called_once()
        runtime.tree.close.assert_called_once()
        self.assertEqual(self.setsignal.call_count, 2)
        self.assertIs(self.setsignal.call_args_list[-1].args[1], self.saved_handler)

    def test_child_close_interrupt_continues_other_streams_and_descriptors(self):
        process = mock.Mock()
        process.stdin.close.side_effect = KeyboardInterrupt()
        child = run.Child(process, {}, master=8, slave=9)
        with mock.patch.object(run.os, "close") as closed:
            with self.assertRaises(run.FixtureFailure):
                child.close()
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()
        self.assertEqual([call.args[0] for call in closed.call_args_list], [8, 9])
        self.assertTrue(child.closed)

    def test_until_drains_exit_output_before_declaring_failure(self):
        process = mock.Mock()
        process.poll.return_value = 0
        child = run.Child(process, {})
        child.pump = lambda _: child.output.append(b"ready")
        child.until(lambda: b"ready" in child.output.data, run.time.monotonic() + 1)
        self.assertEqual(child.output.data, b"ready")

    def test_invitation_requires_hidden_terminal_and_clears_write_copy(self):
        process = mock.Mock()
        process.poll.return_value = None
        child = run.Child(process, {}, master=8, slave=9, original=[])
        child.echo_hidden = lambda: True
        received = []
        def record(fd, payload, deadline):
            self.assertEqual(fd, 8)
            self.assertEqual(payload, b"A" * 43 + b"\n")
            received.append(payload)
        with mock.patch.object(run, "_bounded_write", side_effect=record):
            child.send_invitation(bytearray(b"A" * 43))
        self.assertEqual(received[0], b"\0" * 44)
        child.echo_hidden = lambda: False
        with mock.patch.object(run, "_bounded_write") as write:
            with self.assertRaises(run.FixtureFailure):
                child.send_invitation(bytearray(b"A" * 43))
            write.assert_not_called()

    def test_cleanup_never_deletes_tree_on_prior_custody_failure(self):
        runtime = object.__new__(run.NativeRuntime)
        runtime.peer = None
        runtime.peer_stopped = True
        child = mock.Mock()
        child.stop.return_value = True
        runtime.children = [child]
        runtime.tree = mock.Mock()
        result = runtime.cleanup(preserve_tree=True)
        self.assertEqual(result, (True, True, False, True))
        runtime.tree.cleanup.assert_not_called()
        child.stop.assert_called_once()
        child.close.assert_called_once()
        runtime.tree.close.assert_called_once()

    def test_cleanup_never_deletes_tree_while_child_is_unreaped(self):
        runtime = object.__new__(run.NativeRuntime)
        runtime.peer = None
        runtime.peer_stopped = True
        child = mock.Mock()
        child.stop.return_value = False
        runtime.children = [child]
        runtime.tree = mock.Mock()
        result = runtime.cleanup()
        self.assertEqual(result, (False, True, False, False))
        runtime.tree.cleanup.assert_not_called()

    def test_inventory_rejects_unexpected_file_before_deletion(self):
        tree = object.__new__(run.OwnedTree)
        tree.uid = 501
        entry = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=501,
                                      st_nlink=1, st_size=3, st_dev=1, st_ino=4)
        with mock.patch.object(run, "_directory_names", return_value=["unrelated-user-file"]), \
             mock.patch.object(run.os, "stat", return_value=entry), \
             mock.patch.object(run.os, "unlink") as unlink, \
             mock.patch.object(run.os, "rmdir") as rmdir:
            with self.assertRaises(run.CustodyFailure):
                tree._inventory(10)
            unlink.assert_not_called()
            rmdir.assert_not_called()

    def test_inventory_rejects_symlink_and_hardlink_without_open(self):
        tree = object.__new__(run.OwnedTree)
        tree.uid = 501
        for mode, nlink in ((stat.S_IFLNK | 0o600, 1), (stat.S_IFREG | 0o600, 2)):
            entry = types.SimpleNamespace(st_mode=mode, st_uid=501, st_nlink=nlink,
                                          st_size=3, st_dev=1, st_ino=4)
            with mock.patch.object(run, "_directory_names", return_value=["bootstrap.json"]), \
                 mock.patch.object(run.os, "stat", return_value=entry), \
                 mock.patch.object(run.os, "open") as opened:
                with self.assertRaises(run.CustodyFailure):
                    tree._inventory(10)
                opened.assert_not_called()

    def test_allowed_cleanup_paths_are_basic_only(self):
        self.assertIn("state/agent-key.pem", run.OWNED_LAYOUT)
        self.assertIn("state/telemetry/state.json", run.OWNED_LAYOUT)
        for path in ("state/renewal-manifest.json", "state/macos-inventory-consent.json",
                     "state/service-enrollment.json", "../user-data", "other"):
            self.assertNotIn(path, run.OWNED_LAYOUT)


class OrchestrationTests(unittest.TestCase):
    def exercise(self, runtime):
        # Fake time and pause guarantee unit tests cannot sleep on a native case.
        now = [0.0]
        def tick():
            now[0] += 0.01
            return now[0]
        return run._exercise(runtime, clock=tick, pause=lambda _: None)

    def test_fake_endpoint_subset_complete_but_full_stage1_stays_blocked(self):
        runtime = FakeRuntime()
        result = self.exercise(runtime)
        self.assertTrue(result["endpoint_cases_passed"])
        self.assertTrue(result["blocked"])
        self.assertFalse(result["stage1_passed"])
        self.assertFalse(result["custody_case_implemented"])
        self.assertTrue(runtime.cleaned)
        self.assertEqual(runtime.sender_calls, [True, False, False, False, False])
        self.assertNotIn(b"A" * 43, runtime.bootstrap_raw)
        self.assertEqual([c for c, _ in runtime.commands].count("approve"), 1)
        approval = next(fields for c, fields in runtime.commands if c == "approve")
        self.assertEqual(approval, {"fingerprint": "a" * 64, "comparison": "b" * 32})

    def test_all_false_pending_approval_can_poll_then_compare_exact_values(self):
        runtime = FakeRuntime("approval_pending")
        self.assertTrue(self.exercise(runtime)["endpoint_cases_passed"])
        self.assertEqual(runtime.approval_calls, 3)
        values = [f for c, f in runtime.commands if c == "approve"]
        self.assertTrue(all(v == values[0] for v in values))

    def test_failures_close_and_always_cleanup_without_raw_errors(self):
        for fault in ("echo_on", "echo_unrestored", "secret_echo", "comparison", "display_change",
                      "key_change", "receipt", "no_client", "status_extra", "missing_pending",
                      "unexpected_error", "cleanup_error", "unreaped", "not_removed"):
            with self.subTest(fault=fault):
                runtime = FakeRuntime(fault)
                result = self.exercise(runtime)
                self.assertFalse(result["endpoint_cases_passed"])
                self.assertFalse(result["stage1_passed"])
                self.assertTrue(runtime.cleaned)
                serialized = run.result_json(result)
                for forbidden in ("SECRET", "/private/", "inert", "AAAA", "private report marker"):
                    self.assertNotIn(forbidden, serialized)

    def test_custody_mismatch_preserves_tree_and_blocks_delete(self):
        runtime = FakeRuntime("custody")
        result = self.exercise(runtime)
        self.assertTrue(result["custody_mismatch"])
        self.assertTrue(runtime.preserved)
        self.assertFalse(result["owned_tree_removed"])
        self.assertFalse(result["endpoint_cases_passed"])

    def test_comparison_failure_never_starts_sender(self):
        runtime = FakeRuntime("comparison")
        result = self.exercise(runtime)
        self.assertFalse(result["enrolled"])
        self.assertEqual(runtime.sender_calls, [])


if __name__ == "__main__":
    unittest.main()
