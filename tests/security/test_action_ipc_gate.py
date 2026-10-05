"""Inert native IPC gate checks; no sockets, host services or privilege changes."""
import contextlib
import io
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import check_action_ipc_gate as gate

SOURCE = "a" * 40


def event(action, package=gate.HELPER, test=None, **extra):
    value = {"Time": "2026-10-05T00:00:00.123456789Z", "Action": action, "Package": package}
    if test is not None:
        value["Test"] = test
    return dict(value, **extra)


def valid_events():
    events = []
    for package, required in gate.REQUIRED.items():
        events.append(event("start", package))
        for root in sorted(name for name in required if "/" not in name):
            events.append(event("run", package, root))
            events.append(event("output", package, root, Output="=== RUN   " + root + "\n", OutputType="frame"))
            for child in sorted(name for name in required if name.startswith(root + "/")):
                events += [event("run", package, child), event("pass", package, child, Elapsed=0)]
            events.append(event("pass", package, root, Elapsed=0.001))
        events += [event("output", package, Output="PASS\n", OutputType="frame"), event("pass", package, Elapsed=0.002)]
    return events


class CompletionTests(unittest.TestCase):
    def validate(self, events):
        return gate.validate(events, 0, SOURCE)

    def test_exact_required_list_and_pass(self):
        self.assertEqual(sum(map(len, gate.REQUIRED.values())), 13)
        self.assertIsNone(self.validate(valid_events()))
        for required in gate.REQUIRED.values():
            for root in (name for name in required if "/" not in name):
                self.assertIsNotNone(re.fullmatch(gate.RUN_PATTERN, root))
        self.assertIsNone(re.fullmatch(gate.RUN_PATTERN, "TestProtectedSocketAndDirectoryMetadata"))

    def test_every_required_lifecycle_event_is_required(self):
        events = valid_events()
        for index, value in enumerate(events):
            if value["Action"] == "output":
                continue
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.validate(events[:index] + events[index + 1:])

    def test_duplicate_lifecycle_events_reject(self):
        events = valid_events()
        for index, value in enumerate(events):
            if value["Action"] == "output":
                continue
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.validate(events[:index] + [value] + events[index:])

    def test_any_skip_or_failure_rejects_including_unexpected_subtest(self):
        for index in range(len(valid_events())):
            for action in ("skip", "fail", "build-fail"):
                changed = valid_events(); changed[index]["Action"] = action
                with self.subTest(index=index, action=action), self.assertRaises(ValueError):
                    self.validate(changed)
        for action in ("skip", "fail", "build-fail"):
            for test in (None, gate.MISMATCH + "/pid", gate.MISMATCH + "/future_child"):
                with self.subTest(action=action, test=test), self.assertRaises(ValueError):
                    self.validate(valid_events() + [event(action, test=test)])
        # A skipped descendant followed by passing parent/package is still fatal.
        changed = valid_events()
        index = next(i for i, value in enumerate(changed) if value.get("Test") == gate.MISMATCH and value["Action"] == "pass")
        changed.insert(index, event("skip", test=gate.MISMATCH + "/future_child"))
        with self.assertRaises(ValueError): self.validate(changed)

    def test_early_parent_package_and_output_after_completion_reject(self):
        events = valid_events()
        index = next(i for i, value in enumerate(events) if value.get("Test") == gate.MISMATCH and value["Action"] == "pass")
        changed = events.copy(); completion = changed.pop(index); changed.insert(2, completion)
        with self.assertRaises(ValueError): self.validate(changed)
        changed = events.copy(); changed.insert(1, event("pass"))
        with self.assertRaises(ValueError): self.validate(changed)
        changed = events + [event("output", gate.CLIENT, Output="private-fixture\n")]
        with self.assertRaises(ValueError): self.validate(changed)

    def test_bad_schema_wrong_test_package_and_actions_reject(self):
        malformed = [None, [], {}, {"Action": "pass"}, event("pause"), event("run"),
                     event("pass", package="elsewhere"), event("run", test="TestOther"),
                     event("run", test=gate.MISMATCH + "/unexpected"),
                     event("output", Output=1), event("output", Output=""),
                     event("pass", Output="private-fixture"), event("pass", Unknown=1),
                     event("output", Output="private-fixture", OutputType="error"),
                     event("output", Output="private-fixture", OutputType="error-continue"),
                     event("output", Output="private-fixture", OutputType=None),
                     event("pass", OutputType="frame"), event([], Test=gate.MISMATCH),
                     event("pass", Test=None), event("pass", Elapsed=True),
                     event("pass", Elapsed=-1), event("pass", Elapsed=float("inf")),
                     event("pass", Elapsed=float("nan")), event("pass", Time="not a timestamp"),
                     event("pass", Time="2026-99-99T00:00:00Z")]
        for value in malformed:
            changed = valid_events(); changed[1] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.validate(changed)

    def test_command_failure_and_source_are_mandatory(self):
        for status in (1, 2, 124, 137, -1, "0", None, False):
            with self.subTest(status=status), self.assertRaises(ValueError):
                gate.validate(valid_events(), status, SOURCE)
        for source in (None, "", "a" * 39, "A" * 40, "private-fixture", SOURCE + "\n"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                gate.validate(valid_events(), 0, source)

    def test_empty_partial_and_event_limit_reject(self):
        events = valid_events()
        for end in range(len(events)):
            with self.subTest(end=end), self.assertRaises(ValueError): self.validate(events[:end])
        with mock.patch.object(gate, "MAX_EVENTS", len(events) - 1):
            with self.assertRaises(ValueError): self.validate(events)

    def test_cli_bounds_malformed_json_and_fixed_failure_output(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "input.jsonl"
            raw = "".join(json.dumps(value) + "\n" for value in valid_events()).encode()
            args = ["gate", str(path), "--go-exit-code", "0", "--source-sha", SOURCE]
            path.write_bytes(raw)
            output = io.StringIO()
            with contextlib.redirect_stdout(output): code = gate.main(args)
            self.assertEqual(code, 0)
            self.assertIn("source=" + SOURCE, output.getvalue())
            bad_inputs = [b"", b"private-fixture\n", b"[]\n", b"null\n", b"{}\n", b"\xff\n",
                          b'{"Action":"pass","Action":"fail"}\n', b'{"value":NaN}\n',
                          b'x' * (gate.MAX_LINE + 1) + b'\n', raw[:-1], raw + b'{"Action":',
                          raw + b'\n', raw + b'private-fixture\n']
            for bad in bad_inputs:
                path.write_bytes(bad); output = io.StringIO()
                with contextlib.redirect_stdout(output): code = gate.main(args)
                self.assertEqual(code, 1)
                self.assertEqual(output.getvalue(), gate.FAILURE + "\n")
            path.write_bytes(raw)
            for bad_args in (args[:2], args + ["extra"], args[:3] + ["1"] + args[4:],
                             args[:3] + ["00"] + args[4:], args[:-1] + ["private-fixture"]):
                output = io.StringIO()
                with contextlib.redirect_stdout(output): code = gate.main(bad_args)
                self.assertEqual(code, 1)
                self.assertEqual(output.getvalue(), gate.FAILURE + "\n")
            with path.open("wb") as stream: stream.truncate(gate.MAX_FILE + 1)
            with self.assertRaises(ValueError): list(gate.read_events(path))

    def test_special_files_reject_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "input.jsonl"; path.write_text('{}\n')
            link = Path(temp) / "link"; link.symlink_to(path)
            fifo = Path(temp) / "fifo"; os.mkfifo(fifo)
            for target in (link, fifo, Path(temp), Path(temp) / "missing"):
                with self.assertRaises((ValueError, OSError)): list(gate.read_events(target))

    def test_interleaved_packages_remain_valid(self):
        events = valid_events()
        helper = [value for value in events if value["Package"] == gate.HELPER]
        client = [value for value in events if value["Package"] == gate.CLIENT]
        interleaved = []
        while helper or client:
            if helper: interleaved.append(helper.pop(0))
            if client: interleaved.append(client.pop(0))
        self.assertIsNone(self.validate(interleaved))


if __name__ == "__main__":
    unittest.main()
