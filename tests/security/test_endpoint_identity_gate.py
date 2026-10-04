"""Inert evidence-validator checks; no source collection or privilege changes."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import check_endpoint_identity_gate as gate


def marker(payload, test):
    return {"Package": gate.PACKAGE, "Action": "output", "Test": test,
            "Output": "    complete_mvp_process_test.go:123: " + payload + "\n"}


def valid_events():
    events = []
    fixed = {v: k for k, v in gate.FIXED.items()}
    for profile in ("tls", "http-test"):
        test = gate.ROOT + "/" + profile
        for stage in gate.ORDER:
            payload = fixed.get(stage)
            if payload is None:
                payload = ("endpoint identity observation: stage=" + stage
                           + " hostname=complete interfaces=complete countExact=true observedRows=2"
                           + " addresses=complete countExact=true ipv4Rows=1 ipv6Rows=0 assignedRows=1")
            events.append(marker(payload, test))
        events.append({"Package": gate.PACKAGE, "Test": test, "Action": "pass"})
    events.append({"Package": gate.PACKAGE, "Test": gate.ROOT, "Action": "pass"})
    events.append({"Package": gate.PACKAGE, "Action": "pass"})
    return events


class CompletionTests(unittest.TestCase):
    def test_exact_two_profile_contract(self):
        self.assertIsNone(gate.validate(valid_events()))

    def test_each_required_event_is_required(self):
        events = valid_events()
        for index in range(len(events)):
            with self.subTest(index=index), self.assertRaises(ValueError):
                gate.validate(events[:index] + events[index + 1:])

    def test_duplicates_and_reordering_reject(self):
        events = valid_events()
        for index in range(len(events)):
            with self.subTest(index=index), self.assertRaises(ValueError):
                gate.validate(events[:index] + [events[index]] + events[index:])
        changed = copy.deepcopy(events)
        changed[0], changed[1] = changed[1], changed[0]
        with self.assertRaises(ValueError): gate.validate(changed)
        with self.assertRaises(ValueError): gate.validate([events[-2]] + events[:-2] + [events[-1]])

    def test_failure_skip_and_wrong_scope_reject(self):
        for index in (6, 13, 14, 15):
            for field, value in (("Action", "fail"), ("Action", "skip"), ("Package", "other"), ("Test", "other")):
                changed = valid_events(); changed[index][field] = value
                with self.subTest(index=index, field=field, value=value), self.assertRaises(ValueError):
                    gate.validate(changed)
        for field, value in (("Package", "other"), ("Test", gate.ROOT), ("Test", gate.ROOT + "/tls/other"), ("Action", "pass")):
            changed = valid_events(); changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): gate.validate(changed)
        with self.assertRaises(ValueError): gate.validate(valid_events() + [{"Action": "build-fail"}])

    def test_evidence_is_exact_and_positive(self):
        for old, new in (("observedRows=2", "observedRows=0"), ("observedRows=2", "observedRows=33"),
                         ("ipv4Rows=1", "ipv4Rows=129"), ("ipv6Rows=0", "ipv6Rows=129"),
                         ("assignedRows=1", "assignedRows=0"), ("assignedRows=1", "assignedRows=129"),
                         ("assignedRows=1", "assignedRows=2"), ("observedRows=2", "observedRows=02"),
                         ("hostname=complete", "hostname=failed"), ("interfaces=complete", "interfaces=failed"),
                         ("addresses=complete", "addresses=failed"), ("countExact=true", "countExact=false")):
            changed = valid_events(); changed[2]["Output"] = changed[2]["Output"].replace(old, new)
            with self.subTest(old=old, new=new), self.assertRaises(ValueError): gate.validate(changed)
        for replacement in ("private.go", "complete_mvp_endpoint_test.go"):
            changed = valid_events(); changed[0]["Output"] = changed[0]["Output"].replace("complete_mvp_process_test.go", replacement)
            with self.assertRaises(ValueError): gate.validate(changed)
        for extra in (" private-fixture", "\nprivate-fixture"):
            changed = valid_events(); changed[0]["Output"] = changed[0]["Output"].rstrip("\n") + extra + "\n"
            with self.assertRaises(ValueError): gate.validate(changed)

    def test_bounds_and_fixed_output(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "input.jsonl"
            p.write_text("".join(json.dumps(v) + "\n" for v in valid_events()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output): code = gate.main(["gate", str(p)])
            self.assertEqual(code, 0); self.assertNotIn("observedRows", output.getvalue())
            for raw in (b"", b"private-fixture\n", b"[]\n", b'{"Action":"pass","Action":"fail"}\n',
                        b'{"value":NaN}\n', b'x' * (gate.MAX_LINE + 1) + b'\n',
                        json.dumps(valid_events()[0]).encode()):
                p.write_bytes(raw); output = io.StringIO()
                with contextlib.redirect_stdout(output): code = gate.main(["gate", str(p)])
                self.assertEqual(code, 1); self.assertEqual(output.getvalue(), "FAIL: missing, skipped, malformed or incomplete endpoint-identity native evidence.\n")
            with p.open("wb") as stream: stream.truncate(gate.MAX_FILE + 1)
            with self.assertRaises(ValueError): list(gate.read_events(p))

    def test_special_files_reject_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "input.jsonl"; p.write_text('{}\n')
            link = Path(temp) / "link"; link.symlink_to(p)
            fifo = Path(temp) / "fifo"; os.mkfifo(fifo)
            for target in (link, fifo, Path(temp)):
                with self.assertRaises((ValueError, OSError)): list(gate.read_events(target))


if __name__ == "__main__":
    unittest.main()
