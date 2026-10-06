"""Inert evidence-gate checks; no host identities, grants or setup are changed."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import check_action_setup_identity_gate as gate


def event(action, test=None, **fields):
    value = {"Action": action, "Package": gate.PACKAGE, **fields}
    if test is not None:
        value["Test"] = test
    return value


def complete():
    records = [event("start")]
    for root in (gate.COMPLETE, gate.MISSING, gate.LOCKED):
        records.append(event("run", root))
        leaves = sorted(name for name in gate.EVIDENCE if name.startswith(root + "/"))
        for leaf in leaves or [root]:
            if leaf != root:
                records.append(event("run", leaf))
            records.append(event("output", leaf, Output="    action_setup_linux_test.go:99: "
                                 "action setup identity: public_reader=" + gate.EVIDENCE[leaf] + "\n"))
            if leaf != root:
                records.append(event("pass", leaf))
        records.append(event("pass", root))
    records.append(event("pass"))
    return records


def encode(records):
    return b"".join(json.dumps(record).encode() + b"\n" for record in records)


class GateTests(unittest.TestCase):
    def test_requires_every_pass_and_actual_public_reader_marker(self):
        records = complete()
        gate.validate(encode(records))
        for index, record in enumerate(records):
            if record["Action"] in {"run", "pass", "output"}:
                with self.subTest(index=index), self.assertRaises(ValueError):
                    gate.validate(encode(records[:index] + records[index + 1:]))

    def test_rejects_skip_failure_duplicate_and_wrong_package(self):
        for index, record in enumerate(complete()):
            for action in ("skip", "fail", "build-fail"):
                records = complete()
                records[index] = {**record, "Action": action}
                with self.subTest(index=index, action=action), self.assertRaises(ValueError):
                    gate.validate(encode(records))
            records = complete()
            records[index] = {**record, "Package": "localrmm/other"}
            with self.assertRaises(ValueError):
                gate.validate(encode(records))
            if record["Action"] != "start":
                records = complete()
                records.insert(index, record)
                with self.assertRaises(ValueError):
                    gate.validate(encode(records))

    def test_rejects_marker_for_wrong_test_kind_and_order(self):
        for payload in ("accepted", "state_rejected", "accepted invented-private-value"):
            records = complete()
            for record in records:
                if record["Action"] == "output":
                    record["Output"] = "    action_setup_linux_test.go:99: action setup identity: public_reader=" + payload + "\n"
            with self.assertRaises(ValueError):
                gate.validate(encode(records))
        records = complete()
        records[1], records[3] = records[3], records[1]
        with self.assertRaises(ValueError):
            gate.validate(encode(records))

    def test_rejects_malformed_truncated_and_unbounded_input(self):
        for raw in (b"", b"{}\n", b"[]\n", b"not-json\n", encode(complete())[:-1],
                    b'{"Action":"start","Action":"pass"}\n',
                    b'{"Action":"pass","Elapsed":NaN}\n',
                    b" " * (gate.MAX_LINE + 1) + b"\n",
                    b" " * (gate.MAX_FILE + 1)):
            with self.assertRaises(ValueError):
                gate.validate(raw)

    def test_private_cli_emits_only_fixed_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(encode(complete()))
            path.chmod(0o600)
            for mode, expected in ((0o600, 0), (0o644, 1)):
                path.chmod(mode)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(gate.main(["gate", str(path)]), expected)
                self.assertNotIn(str(path), output.getvalue())
            path.chmod(0o600)
            path.write_bytes(b"invented-private-value\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(gate.main(["gate", str(path)]), 1)
            self.assertNotIn("invented-private-value", output.getvalue())


if __name__ == "__main__":
    unittest.main()
