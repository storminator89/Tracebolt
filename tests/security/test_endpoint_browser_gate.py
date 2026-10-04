"""Inert completeness/privacy checks for the fixed endpoint browser report."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_endpoint_browser_gate as gate

SHA = "a" * 40


def valid_report():
    value = {key: False for key in gate.FLAGS}
    value.update({key: "Synthetic fixture" for key in gate.TEXT})
    value.update(sourceSha=SHA, runtimeErrorCount=0,
                 summary={"passed": 6, "failed": 0, "setupFailure": False},
                 results=[{"name": name, "status": "PASS", "durationMs": 1} for name in sorted(gate.CASES)])
    return value


class BrowserEvidenceTests(unittest.TestCase):
    def test_exact_complete_report(self):
        self.assertIsNone(gate.validate(valid_report(), SHA))

    def test_each_field_required_and_unknown_fields_rejected(self):
        for key in gate.KEYS:
            value = valid_report(); del value[key]
            with self.subTest(key=key), self.assertRaises(ValueError): gate.validate(value, SHA)
        for target in ("root", "summary", "result"):
            value = valid_report()
            part = value if target == "root" else value["summary"] if target == "summary" else value["results"][0]
            part["private"] = "private-fixture"
            with self.subTest(target=target), self.assertRaises(ValueError): gate.validate(value, SHA)

    def test_identity_flags_counts_and_setup(self):
        for expected in (None, "", "B" * 40, "b" * 40, "a" * 39):
            with self.subTest(expected=expected), self.assertRaises(ValueError): gate.validate(valid_report(), expected)
        for key in gate.FLAGS:
            for wrong in (True, 0, None, "false"):
                value = valid_report(); value[key] = wrong
                with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError): gate.validate(value, SHA)
        for key, wrong in (("passed", 5), ("passed", 7), ("passed", 6.0), ("failed", 1),
                           ("failed", False), ("setupFailure", True), ("setupFailure", 0)):
            value = valid_report(); value["summary"][key] = wrong
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError): gate.validate(value, SHA)
        for wrong in (1, False, "0", 0.0):
            value = valid_report(); value["runtimeErrorCount"] = wrong
            with self.assertRaises(ValueError): gate.validate(value, SHA)

    def test_exact_case_set_status_and_duration(self):
        for index in range(6):
            value = valid_report(); del value["results"][index]
            with self.assertRaises(ValueError): gate.validate(value, SHA)
            for field, wrong in (("name", "unknown"), ("name", []), ("status", "SKIPPED"),
                                 ("status", "FAIL"), ("durationMs", -1), ("durationMs", 600001),
                                 ("durationMs", True), ("durationMs", 1.5)):
                value = valid_report(); value["results"][index][field] = wrong
                with self.subTest(index=index, field=field), self.assertRaises(ValueError): gate.validate(value, SHA)
        value = valid_report(); value["results"][1] = copy.deepcopy(value["results"][0])
        with self.assertRaises(ValueError): gate.validate(value, SHA)

    def test_bound_reader_and_fixed_cli_messages(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "report.json"; p.write_text(json.dumps(valid_report()))
            self.assertEqual(gate.read_report(p), valid_report())
            with patch.dict(os.environ, {"TRACEBOLT_SOURCE_SHA": SHA}):
                out = io.StringIO()
                with contextlib.redirect_stdout(out): code = gate.main(["gate", str(p)])
                self.assertEqual(code, 0); self.assertNotIn(SHA, out.getvalue())
                for raw in (b"", b"private-fixture", b'{"x":1,"x":2}', b'{"x":Infinity}', b'x' * (gate.MAX_BYTES + 1)):
                    p.write_bytes(raw); out = io.StringIO()
                    with contextlib.redirect_stdout(out): code = gate.main(["gate", str(p)])
                    self.assertEqual(code, 1); self.assertEqual(out.getvalue(), "FAIL: missing, partial, mismatched or unsafe endpoint-browser evidence.\n")

    def test_special_files_reject_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "report.json"; p.write_text('{}')
            link = Path(temp) / "link"; link.symlink_to(p)
            fifo = Path(temp) / "fifo"; os.mkfifo(fifo)
            for target in (link, fifo, Path(temp)):
                with self.assertRaises((ValueError, OSError)): gate.read_report(target)


if __name__ == "__main__":
    unittest.main()
