"""Inert privacy/bounds checks; no host collection, network or installer."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import report_complete_mvp as reporter


def event(payload, test=None):
    return {"Package": reporter.PACKAGE, "Action": "output", "Test": test or reporter.ROOT + "/tls", "Output": "    complete_mvp_process_test.go:123: " + payload + "\n"}


class ProjectionTests(unittest.TestCase):
    def test_all_fixed_categories_for_all_three_exact_tests(self):
        for test, profile in reporter.PROFILES.items():
            for payload, fixed in reporter.FAILURES.items():
                with self.subTest(profile=profile, category=fixed["category"]):
                    self.assertEqual(reporter.project(event(payload, test)), {"profile": profile, "stage": fixed["stage"], "category": fixed["category"]})

    def test_status_projects_enums_only(self):
        payload = "native report: sequence=123 systemSequence=456 packageStatus=failure_acknowledged servicesCoverage=failed servicesReason=invalid_source socketsCoverage=complete socketsReason=none"
        value = reporter.project(event(payload))
        self.assertEqual(value, {"profile": "tls", "stage": "observation", "category": "native_report", "packageStatus": "failure_acknowledged", "servicesCoverage": "failed", "servicesReason": "invalid_source", "socketsCoverage": "complete", "socketsReason": "none"})
        self.assertNotIn("123", json.dumps(value)); self.assertNotIn("456", json.dumps(value))
        self.assertEqual(reporter.project(event("native complete package attempt: failure=source_invalid; no complete package count claimed"))["reason"], "source_invalid")

    def test_exact_scope_and_full_source_line_only(self):
        good = event("complete_positive_package_required")
        for key, value in [("Package", "other"), ("Action", "pass"), ("Test", reporter.ROOT + "/tls/extra"), ("Test", []), ("Output", "prefix" + good["Output"]), ("Output", good["Output"] + "private-fixture\n"), ("Output", good["Output"].replace("complete_mvp_process_test.go", "private.go")), ("Output", good["Output"].replace(":123:", ":0:")), ("Output", good["Output"].rstrip("\n"))]:
            changed = dict(good); changed[key] = value
            with self.subTest(key=key, value=value): self.assertIsNone(reporter.project(changed))

    def test_unknowns_and_extra_fields_never_echo(self):
        value = event("complete_positive_package_required private-fixture-secret")
        value["private"] = "private-fixture-secret"
        projected = reporter.project(value)
        self.assertEqual(projected, {"profile": "tls", "stage": "unclassified", "category": "unclassified"})
        self.assertNotIn("private-fixture-secret", json.dumps(projected))
        self.assertEqual(reporter.project(event("native complete package attempt: failure=private-fixture; no complete package count claimed"))["category"], "unclassified")

    def test_reader_bounds_json_and_projection_cap(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "input.jsonl"
            p.write_text((json.dumps(event("complete_positive_services_required")) + "\n") * 100)
            self.assertEqual(len(reporter.read_markers(p)), 64)
            for raw in [b"", b"not json\n", b'[]\n', b'{"Action":"output","Action":"pass"}\n', b'{"x":NaN}\n', json.dumps(event("complete_positive_services_required")).encode(), b'x' * (reporter.MAX_LINE + 1) + b'\n']:
                p.write_bytes(raw)
                with self.assertRaises((ValueError, json.JSONDecodeError)): reporter.read_markers(p)
            with p.open("wb") as stream: stream.truncate(reporter.MAX_FILE + 1)
            with self.assertRaises(ValueError): reporter.read_markers(p)

    def test_symlink_fifo_and_directory_reject_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "input.jsonl"; p.write_text(json.dumps(event("complete_positive_services_required")) + "\n")
            link = Path(temp) / "link"; link.symlink_to(p)
            fifo = Path(temp) / "fifo"; os.mkfifo(fifo)
            for target in [link, fifo, Path(temp)]:
                with self.assertRaises((OSError, ValueError)): reporter.read_markers(target)

    def test_cli_errors_are_fixed_and_success_is_only_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "input.jsonl"; p.write_text(json.dumps(event("private-fixture-secret")) + "\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out): code = reporter.main(["reporter", str(p)])
            self.assertEqual(code, 0); self.assertNotIn("private-fixture-secret", out.getvalue()); self.assertIn('"category":"unclassified"', out.getvalue())
            p.write_text("private-fixture-secret")
            out = io.StringIO()
            with contextlib.redirect_stdout(out): code = reporter.main(["reporter", str(p)])
            self.assertEqual(code, 1); self.assertEqual(out.getvalue(), 'V3_NATIVE_DIAGNOSTIC {"category":"unavailable","profile":"unknown","stage":"diagnostic"}\n')


if __name__ == "__main__":
    unittest.main()
