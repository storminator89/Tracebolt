"""Inert tests for fail-closed service-action browser artifact admission."""
import contextlib
import copy
import io
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_service_action_browser_gate as gate

SHA = 'a' * 40


def valid_report():
    return {
        'schemaVersion': 'tracebolt.service-action-browser.v1', 'sourceSha': SHA,
        'createdAt': '2026-10-05T19:00:00.000Z', 'transportProfile': 'disposable-http-test',
        'fixture': gate.FIXTURE,
        'scope': {**{key: True for key in gate.TRUE_FLAGS}, **{key: False for key in gate.FALSE_FLAGS}},
        'runtimeErrorCount': 0,
        'results': [{'name': name, 'status': 'PASS', 'durationMs': 1} for name in sorted(gate.CASES)],
        'summary': {'passed': 4, 'failed': 0, 'setupFailure': False},
    }


class ServiceActionBrowserEvidenceTests(unittest.TestCase):
    def test_exact_complete_report(self):
        self.assertEqual(len(gate.CASES), 4)
        self.assertIsNone(gate.validate(valid_report(), SHA))

    def test_browser_declares_the_same_exact_cases_and_fixture_scope(self):
        script = (Path(__file__).resolve().parents[1] / 'e2e-review' / 'service-action-browser.mjs').read_text()
        cases = re.search(r'const names=\[\n(.*?)\n\];', script, re.DOTALL)
        self.assertIsNotNone(cases)
        declared = re.findall(r"^ '([^']+)',$", cases.group(1), re.MULTILINE)
        self.assertEqual(len(declared), len(gate.CASES))
        self.assertEqual(set(declared), gate.CASES)
        self.assertIn("const fixture='" + gate.FIXTURE + "';", script)
        scope = re.search(r'const scope=\{\n(.*?)\n\};', script, re.DOTALL)
        self.assertIsNotNone(scope)
        self.assertEqual(dict(re.findall(r'([A-Za-z]+):(true|false)', scope.group(1))),
                         {**{key: 'true' for key in gate.TRUE_FLAGS}, **{key: 'false' for key in gate.FALSE_FLAGS}})

    def test_every_field_required_and_unknown_fields_rejected(self):
        for section in ('root', 'scope', 'summary', 'result'):
            def part(value):
                return value if section == 'root' else value['results'][0] if section == 'result' else value[section]
            for key in list(part(valid_report())):
                value = valid_report(); del part(value)[key]
                with self.subTest(section=section, key=key), self.assertRaises(ValueError): gate.validate(value, SHA)
            value = valid_report(); part(value)['private'] = 'private-fixture'
            with self.subTest(section=section), self.assertRaises(ValueError): gate.validate(value, SHA)

    def test_source_and_fixed_disclosure(self):
        for expected in (None, '', 'A' * 40, 'b' * 40, 'a' * 39, True):
            with self.subTest(expected=expected), self.assertRaises(ValueError): gate.validate(valid_report(), expected)
        for field in ('schemaVersion', 'sourceSha', 'transportProfile', 'fixture'):
            for wrong in (None, '', True, 'private-fixture', 'https://private.invalid/secret'):
                value = valid_report(); value[field] = wrong
                with self.subTest(field=field, wrong=wrong), self.assertRaises(ValueError): gate.validate(value, SHA)
        for wrong in ('2026-02-30T19:00:00.000Z', '2026-10-05', 'private-fixture', None, 1):
            value = valid_report(); value['createdAt'] = wrong
            with self.assertRaises(ValueError): gate.validate(value, SHA)

    def test_safety_flags_runtime_and_summary(self):
        for key in gate.TRUE_FLAGS | gate.FALSE_FLAGS:
            for wrong in (None, 0, 1, 'false', key not in gate.TRUE_FLAGS):
                value = valid_report(); value['scope'][key] = wrong
                with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError): gate.validate(value, SHA)
        for wrong in (1, False, 0.0, '0'):
            value = valid_report(); value['runtimeErrorCount'] = wrong
            with self.assertRaises(ValueError): gate.validate(value, SHA)
        for key, wrong in (('passed', 3), ('passed', 5), ('passed', 4.0), ('failed', 1), ('failed', False), ('setupFailure', True), ('setupFailure', 0)):
            value = valid_report(); value['summary'][key] = wrong
            with self.subTest(key=key), self.assertRaises(ValueError): gate.validate(value, SHA)

    def test_each_exact_case_required_without_duplicates_or_failures(self):
        for index in range(len(gate.CASES)):
            value = valid_report(); del value['results'][index]
            with self.assertRaises(ValueError): gate.validate(value, SHA)
            for field, wrong in (('name', 'unknown'), ('name', []), ('status', 'SKIP'), ('status', 'FAIL'), ('durationMs', -1), ('durationMs', 600001), ('durationMs', True), ('durationMs', 1.5)):
                value = valid_report(); value['results'][index][field] = wrong
                with self.subTest(index=index, field=field), self.assertRaises(ValueError): gate.validate(value, SHA)
        value = valid_report(); value['results'][1] = copy.deepcopy(value['results'][0])
        with self.assertRaises(ValueError): gate.validate(value, SHA)

    def test_bounded_reader_rejects_duplicate_keys_nonfinite_and_unsafe_input(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'report.json'; target.write_text(json.dumps(valid_report()))
            self.assertEqual(gate.read_report(target), valid_report())
            with patch.dict(os.environ, {'TRACEBOLT_SOURCE_SHA': SHA}):
                out = io.StringIO()
                with contextlib.redirect_stdout(out): code = gate.main(['gate', str(target)])
                self.assertEqual(code, 0); self.assertNotIn(SHA, out.getvalue())
                for raw in (b'', b'private-fixture', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'x' * (gate.MAX_BYTES + 1)):
                    target.write_bytes(raw); out = io.StringIO()
                    with contextlib.redirect_stdout(out): code = gate.main(['gate', str(target)])
                    self.assertEqual(code, 1)
                    self.assertEqual(out.getvalue(), 'FAIL: missing, partial, mismatched or unsafe service-action browser evidence.\n')
                target.unlink(); out = io.StringIO()
                with contextlib.redirect_stdout(out): code = gate.main(['gate', str(target)])
                self.assertEqual(code, 1)

    def test_special_files_reject_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'report.json'; target.write_text('{}')
            link = Path(temp) / 'link'; link.symlink_to(target)
            fifo = Path(temp) / 'fifo'; os.mkfifo(fifo)
            for path in (link, fifo, Path(temp)):
                with self.assertRaises((ValueError, OSError)): gate.read_report(path)


if __name__ == '__main__':
    unittest.main()
