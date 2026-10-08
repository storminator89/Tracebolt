import contextlib
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("public_probe", Path(__file__).with_name("run_public_conpty_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def records(unknown=False):
    summary = " ".join(name + "=" + ("true" if name in {"unknown", "win32_input_enable"} and unknown else "false") for name in probe.FIELDS)
    return [
        {"Action": "start", "Package": probe.PACKAGE},
        {"Action": "run", "Package": probe.PACKAGE, "Test": probe.TEST},
        {"Action": "output", "Package": probe.PACKAGE, "Test": probe.TEST,
         "Output": "    native_windows_test.go:38: " + summary + " first_residual_kind=none " + " ".join(name + "=false" for name in probe.TEXT_FIELDS) + "\n"},
        {"Action": "output", "Package": probe.PACKAGE, "Test": probe.TEST,
         "Output": "    native_windows_test.go:50: " + " ".join(name+"="+("true" if name=="conout_console" else "false") for name in probe.DESTINATION_FIELDS) + " conout_first_residual_kind=none\n"},
        {"Action": "output", "Package": probe.PACKAGE, "Test": probe.TEST,
         "Output": "    native_windows_test.go:60: " + " ".join(name + "=true" for name in probe.PREINPUT_FIELDS) +
         ' preinput_rejection=none preinput_first_csi=none preinput_csi_final=none preinput_csi_params=""\n'},
        {"Action": "pass", "Package": probe.PACKAGE, "Test": probe.TEST},
        {"Action": "pass", "Package": probe.PACKAGE},
    ]


def failure_records(reason="child_exit"):
    rows = records()
    del rows[3:5]
    rows[2]["Output"] = "    native_windows_test.go:41: " + reason + "\n"
    rows[3]["Action"] = rows[4]["Action"] = "fail"
    return rows


def preinput_failure_records(reason="preinput_guard_rejected", **values):
    rows = records()
    if reason == "preinput_guard_rejected":
        values = dict(preinput_prompt_ready=False, preinput_no_rejection=False,
                      preinput_rejection="csi_unsupported", preinput_first_csi="cursor_blink_enable") | values
    else:
        values = dict(preinput_prompt_ready=False) | values
    set_preinput(rows, **values)
    rows.insert(5, dict(rows[4], Output="    native_windows_test.go:61: " + reason + "\n"))
    rows[-2]["Action"] = rows[-1]["Action"] = "fail"
    return rows


def set_preinput(rows, **values):
    for name, value in values.items():
        value = str(value).lower() if type(value) is bool else value
        if name == "preinput_csi_params":
            value = '"' + value + '"'
        rows[4]["Output"], count = re.subn(preinput_field_pattern(name), lambda _: name + "=" + value, rows[4]["Output"])
        assert count == 1


def preinput_field_pattern(name):
    return r"\b" + re.escape(name) + r'=(?:"[^"]*"|[^\s]+)'


def encode(rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


class PublicProbeTests(unittest.TestCase):
    def test_preinput_vocabularies_match_source(self):
        source = (probe.ROOT / "internal/windowsacceptance/freshgate/output_rejection.go").read_text()
        self.assertEqual(set(re.findall(r'OutputRejection = "([a-z_]+)"', source)), set(probe.OUTPUT_REJECTIONS))
        source = (probe.ROOT / "internal/conptyrendering/preinput_fixture_test.go").read_text()
        signature = re.search(r"func publicCSISignature\([^\n]+\n.*?\n\}", source, re.DOTALL)
        self.assertIsNotNone(signature)
        self.assertEqual(set(re.findall(r'return "([a-z_]+)"', signature.group())) | {"none"}, set(probe.FIRST_CSI_KINDS))
        source = (probe.ROOT / "internal/conptyrendering/native_windows_test.go").read_text()
        shape = " ".join(name + "=%t" for name in probe.PREINPUT_FIELDS)
        self.assertIn(shape + " preinput_rejection=%s preinput_first_csi=%s preinput_csi_final=%s preinput_csi_params=%q", source)

    def test_preinput_requires_one_exact_finite_record(self):
        rows = records()
        del rows[4]
        with self.assertRaises(probe.ProbeFailure) as caught:
            probe.project(encode(rows))
        self.assertEqual(caught.exception.reason, "projection_preinput_missing")
        body = records()[4]["Output"]
        malformed = [body + body, body.rstrip("\n") + " preinput_live_output=true\n",
                     body.replace("\n", "\r\n"), body.rstrip("\n") + " PRIVATE_SENTINEL\n",
                     body.replace("preinput_rejection=none", "preinput_rejection=none extra=PRIVATE_SENTINEL"),
                     body.replace("preinput_live_output=true preinput_public_trust=true",
                                  "preinput_public_trust=true preinput_live_output=true")]
        for name in probe.PREINPUT_FIELDS + ("preinput_rejection", "preinput_first_csi", "preinput_csi_final", "preinput_csi_params"):
            malformed.append(re.sub(preinput_field_pattern(name) + " ?", "", body))
            for value in ("PRIVATE_SENTINEL", "1", "TRUE", "", "none\x1b[31m"):
                malformed.append(re.sub(preinput_field_pattern(name), lambda _: name + "=" + value, body))
        for other in (records()[2]["Output"], records()[3]["Output"]):
            malformed += [other.rstrip("\n") + " " + body, body.rstrip("\n") + " " + other]
        for text in malformed:
            with self.subTest(text=text):
                rows = records()
                rows[4]["Output"] = text
                with self.assertRaises(probe.ProbeFailure):
                    probe.project(encode(rows))
        rows = records()
        rows.insert(5, rows[4])
        with self.assertRaises(probe.ProbeFailure) as caught:
            probe.project(encode(rows))
        self.assertEqual(caught.exception.reason, "projection_preinput_duplicate")

    def test_preinput_pass_requires_every_success_boolean(self):
        summary = probe.project(encode(records()))
        self.assertTrue(all(summary[name] for name in probe.PREINPUT_FIELDS))
        self.assertEqual(summary["preinput_rejection"], "none")
        self.assertEqual(summary["preinput_first_csi"], "none")
        self.assertEqual(summary["preinput_csi_final"], "none")
        self.assertEqual(summary["preinput_csi_params"], "")
        for name in probe.PREINPUT_FIELDS:
            rows = records()
            set_preinput(rows, **{name: False})
            with self.subTest(field=name), self.assertRaises(probe.ProbeFailure):
                probe.project(encode(rows))
        for rejection in probe.OUTPUT_REJECTIONS[1:]:
            rows = records()
            set_preinput(rows, preinput_no_rejection=False, preinput_rejection=rejection)
            with self.subTest(rejection=rejection), self.assertRaises(probe.ProbeFailure):
                probe.project(encode(rows))
        for kind in probe.FIRST_CSI_KINDS[1:]:
            rows = records()
            set_preinput(rows, preinput_first_csi=kind)
            with self.subTest(kind=kind), self.assertRaises(probe.ProbeFailure):
                probe.project(encode(rows))

    def test_preinput_csi_descriptor_accepts_exact_closed_values(self):
        self.assertEqual(probe.CSI_FINALS, ("none",) + tuple(format(value, "02x") for value in range(0x40, 0x7f)))
        for final in probe.CSI_FINALS[1:]:
            for params in ("", " ", "?12", "0123456789;:? ", " ?0:1;23 ", ("0123456789;:? " * 5)[:64]):
                rows = preinput_failure_records(preinput_first_csi="other", preinput_csi_final=final,
                                               preinput_csi_params=params)
                with self.subTest(final=final, params=params):
                    value = probe.failed_preinput_record(encode(rows), "preinput_guard_rejected")
                    self.assertIsNotNone(value)
                    self.assertEqual(value["preinput_csi_final"], final)
                    self.assertEqual(value["preinput_csi_params"], params)
                    self.assertTrue(probe.format_preinput(value).endswith(
                        ' preinput_csi_final=' + final + ' preinput_csi_params="' + params + '"'))
        # Test builders must replace the whole quoted field, including spaces.
        rows = preinput_failure_records(preinput_csi_final="71", preinput_csi_params="1 ")
        set_preinput(rows, preinput_csi_params=" 2 ")
        value = probe.failed_preinput_record(encode(rows), "preinput_guard_rejected")
        self.assertEqual(value["preinput_csi_params"], " 2 ")

    def test_preinput_csi_descriptor_rejects_every_forbidden_ascii_character(self):
        allowed = set("0123456789;:? ")
        forbidden = [chr(value) for value in range(128) if chr(value) not in allowed]
        forbidden += ["é", "０", "١", "\u00a0", "\u2028", "\U0001f512"]
        for char in forbidden:
            with self.subTest(char=repr(char)):
                rows = preinput_failure_records(preinput_first_csi="other", preinput_csi_final="7e",
                                               preinput_csi_params="1" + char + "2")
                self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))

    def test_preinput_csi_descriptor_bounds_and_quoting_fail_closed(self):
        for size in (0, 1, 63, 64, 65):
            rows = preinput_failure_records(preinput_csi_final="71", preinput_csi_params=" " * size)
            with self.subTest(size=size):
                value = probe.failed_preinput_record(encode(rows), "preinput_guard_rejected")
                if size <= 64:
                    self.assertEqual(value["preinput_csi_params"], " " * size)
                else:
                    self.assertIsNone(value)
        invalid_finals = [format(value, "02x") for value in range(256) if not 0x40 <= value <= 0x7e]
        invalid_finals += [final.upper() for final in probe.CSI_FINALS[1:] if final.upper() != final]
        invalid_finals += ["NONE", "None", "", "4", "040", "0x40", "40 ", " 40", "7e;", "PRIVATE_SENTINEL"]
        for final in invalid_finals:
            with self.subTest(final=final):
                rows = preinput_failure_records(preinput_csi_final=final)
                self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))
        for encoded in ('', '12', "'12'", '"12', '12"', '"12" ', ' "12"', '"12" extra=0',
                        '"12"""', r'"\x31"', r'"\u0031"', r'"\061"', r'"1\ 2"', '"1\t2"'):
            rows = preinput_failure_records(preinput_csi_final="71")
            rows[4]["Output"] = rows[4]["Output"].replace('preinput_csi_params=""', "preinput_csi_params=" + encoded)
            with self.subTest(encoded=encoded):
                self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))

    def test_preinput_csi_descriptor_requires_its_own_actual_guard_rejection(self):
        for params in ("1", " ", "?12"):
            rows = preinput_failure_records(preinput_csi_final="none", preinput_csi_params=params)
            self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))
        for rejection in probe.OUTPUT_REJECTIONS:
            if rejection == "csi_unsupported":
                continue
            rows = preinput_failure_records(preinput_rejection=rejection,
                                           preinput_no_rejection=(rejection == "none"),
                                           preinput_first_csi="none", preinput_csi_final="68", preinput_csi_params="?12")
            with self.subTest(rejection=rejection):
                self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))
        rows = preinput_failure_records(preinput_first_csi="none", preinput_csi_final="68", preinput_csi_params="?12")
        self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))
        for reason in probe.NATIVE_FAILURES - {"preinput_guard_rejected"}:
            rows = preinput_failure_records(reason, preinput_no_rejection=False, preinput_rejection="csi_unsupported",
                                           preinput_first_csi="other", preinput_csi_final="7e", preinput_csi_params="?12")
            self.assertIsNone(probe.failed_preinput_record(encode(rows), reason))
        for values in (dict(preinput_csi_final="68", preinput_csi_params="?12"),
                       dict(preinput_csi_final="none", preinput_csi_params=" ")):
            rows = records()
            set_preinput(rows, **values)
            with self.assertRaises(probe.ProbeFailure):
                probe.project(encode(rows))

    def test_preinput_csi_descriptor_cannot_be_borrowed_from_another_record(self):
        original = preinput_failure_records(preinput_first_csi="other", preinput_csi_final="7e", preinput_csi_params=" ?0:1 ")
        text = original[4]["Output"]
        for key, value in (("Package", "Other"), ("Test", "Other"), ("Test", None),
                           ("Action", "skip"), ("OutputType", "frame")):
            rows = [dict(row) for row in original]
            rows[4][key] = value
            self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))
        body, descriptor = text.split(" preinput_csi_final=", 1)
        for detached in (" preinput_csi_final=" + descriptor, "PRIVATE_SENTINEL preinput_csi_final=" + descriptor):
            rows = [dict(row) for row in original]
            rows[4:5] = [dict(rows[4], Output=body + "\n"), dict(rows[4], Output=detached)]
            self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))
        for index in (2, 3, 4, 5):
            rows = [dict(row) for row in original]
            rows.insert(index, dict(rows[4], Output=text.replace('" ?0:1 "', '"?12"')))
            self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))

    def test_preinput_csi_private_path_title_and_escaped_payloads_are_not_exported(self):
        private_values = ("PRIVATE_SENTINEL", "C:\\PRIVATE_SENTINEL\\file", "/home/PRIVATE_SENTINEL",
                          "\x1b]0;PRIVATE_SENTINEL\x07", '" PRIVATE_SENTINEL "', r"\x31", r"\u0031")
        for private in private_values:
            rows = preinput_failure_records(preinput_csi_final="7e", preinput_first_csi="other", preinput_csi_params=private)
            process = mock.Mock(stdout=io.BytesIO(encode(rows)))
            process.wait.return_value = 1
            output = io.StringIO()
            with mock.patch.object(probe.sys, "platform", "win32"), mock.patch.object(probe.subprocess, "Popen", return_value=process), contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(), 1)
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertIn("reason=preinput_guard_rejected;", output.getvalue())
            self.assertNotIn("preinput_csi_final=", output.getvalue())
            self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
            self.assertNotIn(private, output.getvalue())

    def test_preinput_fragments_and_private_prefixes_are_safely_projected(self):
        for failure_reason in (None, "preinput_guard_rejected", "preinput_prompt_missing"):
            original = records() if failure_reason is None else preinput_failure_records(failure_reason)
            if failure_reason == "preinput_guard_rejected":
                set_preinput(original, preinput_first_csi="other", preinput_csi_final="7e", preinput_csi_params=" ?0:1;23 ")
            project = probe.project if failure_reason is None else lambda raw: probe.failed_preinput_record(raw, failure_reason)
            expected = project(encode(original))
            self.assertIsNotNone(expected)
            body = original[4]["Output"].split("preinput_live_output=", 1)[1]
            for prefix in ("", "    native_windows_test.go:60: ", "C:\\PRIVATE_SENTINEL\\fixture.go:8: ",
                           "PRIVATE_SENTINEL\nPRIVATE_SENTINEL "):
                text = prefix + "preinput_live_output=" + body
                for split in range(len(text) + 1):
                    rows = original[:4] + [dict(original[4], Output=text[:split]),
                                          dict(original[4], Output=text[split:])] + original[5:]
                    self.assertEqual(project(encode(rows)), expected)
                rows = original[:4] + [dict(original[4], Output=c) for c in text] + original[5:]
                self.assertEqual(project(encode(rows)), expected)

    def test_preinput_fragments_never_cross_context_boundaries(self):
        for failure_reason in (None, "preinput_guard_rejected"):
            original = records() if failure_reason is None else preinput_failure_records(failure_reason)
            if failure_reason:
                set_preinput(original, preinput_csi_final="68", preinput_csi_params="?12")
            text = original[4]["Output"]
            boundaries = [dict(Action="output", Package=probe.PACKAGE, Output="PRIVATE_SENTINEL\n"),
                          dict(Action="output", Package=probe.PACKAGE, Test=probe.TEST, OutputType="frame", Output="PRIVATE_SENTINEL\n"),
                          dict(Action="output", Package=probe.PACKAGE, Test="Other", Output="PRIVATE_SENTINEL\n"),
                          dict(Action="fail" if failure_reason else "pass", Package=probe.PACKAGE, Test=probe.TEST)]
            for boundary in boundaries:
                for split in (50, text.index('preinput_csi_params="') + len('preinput_csi_params="')):
                    rows = original[:4] + [dict(original[4], Output=text[:split]), boundary,
                                          dict(original[4], Output=text[split:])] + original[5:]
                    if failure_reason:
                        self.assertIsNone(probe.failed_preinput_record(encode(rows), failure_reason))
                    else:
                        with self.assertRaises(probe.ProbeFailure):
                            probe.project(encode(rows))
            for replacement in (text[:-1], "x" * (probe.MAX_LINE + 1) + "\n" + text):
                rows = original[:4] + [dict(original[4], Output=replacement)] + original[5:]
                if failure_reason:
                    self.assertIsNone(probe.failed_preinput_record(encode(rows), failure_reason))
                else:
                    with self.assertRaises(probe.ProbeFailure):
                        probe.project(encode(rows))

    def test_preinput_failure_projection_accepts_only_closed_vocabulary(self):
        for rejection in probe.OUTPUT_REJECTIONS[1:]:
            rows = preinput_failure_records(preinput_rejection=rejection, preinput_first_csi="none")
            value = probe.failed_preinput_record(encode(rows), "preinput_guard_rejected")
            self.assertIsNotNone(value)
            self.assertEqual(value["preinput_rejection"], rejection)
            self.assertFalse(value["preinput_no_rejection"])
        for kind in probe.FIRST_CSI_KINDS:
            rows = preinput_failure_records(preinput_first_csi=kind)
            value = probe.failed_preinput_record(encode(rows), "preinput_guard_rejected")
            self.assertIsNotNone(value)
            self.assertEqual(value["preinput_first_csi"], kind)
        for values in (dict(preinput_prompt_ready=False), dict(preinput_mode_restored=False, preinput_prompt_ready=True),
                       dict(preinput_live_output=False, preinput_public_trust=False, preinput_prompt_ready=False)):
            rows = preinput_failure_records("preinput_prompt_missing", **values)
            self.assertIsNotNone(probe.failed_preinput_record(encode(rows), "preinput_prompt_missing"))
        # Trust can be an older live snapshot; readiness is rechecked at EOF.
        rows = preinput_failure_records(preinput_public_trust=True)
        value = probe.failed_preinput_record(encode(rows), "preinput_guard_rejected")
        self.assertTrue(value["preinput_public_trust"])
        self.assertFalse(value["preinput_prompt_ready"])

    def test_preinput_failure_invariants_fail_closed(self):
        cases = [dict(preinput_no_rejection=True), dict(preinput_rejection="none"),
                 dict(preinput_live_output=False), dict(preinput_prompt_ready=True),
                 dict(preinput_prompt_ready=True, preinput_public_trust=False),
                 dict(preinput_rejection="echo"), dict(preinput_first_csi="PRIVATE_SENTINEL"),
                 dict(preinput_rejection="PRIVATE_SENTINEL"), dict(preinput_mode_restored="PRIVATE_SENTINEL")]
        for values in cases:
            rows = preinput_failure_records(**values)
            with self.subTest(values=values):
                self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_guard_rejected"))
        for values in (dict(preinput_prompt_ready=True), dict(preinput_no_rejection=False, preinput_rejection="echo"),
                       dict(preinput_first_csi="cursor_blink_enable")):
            rows = preinput_failure_records("preinput_prompt_missing", **values)
            self.assertIsNone(probe.failed_preinput_record(encode(rows), "preinput_prompt_missing"))

    def test_preinput_failure_records_require_exact_attribution_and_completion(self):
        reason = "preinput_guard_rejected"
        cases = [encode(records()), encode(failure_records(reason)), b"PRIVATE_SENTINEL", b"[]\n",
                 b"x" * (probe.MAX_OUTPUT + 1)]
        for index in (4, 5, 6, 7):
            rows = preinput_failure_records(); del rows[index]; cases.append(encode(rows))
            rows = preinput_failure_records(); rows.insert(index, rows[index]); cases.append(encode(rows))
        for index in (4, 5):
            for key, value in (("Package", "Other"), ("Test", "Other"), ("Test", None),
                               ("Action", "skip"), ("OutputType", "frame")):
                rows = preinput_failure_records(); rows[index][key] = value; cases.append(encode(rows))
        for text in ("PRIVATE_SENTINEL", "preinput_guard_rejected PRIVATE_SENTINEL", "../preinput_guard_rejected"):
            rows = preinput_failure_records(); rows[5]["Output"] = "    native_windows_test.go:61: " + text + "\n"
            cases.append(encode(rows))
        raw = encode(preinput_failure_records())
        cases += [raw[:-1], raw.replace(b'"Package":', b'"Package":"duplicate", "Package":', 1),
                  raw.replace(b'"Action": "start"', b'"private": NaN, "Action": "start"', 1)]
        for raw in cases:
            self.assertIsNone(probe.failed_preinput_record(raw, reason))
        for reason in probe.NATIVE_FAILURES - probe.PREINPUT_FAILURES:
            rows = preinput_failure_records(reason)
            self.assertEqual(probe.native_failure_reason(encode(rows)), reason)
            self.assertIsNone(probe.failed_preinput_record(encode(rows), reason))

    def test_capture_projects_preinput_failures_without_raw_output(self):
        for reason in probe.PREINPUT_FAILURES:
            rows = preinput_failure_records(reason)
            if reason == "preinput_guard_rejected":
                set_preinput(rows, preinput_first_csi="other", preinput_csi_final="7e", preinput_csi_params=" ?0:1;23 ")
            rows[4]["Output"] = "C:\\PRIVATE_SENTINEL\\fixture.go:1: " + rows[4]["Output"]
            rows.insert(2, dict(rows[2], Output="PRIVATE_SENTINEL\x1b[31m\n"))
            expected = probe.failed_preinput_record(encode(rows), reason)
            process = mock.Mock(stdout=io.BytesIO(encode(rows))); process.wait.return_value = 1
            output = io.StringIO()
            with mock.patch.object(probe.sys, "platform", "win32"), mock.patch.object(probe.subprocess, "Popen", return_value=process), contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(), 1)
            self.assertEqual(len(output.getvalue().splitlines()), 2)
            self.assertIn(probe.format_preinput(expected), output.getvalue())
            self.assertIn("reason=" + reason + ";", output.getvalue())
            for private in ("PRIVATE_SENTINEL", "fixture.go", "native_windows_test.go", "\x1b"):
                self.assertNotIn(private, output.getvalue())
            # A malformed or duplicated record keeps only the existing finite failure.
            for alteration in ("PRIVATE_SENTINEL", rows[5]["Output"] * 2):
                broken = [dict(row) for row in rows]
                broken[5]["Output"] = alteration
                process = mock.Mock(stdout=io.BytesIO(encode(broken))); process.wait.return_value = 1
                output = io.StringIO()
                with mock.patch.object(probe.sys, "platform", "win32"), mock.patch.object(probe.subprocess, "Popen", return_value=process), contextlib.redirect_stdout(output):
                    self.assertEqual(probe.main(), 1)
                self.assertEqual(len(output.getvalue().splitlines()), 1)
                self.assertIn("reason=" + reason + ";", output.getvalue())
                self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
                self.assertNotIn("preinput_first_csi=", output.getvalue())

    def test_destination_record_required_unique_and_finite(self):
        rows=records();del rows[3]
        with self.assertRaises(probe.ProbeFailure) as caught:probe.project(encode(rows))
        self.assertEqual(caught.exception.reason,"projection_destination_missing")
        rows=records();rows.append(rows[3])
        with self.assertRaises(probe.ProbeFailure):probe.project(encode(rows))
        for field in probe.DESTINATION_FIELDS:
            rows=records();rows[3]["Output"]=rows[3]["Output"].replace(field+"=",field+"=PRIVATE_SENTINEL")
            with self.assertRaises(probe.ProbeFailure):probe.project(encode(rows))
        for replacements in (("stdout_pipe=false","stdout_pipe=true","stdout_char=false","stdout_char=true"),
                             ("stdout_console=false","stdout_console=true"),
                             ("stderr_console=false","stderr_console=true"),
                             ("conout_console=true","conout_console=false"),
                             ("conout_overflow=false","conout_overflow=true"),
                             ("conout_public_trust=false","conout_public_trust=true"),
                             ("conout_residual_unknown=false","conout_residual_unknown=true")):
            rows=records()
            for old,new in zip(replacements[::2],replacements[1::2]):rows[3]["Output"]=rows[3]["Output"].replace(old,new)
            with self.assertRaises(probe.ProbeFailure):probe.project(encode(rows))
        rows=records()
        for field in ("stdout_pipe","stderr_pipe","conout_live_output","conout_public_trust","conout_exact_prompt"):
            rows[3]["Output"]=rows[3]["Output"].replace(field+"=false",field+"=true")
        self.assertTrue(probe.project(encode(rows))["conout_public_trust"])

    def test_destination_fragmentation_and_prefix_suppression(self):
        rows=records();rows[3]["Output"]="PRIVATE_SENTINEL "+rows[3]["Output"]
        text=rows[3]["Output"];expected=probe.project(encode(rows))
        for split in range(len(text)+1):
            parts=rows[:3]+[dict(rows[3],Output=text[:split]),dict(rows[3],Output=text[split:])]+rows[4:]
            self.assertEqual(probe.project(encode(parts)),expected)
        output=io.StringIO()
        with mock.patch.object(probe.sys,"platform","win32"),mock.patch.object(probe,"capture",return_value=encode(rows)),contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(),0)
        self.assertNotIn("PRIVATE_SENTINEL",output.getvalue())

    def test_presentation_prefix_is_discarded_without_export(self):
        expected = probe.project(encode(records()))
        body = records()[2]["Output"].split("cursor_position=", 1)[1]
        body = "cursor_position=" + body
        for prefix in ("", "    native_windows_test.go:44: ", "\tfixture.go:9: ",
                       "    C:\\PRIVATE_SENTINEL\\native_windows_test.go:44: ",
                       "PRIVATE_SENTINEL presentation prefix: "):
            rows=records();rows[2]["Output"]=prefix+body
            self.assertEqual(probe.project(encode(rows)),expected)
            output=io.StringIO()
            with mock.patch.object(probe.sys,"platform","win32"),mock.patch.object(probe,"capture",return_value=encode(rows)),contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(),0)
            self.assertNotIn("PRIVATE_SENTINEL",output.getvalue())
            self.assertNotIn("native_windows_test.go",output.getvalue())
            text=rows[2]["Output"]
            for split in range(len(text)+1):
                parts=rows[:2]+[dict(rows[2],Output=text[:split]),dict(rows[2],Output=text[split:])]+rows[3:]
                self.assertEqual(probe.project(encode(parts)),expected)

    def test_prefix_cannot_hide_duplicate_or_malformed_finite_body(self):
        body=records()[2]["Output"].split("cursor_position=",1)[1]
        body="cursor_position="+body
        for text in ("cursor_position=PRIVATE_SENTINEL "+body,
                     "PRIVATE_SENTINEL "+body.rstrip("\n")+" cursor_position=false\n",
                     "PRIVATE_SENTINEL "+body.replace("title=false","title=PRIVATE_SENTINEL"),
                     "PRIVATE_SENTINEL "+body.rstrip("\n")+" extra=PRIVATE_SENTINEL\n"):
            rows=records();rows[2]["Output"]=text
            with self.assertRaises(probe.ProbeFailure):probe.project(encode(rows))
            output=io.StringIO()
            with mock.patch.object(probe.sys,"platform","win32"),mock.patch.object(probe,"capture",return_value=encode(rows)),contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(),1)
            self.assertNotIn("PRIVATE_SENTINEL",output.getvalue())

    def test_missing_summary_shape_is_finite_and_still_rejected(self):
        cases=[]
        rows=records();rows[2]["Output"]=rows[2]["Output"].replace("\n","\r\n");cases.append((rows,"projection_summary_crlf"))
        rows=records();rows[2]["Output"]=rows[2]["Output"].replace("public_trust=false","public_trust=PRIVATE_SENTINEL");cases.append((rows,"projection_summary_fields"))
        rows=records();del rows[2]["Test"];cases.append((rows,"projection_summary_attribution"))
        for rows,reason in cases:
            with self.assertRaises(probe.ProbeFailure) as caught: probe.project(encode(rows))
            self.assertEqual(caught.exception.reason,reason)
            output=io.StringIO()
            with mock.patch.object(probe.sys,"platform","win32"),mock.patch.object(probe,"capture",return_value=encode(rows)),contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(),1)
            self.assertIn("reason="+reason+";",output.getvalue())
            self.assertNotIn("PRIVATE_SENTINEL",output.getvalue())

    def test_summary_fragments_reassemble_at_every_split(self):
        original = records()
        text = original[2]["Output"]
        for split in range(len(text)+1):
            rows = original[:2] + [dict(original[2], Output=text[:split]),
                                  dict(original[2], Output=text[split:])] + original[3:]
            self.assertEqual(probe.project(encode(rows)), probe.project(encode(original)))
        rows = original[:2] + [dict(original[2], Output=c) for c in text] + original[3:]
        self.assertEqual(probe.project(encode(rows)), probe.project(encode(original)))
        rows=records(); rows[2]["Output"]="PRIVATE_SENTINEL\n"+text+"unrelated fixed text\n"
        self.assertEqual(probe.project(encode(rows)), probe.project(encode(original)))

    def test_summary_fragments_do_not_cross_context_or_terminal_boundary(self):
        text=records()[2]["Output"]
        for boundary in ({"Action":"output","Package":probe.PACKAGE,"Output":"package text\n"},
                         {"Action":"output","Package":probe.PACKAGE,"Test":probe.TEST,"OutputType":"frame","Output":"frame text\n"},
                         {"Action":"pass","Package":probe.PACKAGE,"Test":probe.TEST},
                         {"Action":"output","Package":probe.PACKAGE,"Test":"Other","Output":"other text\n"}):
            rows=records(); rows[2:3]=[dict(rows[2],Output=text[:60]),boundary,dict(rows[2],Output=text[60:])]
            with self.assertRaises(probe.ProbeFailure): probe.project(encode(rows))
        rows=records();rows[2]["Output"]=text[:-1]
        with self.assertRaises(probe.ProbeFailure) as caught: probe.project(encode(rows))
        self.assertEqual(caught.exception.reason,"projection_line_incomplete")

    def test_summary_line_bound_duplicate_and_private_output(self):
        rows=records(); rows[2]["Output"]="x"*(probe.MAX_LINE+1)+"\n"
        with self.assertRaises(probe.ProbeFailure) as caught: probe.project(encode(rows))
        self.assertEqual(caught.exception.reason,"projection_line_bound")
        rows=records();rows[2]["Output"]*=2
        with self.assertRaises(probe.ProbeFailure) as caught: probe.project(encode(rows))
        self.assertEqual(caught.exception.reason,"projection_duplicate_summary")
        rows=records();rows[2]["Output"]="PRIVATE_SENTINEL"
        output=io.StringIO()
        with mock.patch.object(probe.sys,"platform","win32"),mock.patch.object(probe,"capture",return_value=encode(rows)),contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(),1)
        self.assertNotIn("PRIVATE_SENTINEL",output.getvalue())

    def test_native_failure_labels_are_exact_and_source_bound(self):
        source = (Path(probe.ROOT) / "internal/conptyrendering/native_windows_test.go").read_text()
        labels = set(re.findall(r'(?:return empty, |reason = |t.Fatal\()"([a-z_]+)"', source))
        self.assertEqual(labels, probe.NATIVE_FAILURES)
        for reason in probe.NATIVE_FAILURES:
            self.assertEqual(probe.native_failure_reason(encode(failure_records(reason))), reason)
        for reason in ("PRIVATE_SENTINEL", "child_exit PRIVATE_SENTINEL", "child_exit\nPRIVATE_SENTINEL", "../child_exit"):
            self.assertEqual(probe.native_failure_reason(encode(failure_records(reason))), "go_test_failed")
        self.assertEqual(probe.ProbeFailure("PRIVATE_SENTINEL").reason, "go_test_failed")

    def test_failed_json_never_promotes_pass_or_ambiguous_labels(self):
        cases = [encode(records()), b"PRIVATE_SENTINEL", b"{}", b"[]\n", b"x"*(probe.MAX_OUTPUT+1)]
        for index in (2, 3, 4):
            rows = failure_records(); del rows[index]; cases.append(encode(rows))
            rows = failure_records(); rows.append(rows[index]); cases.append(encode(rows))
        for key, value in (("Package", "PRIVATE_SENTINEL"), ("Test", "Other"), ("Action", "skip")):
            rows = failure_records(); rows[2][key] = value; cases.append(encode(rows))
        cases += [encode(failure_records()).replace(b'"Package":', b'"Package":"duplicate", "Package":', 1),
                  encode(failure_records()).replace(b'"Action": "start"', b'"extra":NaN, "Action":"start"', 1)]
        for raw in cases:
            self.assertEqual(probe.native_failure_reason(raw), "go_test_failed")

    def test_capture_failure_keeps_only_closed_reason(self):
        for raw, reason in ((encode(failure_records()), "child_exit"), (encode(records()), "go_test_failed"),
                            (b"PRIVATE_SENTINEL", "go_test_failed"),
                            (b"x"*(probe.MAX_OUTPUT+1), "capture_incomplete")):
            process = mock.Mock(stdout=io.BytesIO(raw)); process.wait.return_value = 1
            with mock.patch.object(probe.subprocess, "Popen", return_value=process):
                with self.assertRaises(probe.ProbeFailure) as caught:
                    probe.capture({})
            self.assertEqual(caught.exception.reason, reason)
        for reason in probe.NATIVE_FAILURES | probe.LAUNCHER_FAILURES:
            output = io.StringIO()
            with mock.patch.object(probe.sys, "platform", "win32"), mock.patch.object(probe, "capture", side_effect=probe.ProbeFailure(reason)), contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(), 1)
            self.assertIn("reason="+reason+";", output.getvalue())
            self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())

    def test_projection_failure_names_exact_boundary(self):
        cases = [(b"", "projection_frame"), (b"PRIVATE_SENTINEL\n", "projection_json")]
        for key,value,reason in (("Package","other","projection_package"),("Test","Other","projection_test"),("Action","skip","projection_action")):
            rows=records();rows[2][key]=value;cases.append((encode(rows),reason))
        for index,reason in ((2,"projection_missing_summary"),(5,"projection_missing_pass")):
            rows=records();del rows[index];cases.append((encode(rows),reason))
        for raw,reason in cases:
            with self.assertRaises(probe.ProbeFailure) as caught:
                probe.project(raw)
            self.assertEqual(caught.exception.reason,reason)


    def test_live_text_flags_are_finite_and_consistent(self):
        for field in probe.TEXT_FIELDS:
            rows = records()
            rows[2]["Output"] = rows[2]["Output"].replace(" " + field + "=false", "")
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
            rows = records()
            rows[2]["Output"] = rows[2]["Output"].replace(field + "=false", field + "=PRIVATE_SENTINEL")
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for selected in ({"public_trust"}, {"exact_prompt"}, {"prompt_without_final_space"},
                         {"live_output", "exact_prompt", "prompt_without_final_space"}):
            rows = records()
            for field in selected:
                rows[2]["Output"] = rows[2]["Output"].replace(field + "=false", field + "=true")
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for chosen in ("exact_prompt", "prompt_without_final_space"):
            rows = records()
            for field in ("live_output", "public_trust", chosen):
                rows[2]["Output"] = rows[2]["Output"].replace(field + "=false", field + "=true")
            self.assertTrue(probe.project(encode(rows))[chosen])

    def test_refinement_enum_and_aggregate_consistency(self):
        for kind in probe.RESIDUAL_KINDS:
            rows = records()
            output = rows[2]["Output"]
            if kind != "none":
                output = output.replace("unknown=false", "unknown=true")
            rows[2]["Output"] = output.replace("first_residual_kind=none", "first_residual_kind=" + kind)
            self.assertEqual(probe.project(encode(rows))["first_residual_kind"], kind)
        for replacement in ("private_text", "0", "CSI", "none extra", "none\nPRIVATE_SENTINEL"):
            rows = records()
            rows[2]["Output"] = rows[2]["Output"].replace("first_residual_kind=none", "first_residual_kind=" + replacement)
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for old, new in (("first_residual_kind=none", "first_residual_kind=csi"),
                         ("residual_unknown=false", "residual_unknown=true"),
                         ("unknown=false overflow", "unknown=true overflow"),
                         ("win32_input_enable=false", "win32_input_enable=true")):
            rows = records()
            rows[2]["Output"] = rows[2]["Output"].replace(old, new)
            with self.assertRaises(ValueError):
                probe.project(encode(rows))

    def test_refinement_requires_every_fixed_field_and_no_extra_payload(self):
        for field in probe.FIELDS[8:]:
            rows = records()
            rows[2]["Output"] = rows[2]["Output"].replace(" " + field + "=false", "")
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        rows = records()
        rows[2]["Output"] = rows[2]["Output"].replace("\n", " title_payload=PRIVATE_SENTINEL\n")
        with self.assertRaises(ValueError):
            probe.project(encode(rows))

    def test_requires_exact_test_package_and_summary(self):
        self.assertEqual(set(probe.project(encode(records()))), set(probe.FIELDS) | set(probe.TEXT_FIELDS) | set(probe.DESTINATION_FIELDS) | set(probe.PREINPUT_FIELDS) | {"first_residual_kind", "conout_first_residual_kind", "preinput_rejection", "preinput_first_csi", "preinput_csi_final", "preinput_csi_params"})
        self.assertTrue(probe.project(encode(records(True)))["unknown"])
        for index in (2, 3, 4, 5, 6):
            rows = records()
            del rows[index]
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for action in ("fail", "skip", "bench", "pause"):
            rows = records()
            rows[5]["Action"] = action
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for field, value in (("Package", "localrmm/cmd/windows-service"), ("Test", "Other")):
            rows = records()
            rows[5][field] = value
            with self.assertRaises(ValueError):
                probe.project(encode(rows))

    def test_duplicate_malformed_and_nonfinite_reports_fail(self):
        for index in (2, 3, 4, 5, 6):
            rows = records()
            rows.append(rows[index])
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for raw in (b"", b"[]\n", b"not json\n", b"{}", b"x" * (probe.MAX_OUTPUT + 1),
                    b'{"Package":"x","Package":"y"}\n'):
            with self.assertRaises(ValueError):
                probe.project(raw)
        for name in ("overflow", "incomplete"):
            rows = records()
            rows[2]["Output"] = rows[2]["Output"].replace(name + "=false", name + "=true")
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for value in ("TRUE", "1", "private", "false extra"):
            rows = records()
            rows[2]["Output"] = rows[2]["Output"].replace("title=false", "title=" + value)
            with self.assertRaises(ValueError):
                probe.project(encode(rows))

    def test_main_emits_only_projection_or_constant_failure(self):
        rows = records(True)
        rows.insert(2, {"Action": "output", "Package": probe.PACKAGE, "Test": probe.TEST,
                        "Output": "PRIVATE_SENTINEL\n"})
        for raw, status in ((encode(rows), 0), (b"PRIVATE_SENTINEL", 1)):
            output = io.StringIO()
            with mock.patch.object(probe.sys, "platform", "win32"), mock.patch.object(probe, "capture", return_value=raw) as capture, contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(), status)
                self.assertNotIn("GOOS", capture.call_args.args[0])
                self.assertNotIn("GOARCH", capture.call_args.args[0])
                self.assertNotIn("GOFLAGS", capture.call_args.args[0])
            self.assertNotIn("PRIVATE_SENTINEL", output.getvalue())
        with mock.patch.object(probe.sys, "platform", "linux"), mock.patch.object(probe, "capture") as capture, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main(), 1)
            capture.assert_not_called()

    def test_capture_exact_fixed_command_and_bounds(self):
        raw = encode(records())
        for data, code, accepted in ((raw, 0, True), (raw, 1, False), (b"x" * (probe.MAX_OUTPUT + 1), 0, False)):
            process = mock.Mock(stdout=io.BytesIO(data))
            process.wait.return_value = code
            with mock.patch.object(probe.subprocess, "Popen", return_value=process) as popen:
                if accepted:
                    self.assertEqual(probe.capture({}), raw)
                else:
                    with self.assertRaises(ValueError):
                        probe.capture({})
                args, kwargs = popen.call_args
                self.assertEqual(args, (probe.ARGS,))
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                process.wait.assert_called_once_with(timeout=120)
        process = mock.Mock(stdout=io.BytesIO(raw))
        process.wait.side_effect = [subprocess.TimeoutExpired(probe.ARGS, 120), 1]
        with mock.patch.object(probe.subprocess, "Popen", return_value=process):
            with self.assertRaises(ValueError):
                probe.capture({})
            process.kill.assert_called_once_with()

    def test_workflow_keeps_probe_separate_from_manual_acceptance(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/windows-service-source.yml").read_text()
        self.assertIn("python tests/security/run_windows_service_source.py", workflow)
        self.assertIn("python -I -B tests/security/run_public_conpty_probe.py", workflow)
        self.assertIn("timeout-minutes: 3", workflow)
        self.assertNotIn("tracebolt_fresh_native", workflow)
        self.assertNotIn("run_acceptance.py", workflow)
        self.assertNotIn("run_fresh_conpty.py", workflow)
        self.assertEqual(probe.ARGS[-1], "./internal/conptyrendering")
        self.assertIn("-run=^TestNativePublicRendering$", probe.ARGS)
        self.assertIn("-timeout=45s", probe.ARGS)


if __name__ == "__main__":
    unittest.main()
