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
        {"Action": "pass", "Package": probe.PACKAGE, "Test": probe.TEST},
        {"Action": "pass", "Package": probe.PACKAGE},
    ]


def failure_records(reason="child_exit"):
    rows = records()
    del rows[3]
    rows[2]["Output"] = "    native_windows_test.go:41: " + reason + "\n"
    rows[3]["Action"] = rows[4]["Action"] = "fail"
    return rows


def encode(rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


class PublicProbeTests(unittest.TestCase):
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
        for index,reason in ((2,"projection_missing_summary"),(4,"projection_missing_pass")):
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
        self.assertEqual(set(probe.project(encode(records()))), set(probe.FIELDS) | set(probe.TEXT_FIELDS) | set(probe.DESTINATION_FIELDS) | {"first_residual_kind", "conout_first_residual_kind"})
        self.assertTrue(probe.project(encode(records(True)))["unknown"])
        for index in (2, 3, 4, 5):
            rows = records()
            del rows[index]
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for action in ("fail", "skip", "bench", "pause"):
            rows = records()
            rows[4]["Action"] = action
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for field, value in (("Package", "localrmm/cmd/windows-service"), ("Test", "Other")):
            rows = records()
            rows[4][field] = value
            with self.assertRaises(ValueError):
                probe.project(encode(rows))

    def test_duplicate_malformed_and_nonfinite_reports_fail(self):
        for index in (2, 3, 4, 5):
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
