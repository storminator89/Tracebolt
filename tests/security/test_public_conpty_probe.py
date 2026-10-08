import contextlib
import importlib.util
import io
import json
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
        {"Action": "pass", "Package": probe.PACKAGE, "Test": probe.TEST},
        {"Action": "pass", "Package": probe.PACKAGE},
    ]


def encode(rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


class PublicProbeTests(unittest.TestCase):
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
        self.assertEqual(set(probe.project(encode(records()))), set(probe.FIELDS) | set(probe.TEXT_FIELDS) | {"first_residual_kind"})
        self.assertTrue(probe.project(encode(records(True)))["unknown"])
        for index in (2, 3, 4):
            rows = records()
            del rows[index]
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for action in ("fail", "skip", "bench", "pause"):
            rows = records()
            rows[3]["Action"] = action
            with self.assertRaises(ValueError):
                probe.project(encode(rows))
        for field, value in (("Package", "localrmm/cmd/windows-service"), ("Test", "Other")):
            rows = records()
            rows[3][field] = value
            with self.assertRaises(ValueError):
                probe.project(encode(rows))

    def test_duplicate_malformed_and_nonfinite_reports_fail(self):
        for index in (2, 3, 4):
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
