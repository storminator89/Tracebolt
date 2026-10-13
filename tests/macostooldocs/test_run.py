"""Inert tests: every child is this Python interpreter with literal test input.

No macOS command, provider, OS binary identity read or host inspection executes.
The sample text tests transport/validation; it is not Apple tool/schema evidence.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("tool_docs_driver", Path(__file__).with_name("run.py"))
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)
REAL_POPEN = subprocess.Popen


def environment(label="macos-15"):
    return {"TRACEBOLT_RUNNER_LABEL": label, "TRACEBOLT_RUNNER_OS": "macOS",
            "TRACEBOLT_RUNNER_ARCH": DRIVER.RUNNERS[label][0],
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "TRACEBOLT_REPOSITORY_PRIVATE": "false", "GITHUB_SHA": "a" * 40,
            "ImageOS": "macos15", "ImageVersion": "20261001.1"}


def row(command_id, text, status="captured"):
    return {"id": command_id, "argv": list(DRIVER.COMMANDS[command_id]),
            "text": text, "status": status}


def fake_capture(command_id):
    versions = {"product-version": "15.7\n", "build-version": "24G000\n",
                "kernel-release": "24.0.0\n", "architecture": "arm64\n"}
    return row(command_id, versions.get(command_id, "Usage: synthetic documentation\n"))


def fake_manual(source_id):
    tool, path, compression = DRIVER.MANUAL_SOURCES[source_id]
    return {"id": source_id, "tool": tool, "path": path, "status": "captured", "text": "Synthetic manual"}


class ToolDocumentationTests(unittest.TestCase):
    def inert_capture(self, code, command_id="log-help", **limits):
        calls = []
        def substitute(argv, **kwargs):
            calls.append((argv, kwargs))
            # The fixed tool argv is recorded, then REPLACED before any exec.
            return REAL_POPEN([sys.executable, "-I", "-c", code], **kwargs)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(DRIVER.subprocess, "Popen", substitute))
            for key, value in limits.items():
                stack.enter_context(mock.patch.object(DRIVER, key, value))
            result = DRIVER.capture(command_id)
        return result, calls

    def test_exact_allowlist_is_help_or_nonidentifying_version_only(self):
        DRIVER.check_commands()
        self.assertEqual(len(DRIVER.COMMANDS), 10)
        for command_id, argv in DRIVER.COMMANDS.items():
            if command_id not in DRIVER.VERSION_IDS:
                self.assertEqual(argv[1], "help")
                self.assertLessEqual(len(argv), 3)
        with self.assertRaises(TypeError):
            DRIVER.COMMANDS["log-query"] = ("/usr/bin/log", "show")

    def test_unknown_command_never_spawns(self):
        with mock.patch.object(DRIVER.subprocess, "Popen") as spawn:
            for value in ("log-show", "launchctl-list", "/bin/launchctl", "help; id"):
                with self.assertRaises(KeyError):
                    DRIVER.capture(value)
            spawn.assert_not_called()

    def test_check_mode_never_spawns_or_reads_tools(self):
        with mock.patch.object(DRIVER.subprocess, "Popen") as spawn, \
                mock.patch.object(DRIVER, "tool_identity") as identity, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(DRIVER.main(["--check"]), 0)
            spawn.assert_not_called()
            identity.assert_not_called()

    def test_cli_accepts_no_arbitrary_command_or_output_path(self):
        with mock.patch.object(DRIVER.subprocess, "Popen") as spawn, \
                contextlib.redirect_stderr(io.StringIO()):
            for argv in (["--command", "show"], ["--output", "/tmp/elsewhere"], ["show"]):
                with self.assertRaises(SystemExit):
                    DRIVER.main(argv)
            spawn.assert_not_called()

    def test_public_hosted_context_and_architectures(self):
        for label, (arch, machine) in DRIVER.RUNNERS.items():
            context = DRIVER.hosted_context(environment(label), "darwin")
            self.assertEqual(context["runnerArch"], arch)
            self.assertEqual(context["expectedMachine"], machine)

    def test_context_rejects_private_self_hosted_wrong_arch_or_non_mac(self):
        for key, value in (("TRACEBOLT_REPOSITORY_PRIVATE", "true"),
                           ("RUNNER_ENVIRONMENT", "self-hosted"),
                           ("TRACEBOLT_RUNNER_ARCH", "X64"), ("GITHUB_ACTIONS", "false"),
                           ("TRACEBOLT_RUNNER_OS", "Linux"), ("GITHUB_SHA", "invalid"),
                           ("TRACEBOLT_RUNNER_LABEL", "macos-latest")):
            env = environment()
            env[key] = value
            with self.assertRaises(ValueError, msg=key):
                DRIVER.hosted_context(env, "darwin")
        with self.assertRaises(ValueError):
            DRIVER.hosted_context(environment(), "linux")

    def test_environment_never_retains_identity_or_secret_fields(self):
        env = dict(environment(), USER="DO_NOT_KEEP_USER", HOME="/Users/private",
                   HOSTNAME="DO_NOT_KEEP_HOST", SECRET="DO_NOT_KEEP_SECRET", ImageVersion="/private/path")
        encoded = json.dumps(DRIVER.hosted_context(env, "darwin"))
        self.assertNotIn("DO_NOT_KEEP", encoded)
        self.assertNotIn("/private", encoded)
        self.assertNotIn("/Users", encoded)

    def test_success_preserves_exact_help_bytes_and_spawn_contract(self):
        result, calls = self.inert_capture("print('Usage: log <synthetic-command>')")
        self.assertEqual(result["status"], "captured")
        self.assertEqual(result["text"], "Usage: log <synthetic-command>\n")
        argv, kwargs = calls[0]
        self.assertEqual(argv, ("/usr/bin/log", "help"))
        self.assertFalse(kwargs["shell"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertTrue(kwargs["close_fds"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["cwd"], "/")
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})

    def test_stderr_only_help_is_discarded_and_inconclusive(self):
        result, _ = self.inert_capture("import sys; sys.stderr.write('Usage: launchctl help\\n')", "launchctl-help")
        self.assertEqual(result["status"], "inconclusive")
        self.assertIsNone(result["text"])
        self.assertTrue(result["stderrDiscarded"])
        self.assertGreater(result["stderrBytes"], 0)

    def test_valid_stdout_help_never_exports_sensitive_looking_stderr(self):
        code = "import sys; print('Usage: log synthetic help'); sys.stderr.write('/Users/PRIVATE_USER token=DO_NOT_KEEP eventMessage=PRIVATE_LOG')"
        result, calls = self.inert_capture(code)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["reason"], "stderr_present")
        self.assertIsNone(result["text"])
        self.assertEqual(calls[0][1]["stderr"], subprocess.PIPE)
        self.assertGreater(result["stderrBytes"], 0)
        for value in ("PRIVATE_USER", "DO_NOT_KEEP", "PRIVATE_LOG", "/Users/"):
            self.assertNotIn(value, json.dumps(result))

    def test_stderr_has_separate_cap_and_no_retained_prefix(self):
        result, _ = self.inert_capture("import sys; print('Usage: log help'); sys.stderr.write('PRIVATE' * 10000)", STDERR_LIMIT_BYTES=128)
        self.assertEqual(result["reason"], "stderr_limit")
        self.assertEqual(result["stderrBytes"], 128)
        self.assertIsNone(result["text"])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_streams_share_total_output_cap(self):
        code = "import os; os.write(1, b'Usage: log ' + b'x' * 69); os.write(2, b'y' * 80)"
        result, _ = self.inert_capture(code, LIMIT_BYTES=128)
        self.assertEqual(result["reason"], "output_limit")
        self.assertEqual(result["capturedBytes"], 128)
        self.assertIsNone(result["text"])

    def test_nonzero_output_discarded_even_if_help_shaped(self):
        result, _ = self.inert_capture("import sys; print('Usage: log DO_NOT_KEEP'); sys.exit(64)")
        self.assertEqual(result["reason"], "nonzero_exit")
        self.assertEqual(result["exitCode"], 64)
        self.assertIsNone(result["text"])
        self.assertNotIn("DO_NOT_KEEP", json.dumps(result))

    def test_output_limit_discards_prefix_and_is_memory_bounded(self):
        result, _ = self.inert_capture("import sys; sys.stdout.write('Usage: log ' + 'x' * 100000)", LIMIT_BYTES=128)
        self.assertEqual(result["reason"], "output_limit")
        self.assertIsNone(result["text"])
        self.assertEqual(result["capturedBytes"], 128)

    def test_timeout_discards_partial_output(self):
        result, _ = self.inert_capture("import time; print('Usage: log incomplete', flush=True); time.sleep(5)", TIMEOUT_SECONDS=0.2)
        self.assertEqual(result["reason"], "timeout")
        self.assertIsNone(result["text"])
        self.assertLess(result["elapsedMilliseconds"], 2000)

    def test_closed_output_but_running_process_still_times_out(self):
        code = "import os,time; os.close(1); os.close(2); time.sleep(5)"
        result, _ = self.inert_capture(code, TIMEOUT_SECONDS=0.2)
        self.assertEqual(result["reason"], "timeout")
        self.assertLess(result["elapsedMilliseconds"], 2000)

    def test_invalid_empty_and_unrecognized_help_are_inconclusive(self):
        for code, reason in (("pass", "invalid_text"),
                             ("print('some operational result')", "unrecognized_help_shape"),
                             ("import os; os.write(1, b'Usage: log \\xff')", "invalid_text"),
                             ("print('Usage: log \\x1b[31m')", "invalid_text")):
            result, _ = self.inert_capture(code)
            self.assertEqual(result["status"], "inconclusive")
            self.assertEqual(result["reason"], reason)
            self.assertIsNone(result["text"])

    def test_spawn_error_message_never_exported(self):
        with mock.patch.object(DRIVER.subprocess, "Popen", side_effect=OSError("DO_NOT_KEEP")):
            result = DRIVER.capture("log-help")
        self.assertEqual(result["reason"], "spawn_failed")
        self.assertNotIn("DO_NOT_KEEP", json.dumps(result))

    def test_version_shapes_accept_only_nonidentifying_expected_values(self):
        cases = (("product-version", "15.7.1", True), ("product-version", "26.0", False),
                 ("build-version", "24G000", True), ("architecture", "arm64", True),
                 ("architecture", "a-host-name", False), ("kernel-release", "24.0.0", True),
                 ("build-version", "24G000 user", False))
        for command_id, value, valid in cases:
            result, _ = self.inert_capture("print(" + repr(value) + ")", command_id)
            self.assertEqual(result["status"] == "captured", valid)
            if not valid:
                self.assertIsNone(result["text"])

    def test_tool_identity_rejects_any_unreviewed_path_before_open(self):
        with mock.patch.object(DRIVER.os, "open") as opened:
            with self.assertRaises(ValueError):
                DRIVER.tool_identity("/Users/example/private")
            opened.assert_not_called()

    def test_tool_read_error_is_inconclusive_without_error_text(self):
        with mock.patch.object(DRIVER.os, "open", side_effect=OSError("DO_NOT_KEEP")):
            result = DRIVER.tool_identity("/usr/bin/log")
        self.assertEqual(result["status"], "inconclusive")
        self.assertIsNone(result["standaloneVersion"])
        self.assertNotIn("DO_NOT_KEEP", json.dumps(result))

    def test_fingerprint_hashes_only_a_bounded_synthetic_regular_file(self):
        import hashlib
        with tempfile.TemporaryFile() as synthetic:
            synthetic.write(b"inert tool bytes")
            synthetic.flush()
            synthetic.seek(0)
            # Substitute an existing synthetic descriptor; no OS binary opens.
            with mock.patch.object(DRIVER.os, "open", return_value=os.dup(synthetic.fileno())) as opened:
                result = DRIVER.tool_identity("/usr/bin/log")
            self.assertEqual(result["status"], "fingerprinted")
            self.assertEqual(result["sha256"], hashlib.sha256(b"inert tool bytes").hexdigest())
            self.assertEqual(set(result), {"path", "standaloneVersion", "versionSource", "sha256", "status"})
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        with tempfile.TemporaryFile() as synthetic:
            synthetic.write(b"oversize")
            synthetic.flush()
            with mock.patch.object(DRIVER.os, "open", return_value=os.dup(synthetic.fileno())), \
                    mock.patch.object(DRIVER, "BINARY_LIMIT_BYTES", 2):
                result = DRIVER.tool_identity("/usr/bin/log")
            self.assertEqual(result["status"], "inconclusive")
            self.assertIsNone(result["sha256"])

    def test_artifact_write_preserves_inconclusive_or_success_result(self):
        for status, exit_code in (("documentation_acquired", 0), ("inconclusive", 1)):
            with tempfile.TemporaryDirectory() as temp:
                target = Path(temp) / "review" / "evidence.json"
                with mock.patch.object(DRIVER, "DESTINATION", target), \
                        mock.patch.object(DRIVER, "hosted_context", return_value={}), \
                        mock.patch.object(DRIVER, "collect", return_value={"result": status}), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(DRIVER.main([]), exit_code)
                self.assertEqual(json.loads(target.read_text()), {"result": status})

    def test_bad_version_or_architecture_stops_before_help_or_binary_reads(self):
        for bad_id in ("product-version", "architecture"):
            def fake(command_id):
                if command_id == bad_id:
                    return row(command_id, "x86_64\n" if bad_id == "architecture" else None,
                               "captured" if bad_id == "architecture" else "inconclusive")
                return fake_capture(command_id)
            with mock.patch.object(DRIVER, "capture", side_effect=fake) as captured, \
                    mock.patch.object(DRIVER, "tool_identity") as identity:
                result = DRIVER.collect(DRIVER.hosted_context(environment(), "darwin"))
                self.assertEqual(result["result"], "inconclusive")
                self.assertEqual([call.args[0] for call in captured.call_args_list], list(DRIVER.VERSION_IDS))
                identity.assert_not_called()

    def test_success_records_only_documentation_claims_and_exact_selection(self):
        with mock.patch.object(DRIVER, "capture", side_effect=fake_capture) as captured, \
                mock.patch.object(DRIVER, "tool_identity", return_value={"status": "fingerprinted"}), \
                mock.patch.object(DRIVER, "manual_capture", side_effect=fake_manual):
            result = DRIVER.collect(DRIVER.hosted_context(environment(), "darwin"))
        self.assertEqual(result["result"], "documentation_acquired")
        self.assertEqual([call.args[0] for call in captured.call_args_list], list(DRIVER.COMMANDS))
        for key in ("nativeAcceptance", "logVisibilityEstablished", "logSchemaEstablished", "launchdBindingEstablished"):
            self.assertIs(result[key], False)
        self.assertEqual(set(result["sourceFiles"]), set(DRIVER.SOURCE_PATHS))

    def test_incomplete_help_never_establishes_absence_or_permission_state(self):
        def fake(command_id):
            return row(command_id, None, "inconclusive") if command_id == "log-help-show" else fake_capture(command_id)
        with mock.patch.object(DRIVER, "capture", side_effect=fake), \
                mock.patch.object(DRIVER, "tool_identity", return_value={"status": "fingerprinted"}), \
                mock.patch.object(DRIVER, "manual_capture", side_effect=fake_manual):
            result = DRIVER.collect(DRIVER.hosted_context(environment(), "darwin"))
        self.assertEqual(result["result"], "documentation_acquired")
        self.assertEqual(result["coverage"]["requestedHelpCoverage"], "partial")
        self.assertEqual(result["coverage"]["requestedDocumentationCoverage"], "partial")
        withheld = next(row for row in result["commands"] if row["id"] == "log-help-show")
        self.assertEqual(withheld["status"], "inconclusive")
        self.assertIsNone(withheld["text"])
        self.assertNotIn("permissionDenied", result)
        self.assertNotIn("absent", result)

    def test_main_refuses_non_mac_before_capture_and_output(self):
        with mock.patch.dict(os.environ, environment(), clear=True), \
                mock.patch.object(DRIVER.sys, "platform", "linux"), \
                mock.patch.object(DRIVER, "collect") as collect:
            with self.assertRaises(ValueError):
                DRIVER.main([])
            collect.assert_not_called()

    def test_existing_evidence_and_symlink_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "evidence.json"
            for kind in ("file", "symlink"):
                if kind == "file":
                    target.write_text("existing")
                else:
                    target.symlink_to(Path(temp) / "nonexistent")
                with mock.patch.object(DRIVER, "DESTINATION", target), \
                        mock.patch.object(DRIVER, "hosted_context", return_value={}), \
                        mock.patch.object(DRIVER, "collect") as collect:
                    with self.assertRaises(ValueError):
                        DRIVER.main([])
                    collect.assert_not_called()
                target.unlink()

    def manual_fixture(self, payload, source_id="log-man", bad_index=None, attrs=None, changed=False):
        from types import SimpleNamespace
        import stat
        stream = io.BytesIO(payload)
        opened, closed, file_stats = [], [], [0]
        def fake_open(component, flags, **kwargs):
            index = len(opened)
            self.assertLess(index, 6)
            expected = ["/", "usr", "share", "man", "man1", DRIVER.MANUAL_SOURCES[source_id][1].split("/")[-1]][index]
            self.assertEqual(component, expected)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_NONBLOCK)
            if index:
                self.assertEqual(kwargs, {"dir_fd": 99 + index})
            else:
                self.assertEqual(kwargs, {})
            if index < 5:
                self.assertTrue(flags & os.O_DIRECTORY)
            opened.append(component)
            return 100 + index
        def fake_stat(fd):
            index = fd - 100
            values = dict(st_mode=(stat.S_IFDIR | 0o755) if index < 5 else (stat.S_IFREG | 0o644),
                          st_uid=0, st_dev=1, st_ino=index, st_size=len(payload), st_mtime_ns=1, st_ctime_ns=1)
            if index == bad_index:
                values.update(attrs or {})
            if index == 5:
                file_stats[0] += 1
                if changed and file_stats[0] > 1:
                    values["st_mtime_ns"] = 2
            return SimpleNamespace(**values)
        with mock.patch.object(DRIVER.os, "open", side_effect=fake_open), \
                mock.patch.object(DRIVER.os, "fstat", side_effect=fake_stat), \
                mock.patch.object(DRIVER.os, "read", side_effect=lambda fd, size: stream.read(size)), \
                mock.patch.object(DRIVER.os, "close", side_effect=closed.append), \
                mock.patch.object(DRIVER.subprocess, "Popen") as spawn:
            result = DRIVER.manual_capture(source_id)
            spawn.assert_not_called()
        self.assertEqual(closed, list(reversed(range(100, 100 + len(opened)))))
        return result

    def test_fixed_manual_raw_and_gzip_descriptor_capture(self):
        import gzip
        import hashlib
        for source_id, (tool, path, compression) in DRIVER.MANUAL_SOURCES.items():
            raw = ('.Dd January 1, 2000\n.Dt ' + tool.upper() + ' 1\n.Os\n.Sh NAME\n.Nm ' + tool + '\n.Sh SYNOPSIS\nSynthetic documentation only.\n').encode()
            payload = gzip.compress(raw) if compression == "gzip" else raw
            result = self.manual_fixture(payload, source_id)
            self.assertEqual(result["status"], "captured")
            self.assertEqual(result["text"], raw.decode())
            self.assertEqual(result["sourceSHA256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(result["textSHA256"], hashlib.sha256(raw).hexdigest())
            self.assertTrue(result["descriptorRootOwnedChecks"])
            self.assertEqual(result["path"], path)

    def test_unknown_manual_never_opens_a_path(self):
        with mock.patch.object(DRIVER.os, "open") as opened:
            for value in ("/Users/private/log.1", "../log.1", "log", "log-man; id"):
                with self.assertRaises(KeyError):
                    DRIVER.manual_capture(value)
            opened.assert_not_called()
        with self.assertRaises(TypeError):
            DRIVER.MANUAL_SOURCES["new"] = ("log", "/tmp/private", "none")

    def test_manual_read_error_is_content_free_and_no_search(self):
        with mock.patch.object(DRIVER.os, "open", side_effect=OSError("PRIVATE_PATH SECRET")) as opened, \
                mock.patch.object(DRIVER.subprocess, "Popen") as spawn:
            result = DRIVER.manual_capture("log-man")
            self.assertEqual(opened.call_count, 1)
            spawn.assert_not_called()
        self.assertEqual(result["reason"], "source_unavailable")
        self.assertIsNone(result["text"])
        self.assertNotIn("PRIVATE_PATH", json.dumps(result))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_manual_root_owner_modes_and_types_fail_closed(self):
        import stat
        raw = b'.Dt LOG 1\n.Sh NAME\n.Nm log\n.Sh SYNOPSIS\nSynthetic.\n'
        for index, attrs in ((0, {"st_uid": 501}), (2, {"st_mode": stat.S_IFDIR | 0o777}),
                             (5, {"st_uid": 501}), (5, {"st_mode": stat.S_IFREG | 0o666}),
                             (5, {"st_mode": stat.S_IFLNK | 0o777}),
                             (5, {"st_mode": stat.S_IFIFO | 0o644})):
            result = self.manual_fixture(raw, bad_index=index, attrs=attrs)
            self.assertEqual(result["reason"], "unsafe_manual_source")
            self.assertIsNone(result["text"])

    def test_manual_changed_or_oversized_source_never_publishes_prefix(self):
        raw = b'.Dt LOG 1\n.Sh NAME\n.Sh SYNOPSIS\nSynthetic.\n'
        result = self.manual_fixture(raw, changed=True)
        self.assertEqual(result["reason"], "manual_changed_during_read")
        self.assertIsNone(result["text"])
        with mock.patch.object(DRIVER, "MANUAL_SOURCE_LIMIT", 16):
            result = self.manual_fixture(raw)
        self.assertEqual(result["reason"], "manual_source_size")
        self.assertIsNone(result["text"])

    def test_manual_gzip_caps_malformed_trailing_or_multiple_members(self):
        import gzip
        raw = b'.Dt LOG 1\n.Sh NAME\n.Sh SYNOPSIS\n' + b'x' * 512
        with mock.patch.object(DRIVER, "MANUAL_TEXT_LIMIT", 128):
            result = self.manual_fixture(gzip.compress(raw), "log-man-gzip")
        self.assertEqual(result["reason"], "manual_expansion_limit")
        self.assertIsNone(result["text"])
        for payload in (b'not gzip', gzip.compress(raw)[:-3], gzip.compress(raw) + b'trailer',
                        gzip.compress(raw) + gzip.compress(raw)):
            result = self.manual_fixture(payload, "log-man-gzip")
            self.assertEqual(result["status"], "inconclusive")
            self.assertIsNone(result["text"])

    def test_manual_text_must_be_exact_tool_section_and_control_safe(self):
        valid = b'.Dt LOG 1\n.Sh NAME\n.Nm log\n.Sh SYNOPSIS\nSynthetic.\n'
        for payload in (valid.replace(b'LOG 1', b'LAUNCHCTL 1'), valid.replace(b'LOG 1', b'LOG 2'),
                        valid.replace(b'.Sh SYNOPSIS', b'.Sh OTHER'), b'.so /private/data\n',
                        valid + b'\x00PRIVATE', valid + b'\xff', valid + '\u202e'.encode()):
            result = self.manual_fixture(payload)
            self.assertEqual(result["status"], "inconclusive")
            self.assertIsNone(result["text"])
            self.assertNotIn("PRIVATE", json.dumps(result))

    def test_manual_deadline_checked_before_any_path_is_opened(self):
        with mock.patch.object(DRIVER.time, "monotonic", side_effect=[0, 10]), \
                mock.patch.object(DRIVER.os, "open") as opened:
            result = DRIVER.manual_capture("log-man")
        self.assertEqual(result["reason"], "manual_timeout")
        opened.assert_not_called()

    def test_manuals_are_required_even_if_all_help_succeeds(self):
        with mock.patch.object(DRIVER, "capture", side_effect=fake_capture), \
                mock.patch.object(DRIVER, "tool_identity", return_value={"status": "fingerprinted"}), \
                mock.patch.object(DRIVER, "manual_capture", side_effect=lambda source: dict(fake_manual(source), status="inconclusive", text=None)):
            result = DRIVER.collect(DRIVER.hosted_context(environment(), "darwin"))
        self.assertEqual(result["result"], "inconclusive")
        self.assertFalse(any(result["coverage"]["installedManualCaptured"].values()))

    def test_one_manual_per_tool_suffices_but_missing_alternatives_stay_inconclusive(self):
        def fake(source):
            result = fake_manual(source)
            if source.endswith("gzip"):
                result.update(status="inconclusive", text=None)
            return result
        with mock.patch.object(DRIVER, "capture", side_effect=fake_capture), \
                mock.patch.object(DRIVER, "tool_identity", return_value={"status": "fingerprinted"}), \
                mock.patch.object(DRIVER, "manual_capture", side_effect=fake):
            result = DRIVER.collect(DRIVER.hosted_context(environment(), "darwin"))
        self.assertEqual(result["result"], "documentation_acquired")
        self.assertEqual([row["status"] for row in result["manuals"]], ["captured", "inconclusive", "captured", "inconclusive"])
        self.assertTrue(all(result["coverage"]["installedManualCaptured"].values()))

    def test_missing_tool_identity_prevents_completed_acquisition(self):
        with mock.patch.object(DRIVER, "capture", side_effect=fake_capture), \
                mock.patch.object(DRIVER, "tool_identity", return_value={"status": "inconclusive"}), \
                mock.patch.object(DRIVER, "manual_capture", side_effect=fake_manual):
            result = DRIVER.collect(DRIVER.hosted_context(environment(), "darwin"))
        self.assertEqual(result["result"], "inconclusive")
        self.assertFalse(result["coverage"]["requiredProvenanceCaptured"])

    def test_workflow_keeps_public_pinned_standard_runner_scope(self):
        text = (DRIVER.ROOT / ".github/workflows/macos-tool-docs.yml").read_text()
        self.assertIn("github.event.repository.private == false", text)
        self.assertIn("runner: [macos-15, macos-15-intel]", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("path: artifacts/review/macos-tool-docs.json", text)
        # GitHub runner context is supported at step env, not job-level env.
        job_env = text.split("    env:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertNotIn("runner.os", job_env)
        self.assertNotIn("runner.arch", job_env)
        capture_step = text.split("      - name: Capture only help, public manuals and versions\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("          TRACEBOLT_RUNNER_OS: ${{ runner.os }}", capture_step)
        self.assertIn("          TRACEBOLT_RUNNER_ARCH: ${{ runner.arch }}", capture_step)
        for forbidden in ("sudo", "setup-go", "brew", "pull_request_target", "secrets."):
            self.assertNotIn(forbidden, text)
        import re
        actions = re.findall(r"uses: (\S+)", text)
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", action) for action in actions))


if __name__ == "__main__":
    unittest.main()
