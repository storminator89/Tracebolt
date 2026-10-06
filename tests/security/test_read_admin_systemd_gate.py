"""Inert wrapper checks: inspect YAML text and validate in-memory fake evidence.

No workflow shell, native program, collector, account or service is executed.
Only the two embedded JSON readers run, with every file operation replaced.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import textwrap
from types import SimpleNamespace
import unittest
from unittest import mock


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/read-admin-systemd-acceptance.yml"
TRANSPORTS = ("tls", "http-test")
SCENARIOS = ("complete", "cancel-enrollment", "retained-journal")
STAGES = {
    "preflight", "manager_start", "operator_login", "install_enroll", "approval",
    "initial_reports", "read_admin_cancel", "read_admin_inventory", "read_admin_journal",
    "read_admin_repeat", "read_admin_retained", "read_admin_readiness", "complete",
    "installer_preflight", "installer_prepare", "installer_stage", "installer_enroll",
    "installer_validate", "installer_publish", "installer_start", "installer_commit",
}
INVALID = "FAIL: missing or invalid sanitized read-admin acceptance evidence."
INCOMPLETE = "FAIL: sanitized read-admin acceptance records an incomplete or failing run."


def result(transport="tls", scenario="complete", **changes):
    return {
        "schemaVersion": "tracebolt.read-admin-systemd-acceptance.v1",
        "status": "pass", "stage": "complete", "profile": transport,
        "collectionProfile": "managed-operations-v3", "scenario": scenario,
        "osRebootTested": False, "telemetryExported": False, **changes,
    }


class FakeFile(io.BytesIO):
    def fileno(self):
        return 123


class ReadAdminWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        blocks = re.findall(r"<<'PYTHON'(?:; then)?\n(.*?)^          PYTHON$", cls.source, re.M | re.S)
        if len(blocks) != 2:
            raise ValueError("expected exactly two isolated JSON readers")
        cls.readers = tuple(compile(textwrap.dedent(block), "<fixed-result-reader>", "exec") for block in blocks)

    def validate(self, raw, transport="tls", scenario="complete", *, mode=stat.S_IFREG | 0o600,
                 size=None, open_error=None):
        stream = FakeFile(raw)
        stream.read = mock.Mock(wraps=stream.read)
        fake_os = SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW,
            O_NONBLOCK=os.O_NONBLOCK, O_CLOEXEC=os.O_CLOEXEC,
            open=mock.Mock(return_value=123, side_effect=open_error),
            fdopen=mock.Mock(return_value=stream),
            fstat=mock.Mock(return_value=SimpleNamespace(st_mode=mode, st_size=len(raw) if size is None else size)),
        )
        output, error = io.StringIO(), None
        with contextlib.redirect_stdout(output), mock.patch.dict(sys.modules, {"os": fake_os}), \
                mock.patch.object(sys, "argv", ["validator", "private-fixture-path", transport, scenario]):
            try:
                exec(self.readers[0], {"__name__": "__main__"})
            except SystemExit as exc:
                error = str(exc)
        return output.getvalue(), error, fake_os, stream

    def complete(self, raw):
        output, error = io.StringIO(), None
        with contextlib.redirect_stdout(output), mock.patch("builtins.open", return_value=FakeFile(raw)), \
                mock.patch.object(sys, "argv", ["validator", "normalized-fixture-path"]):
            try:
                exec(self.readers[1], {"__name__": "__main__"})
            except SystemExit as exc:
                error = str(exc)
        return output.getvalue(), error

    def assert_rejected(self, raw, **options):
        output, error, _, _ = self.validate(raw, **options)
        self.assertEqual(output, "")
        self.assertEqual(error, INVALID)

    def test_manual_only_approval_and_transport_choice(self):
        source = self.source
        self.assertEqual(re.findall(r"^([a-z][a-z-]*):", source, re.M),
                         ["name", "on", "permissions", "concurrency", "jobs"])
        triggers = source.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  (\w+):", triggers, re.M), ["workflow_dispatch"])
        self.assertIn("      approved_disposable_read_admin_systemd:\n", triggers)
        self.assertIn("        required: true\n        default: false\n        type: boolean\n", triggers)
        self.assertIn("        default: tls\n        type: choice\n        options:\n          - tls\n          - http-test\n", triggers)
        self.assertIn("plaintext passwords, sessions, telemetry and journal content", triggers)
        self.assertIn("server/UI impersonation", triggers)
        self.assertIn("    if: ${{ github.event_name == 'workflow_dispatch' && inputs.approved_disposable_read_admin_systemd }}\n", source)
        self.assertIn("permissions:\n  contents: read\n", source)
        self.assertNotIn("write", source)

    def test_each_scenario_has_fresh_hosted_runner_and_exact_source_build(self):
        source = self.source
        self.assertEqual(re.findall(r"^  ([a-z-]+):", source.split("jobs:\n", 1)[1], re.M), ["disposable-systemd"])
        self.assertIn("    runs-on: ubuntu-24.04\n", source)
        self.assertIn("      fail-fast: false\n      matrix:\n        scenario: [complete, cancel-enrollment, retained-journal]\n", source)
        self.assertIn('test "$RUNNER_ENVIRONMENT" = github-hosted', source)
        self.assertIn('test "$RUNNER_OS" = Linux', source)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', source)
        self.assertIn("          ref: ${{ github.sha }}\n          persist-credentials: false\n", source)
        self.assertIn("          go-version-file: go.mod\n          cache: false\n", source)
        self.assertIn('git archive --format=tar --output="$STAGE/source.tar" "$GITHUB_SHA"', source)
        for name in ("agent-service", "lan-manager", "enroll-agent", "lan-agent"):
            self.assertIn(f'go build -buildvcs=false -o "$STAGE/{name}" ./cmd/{name}', source)
        for name in ("enroll-agent", "lan-agent"):
            self.assertIn(f'go build -buildvcs=false -trimpath -ldflags=-buildid=tracebolt-disposable-upgrade -o "$STAGE/{name}-upgrade" ./cmd/{name}', source)
        self.assertIn('go test -c -o "$STAGE/systemd.test" ./cmd/lan-manager', source)
        for action in re.findall(r"uses: ([^\s]+)", source):
            self.assertRegex(action, r"^actions/(checkout|setup-go|upload-artifact)@[0-9a-f]{40}$")
        self.assertNotRegex(source, r"\b(?:container|services|environment):")
        self.assertNotIn("self-hosted", source)

    def test_only_exact_harness_gets_bounded_privileged_environment(self):
        source = self.source
        execution = source.split("      - name: Execute", 1)[1].split("      - name: Validate", 1)[0]
        self.assertEqual(execution.count("sudo env -i"), 1)
        self.assertIn("          umask 077\n", execution)
        self.assertIn("            TRACEBOLT_APPROVED_SYSTEMD_TEST=1 \\\n", execution)
        self.assertIn("            TRACEBOLT_APPROVED_READ_ADMIN_SYSTEMD_TEST=1 \\\n", execution)
        self.assertIn('            GITHUB_SHA="$GITHUB_SHA" \\\n', execution)
        for field in ("TRANSPORT", "SCENARIO"):
            self.assertIn(f'TRACEBOLT_READ_ADMIN_{field}="$TRACEBOLT_READ_ADMIN_{field}"', execution)
        for field, value in (("BINARY_DIRECTORY", "$STAGE"), ("SOURCE_ARCHIVE", "$STAGE/source.tar"),
                             ("RESULT_FILE", "$STAGE/read-admin-systemd-result.json")):
            self.assertIn(f'TRACEBOLT_SYSTEMD_{field}="{value}"', execution)
        self.assertEqual(re.findall(r"-test.run '([^']+)'", source),
                         ["^TestApprovedReadAdminDisposableSystemdInstallation$"])
        self.assertIn('-test.v -test.timeout 10m > "$STAGE/private-test.log" 2>&1', execution)
        self.assertNotIn("${{", execution)
        self.assertNotRegex(execution, r"(?i)(?:password|invitation|cookie|token|proxy|ld_preload)=")
        self.assertNotRegex(execution, r"(?m)^\s*(?:cat|tee|tail|journalctl|systemctl|chmod|chown|rm)\b")

    def test_artifact_is_only_normalized_bounded_result(self):
        source = self.source
        artifact = source.split("      - name: Upload", 1)[1]
        self.assertEqual(source.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("        if: ${{ always() && !cancelled() }}\n", artifact)
        self.assertIn("          name: read-admin-systemd-acceptance-${{ inputs.transport }}-${{ matrix.scenario }}-${{ github.sha }}\n", artifact)
        self.assertIn("          path: ${{ runner.temp }}/read-admin-systemd-result.json\n", artifact)
        self.assertNotIn("*", artifact)
        self.assertNotIn("private", artifact)
        self.assertIn("          if-no-files-found: ignore\n          retention-days: 3\n", artifact)
        self.assertEqual(re.findall(r"(?m)^\s*(rm .+)$", source), ['rm -f -- "$TARGET"'])
        self.assertIn('TARGET="$RUNNER_TEMP/read-admin-systemd-result.json"', source)
        self.assertIn('> "$TARGET" <<\'PYTHON\'; then', source)
        self.assertIn('"$TRACEBOLT_READ_ADMIN_TRANSPORT" "$TRACEBOLT_READ_ADMIN_SCENARIO"', source)
        self.assertNotRegex(source, r"(?m)^\s*(?:cat|tee|tail|journalctl|reboot)\b")

    def test_all_profile_scenario_completions_and_fixed_read_flags(self):
        for transport in TRANSPORTS:
            for scenario in SCENARIOS:
                with self.subTest(transport=transport, scenario=scenario):
                    expected = result(transport, scenario)
                    raw = json.dumps(expected).encode()
                    output, error, fake_os, stream = self.validate(raw, transport, scenario)
                    self.assertIsNone(error)
                    self.assertEqual(json.loads(output), expected)
                    fake_os.open.assert_called_once_with("private-fixture-path", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    fake_os.fdopen.assert_called_once_with(123, "rb")
                    fake_os.fstat.assert_called_once_with(123)
                    stream.read.assert_called_once_with(4097)
                    self.assertEqual(self.complete(output.encode()),
                                     ("PASS: selected read-admin scenario completed; OS reboot remains untested.\n", None))

    def test_fail_stage_is_sanitized_but_never_success(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                raw = json.dumps(result(status="fail", stage=stage)).encode()
                output, error, _, _ = self.validate(raw)
                self.assertIsNone(error)
                self.assertEqual(json.loads(output), json.loads(raw))
                self.assertEqual(self.complete(output.encode()), ("", INCOMPLETE))
                if stage != "complete":
                    self.assert_rejected(json.dumps(result(stage=stage)).encode())

    def test_exact_schema_and_boolean_types(self):
        valid = result()
        for field in valid:
            changed = dict(valid)
            del changed[field]
            with self.subTest(missing=field):
                self.assert_rejected(json.dumps(changed).encode())
            for invalid in (None, 0, 1, [], {}, "private-fixture-value"):
                with self.subTest(field=field, invalid=invalid):
                    self.assert_rejected(json.dumps(result(**{field: invalid})).encode())
        for field in ("osRebootTested", "telemetryExported"):
            self.assert_rejected(json.dumps(result(**{field: True})).encode())
        for field, value in (("private", "private-fixture-value"), ("collectionProfile", "managed-operations-v2"),
                             ("schemaVersion", "tracebolt.managed-systemd-acceptance.v1"),
                             ("status", "skip"), ("stage", "restart"), ("stage", "read_admin_unknown")):
            self.assert_rejected(json.dumps(result(**{field: value})).encode())

    def test_selected_profile_and_scenario_cannot_be_substituted(self):
        for transport in TRANSPORTS:
            for scenario in SCENARIOS:
                raw = json.dumps(result(transport, scenario)).encode()
                for other in TRANSPORTS:
                    if other != transport:
                        self.assert_rejected(raw, transport=other, scenario=scenario)
                for other in SCENARIOS:
                    if other != scenario:
                        self.assert_rejected(raw, transport=transport, scenario=other)
        for field in ("transport", "scenario"):
            for value in ("", "other", "private-fixture-value"):
                output, error, fake_os, _ = self.validate(json.dumps(result()).encode(), **{field: value})
                self.assertEqual((output, error), ("", INVALID))
                fake_os.open.assert_not_called()

    def test_malformed_duplicate_truncated_and_oversized_results_reject(self):
        valid = json.dumps(result()).encode()
        for raw in (b"", b"{}", b"[]", b"null", b"true", b'"private-fixture-value"',
                    b"private-fixture-value", valid[:-1], valid + b"garbage", b" " * 4097):
            self.assert_rejected(raw)
        for field, value in result().items():
            # Even an identical duplicate is ambiguous evidence.
            raw = valid[:-1] + b", " + json.dumps(field).encode() + b": " + json.dumps(value).encode() + b"}"
            self.assert_rejected(raw)

    def test_unsafe_file_shape_bounded_read_and_open_failures(self):
        raw = json.dumps(result()).encode()
        for mode in (stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR):
            output, error, _, stream = self.validate(raw, mode=mode)
            self.assertEqual((output, error), ("", INVALID))
            stream.read.assert_not_called()
        for size in (0, -1, 4097, len(raw) - 1, len(raw) + 1):
            self.assert_rejected(raw, size=size)
        # A file growing after fstat is still bounded, even if its JSON prefix was valid.
        self.assert_rejected(raw + b" " * 4097, size=len(raw))
        for error in (FileNotFoundError("private-fixture-path"), PermissionError("private-fixture-path"),
                      OSError("private-fixture-value")):
            self.assert_rejected(raw, open_error=error)


if __name__ == "__main__":
    unittest.main()
