"""Inert wrapper checks: inspect YAML text and validate in-memory fake evidence.

No workflow shell, native program, collector, account or service is executed.
Only embedded input validation and JSON readers run, with fake inputs and files.
"""
import contextlib
import io
import itertools
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
READ_PROFILE = "tracebolt.linux-read-admin.v2"
SOURCE = "a" * 40
CHECKS = ("installedServiceOwners", "v4Provenance", "revocationCompleted", "revokedNoAuthority",
          "journalContent", "serviceRestartOnline")
STAGES = {
    "preflight", "manager_start", "operator_login", "install_enroll", "approval",
    "initial_reports", "read_admin_cancel", "read_admin_fixture_opt", "read_admin_inventory", "read_admin_journal",
    "read_admin_repeat", "read_admin_retained", "read_admin_readiness", "complete",
    "read_admin_socket", "read_admin_socket_owners", "read_admin_revoke",
    "read_admin_post_revoke",
    "read_admin_journal_content", "read_admin_restart",
    'installer_preflight_inspect',
    'installer_preflight_systemd',
    'installer_preflight_terminal',
    'installer_preflight_systemctl_tool',
    'installer_preflight_useradd_tool',
    'installer_preflight_nologin_tool',
    'installer_preflight_opt_directory',
    'installer_preflight_etc_directory',
    'installer_preflight_state_directory',
    'installer_preflight_unit_directory',
    'installer_preflight_unit_status',
    'installer_preflight_account',
    'installer_preflight_installation_state',
    'installer_preflight_ownership_state',
    'installer_preflight_fresh_paths',
    'installer_preflight_bootstrap',
    'installer_preflight_complete_profile',
    'installer_preflight_artifacts',
    'installer_preflight_plan',
    'installer_preflight_begin',
    'installer_preflight_reinspect',
    'installer_preflight_replan',
    'installer_preflight_unit_command',
    'installer_preflight_unit_members',
    'installer_preflight_unit_pid',
    'installer_preflight_unit_absence',
    'installer_preflight_manifest_absence',
    'installer_preflight_begin_request',
    'installer_preflight_begin_control',
    'installer_preflight_begin_lock',
    'installer_preflight_begin_journal',
    'installer_preflight_begin_entropy',
    'installer_preflight_begin_ownership',
    'installer_preflight_begin_unit',
    'installer_preflight_begin_artifacts',
    'installer_preflight_begin_bootstrap',
    'installer_preflight_begin_save',
    "installer_preflight", "installer_prepare", "installer_stage", "installer_enroll",
    "installer_validate", "installer_publish", "installer_start", "installer_commit",
}
INVALID = "FAIL: missing or invalid sanitized read-admin acceptance evidence."
INCOMPLETE = "FAIL: sanitized read-admin acceptance records an incomplete or failing run."


def result(transport="tls", scenario="complete", **changes):
    expected = (True,) * len(CHECKS) if scenario == "complete" else (False,) * len(CHECKS)
    return {
        "schemaVersion": "tracebolt.read-admin-systemd-acceptance.v2",
        "status": "pass", "stage": "complete", "profile": transport,
        "collectionProfile": "managed-operations-v3", "scenario": scenario,
        "osRebootTested": False, "telemetryExported": False,
        "readProfile": READ_PROFILE, "sourceCommit": SOURCE,
        "ptraceRiskAcknowledged": True, "socketNativeChecks": dict(zip(CHECKS, expected)),
        "initialProbe": {"failure": "none", "childExit": "zero", "scopePromptSeen": True}, "setupFailure": "none", **changes,
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
        validation = cls.source.split("  validate-inputs:\n", 1)[1].split("  disposable-systemd:\n", 1)[0]
        cls.input_script = textwrap.dedent(validation.split("          python3 - <<'PYTHON_INPUTS'\n", 1)[1]
                                          .split("          PYTHON_INPUTS\n", 1)[0])
        cls.input_validator = compile(cls.input_script, "<fixed-input-validator>", "exec")

    def dispatch_inputs(self, changes=None, *, source=SOURCE, raw=None):
        values = {"read_profile": READ_PROFILE, "reviewed_source_commit": SOURCE,
                  "approved_fresh_v2_read_admin_systemd": "true",
                  "approved_cap_sys_ptrace_process_memory": "true"}
        values.update(changes or {})
        event = json.dumps({"inputs": values}).encode() if raw is None else raw
        fake_os = SimpleNamespace(environ={"GITHUB_EVENT_PATH": "fake-event.json", "GITHUB_SHA": source})
        output, error = io.StringIO(), None
        with contextlib.redirect_stdout(output), mock.patch.dict(sys.modules, {"os": fake_os}), \
                mock.patch("builtins.open", return_value=FakeFile(event)) as opened:
            try:
                exec(self.input_validator, {"__name__": "__main__"})
            except SystemExit as exc:
                error = exc.code
        opened.assert_called_once_with("fake-event.json", encoding="utf-8")
        return output.getvalue(), error

    def test_opt_fixture_is_explicit_bounded_and_native_only(self):
        self.assertIn('root-owned hosted /opt directory inode from 0777 to 0755 (no recursion)', self.source)
        root = WORKFLOW.parents[2]
        native = (root / 'cmd/lan-manager/read_admin_systemd_test.go').read_text()
        helper = native.split('func readAdminPrepareDisposableOpt', 1)[1].split('func TestReadAdminOptFixturePreparationIsNarrow', 1)[0]
        self.assertIn('unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC', helper)
        self.assertIn('unix.Fchmod(fd, 0755)', helper)
        self.assertIn('current.Ino != after.Ino', helper)
        self.assertNotIn('Chown', helper)
        self.assertNotIn('Walk', helper)
        self.assertNotIn('Remove', helper)
        driver = (root / 'cmd/lan-manager/systemd_install_test.go').read_text()
        self.assertIn('if readAdmin != nil {\n\t\tstage = "read_admin_fixture_opt"\n\t\treadAdminPrepareDisposableOpt(t)\n\t}', driver)
        self.assertLess(driver.index('t.Cleanup(func()'), driver.index('readAdminPrepareDisposableOpt(t)'))

    def test_input_validation_job_is_isolated_and_required(self):
        validation = self.source.split("jobs:\n", 1)[1].split("  disposable-systemd:\n", 1)[0]
        prefix, script = validation.split("        run: |\n", 1)
        self.assertEqual(prefix, """  validate-inputs:
    if: ${{ github.event_name == 'workflow_dispatch' }}
    name: Validate dispatch approvals
    runs-on: ubuntu-24.04
    timeout-minutes: 1
    permissions: {}
    steps:
      - name: Report fixed reasons for missing dispatch approval
        shell: bash
""")
        self.assertEqual(script, "          python3 - <<'PYTHON_INPUTS'\n" +
                         textwrap.indent(self.input_script, "          ") + "          PYTHON_INPUTS\n")
        self.assertNotIn("${{", script)
        self.assertNotRegex(script, r"\b(?:sudo|secrets|token|subprocess|eval|exec)\b")
        self.assertIn("  disposable-systemd:\n    needs: validate-inputs\n", self.source)

    def test_input_validation_accepts_only_exact_provider_approvals(self):
        for fresh, cap in itertools.product((True, "true"), repeat=2):
            with self.subTest(fresh=fresh, cap=cap):
                self.assertEqual(self.dispatch_inputs({"approved_fresh_v2_read_admin_systemd": fresh,
                                                       "approved_cap_sys_ptrace_process_memory": cap}),
                                 ("PASS: dispatch input approvals validated.\n", None))
        reasons = {"read_profile": "READ_PROFILE_MISMATCH",
                   "reviewed_source_commit": "REVIEWED_SOURCE_MISMATCH",
                   "approved_fresh_v2_read_admin_systemd": "FRESH_V2_APPROVAL_MISSING",
                   "approved_cap_sys_ptrace_process_memory": "CAP_SYS_PTRACE_APPROVAL_MISSING"}
        hostile = (None, False, 1, "", "false", "True", [], {}, "*", "$(echo injected)",
                   "`echo injected`", "'; echo injected; #", "${{ secrets.EXAMPLE }}", "::error::injected\n")
        for field, reason in reasons.items():
            for value in hostile:
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.dispatch_inputs({field: value}), ("::error::" + reason + "\n", 1))

    def test_input_validation_never_normalizes_profile_or_source(self):
        for field, correct, reason in (("read_profile", READ_PROFILE, "READ_PROFILE_MISMATCH"),
                                       ("reviewed_source_commit", SOURCE, "REVIEWED_SOURCE_MISMATCH")):
            for value in (correct.upper(), " " + correct, correct + "\n", correct[:8] + "-" + correct[8:]):
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.dispatch_inputs({field: value}), ("::error::" + reason + "\n", 1))
        self.assertEqual(self.dispatch_inputs(source=""), ("::error::REVIEWED_SOURCE_MISMATCH\n", 1))

    def test_input_validation_has_fixed_errors_for_malformed_event(self):
        for raw in (b"hostile invalid JSON", b"{}", b"[]", b'{"inputs":null}', b'{"inputs":[]}'):
            with self.subTest(raw=raw):
                self.assertEqual(self.dispatch_inputs(raw=raw), ("", "::error::INVALID_DISPATCH_INPUTS"))

    def validate(self, raw, transport="tls", scenario="complete", *, read_profile=READ_PROFILE,
                 source=SOURCE, mode=stat.S_IFREG | 0o600,
                 size=None, open_error=None, private_log=None, log_mode=stat.S_IFREG | 0o600, log_size=None,
                 log_open_error=None, log_read_error=None):
        stream = FakeFile(raw)
        stream.read = mock.Mock(wraps=stream.read)
        log_stream = FakeFile(private_log or b'')
        log_stream.fileno = lambda: 124
        log_stream.read = mock.Mock(wraps=log_stream.read, side_effect=log_read_error)
        def opened(path, flags):
            if open_error is not None:
                raise open_error
            if path == 'private-fixture-path':
                return 123
            if path.endswith('/private-test.log'):
                if log_open_error is not None:
                    raise log_open_error
                if private_log is not None:
                    return 124
            raise FileNotFoundError()
        fake_os = SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW,
            O_NONBLOCK=os.O_NONBLOCK, O_CLOEXEC=os.O_CLOEXEC,
            open=mock.Mock(side_effect=opened),
            fdopen=mock.Mock(side_effect=lambda fd, mode: stream if fd == 123 else log_stream),
            fstat=mock.Mock(side_effect=lambda fd: SimpleNamespace(st_mode=mode, st_size=len(raw) if size is None else size) if fd == 123 else SimpleNamespace(st_mode=log_mode, st_size=len(private_log) if log_size is None else log_size)),
        )
        output, error = io.StringIO(), None
        with contextlib.redirect_stdout(output), mock.patch.dict(sys.modules, {"os": fake_os}), \
                mock.patch.object(sys, "argv", ["validator", "private-fixture-path", transport, scenario, read_profile, source]):
            try:
                exec(self.readers[0], {"__name__": "__main__"})
            except SystemExit as exc:
                error = str(exc)
        fake_os.log_stream = log_stream
        return output.getvalue(), error, fake_os, stream

    def complete(self, raw):
        output, error = io.StringIO(), None
        stream = FakeFile(raw)
        stream.read = mock.Mock(wraps=stream.read)
        with contextlib.redirect_stdout(output), mock.patch("builtins.open", return_value=stream), \
                mock.patch.object(sys, "argv", ["validator", "normalized-fixture-path"]):
            try:
                exec(self.readers[1], {"__name__": "__main__"})
            except SystemExit as exc:
                error = str(exc)
        stream.read.assert_called_once_with(16385)
        return output.getvalue(), error

    def assert_rejected(self, raw, **options):
        output, error, _, _ = self.validate(raw, **options)
        self.assertEqual(output, "")
        self.assertEqual(error, INVALID)

    def test_initial_probe_diagnostic_is_closed_and_cannot_grant_pass(self):
        for failure in ('systemd-status-members', 'fixed-command-failed', 'unit-dropin',
                        'acceptance-launcher-host', 'acceptance-launcher-components'):
            value = result(status='fail', stage='read_admin_cancel', initialProbe={
                'failure': failure, 'childExit': 'nonzero', 'scopePromptSeen': False})
            output, error, _, _ = self.validate(json.dumps(value).encode())
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['initialProbe'], value['initialProbe'])
            value['status'] = 'pass'
            value['stage'] = 'complete'
            self.assert_rejected(json.dumps(value).encode())
        for bad in ({'failure': 'secret', 'childExit': 'zero', 'scopePromptSeen': False},
                    {'failure': 'none', 'childExit': 'secret', 'scopePromptSeen': True},
                    {'failure': 'none', 'childExit': 'zero', 'scopePromptSeen': 1},
                    {'failure': 'none', 'childExit': 'zero', 'scopePromptSeen': True, 'raw': 'secret'}):
            self.assert_rejected(json.dumps(result(initialProbe=bad)).encode())

    def test_all_setup_codes_and_native_assertions_are_closed(self):
        root = WORKFLOW.parents[2]
        go = (root / 'cmd/lan-manager/read_admin_systemd_test.go').read_text()
        codes = set(re.search(r'const readAdminSetupFailureCodes = `([^`]*)`', go).group(1).split())
        self.assertEqual(codes, set(re.search(r"setup_failures = frozenset\('''(.*?)'''\.split\(\)\)", self.source, re.S).group(1).split()))
        scripts = (root / 'cmd/lan-manager/read_admin_scripts_test.go').read_text()
        self.assertEqual(codes, set(re.search(r"FAILURES = frozenset\('''(.*?)'''\.split\(\)\)", scripts, re.S).group(1).split()))
        for code in codes:
            raw = json.dumps(result(status='fail', setupFailure=code)).encode()
            output, error, _, _ = self.validate(raw)
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['setupFailure'], code)
        self.assert_rejected(json.dumps(result(status='fail', setupFailure='private arbitrary reason')).encode())
        self.assert_rejected(json.dumps(result(setupFailure='installed-owner-record')).encode())
        for scenario in ('cancel-enrollment', 'retained-journal'):
            value = result(scenario=scenario, setupFailure='uncertain-journal-phase-retained')
            self.assertIsNone(self.validate(json.dumps(value).encode(), scenario=scenario)[1])
        known = b'    read_admin_socket_systemd_test.go:402: actual bounded journal content request did not complete\n'
        raw = json.dumps(result(status='fail', stage='read_admin_journal_content')).encode()
        output, error, _, _ = self.validate(raw, private_log=b'private secret and raw telemetry\n' + known)
        self.assertIsNone(error)
        self.assertEqual(json.loads(output)['nativeAssertion'], 'actual bounded journal content request did not complete')
        self.assertNotIn('private secret', output)
        for log in (b'    arbitrary.go:1: private secret and raw telemetry\n', b'not a test assertion', b'x' * 1048577):
            output, error, _, _ = self.validate(raw, private_log=log)
            self.assertIsNone(error)
            self.assertIn(json.loads(output)['nativeAssertion'], ('no-known-native-assertion', 'private-diagnostic-unavailable'))
            self.assertNotIn('private secret', output)

    def operator_line(self, **changes):
        values = dict(method='get', resource='journal', status='http_500', failure='status', code='journal_unavailable')
        values.update(changes)
        text = '    systemd_install_test.go:300: native_operator ' + ' '.join(f'{key}={value}' for key, value in values.items())
        return (text + '\n').encode(), values

    def test_operator_diagnostics_share_one_bounded_private_read(self):
        line, expected = self.operator_line()
        raw = json.dumps(result(status='fail', stage='read_admin_journal_content')).encode()
        log = (b'private secret and raw telemetry\n' + line +
               b'    systemd_install_test.go:301: operator fixture contract\n' +
               b'    systemd_install_test.go:302: operator fixture read contract\n')
        output, error, fake_os, _ = self.validate(raw, private_log=log)
        self.assertIsNone(error)
        projected = json.loads(output)
        self.assertEqual(projected['nativeAssertion'], 'operator fixture contract')
        self.assertEqual(projected['operatorFailures'], [expected])
        self.assertNotIn('private secret', output)
        self.assertEqual(fake_os.open.call_count, 2)
        self.assertEqual(fake_os.open.call_args_list[1].args[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        fake_os.log_stream.read.assert_called_once_with(1048577)
        self.assertEqual(self.complete(output.encode()), ('', INCOMPLETE))
        self.assert_rejected(json.dumps(result(operatorFailures=[expected])).encode())

    def test_operator_diagnostics_accept_only_closed_enums(self):
        enums = {
            'method': 'get post',
            'resource': 'auth enrollment invitation approval devices packages operational system system_query journal journal_create journal_query other',
            'status': 'not_received http_200 http_201 http_400 http_401 http_403 http_404 http_405 http_409 http_429 http_500 http_503 http_other',
            'failure': 'request transport deadline body oversize status decode',
            'code': 'none unknown invalid storage_busy journal_busy authentication_required journal_not_configured invalid_journal_request journal_conflict journal_unavailable journal_generation_stale journal_not_ready journal_not_found not_found method_not_allowed forbidden invalid_request',
        }
        raw = json.dumps(result(status='fail')).encode()
        for field, allowed in enums.items():
            for value in allowed.split():
                with self.subTest(field=field, value=value):
                    line, expected = self.operator_line(**{field: value})
                    output, error, _, _ = self.validate(raw, private_log=line)
                    self.assertIsNone(error)
                    self.assertEqual(json.loads(output)['operatorFailures'], [expected])
            for invalid in ('', 'PRIVATE_SECRET', 'private_secret', 'private-token', '/private/path', 'http_418', 'GET'):
                with self.subTest(field=field, invalid=invalid):
                    line, _ = self.operator_line(**{field: invalid})
                    output, error, _, _ = self.validate(raw, private_log=line)
                    self.assertIsNone(error)
                    self.assertEqual(json.loads(output)['operatorFailures'], [])
                    self.assertNotIn('PRIVATE_SECRET', output)
                    self.assertNotIn('private_secret', output)
                    self.assertNotIn('/private/path', output)

    def test_operator_diagnostics_are_anchored_deduplicated_and_capped(self):
        raw = json.dumps(result(status='fail')).encode()
        line, _ = self.operator_line()
        for malformed in (line.lstrip(), b'private ' + line, line.replace(b'.go:', b'.txt:'),
                          line.replace(b'systemd_install_test.go', b'/private/systemd_install_test.go'),
                          line.replace(b'method=get', b'method=get method=post'),
                          line.replace(b' resource=', b'  resource='),
                          line.rstrip() + b' private-secret\n',
                          line.replace(b'failure=status', b'failure=status\x00')):
            output, error, _, _ = self.validate(raw, private_log=malformed)
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['operatorFailures'], [])
            self.assertNotIn('private-secret', output)
        lines, expected = [], []
        for resource in 'auth enrollment invitation approval devices packages operational system system_query journal journal_create journal_query other'.split():
            current, values = self.operator_line(resource=resource)
            lines.extend([current, current])
            expected.append(values)
        log = b''.join(lines) + b'    systemd_install_test.go:999: operator fixture contract\n'
        output, error, _, _ = self.validate(raw, private_log=log)
        self.assertIsNone(error)
        self.assertEqual(json.loads(output)['operatorFailures'], expected[:8])
        self.assertEqual(json.loads(output)['nativeAssertion'], 'operator fixture contract')
        self.assertLess(len(output.encode()), 4096)

    def test_operator_diagnostics_unavailable_is_empty_and_never_read_for_pass(self):
        raw = json.dumps(result(status='fail')).encode()
        line, expected = self.operator_line()
        for options in ({}, {'private_log': b''}, {'private_log': b'x' * 1048577},
                        {'private_log': line, 'log_mode': stat.S_IFIFO | 0o600},
                        {'private_log': line, 'log_mode': stat.S_IFLNK | 0o600},
                        {'private_log': line, 'log_size': len(line) + 1},
                        {'private_log': line, 'log_size': 1048577}):
            output, error, _, _ = self.validate(raw, **options)
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['operatorFailures'], [])
            self.assertEqual(json.loads(output)['lifecycleFailures'], [])
            self.assertEqual(json.loads(output)['nativeAssertion'], 'private-diagnostic-unavailable')
            self.assertNotIn('/private/path', output)
            self.assertNotIn('private secret', output)
        boundary_log = b'x' * (1048576 - len(line) - 1) + b'\n' + line
        output, error, _, _ = self.validate(raw, private_log=boundary_log)
        self.assertIsNone(error)
        self.assertEqual(json.loads(output)['operatorFailures'], [expected])
        for scenario in SCENARIOS:
            output, error, fake_os, _ = self.validate(json.dumps(result(scenario=scenario)).encode(), scenario=scenario, private_log=line)
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['operatorFailures'], [])
            self.assertEqual(json.loads(output)['lifecycleFailures'], [])
            self.assertEqual(json.loads(output)['nativeAssertion'], 'none')
            self.assertEqual(fake_os.open.call_count, 1)
            fake_os.log_stream.read.assert_not_called()

    def lifecycle_enums(self):
        transaction = (WORKFLOW.parents[2] / 'internal/agentinstall/transaction.go').read_text()
        inspection = transaction.split('func inspectionFailureStage', 1)[1].split('default:', 1)[0]
        stages = set(re.findall(r'"(preflight_[a-z_]+)"', inspection))
        stages.update('stop_owned_service validate_existing_guided_state start_owned_service disable_owned_service remove_owned_installation_files commit reset_owned_service_restart_state none invalid'.split())
        maintenance = set(re.search(r"setup_failures = frozenset\('\'\'(.*?)'\'\'\.split\(\)\)", self.source, re.S).group(1).split())
        frozen = set(re.search(r"lifecycle_stages = frozenset\('\'\'(.*?)'\'\'\.split\(\)\)", self.source, re.S).group(1).split())
        self.assertEqual(frozen, stages)
        return {
            'operation': set('restart_preflight restart_apply uninstall_cleanup inspect_socket revoke_socket helper_cleanup'.split()),
            'failureStage': stages | maintenance,
            'committed': {'true', 'false', 'unavailable'},
            'rolledBack': {'true', 'false', 'unavailable'},
            'identityRetained': {'true', 'false', 'unavailable'},
            'unit': set('agent socket_helper socket_listener'.split()),
            'activeState': set('active reloading inactive failed activating deactivating maintenance refreshing unknown unavailable invalid'.split()),
            'subState': set('dead running exited failed auto-restart auto-restart-queued start-pre start start-post stop stop-sigterm stop-sigkill stop-post final-sigterm final-sigkill reload reload-signal reload-notify listening start-chown stop-pre stop-pre-sigterm stop-pre-sigkill unknown unavailable invalid'.split()),
            'result': set('success resources protocol timeout exit-code signal core-dump watchdog start-limit-hit oom-kill exec-condition skip-condition unknown unavailable invalid'.split()),
        }

    def lifecycle_line(self, **changes):
        values = dict(operation='restart_apply', failureStage='start_owned_service', committed='false',
                      rolledBack='true', identityRetained='true', unit='agent', activeState='failed',
                      subState='auto-restart', result='start-limit-hit')
        values.update(changes)
        line = '    read_admin_socket_systemd_test.go:300: native_lifecycle ' + ' '.join(f'{key}={value}' for key, value in values.items())
        expected = dict(values)
        for field in ('committed', 'rolledBack', 'identityRetained'):
            expected[field] = {'true': True, 'false': False, 'unavailable': None}.get(values[field])
        return (line + '\n').encode(), expected

    def test_lifecycle_and_operator_diagnostics_share_one_bounded_private_read(self):
        lifecycle, lifecycle_expected = self.lifecycle_line()
        operator, operator_expected = self.operator_line()
        raw = json.dumps(result(status='fail', stage='read_admin_restart')).encode()
        log = (b'private secret and raw telemetry\n' + lifecycle + operator +
               b'    read_admin_socket_systemd_test.go:302: owned native agent restart failed\n')
        output, error, fake_os, stream = self.validate(raw, private_log=log)
        self.assertIsNone(error)
        projected = json.loads(output)
        self.assertEqual(projected['nativeAssertion'], 'owned native agent restart failed')
        self.assertEqual(projected['operatorFailures'], [operator_expected])
        self.assertEqual(projected['lifecycleFailures'], [lifecycle_expected])
        self.assertNotIn('private secret', output)
        self.assertNotIn('.go:', output)
        self.assertEqual(fake_os.open.call_count, 2)
        self.assertEqual(fake_os.open.call_args_list[1].args[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        stream.read.assert_called_once_with(4097)
        fake_os.log_stream.read.assert_called_once_with(1048577)
        self.assertEqual(self.complete(output.encode()), ('', INCOMPLETE))
        for status in ('pass', 'fail'):
            self.assert_rejected(json.dumps(result(status=status, lifecycleFailures=[lifecycle_expected])).encode())

    def test_lifecycle_diagnostics_accept_only_closed_enums_and_boolean_lexemes(self):
        raw = json.dumps(result(status='fail')).encode()
        for field, allowed in self.lifecycle_enums().items():
            for value in sorted(allowed):
                with self.subTest(field=field, value=value):
                    line, expected = self.lifecycle_line(**{field: value})
                    output, error, _, _ = self.validate(raw, private_log=line)
                    self.assertIsNone(error)
                    self.assertEqual(json.loads(output)['lifecycleFailures'], [expected])
            for invalid in ('', 'PRIVATE_SECRET', 'private_secret', 'private-token', '/private/path',
                            'https://private.invalid', '1', '0', 'True', 'null'):
                with self.subTest(field=field, invalid=invalid):
                    line, _ = self.lifecycle_line(**{field: invalid})
                    output, error, _, _ = self.validate(raw, private_log=line)
                    self.assertIsNone(error)
                    self.assertEqual(json.loads(output)['lifecycleFailures'], [])
                    for secret in ('PRIVATE_SECRET', 'private_secret', 'private-token', '/private/path', 'https://private.invalid'):
                        self.assertNotIn(secret, output)

    def test_lifecycle_diagnostics_are_exact_anchored_deduplicated_and_capped(self):
        raw = json.dumps(result(status='fail')).encode()
        line, _ = self.lifecycle_line()
        for malformed in (line.lstrip(), b'private ' + line, line.replace(b'.go:', b'.txt:'),
                          line.replace(b'read_admin_socket_systemd_test.go', b'/private/read_admin_socket_systemd_test.go'),
                          line.replace(b'operation=restart_apply', b'operation=restart_apply operation=helper_cleanup'),
                          line.replace(b' failureStage=', b'  failureStage='),
                          line.replace(b'committed=false rolledBack=true', b'rolledBack=true committed=false'),
                          line.replace(b' committed=false', b''),
                          line.replace(b'failureStage=', b'failure_stage='),
                          line.replace(b'committed=false', b'committed=false\x00'),
                          line.replace(b'committed=false', b'committed=false\xff'),
                          line.rstrip() + b' private-secret\n'):
            output, error, _, _ = self.validate(raw, private_log=malformed)
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['lifecycleFailures'], [])
            self.assertNotIn('private-secret', output)
        lines, expected = [], []
        for failure_stage in sorted(self.lifecycle_enums()['failureStage'])[:12]:
            current, values = self.lifecycle_line(failureStage=failure_stage)
            lines.extend([current, current])
            expected.append(values)
        operator, operator_expected = self.operator_line()
        log = b''.join(lines) + operator + b'    systemd_install_test.go:999: operator fixture contract\n'
        output, error, _, _ = self.validate(raw, private_log=log)
        self.assertIsNone(error)
        self.assertEqual(json.loads(output)['lifecycleFailures'], expected[:8])
        self.assertEqual(json.loads(output)['operatorFailures'], [operator_expected])
        self.assertEqual(json.loads(output)['nativeAssertion'], 'operator fixture contract')

    def test_lifecycle_diagnostics_private_bounds_and_no_pass_read(self):
        raw = json.dumps(result(status='fail')).encode()
        line, expected = self.lifecycle_line()
        for options in ({}, {'private_log': b''}, {'private_log': b'x' * 1048577},
                        {'private_log': line, 'log_mode': stat.S_IFIFO | 0o600},
                        {'private_log': line, 'log_mode': stat.S_IFLNK | 0o600},
                        {'private_log': line, 'log_size': len(line) + 1},
                        {'private_log': line, 'log_size': len(line) - 1},
                        {'private_log': line, 'log_open_error': PermissionError('/private/path')},
                        {'private_log': line, 'log_read_error': OSError('private secret')},
                        {'private_log': line, 'log_size': 1048577}):
            output, error, _, _ = self.validate(raw, **options)
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['lifecycleFailures'], [])
            self.assertEqual(json.loads(output)['nativeAssertion'], 'private-diagnostic-unavailable')
            self.assertNotIn('/private/path', output)
            self.assertNotIn('private secret', output)
        boundary_log = b'x' * (1048576 - len(line) - 1) + b'\n' + line
        output, error, fake_os, _ = self.validate(raw, private_log=boundary_log)
        self.assertIsNone(error)
        self.assertEqual(json.loads(output)['lifecycleFailures'], [expected])
        fake_os.log_stream.read.assert_called_once_with(1048577)
        for scenario in SCENARIOS:
            output, error, fake_os, _ = self.validate(json.dumps(result(scenario=scenario)).encode(), scenario=scenario, private_log=line)
            self.assertIsNone(error)
            self.assertEqual(json.loads(output)['lifecycleFailures'], [])
            self.assertEqual(fake_os.open.call_count, 1)
            fake_os.log_stream.read.assert_not_called()

    def test_two_maximum_diagnostic_lists_fit_bounded_normalized_export(self):
        enums = self.lifecycle_enums()
        widest = {field: max(choices, key=len) for field, choices in enums.items()}
        widest.update(committed='false', rolledBack='false', identityRetained='false')
        lines, lifecycle_expected, operator_expected = [], [], []
        for failure_stage in sorted(enums['failureStage'], key=len, reverse=True)[:8]:
            line, expected = self.lifecycle_line(**dict(widest, failureStage=failure_stage))
            lines.extend([line, line])
            lifecycle_expected.append(expected)
        for resource in 'enrollment invitation approval devices packages operational system_query journal_create'.split():
            line, expected = self.operator_line(method='post', resource=resource, status='not_received', failure='transport',
                                                code='journal_generation_stale')
            lines.extend([line, line])
            operator_expected.append(expected)
        lines.append(b'    read_admin_systemd_test.go:301: read-admin received v3 inventory or broad-journal readiness deadline; no log content queried\n')
        raw = json.dumps(result(status='fail', stage=max(STAGES, key=len), setupFailure=max(enums['failureStage'], key=len),
                                initialProbe={'failure': 'systemd-unit-inspection-command-failed',
                                              'childExit': 'not_observed', 'scopePromptSeen': False})).encode()
        output, error, _, _ = self.validate(raw, private_log=b''.join(lines))
        self.assertIsNone(error)
        projected = json.loads(output)
        self.assertEqual(projected['operatorFailures'], operator_expected)
        self.assertEqual(projected['lifecycleFailures'], lifecycle_expected)
        self.assertGreater(len(output.encode()), 4096)
        self.assertLess(len(output.encode()), 16384)
        self.assertEqual(self.complete(output.encode()), ('', INCOMPLETE))
        padded = output.encode().ljust(16384, b' ')
        self.assertEqual(self.complete(padded), ('', INCOMPLETE))
        self.assertEqual(self.complete(padded + b' '), ('', INVALID))
        self.assert_rejected(raw.ljust(4097, b' '))
        self.assertIn('raw = stream.read(16385)', self.source)
        self.assertIn("check(len(normalized.encode('utf-8')) + 1 <= 16384)", self.source)

    def test_manual_only_fresh_v2_approval_source_and_transport_choice(self):
        source = self.source
        self.assertEqual(re.findall(r"^([a-z][a-z-]*):", source, re.M),
                         ["name", "on", "permissions", "concurrency", "jobs"])
        triggers = source.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  (\w+):", triggers, re.M), ["workflow_dispatch"])
        self.assertEqual(re.findall(r"^      ([a-z0-9_]+):", triggers, re.M),
                         ["read_profile", "reviewed_source_commit", "approved_fresh_v2_read_admin_systemd",
                          "approved_cap_sys_ptrace_process_memory", "transport"])
        for approval in ("approved_fresh_v2_read_admin_systemd", "approved_cap_sys_ptrace_process_memory"):
            self.assertRegex(triggers, rf"      {approval}:\n        description: [^\n]+\n"
                             r"        required: true\n        default: false\n        type: boolean\n")
        self.assertIn("        default: tracebolt.linux-read-admin.v2\n        type: choice\n        options:\n"
                      "          - unapproved\n          - tracebolt.linux-read-admin.v2\n", triggers)
        self.assertRegex(triggers, r"      reviewed_source_commit:\n        description: [^\n]+\n"
                         r"        required: true\n        type: string\n")
        self.assertIn("broad process-memory authority", triggers)
        self.assertIn("metadata-only code is not an OS confidentiality boundary", triggers)
        self.assertIn("owned-helper stop/drain and owned-main-service cleanup", triggers)
        self.assertIn("fixture log service/content query, owned-main-service restart", triggers)
        self.assertIn("clearing its systemd failure/start-limit bookkeeping (Result/NRestarts) after stopped identity validation", triggers)
        self.assertIn("        default: tls\n        type: choice\n        options:\n          - tls\n          - http-test\n", triggers)
        self.assertIn("plaintext passwords, sessions, telemetry and journal content", triggers)
        self.assertIn("server/UI impersonation", triggers)
        self.assertIn("    if: ${{ needs.validate-inputs.result == 'success' && github.event_name == 'workflow_dispatch' && inputs.approved_fresh_v2_read_admin_systemd && inputs.approved_cap_sys_ptrace_process_memory && inputs.read_profile == 'tracebolt.linux-read-admin.v2' && inputs.reviewed_source_commit == github.sha }}\n", source)
        self.assertNotIn("approved_disposable_read_admin_systemd", source)
        self.assertNotIn("TRACEBOLT_APPROVED_READ_ADMIN_SYSTEMD_TEST", source)
        self.assertIn("permissions:\n  contents: read\n", source)
        self.assertNotRegex(source, r"(?m)^\s*(?:contents|actions|id-token): write$")

    def test_each_scenario_has_fresh_hosted_runner_and_exact_source_build(self):
        source = self.source
        self.assertEqual(re.findall(r"^  ([a-z-]+):", source.split("jobs:\n", 1)[1], re.M), ["validate-inputs", "disposable-systemd"])
        self.assertIn("    runs-on: ubuntu-24.04\n", source)
        self.assertIn("      fail-fast: false\n      matrix:\n        scenario: [complete, cancel-enrollment, retained-journal]\n", source)
        self.assertIn('test "$RUNNER_ENVIRONMENT" = github-hosted', source)
        self.assertIn('test "$RUNNER_OS" = Linux', source)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', source)
        self.assertIn("          ref: ${{ github.sha }}\n          persist-credentials: false\n", source)
        self.assertIn("          go-version-file: go.mod\n          cache: false\n", source)
        self.assertIn('git archive --format=tar --output="$STAGE/source.tar" "$GITHUB_SHA"', source)
        for name in ("agent-service", "lan-manager", "enroll-agent", "lan-agent", "socket-owner-reader"):
            self.assertIn(f'go build -buildvcs=false -o "$STAGE/{name}" ./cmd/{name}', source)
        self.assertNotIn("-upgrade", source.split("      - name: Build", 1)[1].split("      - name: Validate", 1)[0])
        self.assertIn('go test -c -o "$STAGE/systemd.test" ./cmd/lan-manager', source)
        for action in re.findall(r"uses: ([^\s]+)", source):
            self.assertRegex(action, r"^actions/(checkout|setup-go|upload-artifact)@[0-9a-f]{40}$")
        self.assertNotRegex(source, r"\b(?:container|services|environment):")
        self.assertNotIn("self-hosted", source)

    def test_authorization_gate_precedes_build_and_every_privileged_invocation(self):
        source = self.source
        gate = source.split("        id: approval_gate\n", 1)[1].split("      - uses: actions/setup-go", 1)[0]
        self.assertLess(source.index("        id: approval_gate\n"), source.index("      - uses: actions/setup-go"))
        self.assertLess(source.index("        id: approval_gate\n"), source.index("          go mod verify"))
        for field, value in (("GITHUB_ACTIONS", "true"), ("RUNNER_ENVIRONMENT", "github-hosted"),
                             ("RUNNER_OS", "Linux"), ("TRACEBOLT_APPROVED_SYSTEMD_TEST", "1"),
                             ("TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST", "1"),
                             ("TRACEBOLT_READ_ADMIN_PROFILE", READ_PROFILE),
                             ("TRACEBOLT_APPROVED_READ_ADMIN_PTRACE", "true")):
            self.assertIn(f'test "${field}" = {value}', gate)
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]', gate)
        self.assertIn('test "$TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE" = "$GITHUB_SHA"', gate)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', gate)
        self.assertIn('case "$TRACEBOLT_READ_ADMIN_TRANSPORT" in tls|http-test) ;; *) exit 1 ;; esac', gate)
        self.assertIn('case "$TRACEBOLT_READ_ADMIN_SCENARIO" in complete|cancel-enrollment|retained-journal) ;; *) exit 1 ;; esac', gate)
        self.assertEqual(source.count("sudo env -i"), 2)
        self.assertNotIn("sudo", source[:source.index("      - name: Execute")])
        execution = source.split("      - name: Execute", 1)[1].split("      - name: Validate", 1)[0]
        self.assertIn("        id: native_acceptance\n", execution)
        self.assertNotIn("always()", execution)
        evidence = source.split("      - name: Validate the bounded result", 1)[1].split("      - name: Upload", 1)[0]
        self.assertIn("        if: ${{ always() && !cancelled() && steps.approval_gate.outcome == 'success' && steps.native_acceptance.outcome != 'skipped' }}\n", evidence)
        self.assertIn("      TRACEBOLT_APPROVED_SYSTEMD_TEST: '1'\n", source)
        self.assertIn("      TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST: ${{ inputs.approved_fresh_v2_read_admin_systemd && '1' || '0' }}\n", source)
        for field, selected in (("PROFILE", "read_profile"), ("REVIEWED_SOURCE", "reviewed_source_commit")):
            self.assertIn(f"      TRACEBOLT_READ_ADMIN_{field}: ${{{{ inputs.{selected} }}}}\n", source)
        self.assertIn("      TRACEBOLT_APPROVED_READ_ADMIN_PTRACE: ${{ inputs.approved_cap_sys_ptrace_process_memory }}\n", source)

    def test_only_exact_harness_gets_bounded_privileged_environment(self):
        source = self.source
        execution = source.split("      - name: Execute", 1)[1].split("      - name: Validate", 1)[0]
        self.assertEqual(execution.count("sudo env -i"), 1)
        self.assertIn("          umask 077\n", execution)
        for field in ("TRACEBOLT_APPROVED_SYSTEMD_TEST", "TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST",
                      "TRACEBOLT_APPROVED_READ_ADMIN_PTRACE"):
            self.assertIn(f'{field}="${field}"', execution)
        self.assertIn('            GITHUB_SHA="$GITHUB_SHA" \\\n', execution)
        for field in ("TRANSPORT", "SCENARIO", "PROFILE", "REVIEWED_SOURCE"):
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
        self.assertIn("          name: read-admin-v2-systemd-acceptance-${{ inputs.transport }}-${{ matrix.scenario }}-${{ github.sha }}\n", artifact)
        self.assertIn("          path: ${{ runner.temp }}/read-admin-systemd-result.json\n", artifact)
        self.assertNotIn("*", artifact)
        self.assertNotIn("private", artifact)
        self.assertIn("          if-no-files-found: ignore\n          retention-days: 3\n", artifact)
        self.assertEqual(re.findall(r"(?m)^\s*(rm .+)$", source), ['rm -f -- "$TARGET"'])
        self.assertIn('TARGET="$RUNNER_TEMP/read-admin-systemd-result.json"', source)
        self.assertIn('> "$TARGET" <<\'PYTHON\'; then', source)
        self.assertIn('"$TRACEBOLT_READ_ADMIN_TRANSPORT" "$TRACEBOLT_READ_ADMIN_SCENARIO"', source)
        self.assertIn('"$TRACEBOLT_READ_ADMIN_PROFILE" "$GITHUB_SHA"', source)
        self.assertNotRegex(source, r"(?m)^\s*(?:cat|tee|tail|journalctl|reboot)\b")

    def test_all_profile_scenario_completions_and_fixed_read_flags(self):
        for transport in TRANSPORTS:
            for scenario in SCENARIOS:
                with self.subTest(transport=transport, scenario=scenario):
                    expected = result(transport, scenario)
                    raw = json.dumps(expected).encode()
                    output, error, fake_os, stream = self.validate(raw, transport, scenario)
                    self.assertIsNone(error)
                    self.assertEqual(json.loads(output), dict(expected, nativeAssertion="none", operatorFailures=[], lifecycleFailures=[]))
                    fake_os.open.assert_called_once_with("private-fixture-path", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    fake_os.fdopen.assert_called_once_with(123, "rb")
                    fake_os.fstat.assert_called_once_with(123)
                    stream.read.assert_called_once_with(4097)
                    self.assertEqual(self.complete(output.encode()),
                                     ("PASS: selected fresh read-admin V2 scenario completed; OS reboot remains untested.\n", None))

    def test_missing_owners_preserves_failure_with_independent_results(self):
        checks = dict.fromkeys(CHECKS, False)
        checks.update(journalContent=True, serviceRestartOnline=True)
        raw = json.dumps(result(status="fail", stage="read_admin_socket_owners",
                                socketNativeChecks=checks, setupFailure="none")).encode()
        private_log = (b'    read_admin_socket_systemd_test.go:260: actual installed-service fixture owners not observed\n'
                       b'    read_admin_systemd_test.go:1360: owned helper containment unconfirmed; preserve state and discard VM\n')
        output, error, _, _ = self.validate(raw, private_log=private_log)
        self.assertIsNone(error)
        projected = json.loads(output)
        self.assertEqual(projected['stage'], 'read_admin_socket_owners')
        self.assertEqual(projected['setupFailure'], 'none')
        self.assertEqual(projected['nativeAssertion'], 'actual installed-service fixture owners not observed')
        self.assertEqual(projected['socketNativeChecks'], checks)
        self.assertEqual(self.complete(output.encode()), ("", INCOMPLETE))
        self.assert_rejected(json.dumps(result(socketNativeChecks=checks)).encode())

    def test_missing_owners_cannot_skip_independent_checks_or_reach_revoke(self):
        root = WORKFLOW.parents[2]
        source = (root / 'cmd/lan-manager/read_admin_socket_systemd_test.go').read_text()
        body = source.split('func readAdminSocketOwnersAndRevoke', 1)[1].split('func readAdminRestartObservationAdvanced', 1)[0]
        missing, observed = body.split('if matched.Sequence == nil {', 1)[1].split('} else {', 1)
        self.assertIn('t.Error("actual installed-service fixture owners not observed")', missing)
        self.assertNotIn('t.Fatal', missing)
        self.assertIn('failureStage = *stage', missing)
        self.assertIn('"inspect-socket"', observed)
        journal = body.index('run("read_admin_journal_content"')
        restart = body.index('run("read_admin_restart"')
        fail = body.index('t.FailNow()')
        revoke = body.index('"revoke-socket"')
        self.assertLess(journal, restart)
        self.assertLess(restart, fail)
        self.assertLess(fail, revoke)
        self.assertIn('if failureStage != "" {', body)
        self.assertIn('*stage = failureStage', body)
        self.assertIn('args := []string{"--action", "restart"}', body)
        self.assertLess(body.index('"owned native agent restart preflight failed"'), body.index('append(args, "--apply")'))
        self.assertLess(body.index('"ordinary restart baseline unavailable"'), body.index('append(args, "--apply")'))
        self.assertIn('readAdminRememberMaintenanceFailure(operation, t.Failed(), c.options.setupDiagnostic())', source)

    def test_independent_operator_errors_target_active_child(self):
        root = WORKFLOW.parents[2]
        driver = (root / 'cmd/lan-manager/systemd_install_test.go').read_text()
        operator = driver.split('operatorTest := t', 1)[1].split('invitation := ', 1)[0]
        self.assertIn('operatorTest.Fatal("operator fixture contract")', operator)
        self.assertNotRegex(operator, r'\bt\.Fatal\("operator fixture contract"\)')
        binding = driver.split('bindOperatorTest := ', 1)[1].split('call := ', 1)[0]
        self.assertIn('previous := operatorTest', binding)
        self.assertIn('operatorTest = current', binding)
        self.assertIn('return func() { operatorTest = previous }', binding)
        native = (root / 'cmd/lan-manager/read_admin_socket_systemd_test.go').read_text()
        phase = native.split('run := func(name string, check func(*testing.T))', 1)[1].split('if c.options.scenario', 1)[0]
        self.assertIn('restore := bindOperatorTest(child)', phase)
        self.assertIn('defer restore()', phase)
        self.assertLess(phase.index('defer restore()'), phase.index('check(child)'))

    def test_fail_stage_is_sanitized_but_never_success(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                raw = json.dumps(result(status="fail", stage=stage)).encode()
                output, error, _, _ = self.validate(raw)
                self.assertIsNone(error)
                self.assertEqual(json.loads(output), dict(json.loads(raw), nativeAssertion="private-diagnostic-unavailable", operatorFailures=[], lifecycleFailures=[]))
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
        self.assert_rejected(json.dumps(result(ptraceRiskAcknowledged=False)).encode())
        for field, value in (("private", "private-fixture-value"), ("collectionProfile", "managed-operations-v2"),
                             ("schemaVersion", "tracebolt.managed-systemd-acceptance.v1"),
                             ("schemaVersion", "tracebolt.read-admin-systemd-acceptance.v1"),
                             ("readProfile", "tracebolt.linux-read-admin.v1"),
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
        for field in ("transport", "scenario", "read_profile", "source"):
            for value in ("", "other", "private-fixture-value"):
                output, error, fake_os, _ = self.validate(json.dumps(result()).encode(), **{field: value})
                self.assertEqual((output, error), ("", INVALID))
                fake_os.open.assert_not_called()

    def test_reviewed_source_binding_rejects_other_or_malformed_commits(self):
        raw = json.dumps(result()).encode()
        self.assert_rejected(raw, source="b" * 40)
        for source in ("A" * 40, "a" * 39, "a" * 41, "a" * 39 + "\n", "unapproved"):
            output, error, fake_os, _ = self.validate(raw, source=source)
            self.assertEqual((output, error), ("", INVALID))
            fake_os.open.assert_not_called()
        self.assert_rejected(json.dumps(result(sourceCommit="b" * 40)).encode())
        self.assert_rejected(json.dumps(result(readProfile="unapproved")).encode())

    def test_scenario_specific_check_vectors_are_required_for_pass(self):
        for scenario in SCENARIOS:
            expected = result(scenario=scenario)["socketNativeChecks"]
            for flags in itertools.product((False, True), repeat=len(CHECKS)):
                checks = dict(zip(CHECKS, flags))
                with self.subTest(scenario=scenario, checks=checks):
                    raw = json.dumps(result(scenario=scenario, socketNativeChecks=checks)).encode()
                    if checks != expected:
                        self.assert_rejected(raw, scenario=scenario)
                    else:
                        self.assertIsNone(self.validate(raw, scenario=scenario)[1])
                    failed = json.dumps(result(scenario=scenario, status="fail", socketNativeChecks=checks)).encode()
                    output, error, _, _ = self.validate(failed, scenario=scenario)
                    self.assertIsNone(error)
                    self.assertEqual(self.complete(output.encode()), ("", INCOMPLETE))

    def test_check_object_is_fixed_strict_and_duplicate_free(self):
        valid = result()
        for field in CHECKS:
            changed = dict(valid["socketNativeChecks"])
            del changed[field]
            self.assert_rejected(json.dumps(result(socketNativeChecks=changed)).encode())
            for invalid in (None, 0, 1, [], {}, "true", "private-fixture-value"):
                changed = {**valid["socketNativeChecks"], field: invalid}
                self.assert_rejected(json.dumps(result(socketNativeChecks=changed)).encode())
            # The duplicate hook must also reject nested duplicate check keys.
            raw = json.dumps(valid).encode()
            duplicated = raw[:-2] + b", " + json.dumps(field).encode() + b": true}}"
            self.assert_rejected(duplicated)
        changed = {**valid["socketNativeChecks"], "independentSyscallDenial": True}
        self.assert_rejected(json.dumps(result(socketNativeChecks=changed)).encode())

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
