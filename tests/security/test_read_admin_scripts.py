"""Inert embedded-script checks. Never fork a PTY, run a launcher, or touch hosts."""
import ast
import json
from pathlib import Path
import re
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'cmd/lan-manager/read_admin_scripts_test.go'
FINAL_FIELDS = {'phase', 'exitCode', 'secretEcho', 'ready', 'httpWarning',
                'installerStage', 'installerRolledBack', 'installerIdentityRetained', 'scopeApprovals', 'readAdminComplete',
                'readAdminCanceled', 'readAdminFailure', 'readAdminPhasesComplete'}


def embedded(name):
    matches = re.findall(r'const ' + re.escape(name) + r' = `([^`]*)`', SOURCE.read_text())
    if len(matches) != 1:
        raise AssertionError('Missing or duplicate embedded script')
    return matches[0]


def inert_module(name):
    source = embedded(name)
    # Compile the whole script, but execute only imports, literal constants and
    # function definitions. No main guard, function invocation or child command.
    tree = ast.parse(source)
    compile(tree, '<embedded-script>', 'exec')
    safe = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.Assign))]
    module = types.ModuleType(name)
    exec(compile(ast.Module(body=safe, type_ignores=[]), '<inert-definitions>', 'exec'), module.__dict__)
    return module


LAUNCHER = inert_module('readAdminLauncher')
PTY = inert_module('readAdminPTY')


def approved_env(**updates):
    return dict(TRACEBOLT_APPROVED_SYSTEMD_TEST='1',
                TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST='1', GITHUB_ACTIONS='true',
                RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux',
                TRACEBOLT_READ_ADMIN_TRANSPORT='tls', TRACEBOLT_READ_ADMIN_SCENARIO='complete',
                GITHUB_SHA='a' * 40, TRACEBOLT_READ_ADMIN_PROFILE='tracebolt.linux-read-admin.v2',
                TRACEBOLT_APPROVED_READ_ADMIN_PTRACE='true', TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE='a' * 40, **updates)


def complete(**updates):
    result = dict(schemaVersion='tracebolt.read-admin-result.v2', readProfile='tracebolt.linux-read-admin.v2',
                  configurationComplete=True, canceled=False, installation='committed',
                  phases={'inventory': 'configured_confirmed', 'journal': 'configured_confirmed', 'socket': 'configured_confirmed'},
                  collectionPerformed=False, nativeAcceptance='not-established')
    result.update(updates)
    return result


def encoded(value, **kwargs):
    return json.dumps(value, **kwargs).encode() + b'\n'


class InertScriptTests(unittest.TestCase):
    def test_scripts_are_linux_test_only_and_compile(self):
        self.assertTrue(SOURCE.read_text().startswith('//go:build linux\n'))
        for name in ('readAdminLauncher', 'readAdminPTY'):
            source = embedded(name)
            compile(source, '<compile-only>', 'exec')
            self.assertNotIn('SIGKILL', source)
            self.assertNotIn('killpg', source)
            self.assertIn("if __name__ == '__main__':", source)

    def test_every_approval_and_execution_context_is_required(self):
        for module in (LAUNCHER, PTY):
            for transport in ('tls', 'http-test'):
                for scenario in ('complete', 'cancel-enrollment', 'retained-journal'):
                    env = approved_env()
                    env.update(TRACEBOLT_READ_ADMIN_TRANSPORT=transport, TRACEBOLT_READ_ADMIN_SCENARIO=scenario)
                    self.assertEqual(module.require_gate(env, 'linux', 0, 0), (transport, scenario, 'a' * 40))
            for key in approved_env():
                for wrong in (None, '', 'true ', '1 ', True, False, 'self-hosted'):
                    env = approved_env()
                    if wrong is None:
                        del env[key]
                    else:
                        env[key] = wrong
                    with self.subTest(script=module.__name__, key=key, wrong=wrong), self.assertRaises(ValueError):
                        module.require_gate(env, 'linux', 0, 0)
            for system, uid, euid in (('darwin', 0, 0), ('Linux', 0, 0), ('linux', 1, 0), ('linux', 0, 1), ('linux', False, 0), ('linux', 0, False)):
                with self.assertRaises(ValueError):
                    module.require_gate(approved_env(), system, uid, euid)
            for sha in ('a' * 39, 'a' * 41, 'A' * 40, 'a' * 39 + '\n', 'g' * 40):
                env = approved_env(); env['GITHUB_SHA'] = sha
                with self.assertRaises(ValueError):
                    module.require_gate(env, 'linux', 0, 0)

    def test_gate_is_pure_and_precedes_all_config_reads_and_host_actions(self):
        # The pure gate may be exercised even with every effect denied. The
        # launcher/driver main functions themselves are never invoked here.
        for module in (LAUNCHER, PTY):
            with mock.patch('builtins.open', side_effect=AssertionError('file access forbidden')), \
                    mock.patch.object(module.os, 'open', side_effect=AssertionError('file access forbidden')), \
                    mock.patch.object(module.os, 'execv', side_effect=AssertionError('execution forbidden')):
                module.require_gate(approved_env(), 'linux', 0, 0)
                with self.assertRaises(ValueError):
                    module.require_gate({}, 'linux', 0, 0)
            tree = ast.parse(embedded(module.__name__))
            main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
            protected = next(node for node in main.body if isinstance(node, ast.Try))
            first_call = next(node for node in ast.walk(protected.body[0]) if isinstance(node, ast.Call))
            self.assertIsInstance(first_call.func, ast.Name)
            self.assertEqual(first_call.func.id, 'require_gate')

    def test_launcher_only_composes_selected_actual_validators(self):
        source = embedded('readAdminLauncher')
        for required in ("manifest['sourceCommit'] == source_commit", "cfg['scenario'] == scenario",
                         "'v0.0.0-read-admin-acceptance'", "member.name != 'deploy/release/linux-bootstrap.py'",
                         'member.isreg() and not member.issparse()', "mode='r:'",
                         'hashlib.file_digest', 'os.O_NOFOLLOW', 'st_nlink == 1',
                         'b.read_admin_sources(directory, manifest)', 'workflow.make_plan(args, manifest, arch)',
                         'workflow.real_adapter(setup, inventory, amendment, journal_guide, socket_setup, templates, plan, artifact)',
                         'lambda: b.run_installer(b.installer_command(args, directory, manifest, arch))',
                         'inventory.confirm_terminal, inventory.emit_terminal', "raise setup.Rejected('interrupted')",
                         "phase == 'journal' and not verify_only",
                         "raise workflow.Rejected('acceptance-injected-before-journal')"):
            self.assertIn(required, source)
        tree = ast.parse(source)
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)]
        called = [node.func.attr for node in calls if isinstance(node.func, ast.Attribute)]
        for forbidden in ('prepare_release', 'verify_attestation', 'extractall', 'extract', 'unlink', 'remove',
                          'chmod', 'chown', 'run_read_admin', 'system'):
            self.assertNotIn(forbidden, called)
        bootstrap_exec = next(node for node in calls if isinstance(node.func, ast.Name) and node.func.id == 'exec')
        hash_calls = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id == 'protected_file']
        self.assertTrue(all(node.lineno < bootstrap_exec.lineno for node in hash_calls))

    def test_parses_pretty_root_privately_amid_other_terminal_output(self):
        installer = {'committed': True, 'identityRetained': True, 'plan': {'private': 'never emit'}}
        raw = b'public fixture terminal\r\n' + encoded(installer) + encoded(complete(), indent=2).replace(b'\n', b'\r\n')
        raw += b'final public fixture line\r\n'
        result = PTY.parse_result(raw)
        self.assertEqual(result, dict(readAdminComplete=True, readAdminCanceled=False,
                                     readAdminFailure='', readAdminPhasesComplete=True))
        resumed = complete(installation='existing_owned_installation',
                           phases={'inventory': 'verified_existing', 'journal': 'verified_existing', 'socket': 'verified_existing'})
        self.assertTrue(PTY.parse_result(encoded(resumed))['readAdminComplete'])
        nested = encoded({'nested': complete()})
        self.assertEqual(PTY.parse_result(nested)['readAdminFailure'], 'read-admin-result-unavailable')

    def test_cancellation_and_retained_failure_are_distinct(self):
        canceled = complete(configurationComplete=False, canceled=True, installation='not_attempted',
                            phases={'inventory': 'not_attempted', 'journal': 'not_attempted', 'socket': 'not_attempted'})
        value = PTY.parse_result(encoded(canceled))
        self.assertTrue(value['readAdminCanceled'])
        self.assertFalse(value['readAdminComplete'])
        self.assertFalse(value['readAdminPhasesComplete'])
        self.assertEqual(value['readAdminFailure'], '')
        for stage in ('acceptance-injected-before-journal', 'uncertain-journal-phase-retained',
                      'install-or-device-approval-incomplete', 'interrupted'):
            failed = complete(configurationComplete=False, failureStage=stage,
                              phases={'inventory': 'configured_confirmed', 'journal': 'uncertain', 'socket': 'not_attempted'})
            value = PTY.parse_result(encoded(failed))
            self.assertEqual(value['readAdminFailure'], stage)
            self.assertFalse(value['readAdminComplete'])
            self.assertFalse(value['readAdminCanceled'])
            self.assertFalse(value['readAdminPhasesComplete'])

    def test_never_projects_arbitrary_failure_text(self):
        sentinel = 'invented-private-path-secret-value'
        raw = encoded(complete(configurationComplete=False, failureStage=sentinel,
                               recovery=sentinel, deviceId=sentinel, limitations={'private': sentinel},
                               phases={'inventory': 'uncertain', 'journal': 'not_attempted', 'socket': 'not_attempted'}))
        event = PTY.exit_event(raw, 1, '', 1)
        self.assertEqual(set(event), FINAL_FIELDS)
        self.assertEqual(event['readAdminFailure'], 'read-admin-phase-incomplete')
        self.assertNotIn(sentinel, json.dumps(event))
        self.assertFalse(event['secretEcho'])
        self.assertEqual(event['scopeApprovals'], 1)
        self.assertFalse(event['readAdminComplete'])

    def test_schema_inconsistency_duplicates_truncation_and_bounds_fail_closed(self):
        bad = [b'', b'garbage\n', b'{}\n', b'[]\n', b'\xff\n', encoded(complete())[:-3],
               encoded(complete()) + encoded(complete()), encoded({'wrapper': complete()}),
               encoded(complete()).rstrip() + encoded(complete()), b'x' * (PTY.MAX_CAPTURE + 1)]
        malformed = [complete(configurationComplete=1), complete(canceled=0), complete(canceled=True),
                     complete(failureStage='interrupted'), complete(collectionPerformed=True),
                     complete(nativeAcceptance='established'), complete(readProfile='other'),
                     complete(installation='not_attempted'), complete(phases=[]),
                     complete(phases={'inventory': 'configured_confirmed'}),
                     complete(phases={'inventory': ['configured_confirmed'], 'journal': 'configured_confirmed', 'socket': 'configured_confirmed'}),
                     complete(phases={'inventory': 'uncertain', 'journal': 'configured_confirmed', 'socket': 'configured_confirmed'}),
                     complete(configurationComplete=False), complete(configurationComplete=False, failureStage=[]),
                     complete(configurationComplete=False, canceled=True),
                     complete(configurationComplete=False, canceled=True, installation='not_attempted',
                              phases={'inventory': 'not_attempted', 'journal': 'not_attempted', 'socket': 'not_attempted'}, failureStage='interrupted')]
        bad.extend(encoded(value) for value in malformed)
        raw = encoded(complete())
        bad += [raw.replace(b'"configurationComplete": true', b'"configurationComplete": false, "configurationComplete": true'),
                raw.replace(b'"configurationComplete": true', b'"configurationComplete": NaN')]
        for raw in bad:
            with self.subTest(raw=raw[:100]):
                result = PTY.parse_result(raw)
                self.assertFalse(result['readAdminComplete'])
                self.assertFalse(result['readAdminCanceled'])
                self.assertIn(result['readAdminFailure'], PTY.FAILURES)
        for raw in (None, '', [], {}):
            self.assertEqual(PTY.parse_result(raw)['readAdminFailure'], 'read-admin-result-invalid')

    def test_final_event_exact_allowlist_and_existing_installer_metadata(self):
        secret = 'private-fixture-invitation'
        installer = dict(committed=False, rolledBack=True, identityRetained=True, plan={'private': secret},
                         failureStage='enroll_as_dedicated_account')
        failed = complete(configurationComplete=False, failureStage='install-or-device-approval-incomplete',
                          installation='uncertain', phases={'inventory': 'not_attempted', 'journal': 'not_attempted', 'socket': 'not_attempted'})
        event = PTY.exit_event(encoded(installer) + encoded(failed) + b'UNENCRYPTED HTTP TEST\n', 1, secret, 1)
        self.assertEqual(set(event), FINAL_FIELDS)
        self.assertTrue(event['secretEcho'])
        self.assertTrue(event['httpWarning'])
        self.assertEqual(event['installerStage'], 'enroll_as_dedicated_account')
        self.assertTrue(event['installerRolledBack'])
        self.assertTrue(event['installerIdentityRetained'])
        self.assertNotIn(secret, json.dumps(event))
        installer['failureStage'] = secret
        self.assertEqual(PTY.exit_event(encoded(installer), 1, '', 0)['installerStage'], '')
        for failure in ('acceptance-deadline-exceeded', 'acceptance-capture-exceeded', secret):
            event = PTY.exit_event(encoded(complete()), 0, '', 1, failure)
            self.assertFalse(event['readAdminComplete'])
            self.assertIn(event['readAdminFailure'], PTY.FAILURES)
            self.assertNotIn(secret, json.dumps(event))

    def test_private_driver_config_is_bounded_and_empty_secret_is_safe(self):
        base = dict(args=['/usr/bin/python3', '-I', '-c', 'inert fixture', '/private/config'],
                    secret='', approval='INSTALL READ ADMIN', cancelApproval=False)
        for transport in ('tls', 'http-test'):
            for secret in ('', 'a' * 43):
                for cancel in (True, False):
                    value = dict(base, secret=secret, cancelApproval=cancel,
                                 approval='INSTALL READ ADMIN' + (' OVER HTTP' if transport == 'http-test' else ''))
                    cfg, phrase = PTY.parse_config(encoded(value), transport)
                    self.assertEqual(cfg, value)
                    self.assertEqual(phrase, value['approval'])
        for changed in (dict(base, secret='a' * 42), dict(base, secret='a' * 44), dict(base, secret='x' * 42 + '\n'),
                        dict(base, secret=None), dict(base, approval='INSTALL READ ADMIN OVER HTTP'),
                        dict(base, cancelApproval=1), dict(base, args=[]), dict(base, args=['python3']),
                        dict(base, args=[1]), dict(base, args=['/usr/bin/python3', '\x00']),
                        dict(base, extra='unexpected')):
            with self.assertRaises(ValueError):
                PTY.parse_config(encoded(changed), 'tls')
        for raw in (None, '', [], {}, b'x' * 131073, b'{}', b'null', b'[]', b'private fixture'):
            with self.assertRaises(ValueError):
                PTY.parse_config(raw, 'tls')
        with self.assertRaises(ValueError):
            PTY.parse_config(encoded(base), 'unknown')
        self.assertFalse(PTY.exit_event(encoded(complete()), 0, '', 1)['secretEcho'])

    def test_success_requires_clean_child_exit_and_one_scope_prompt(self):
        for status, approvals in ((1, 1), (-2, 1), (0, 0), (0, 2), (0, True)):
            event = PTY.exit_event(encoded(complete()), status, '', approvals)
            self.assertFalse(event['readAdminComplete'])
            self.assertEqual(event['readAdminFailure'], 'read-admin-result-invalid')
        event = PTY.exit_event(encoded(complete()), 0, '', 1)
        self.assertTrue(event['readAdminComplete'])

    def test_terminal_protocol_is_exact_bounded_and_graceful(self):
        source = embedded('readAdminPTY')
        for text in ("'Type ' + approval + ' to confirm, or press Enter to cancel: '",
                     'count > 1', 'approvals == 0', "b'\\n' if cfg['cancelApproval']",
                     "bool(secret) and approvals == 1", 'termios.ECHO', "phase='prompt'", 'scopeApprovals=approvals',
                     'time.monotonic() + 300', 'len(buf) + len(chunk) > MAX_CAPTURE',
                     'os.kill(pid, signum)', 'os.kill(pid, signal.SIGTERM)', 'os.waitpid(pid, 0)'):
            self.assertIn(text, source)
        tree = ast.parse(source)
        prints = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                  and node.func.id == 'print']
        self.assertEqual(len(prints), 3)
        for call in prints:
            self.assertEqual(len(call.args), 1)
            encoded_call = call.args[0]
            self.assertIsInstance(encoded_call, ast.Call)
            self.assertIsInstance(encoded_call.func, ast.Attribute)
            self.assertEqual(encoded_call.func.attr, 'dumps')
        # A signal never kills the process group, and no transcript goes to disk.
        self.assertNotIn('open(', source)
        self.assertNotIn('sys.stderr', source)
        self.assertNotIn('sys.stdout.buffer', source)


if __name__ == '__main__':
    unittest.main()
