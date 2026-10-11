"""Essential current-profile contract fixtures. No native or browser work."""
import copy
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run
import contract as c
import linux_native as linux
from test_contract import plan, h


def current_plan():
    p = plan()
    p['schema'] = c.CURRENT_SCHEMA
    p['currentProfile'] = dict(c.CURRENT_PROFILE)
    p['targets']['windows']['platform'] = 'windows-11-x64'
    p['phases'] = {phase: {'approvalRef': 'fixture-only-' + phase, 'targetId': p['targets']['linux' if phase == 'manager-browser' else 'windows']['id']} for phase in c.CURRENT_PHASES}
    p['historyQuery'] = {'approvalRef': 'fixture-search', 'messagesApprovalRef': 'fixture-messages', 'channel': 'Application', 'eventId': 42, 'startUnix': 1020, 'endUnix': 1080, 'maxRows': 100, 'maxMessages': 1}
    return p


class CurrentContractTests(unittest.TestCase):
    def test_current_is_separate_exact_contract_not_old_approval_promotion(self):
        p = current_plan()
        self.assertIs(c.validate_plan(p, 1500), p)
        self.assertIsNone(c.require_current_setup_gate(p))
        with self.assertRaises(c.Rejected): c.require_current_setup_gate(plan())
        for field, value in [('receiptVersion', 11), ('consentVersion', 'tracebolt.windows-capability-consent.v13'), ('renewal', False), ('renewal', 1), ('setupContract', 'fresh-twenty-read-admin-scopes-v1')]:
            wrong = copy.deepcopy(p); wrong['currentProfile'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(c.Rejected): c.validate_plan(wrong)
        for schema in ['tracebolt.windows-linux-native-parity.v3', c.SCHEMA]:
            with self.assertRaises(c.Rejected): c.validate_plan({**p, 'schema': schema})

    def test_explicit_x64_platform_and_build_no_implicit_os_expansion(self):
        for platform, build in [('windows-11-x64', '22000'), ('windows-server-2025-x64', '26100')]:
            p = current_plan(); p['targets']['windows'].update(platform=platform, osBuild=build)
            c.validate_plan(p)
        for platform, build in [('windows-11-arm64', '26100'), ('windows-server-2022-x64', '26100'), ('windows-11-x64', '19045'), ('windows-server-2025-x64', '26000'), ('windows-server-2025-x64', '27000')]:
            p = current_plan(); p['targets']['windows'].update(platform=platform, osBuild=build)
            with self.assertRaises(c.Rejected): c.validate_plan(p)

    def test_only_one_exact_synthetic_application_query_and_message(self):
        p = current_plan()
        for field, value in [('channel', 'System'), ('eventId', 43), ('startUnix', 999), ('endUnix', 2100), ('endUnix', 1081), ('maxRows', 101), ('maxMessages', 2), ('approvalRef', ''), ('messagesApprovalRef', '')]:
            wrong = copy.deepcopy(p); wrong['historyQuery'][field] = value
            with self.subTest(field=field), self.assertRaises(c.Rejected): c.validate_plan(wrong)
        wrong = copy.deepcopy(p); wrong['historyQuery']['automaticLogRead'] = True
        with self.assertRaises(c.Rejected): c.validate_plan(wrong)

    def test_phase_set_and_requirements_are_explicit(self):
        p = current_plan()
        for old in ('event-enable', 'updates-enable', 'event-disable', 'updates-disable'):
            wrong = copy.deepcopy(p); wrong['phases'][old] = {'approvalRef': 'fixture', 'targetId': p['targets']['windows']['id']}
            with self.assertRaises(c.Rejected): c.validate_plan(wrong)
        for phase in c.CURRENT_PHASES:
            checks = {key: True for key in c.required_checks(p, phase)}
            report = c.report(p, h('plan'), phase, checks, 'observed_phase', 'complete', 1)
            c.validate_phase_report(report, p, h('plan'), phase)
            self.assertFalse(report['fullAcceptance'])
            for key in checks:
                missing = {k: v for k, v in checks.items() if k != key}
                with self.subTest(phase=phase, key=key), self.assertRaises(c.Rejected): c.report(p, h('plan'), phase, missing, 'observed_phase', 'complete', 1)

    def test_current_opt_in_preserves_all_external_gates(self):
        p = current_plan()
        args = types.SimpleNamespace(execute=True, target_id=p['targets']['linux']['id'], phase='manager-browser', approval_reference='fixture-only-manager-browser')
        with patch.dict(os.environ, {}, clear=True), patch('sys.stdin.isatty', return_value=True), patch('sys.flags', types.SimpleNamespace(isolated=True)), patch('sys.dont_write_bytecode', True):
            c.require_native_opt_in(args, 'linux', p)  # pure guard only
            for name in ('CI', 'GITHUB_ACTIONS', 'TF_BUILD', 'BUILD_BUILDID'):
                with patch.dict(os.environ, {name: ''}), self.assertRaises(c.Rejected): c.require_native_opt_in(args, 'linux', p)
            with patch('sys.stdin.isatty', return_value=False), self.assertRaises(c.Rejected): c.require_native_opt_in(args, 'linux', p)
            for name in ('execute', 'target_id', 'phase', 'approval_reference'):
                wrong = copy.copy(args); setattr(wrong, name, None)
                with self.subTest(name=name), self.assertRaises(c.Rejected): c.require_native_opt_in(wrong, 'linux', p)

    def test_browser_spec_carries_same_current_contract_and_explicit_query(self):
        p = current_plan(); value = linux.browser_spec(p, h('plan'))
        self.assertEqual(value['schema'], 'tracebolt.windows-linux-native-parity.browser.v2')
        self.assertEqual(value['currentProfile'], p['currentProfile'])
        self.assertEqual(value['historyQuery'], p['historyQuery'])
        self.assertEqual(value['source'], p['source'])
        self.assertEqual(linux.browser_spec(plan(), h('plan'))['schema'], 'tracebolt.windows-linux-native-parity.browser.v1')

    def test_historical_linux_adapter_refuses_before_native_files_or_process(self):
        with patch.object(linux, 'verify_artifact', side_effect=AssertionError('native read')), patch.object(linux.subprocess, 'Popen', side_effect=AssertionError('native process')):
            with self.assertRaises(c.Rejected) as refused: linux.operate(plan(), h('plan'), {})
            self.assertEqual(refused.exception.reason, 'read_admin_native_gate_unavailable')


class CurrentProductionSyncTests(unittest.TestCase):
    def test_current_profile_matches_fresh_production_declarations(self):
        """Intentional fixed contract: new scopes require review, never auto-adopt."""
        import ast
        import re
        import windows_native as windows
        root = Path(__file__).resolve().parents[2]
        profile = (root / 'internal/lanclient/windows_read_admin_profile.go').read_text()
        setup = (root / 'cmd/windows-service/read_admin_setup.go').read_text()
        fresh = re.search(r'func freshReadAdminSetupConsent\([^\n]+\{\n(.*?)\n\}', setup, re.S)
        self.assertIsNotNone(fresh, 'Fresh native profile changed; explicitly review v2 compatibility.')
        self.assertIn('SchemaVersion: lanclient.WindowsCapabilityConsentVersionV14', fresh[1])
        self.assertIn('Scopes: lanclient.WindowsReadAdminScopesV14()', fresh[1])
        self.assertRegex(profile, r'const WindowsCapabilityConsentVersionV14 = "' + re.escape(c.CURRENT_PROFILE['consentVersion']) + '"')
        receipt = (root / 'cmd/windows-service/read_setup.go').read_text()
        self.assertRegex(receipt, r'func readSetupReceiptVersion\([^\n]+\{\s*if c.SchemaVersion == lanclient.WindowsCapabilityConsentVersionV14 \{\s*return 12\s*\}')
        compatibility = (root / 'internal/windowssetup/compatibility.go').read_text()
        self.assertIn('const ReadAdminContractV10 = "' + c.CURRENT_PROFILE['setupContract'] + '"', compatibility)
        self.assertIn('windowssetup.ExpectedReadAdminV10(', (root / 'cmd/windows-service/entry_setup_windows.go').read_text())
        def constant(reference):
            package, name = reference.split('.')
            values = []
            for path in (root / 'internal' / package).glob('*.go'):
                if not path.name.endswith('_test.go'):
                    values.extend(re.findall(r'^\s*(?:const\s+)?' + re.escape(name) + r'\s*(?:string\s*)?=\s*("[^"\n]+")\s*$', path.read_text(), re.M))
            self.assertEqual(len(values), 1, 'Unsupported scope declaration; update reviewed sync check: ' + reference)
            return ast.literal_eval(values[0])
        def scopes(name):
            match = re.search(r'func ' + name + r'\(\) \[\]string \{\s*return ([^\n]+)\s*\}', profile)
            self.assertIsNotNone(match, 'Unsupported scope expression; explicitly review current native contract.')
            expression = match[1]
            if expression.startswith('[]string{') and expression.endswith('}'):
                return [constant(ref.strip()) for ref in expression[len('[]string{'):-1].split(',')]
            append = re.fullmatch(r'append\((WindowsReadAdminScopes(?:V[0-9]+)?)\(\), ([A-Za-z0-9_.]+)\)', expression)
            self.assertIsNotNone(append, 'Unsupported scope expression; do not automatically broaden consent.')
            return scopes(append[1]) + [constant(append[2])]
        actual = scopes('WindowsReadAdminScopesV14')
        self.assertEqual(len(actual), 21)
        self.assertEqual(actual, list(windows.CURRENT_SCOPES))
        self.assertEqual(actual, list(linux.CURRENT_BROWSER_SCOPES))
        browser = (Path(__file__).parent / 'current_browser.mjs').read_text()
        declared = re.search(r'export const CURRENT_SCOPES = \[(.*?)\];', browser, re.S)
        self.assertIsNotNone(declared)
        self.assertEqual(actual, ast.literal_eval('[' + declared[1] + ']'))


class CurrentLinuxContractTests(unittest.TestCase):
    def test_renewable_config_requires_exact_explicit_mode(self):
        e = {'schemaVersion': 'tracebolt.enrollment-config.renewable.v1', 'automaticRenewal': True, 'profile': 'tls', 'collectionProfile': 'managed-operations-v3'}
        linux.validate_enrollment_mode(e, current_plan())
        for field, value in [('schemaVersion', 'tracebolt.enrollment-config.v2'), ('automaticRenewal', False), ('automaticRenewal', 1), ('profile', 'http-test'), ('collectionProfile', 'windows-inventory-v1')]:
            with self.subTest(field=field), self.assertRaises(c.Rejected): linux.validate_enrollment_mode({**e, field: value}, current_plan())
        for key in ('privateKey', 'automaticGrant', 'unknown'):
            with self.assertRaises(c.Rejected): linux.validate_enrollment_mode({**e, key: True}, current_plan())
        with self.assertRaises(c.Rejected): linux.validate_enrollment_mode(e, plan())
        linux.validate_enrollment_mode({'schemaVersion': 'tracebolt.enrollment-config.v2', 'profile': 'tls'}, plan())

    def test_current_result_never_claims_full_coverage_or_native_from_partial_checks(self):
        p = current_plan()
        r = {'schema': 'tracebolt.windows-linux-native-parity.browser-result.v2', 'runId': p['runId'], 'planSHA256': h('plan'), 'source': p['source'], 'currentProfile': p['currentProfile'], 'status': 'passed', 'reason': 'complete', 'fullAcceptance': False, 'nativeExecution': True, 'checks': {k: True for k in linux.CURRENT_BROWSER_CHECKS}, 'observations': {'scopeCount': 21, 'grantCount': 20, 'coverage': 'partial', 'scopeOutcomes': {k: 'not_observed' for k in linux.CURRENT_BROWSER_SCOPES}, 'historySearchQuality': 'observed', 'historySearchRows': 1, 'historySearchComplete': True, 'historySearchTruncated': False, 'historyMessageQuality': 'observed', 'historyEndpointStatus': '', 'retainedHistoryCoverage': 'not_assessed', 'patchCoverage': 'not_assessed', 'renewalExecution': 'not_observed'}, 'omissions': linux.CURRENT_BROWSER_OMISSIONS}
        r['observations']['scopeOutcomes']['windows-security-coverage-v1'] = 'unsupported'
        self.assertIs(linux.validate_browser_result(r, p, h('plan'), passed=True), r)
        for field in ('fullAcceptance', 'nativeExecution'):
            wrong = copy.deepcopy(r); wrong[field] = not wrong[field]
            with self.assertRaises(c.Rejected): linux.validate_browser_result(wrong, p, h('plan'), passed=True)
        for field, value in [('coverage', 'full'), ('renewalExecution', 'observed'), ('historyMessageQuality', 'unavailable'), ('scopeCount', True), ('grantCount', 19)]:
            wrong = copy.deepcopy(r); wrong['observations'][field] = value
            with self.assertRaises(c.Rejected): linux.validate_browser_result(wrong, p, h('plan'), passed=True)
        for key in linux.CURRENT_BROWSER_CHECKS:
            wrong = copy.deepcopy(r); wrong['checks'][key] = False
            with self.subTest(check=key), self.assertRaises(c.Rejected): linux.validate_browser_result(wrong, p, h('plan'), passed=True)
        for raw_field in ('messageText', 'rawInventory', 'screenshot', 'password'):
            wrong = copy.deepcopy(r); wrong['observations'][raw_field] = 'not permitted'
            with self.assertRaises(c.Rejected): linux.validate_browser_result(wrong, p, h('plan'))


class CurrentTransferTests(unittest.TestCase):
    def test_remove_requires_independent_browser_report_digest_before_host_work(self):
        p = current_plan()
        args = types.SimpleNamespace(execute=True, target_id=p['targets']['windows']['id'], phase='remove', approval_reference='fixture-only-remove', browser_report_sha256=h('transferred-report'))
        with patch.dict(os.environ, {}, clear=True), patch('sys.stdin.isatty', return_value=True), patch('sys.flags', types.SimpleNamespace(isolated=True)), patch('sys.dont_write_bytecode', True):
            c.require_native_opt_in(args, 'windows', p)
            for value in (None, '', '0'*64, 'not-a-digest'):
                wrong = copy.copy(args); wrong.browser_report_sha256 = value
                with self.assertRaises(c.Rejected): c.require_native_opt_in(wrong, 'windows', p)
            wrong = copy.copy(args); wrong.phase = 'setup'; wrong.approval_reference = 'fixture-only-setup'
            with self.assertRaises(c.Rejected): c.require_native_opt_in(wrong, 'windows', p)

    def test_current_template_remains_non_executable(self):
        value = c.strict_json((Path(__file__).parent / 'plan.current.template.json').read_bytes())
        with self.assertRaises(c.Rejected): c.validate_plan(value)

if __name__ == '__main__': unittest.main()
