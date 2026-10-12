"""Inert selection/contract tests; no Go tests, browser, network, or host actions."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pr_checks_test', ROOT / 'tests/security/pr_checks.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
SHA = 'a' * 40


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.packages, self.files = p.graph([
            {'ImportPath': 'localrmm/internal/feature', 'GoFiles': ['feature.go'], 'EmbedFiles': ['generated/data.json']},
            {'ImportPath': 'localrmm/internal/api', 'GoFiles': ['windows_maintenance.go'], 'Imports': ['localrmm/internal/feature']},
            {'ImportPath': 'localrmm/cmd/manager', 'GoFiles': ['main.go'], 'Imports': ['localrmm/internal/api']},
            {'ImportPath': 'localrmm/tests/security', 'TestGoFiles': ['boundary_test.go'], 'TestImports': ['localrmm/internal/feature']},
            {'ImportPath': 'localrmm/internal/unrelated', 'GoFiles': ['unrelated.go'], 'XTestImports': ['localrmm/internal/api']},
            {'ImportPath': 'localrmm/internal/independent', 'GoFiles': ['independent.go']},
        ])

    def select(self, *changes):
        return p.select(changes, self.packages, self.files, SHA)

    def test_verified_generated_allowlist_does_not_erase_actual_go_dependency_selection(self):
        edits = [('M', 'internal/api/windows_maintenance.go')]
        expected = self.select(*edits)
        actual = p.select(edits + [('M', p.GENERATED_ALLOWLIST)], self.packages, self.files, SHA,
                          generated_allowlist_verified=True)
        self.assertEqual(actual, expected)
        self.assertIn('localrmm/internal/api', actual['packages'])
        self.assertIn('localrmm/cmd/manager', actual['packages'])
        self.assertNotIn('localrmm/internal/independent', actual['packages'])
        self.assertFalse(actual['broadGo']); self.assertFalse(actual['broadWeb'])
        self.assertEqual(actual['flows'], ['windows-maintenance'])
        self.assertTrue(self.select(('M', p.GENERATED_ALLOWLIST))['broadGo'])

    def test_allowlist_exception_never_weakens_shared_deleted_unknown_or_generator_changes(self):
        for status, path in [('D', p.GENERATED_ALLOWLIST), ('A', p.GENERATED_ALLOWLIST),
                             ('T', p.GENERATED_ALLOWLIST), ('M', 'go.mod'),
                             ('M', 'tests/security/report_go_failure.py'),
                             ('M', 'tests/security/pr_checks.py'),
                             ('M', 'tests/security/generate_allowlist.py'),
                             ('M', 'tests/security/boundary_test.go'),
                             ('D', 'internal/api/windows_maintenance.go'),
                             ('M', 'internal/feature/unknown_specialtag.go')]:
            with self.subTest(path=path, status=status):
                plan = p.select([('M', p.GENERATED_ALLOWLIST), (status, path)], self.packages, self.files, SHA,
                                generated_allowlist_verified=True)
                self.assertTrue(plan['broadGo']); self.assertTrue(plan['broadWeb'])
                self.assertEqual(plan['packages'], sorted(self.packages))

    def test_canonical_allowlist_rederives_all_source_bytes_and_exact_test_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'go.mod').write_text('module localrmm\n')
            source = root / 'internal/feature'; source.mkdir(parents=True)
            (source / 'feature.go').write_text('package feature\nfunc Value() int { return 1 }\n')
            test = source / 'feature_test.go'; test.write_text('package feature\nfunc TestFeature(t *testing.T) {}\n')
            path = root / p.GENERATED_ALLOWLIST; path.parent.mkdir(parents=True)
            canonical = (json.dumps(p.reporter.derive_allowlist(root), indent=2) + '\n').encode()
            path.write_bytes(canonical); path.chmod(0o644)
            diff = b':100644 100644 ' + b'b' * 40 + b' ' + b'c' * 40 + b' M\0' + p.GENERATED_ALLOWLIST.encode() + b'\0'
            with patch.object(p, 'ROOT', root), patch.object(p, 'capture', return_value=diff):
                self.assertTrue(p.verified_generated_allowlist('b' * 40, SHA))
                for changed in [b'{', canonical.rstrip(), canonical.replace(b'TestFeature', b'TestForged'),
                                canonical.replace(b'"schemaVersion": 1', b'"schemaVersion": 2'),
                                canonical.replace(b'TestFeature', b'')]:
                    path.write_bytes(changed)
                    self.assertFalse(p.verified_generated_allowlist('b' * 40, SHA))
                path.write_bytes(canonical)
                (source / 'feature.go').write_text('package feature\nfunc Value() int { return 2 }\n')
                self.assertFalse(p.verified_generated_allowlist('b' * 40, SHA))
                (source / 'feature.go').write_text('package feature\nfunc Value() int { return 1 }\n')
                test.write_text('package feature\nfunc TestFeature(t *testing.T) {}\nfunc TestNewRoot(t *testing.T) {}\n')
                self.assertFalse(p.verified_generated_allowlist('b' * 40, SHA))
                path.write_bytes((json.dumps(p.reporter.derive_allowlist(root), indent=2) + '\n').encode())
                self.assertTrue(p.verified_generated_allowlist('b' * 40, SHA))
                path.chmod(0o755)
                self.assertFalse(p.verified_generated_allowlist('b' * 40, SHA))
                path.chmod(0o644); path.unlink()
                self.assertFalse(p.verified_generated_allowlist('b' * 40, SHA))
                target = root / 'forged.json'; target.write_bytes(canonical); path.symlink_to(target)
                self.assertFalse(p.verified_generated_allowlist('b' * 40, SHA))
            for changed in [diff.replace(b':100644 100644', b':100755 100644'),
                            diff.replace(b':100644 100644', b':100644 100755'),
                            diff.replace(b' M\0', b' D\0'), diff.replace(b' M\0', b' T\0'), b'']:
                with patch.object(p, 'capture', return_value=changed), patch.object(p.reporter, 'derive_allowlist') as derive:
                    self.assertFalse(p.verified_generated_allowlist('b' * 40, SHA))
                    derive.assert_not_called()

    def test_discovery_requires_verification_before_allowlist_exception(self):
        rows = json.dumps({'ImportPath': 'localrmm/internal/api', 'GoFiles': ['windows_maintenance.go']}).encode()
        diff = b'M\0internal/api/windows_maintenance.go\0M\0' + p.GENERATED_ALLOWLIST.encode() + b'\0'
        for verified in [True, False]:
            with patch.dict(os.environ, {'GITHUB_SHA': SHA, 'TRACEBOLT_BASE_SHA': 'b' * 40}), \
                 patch.object(p, 'capture', side_effect=[SHA.encode() + b'\n', rows, rows, diff]), \
                 patch.object(p, 'verified_generated_allowlist', return_value=verified) as guard:
                result = p.discover()
            guard.assert_called_once_with('b' * 40, SHA)
            self.assertEqual(result['broadGo'], not verified)
            self.assertEqual(result['broadWeb'], not verified)
            self.assertEqual(result['packages'], ['localrmm/internal/api'])

    def test_runtime_test_external_test_and_transitive_import_edges(self):
        plan = self.select(('M', 'internal/feature/feature.go'))
        self.assertEqual(set(plan['packages']), set(self.packages) - {'localrmm/internal/independent'})
        self.assertFalse(plan['broadGo'])
        self.assertIn('localrmm/tests/security', plan['packages'])

    def test_changed_test_maps_to_own_package(self):
        plan = self.select(('M', 'tests/security/boundary_test.go'))
        self.assertTrue(plan['broadGo'])  # Security-contract changes are broad, not omitted.

    def test_embedded_generated_files_select_owners_and_dependents(self):
        self.assertEqual(self.select(('M', 'internal/feature/generated/data.json'))['packages'],
                         self.select(('M', 'internal/feature/feature.go'))['packages'])

    def test_deleted_renamed_unknown_or_unrecognized_shared_sources_are_broad(self):
        for change in [('D', 'internal/feature/feature.go'), ('R100', 'README.md'), ('M', 'unknown'),
                       ('M', 'go.mod'), ('M', 'new/generated.json'), ('M', 'docs/lan-api-examples.json'), ('M', 'x\ninjected'),
                       ('M', '../../outside')]:
            with self.subTest(change=change):
                plan = self.select(change)
                self.assertEqual(plan['packages'], sorted(self.packages))
                self.assertTrue(plan['broadWeb'])
                self.assertEqual(plan['flows'], sorted(p.FLOWS))

    def test_ordinary_api_feature_does_not_force_full_race_or_broad_go(self):
        plan = self.select(('M', 'internal/api/windows_maintenance.go'))
        self.assertFalse(plan['broadGo'])
        self.assertFalse(plan['broadWeb'])
        self.assertEqual(plan['flows'], ['windows-maintenance'])
        self.assertNotIn('localrmm/internal/independent', plan['packages'])

    def test_known_ui_flow_and_related_files_are_selected(self):
        plan = self.select(('M', 'web/src/windows-maintenance.tsx'))
        self.assertEqual(plan['web'], ['src/windows-maintenance.tsx'])
        self.assertEqual(plan['flows'], ['windows-maintenance'])
        self.assertFalse(plan['broadWeb'])

    def test_specific_domains_win_over_generic_browser_prefixes(self):
        for filename, flows in {
            'windows-managed-msi-worklists.tsx': ['windows-fleet-msi'],
            'windows-managed-msi-reusable.tsx': ['windows-fleet-msi'],
            'windows-software-catalogue.tsx': ['windows-fleet-msi'],
            'journal-ai.tsx': ['lan'], 'journal-browse.tsx': ['lan'],
            'windows-update-jobs.tsx': ['windows-mutation-coexistence', 'windows-service-actions'],
            'package-updates.tsx': ['conditional', 'lan'],
            'service-actions.tsx': ['service-action', 'service-action-v2'],
            'windows-managed-msi.tsx': ['windows-fleet-msi', 'windows-managed-msi', 'windows-mutation-coexistence'],
        }.items():
            with self.subTest(filename=filename):
                self.assertEqual(self.select(('M', 'web/src/' + filename))['flows'], flows)

    def test_shared_or_unknown_ui_broadens_instead_of_guessing(self):
        for path in ['web/src/App.tsx', 'web/src/api.ts', 'web/src/new-feature.tsx', 'web/package-lock.json']:
            self.assertTrue(self.select(('M', path))['broadWeb'])

    def test_scheduled_msi_product_and_paired_setup_select_existing_hosted_flows(self):
        msi = {'windows-fleet-msi', 'windows-managed-msi', 'windows-mutation-coexistence'}
        for path, extra in {
            'internal/windowsmanagedmsi/schedule.go': set(),
            'internal/windowsmanagedmsimanager/schedule.go': set(),
            'internal/api/windows_managed_msi.go': set(),
            'internal/enrollmentstore/windows_managed_msi_schedule.go': set(),
            'cmd/windows-managed-msi-manager-setup/main.go': set(),
            'cmd/windows-service/scheduled_msi_plan_test.go': {'lan'},
            'cmd/windows-service/managed_msi_provision_windows.go': {'managed'},
            'cmd/windows-service/mutation_provision_windows.go': {'lan', 'windows-service-actions'},
            'internal/enrollmentstore/windows_mutation_pair.go': {'enrollment', 'windows-service-actions'},
        }.items():
            with self.subTest(path=path):
                package = 'localrmm/' + str(Path(path).parent)
                plan = p.select([('M', path)], {package: set()}, {path: {package}}, SHA)
                self.assertEqual(set(plan['flows']), msi | extra)
                self.assertEqual(plan['packages'], [package])
                self.assertFalse(plan['broadGo'])
                self.assertFalse(plan['broadWeb'])
        for path in ['web/src/windows-managed-msi-schedule.tsx', 'web/src/windows-managed-msi-schedule-types.ts',
                     'web/src/windows-managed-msi-schedule.test.tsx']:
            with self.subTest(path=path):
                self.assertEqual(set(self.select(('M', path))['flows']), msi)

    def test_scheduled_msi_captures_stay_in_fleet_runner_and_both_artifact_allowlists(self):
        self.assertEqual(p.FLOWS['windows-fleet-msi'], 'web/scripts/run-windows-fleet-msi-ci.mjs')
        runner = (ROOT / p.FLOWS['windows-fleet-msi']).read_text()
        self.assertIn('await captureWindowsScheduledMSIFixtures', runner)
        self.assertIn('scheduled.captures.length,scheduledMSIScenes.length*4', runner)
        for name in ['windows-scheduled-msi-results.json', 'windows-scheduled-msi-manifest.json']:
            self.assertIn(name, runner)
            for workflow in ['validate.yml', 'pr-checks.yml']:
                source = (ROOT / '.github/workflows' / workflow).read_text()
                self.assertEqual(source.count('            artifacts/review/' + name + '\n'), 1)

    def test_catalogue_companion_runs_in_focused_fleet_flow_and_retains_evidence(self):
        plan = {'flows': ['windows-fleet-msi'], 'sha': SHA, 'broadWeb': False, 'web': []}
        with patch.object(p, 'run') as run, patch.object(p, 'browser_report'):
            p.browser_checks(plan)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands.count(['node', 'web/scripts/run-windows-msi-catalogue-ci.mjs']), 1)
        with patch.object(p, 'run') as run:
            p.web_checks(plan)
        self.assertIn(['node', 'web/scripts/capture-windows-msi-catalogue-fixtures.mjs', '--check'], [call.args[0] for call in run.call_args_list])
        for name in ['windows-msi-catalogue-results.json', 'windows-msi-catalogue-manifest.json']:
            for workflow in ['validate.yml', 'pr-checks.yml']:
                source = (ROOT / '.github/workflows' / workflow).read_text()
                self.assertEqual(source.count('            artifacts/review/' + name + '\n'), 1)
        report = {'sourceSha': SHA, 'status': 'PASS', 'browserAcceptance': True,
                  'scenes': 3, 'screenshots': 12, 'requestsToRealAPI': 0,
                  'actualMutationRequests': 0, 'nativeAcceptance': False}
        p.validate_catalogue_browser_report(report, SHA)
        for key, value in [('sourceSha', 'b' * 40), ('status', 'FAIL'), ('browserAcceptance', False), ('scenes', 2),
                           ('screenshots', 11), ('actualMutationRequests', 1), ('nativeAcceptance', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.validate_catalogue_browser_report({**report, key: value}, SHA)
        alternate = {**report, 'results': [{'name': 'generic result', 'status': 'PASS'}],
                     'summary': {'passed': 1, 'failed': 0}}
        del alternate['browserAcceptance']
        with self.assertRaises(ValueError):
            p.validate_catalogue_browser_report(alternate, SHA)

    def test_docs_keep_fixed_safety_checks_without_affected_package_claim(self):
        plan = self.select(('M', 'docs/example.md'))
        self.assertEqual(plan['packages'], [])
        self.assertEqual(plan['flows'], [])
        self.assertEqual(sum(map(len, p.CRITICAL.values())), 10)

    def test_lan_selection_runs_actual_node_health_guard_not_only_vitest(self):
        command = ['node', '--test', 'tests/e2e-review/windows-health-fixtures.test.mjs']
        for path in ['tests/e2e-review/lan-browser.mjs', 'tests/e2e-review/windows-health-fixtures.test.mjs',
                     'web/src/windows-health.ts']:
            with self.subTest(path=path):
                plan = self.select(('M', path))
                self.assertIn('lan', plan['flows'])
                with patch.object(p, 'run') as run:
                    p.web_checks(plan)
                calls = [call for call in run.call_args_list if call.args[0] == command]
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0].kwargs['stage'], 'ui-windows-health-contract')
        for path in ['docs/example.md', 'web/src/windows-maintenance.tsx']:
            with patch.object(p, 'run') as run:
                p.web_checks(self.select(('M', path)))
            self.assertNotIn(command, [call.args[0] for call in run.call_args_list])
        with patch.object(p, 'run', side_effect=ValueError('inert guard failed')) as run:
            with self.assertRaisesRegex(ValueError, 'inert guard failed'):
                p.web_checks(self.select(('M', 'tests/e2e-review/lan-browser.mjs')))
        run.assert_called_once_with(command, stage='ui-windows-health-contract')

    def test_deterministic_paths_and_graph_order(self):
        first = [('M', 'internal/feature/feature.go'), ('M', 'web/src/windows-maintenance.tsx')]
        self.assertEqual(self.select(*first), self.select(*reversed(first), first[0]))

    def test_all_existing_ui_configs_receive_related_paths_and_changed_tests_run_directly(self):
        plan = self.select(('M', 'web/src/journal.test.tsx'))
        with patch.object(p, 'run') as run:
            p.web_checks(plan)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any('run' in call and 'src/journal.test.tsx' in call for call in calls))
        self.assertTrue(any('related' in call and 'src/journal.test.tsx' in call for call in calls))
        for config in ['vitest.config.mts', 'v3-dom.config.mts']:
            self.assertTrue(any('related' in call and 'tests/e2e-review/' + config in call
                                and 'web/src/journal.test.tsx' in call for call in calls))

    def test_missing_or_skipped_critical_roots_fail_even_with_successful_go_exit(self):
        def process(args, **kwargs):
            package = args[-1]
            for root in p.CRITICAL[package]:
                kwargs['stdout'].write(json.dumps({'Package': package, 'Test': root, 'Action': 'skip'}).encode() + b'\n')
            return SimpleNamespace(returncode=0)
        with patch.object(p.reporter, 'load_allowlist', return_value=p.CRITICAL), \
             patch.object(p.subprocess, 'run', side_effect=process):
            with self.assertRaises(ValueError): p.go_checks({'packages': []})

    def test_plan_rejects_foreign_sha_commands_traversal_unknown_flow_or_duplicate(self):
        plan = self.select(('M', 'web/src/windows-maintenance.tsx'))
        with patch.dict(os.environ, {'GITHUB_SHA': SHA}):
            self.assertEqual(p.checked_plan(json.dumps(plan)), plan)
            for key, value in [('sha', 'b' * 40), ('packages', ['--help']), ('web', ['src/../../secret']),
                               ('flows', ['injected']), ('flows', ['journal', 'journal']), ('broadWeb', True)]:
                bad = {**plan, key: value}
                with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                    p.checked_plan(json.dumps(bad))

    def test_missing_base_history_selects_broad_without_invoking_git_diff(self):
        rows = json.dumps({'ImportPath': 'localrmm/internal/feature', 'GoFiles': ['feature.go']}).encode()
        with patch.dict(os.environ, {'GITHUB_SHA': SHA, 'TRACEBOLT_BASE_SHA': '0' * 40}), \
                patch.object(p, 'capture', side_effect=[SHA.encode() + b'\n', rows, rows]) as call:
            result = p.discover()
        self.assertTrue(result['broadGo']); self.assertTrue(result['broadWeb'])
        self.assertEqual(call.call_count, 3)

    def test_diff_failure_selects_broad(self):
        rows = json.dumps({'ImportPath': 'localrmm/internal/feature', 'GoFiles': ['feature.go']}).encode()
        with patch.dict(os.environ, {'GITHUB_SHA': SHA, 'TRACEBOLT_BASE_SHA': 'b' * 40}), \
                patch.object(p, 'capture', side_effect=[SHA.encode() + b'\n', rows, rows, ValueError('missing history')]):
            self.assertTrue(p.discover()['broadGo'])

    def test_critical_roots_exist_and_remain_small(self):
        source = p.reporter.load_allowlist()
        for package, roots in p.CRITICAL.items():
            self.assertTrue(set(roots) <= set(source[package]))
        self.assertEqual(sum(map(len, p.CRITICAL.values())), 10)
        self.assertEqual(len(p.CRITICAL), 6)

    def test_full_suite_unchanged_and_not_run_on_pr_or_main_push(self):
        full = (ROOT / '.github/workflows/validate.yml').read_text()
        events = full.split('permissions:', 1)[0]
        self.assertIn('  workflow_dispatch:', events)
        self.assertIn('  schedule:', events)
        for event in ['pull_request:', 'pull_request_target:', 'push:', 'workflow_call:', 'workflow_run:']:
            self.assertNotIn(event, events)
        fast = (ROOT / '.github/workflows/pr-checks.yml').read_text()
        self.assertIn('  pull_request:', fast)
        self.assertIn('  push:\n    branches: [main]', fast)
        self.assertIn('name: PR build and affected-flow checks', fast)
        self.assertIn('if: ${{ always() }}', fast)
        self.assertIn('go build -buildvcs=false ./...', fast)
        self.assertIn('go vet -buildvcs=false ./...', fast)
        self.assertNotIn('pull_request_target', fast)
        self.assertNotIn('contents: write', fast)
        self.assertNotIn('-race', fast)
        self.assertIn('name: focused-ui-review-${{ github.sha }}', fast)
        self.assertIn('if: success()', fast)
        self.assertNotIn('artifacts/review/manager.log', fast)

    def test_windows_only_imports_and_test_imports_reach_linux_dependents(self):
        rows = [{'ImportPath': 'localrmm/internal/feature', 'GoFiles': ['feature.go']},
                {'ImportPath': 'localrmm/internal/feature', 'GoFiles': ['feature_windows.go'], 'TestImports': ['localrmm/internal/windowsdep']},
                {'ImportPath': 'localrmm/internal/windowsdep', 'GoFiles': ['native_windows.go']},
                {'ImportPath': 'localrmm/internal/api', 'Imports': ['localrmm/internal/feature']}]
        graph, files = p.graph(rows)
        result = p.select([('M', 'internal/windowsdep/native_windows.go')], graph, files, SHA,
                          {'localrmm/internal/feature', 'localrmm/internal/api'})
        self.assertEqual(result['packages'], ['localrmm/internal/api', 'localrmm/internal/feature'])
        self.assertTrue(result['broadWeb'])

    def test_browser_reports_refuse_noop_missing_skipped_duplicate_or_foreign(self):
        good = {'sourceSha': SHA, 'status': 'PASS', 'browserAcceptance': True, 'runtimeErrorCount': 0}
        p.validate_browser_report('windows-maintenance', good, SHA)
        for bad in [{}, {**good, 'sourceSha': 'b' * 40}, {**good, 'browserAcceptance': False}, {**good, 'runtimeErrorCount': 1}]:
            with self.assertRaises(ValueError): p.validate_browser_report('windows-maintenance', bad, SHA)
        rows = [{'name': str(i), 'status': 'PASS'} for i in range(19)]
        good = {'sourceSha': SHA, 'results': rows, 'summary': {'passed': 19, 'failed': 0}}
        p.validate_browser_report('conditional', good, SHA)
        for bad in [{**good, 'results': []}, {**good, 'results': rows[:-1]},
                    {**good, 'results': [rows[0]] * 19}, {**good, 'summary': {'passed': 19, 'failed': 0, 'skipped': 1}}]:
            with self.assertRaises(ValueError): p.validate_browser_report('conditional', bad, SHA)

    def test_fixed_browser_entrypoints_exist_and_no_native_acceptance_is_called(self):
        for filename in p.FLOWS.values():
            self.assertTrue((ROOT / filename).is_file(), filename)
            self.assertNotIn('windows_native_acceptance', filename)
            source = (ROOT / filename).read_text()
            self.assertIn('chromium.launch', source)
            self.assertIn('process.exitCode', source)
        self.assertEqual(set(p.BROWSER_REPORTS), set(p.FLOWS))
        for name in ['windows-current-setup-acceptance.yml', 'windows-setup-acceptance.yml']:
            events = (ROOT / '.github/workflows' / name).read_text().split('permissions:', 1)[0]
            for event in ['  workflow_call:', '  schedule:', '  push:']:
                self.assertNotIn(event, events)


if __name__ == '__main__':
    unittest.main()
