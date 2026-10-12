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

    def test_docs_keep_fixed_safety_checks_without_affected_package_claim(self):
        plan = self.select(('M', 'docs/example.md'))
        self.assertEqual(plan['packages'], [])
        self.assertEqual(plan['flows'], [])
        self.assertEqual(sum(map(len, p.CRITICAL.values())), 10)

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
