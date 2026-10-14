"""Inert selection/contract tests; no Go tests, browser, network, or host actions."""
import importlib.util
import io
from contextlib import redirect_stdout
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import subprocess
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

    def test_macos_foreground_builder_fixture_is_fail_closed_in_pr_selector(self):
        workflow = (ROOT / '.github/workflows/pr-checks.yml').read_text()
        anchor = '      - name: Verify selector and full-suite contracts with inert fixtures\n        run: |\n'
        command = "          python3 -I -B -m unittest discover -s tests/release -p 'test_macos_foreground_candidate.py' -v\n"

        def has_exact_registration(text):
            if text.count(anchor) != 1 or text.count(command) != 1:
                return False
            step = text.split(anchor, 1)[1].split('      - name:', 1)[0]
            return (step.count(command) == 1 and 'continue-on-error:' not in step
                    and '|| true' not in step and '; true' not in step)

        self.assertTrue(has_exact_registration(workflow))
        for altered in (workflow.replace(command, ''),
                        workflow.replace(command, command + command),
                        workflow.replace(command, command.rstrip('\n') + ' || true\n'),
                        workflow.replace(command, command.replace("test_macos_foreground_candidate.py", "test_*.py"))):
            self.assertFalse(has_exact_registration(altered))

    def test_macos_service_package_fixture_is_fail_closed_in_pr_selector(self):
        workflow = (ROOT / '.github/workflows/pr-checks.yml').read_text()
        anchor = '      - name: Verify selector and full-suite contracts with inert fixtures\n        run: |\n'
        command = "          python3 -I -B -m unittest discover -s tests/release -p 'test_macos_service_test_package.py' -v\n"

        def has_exact_registration(text):
            if text.count(anchor) != 1 or text.count(command) != 1:
                return False
            step = text.split(anchor, 1)[1].split('      - name:', 1)[0]
            return (step.count(command) == 1 and 'continue-on-error:' not in step
                    and '|| true' not in step and '; true' not in step)

        self.assertTrue(has_exact_registration(workflow))
        for altered in (workflow.replace(command, ''),
                        workflow.replace(command, command + command),
                        workflow.replace(command, command.rstrip('\n') + ' || true\n'),
                        workflow.replace(command, command.replace("test_macos_service_test_package.py", "test_*.py"))):
            self.assertFalse(has_exact_registration(altered))

    def test_macos_prerelease_publisher_fixture_is_fail_closed_in_pr_selector(self):
        workflow = (ROOT / '.github/workflows/pr-checks.yml').read_text()
        anchor = '      - name: Verify selector and full-suite contracts with inert fixtures\n        run: |\n'
        command = "          python3 -I -B -m unittest discover -s tests/macos_release -p 'test_publish_prerelease.py' -v\n"

        def has_exact_registration(text):
            if text.count(anchor) != 1 or text.count(command) != 1:
                return False
            step = text.split(anchor, 1)[1].split('      - name:', 1)[0]
            return (step.count(command) == 1 and 'continue-on-error:' not in step
                    and '|| true' not in step and '; true' not in step)

        self.assertTrue(has_exact_registration(workflow))
        for altered in (workflow.replace(command, ''),
                        workflow.replace(command, command + command),
                        workflow.replace(command, command.rstrip('\n') + ' || true\n'),
                        workflow.replace(command, command.replace("test_publish_prerelease.py", "test_*.py"))):
            self.assertFalse(has_exact_registration(altered))

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
            'windows-update-retirement.tsx': ['windows-mutation-coexistence', 'windows-service-actions'],
            'windows-update-retirement-resource.ts': ['windows-mutation-coexistence', 'windows-service-actions'],
            'windows-update-retirement.test.tsx': ['windows-mutation-coexistence', 'windows-service-actions'],
            'package-updates.tsx': ['conditional', 'lan'],
            'service-actions.tsx': ['service-action', 'service-action-v2'],
            'windows-managed-msi.tsx': ['windows-fleet-msi', 'windows-managed-msi', 'windows-mutation-coexistence'],
        }.items():
            with self.subTest(filename=filename):
                self.assertEqual(self.select(('M', 'web/src/' + filename))['flows'], flows)

    def test_selected_download_capture_scripts_reuse_exact_existing_flow(self):
        for name in ['windows-update-download-browser.mjs', 'windows-update-download-fixtures.test.mjs']:
            with self.subTest(name=name):
                path = 'tests/e2e-review/' + name
                self.assertEqual(p.DOMAIN_SCRIPTS[path], {'windows-service-actions'})
                plan = self.select(('A', path))
                self.assertEqual(plan['flows'], ['windows-service-actions'])
                self.assertFalse(plan['broadWeb'])
        for name in ['windows-update-download.tsx', 'windows-update-download.test.tsx']:
            self.assertEqual(self.select(('A', 'web/src/' + name))['flows'],
                             ['windows-mutation-coexistence', 'windows-service-actions'])

    def test_shared_or_unknown_ui_broadens_instead_of_guessing(self):
        for path in ['web/src/App.tsx', 'web/src/api.ts', 'web/src/new-feature.tsx', 'web/package-lock.json']:
            self.assertTrue(self.select(('M', path))['broadWeb'])

    def test_exact_owned_scripts_select_the_existing_complete_fleet_flow(self):
        expected = {
            'capture-windows-msi-catalogue-fixtures.mjs',
            'capture-windows-reusable-msi-fixtures.mjs', 'capture-windows-scheduled-msi-fixtures.mjs',
            'capture-windows-software-catalogue-fixtures.mjs', 'run-windows-fleet-msi-ci.mjs',
            'run-windows-msi-catalogue-ci.mjs',
            'windows-msi-catalogue-scenes.json',
        }
        self.assertEqual({path for path, flows in p.DOMAIN_SCRIPTS.items() if flows == {'windows-fleet-msi'}}, {'web/scripts/' + name for name in expected})
        for path, flows in p.DOMAIN_SCRIPTS.items():
            if flows != {'windows-fleet-msi'}:
                continue
            self.assertEqual(flows, {'windows-fleet-msi'})
            self.assertTrue((ROOT / path).is_file())
            for status in ['A', 'M']:
                with self.subTest(path=path, status=status):
                    plan = self.select((status, path))
                    self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
                    self.assertEqual(plan['packages'], []); self.assertEqual(plan['web'], [])
                    self.assertEqual(plan['flows'], ['windows-fleet-msi'])
                    with patch.object(p, 'run') as run, patch.object(p, 'browser_report') as report:
                        p.browser_checks(plan)
                    self.assertEqual([call.args[0] for call in run.call_args_list], [
                        ['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'],
                        ['node', 'web/scripts/run-windows-fleet-msi-ci.mjs'],
                        ['node', 'web/scripts/run-windows-msi-catalogue-ci.mjs'],
                    ])
                    report.assert_called_once_with('windows-fleet-msi', SHA)

    def test_first_report_selects_bounded_hosted_flow_and_source_dependencies(self):
        owned = {'web/scripts/' + name for name in ['capture-first-report-fixtures.mjs',
                 'run-first-report-ci.mjs', 'check-first-report-evidence.mjs',
                 'first-report-contract.mjs', 'first-report-contract.node.mjs']}
        self.assertEqual({path for path, flows in p.DOMAIN_SCRIPTS.items() if flows == {'first-report'}}, owned)
        for path in owned:
            self.assertTrue((ROOT / path).is_file())
            for status in ['A', 'M']:
                plan = self.select((status, path))
                self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
                self.assertEqual(plan['flows'], ['first-report'])
        shared = self.select(('M', 'web/scripts/capture-windows-fleet-msi-fixtures.mjs'))
        self.assertEqual(shared['flows'], ['first-report', 'windows-fleet-msi'])
        self.assertFalse(shared['broadWeb'])
        for path in ['web/src/enrollment.tsx', 'web/src/enrollment-types.ts', 'web/src/enrollment-report.tsx',
                     'web/src/report-time.tsx', 'web/src/first-report-status.test.tsx']:
            plan = self.select(('M', path))
            self.assertIn('first-report', plan['flows'])
            self.assertIn(path.removeprefix('web/'), plan['web'])
        for path in ['web/src/enrollment.tsx', 'web/src/enrollment-types.ts', 'web/src/enrollment-report.tsx']:
            self.assertIn('enrollment', self.select(('M', path))['flows'])
        for change in [('D', next(iter(owned))), ('M', 'web/scripts/first-report-unknown.mjs'),
                       ('M', 'web/src/App.tsx'), ('M', 'web/package-lock.json')]:
            self.assertEqual(self.select(change)['flows'], sorted(p.FLOWS))

    def test_first_report_runs_inert_contract_and_rechecks_success_before_upload(self):
        plan = {'flows': ['first-report'], 'sha': SHA, 'broadWeb': False, 'web': []}
        with patch.object(p, 'run') as run, patch.object(p, 'browser_report') as report:
            p.browser_checks(plan)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'],
            ['node', 'web/scripts/run-first-report-ci.mjs']])
        report.assert_called_once_with('first-report', SHA)
        with patch.object(p, 'run') as run:
            p.web_checks(plan)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(['node', 'web/scripts/capture-first-report-fixtures.mjs', '--check'], commands)
        self.assertIn(['node', '--test', '--test-concurrency=1', 'web/scripts/first-report-contract.node.mjs'], commands)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); output = root / 'artifacts/review'; output.mkdir(parents=True)
            (output / 'first-report-results.json').write_text(json.dumps({'sourceSha': SHA, 'status': 'PASS', 'browserAcceptance': True}))
            with patch.object(p, 'ROOT', root), patch.object(p, 'run') as run:
                p.browser_report('first-report', SHA)
            run.assert_called_once_with(['node', 'web/scripts/check-first-report-evidence.mjs', SHA], stage='browser-first-report-evidence')
            with patch.object(p, 'ROOT', root), patch.object(p, 'run', side_effect=ValueError('invalid evidence')):
                with self.assertRaises(ValueError):
                    p.browser_report('first-report', SHA)
        workflow = (ROOT / '.github/workflows/pr-checks.yml').read_text()
        for name in ['first-report-results.json', 'first-report-manifest.json']:
            self.assertEqual(workflow.count('            artifacts/review/' + name + '\n'), 1)
        self.assertIn('            artifacts/review/synthetic-*.png\n', workflow)
        self.assertIn('      - name: Keep successful focused public-safe screenshots only\n        if: success()', workflow)
        self.assertNotIn('workflow_dispatch:', workflow)
        self.assertIn("      TRACEBOLT_SOURCE_SHA: ${{ github.sha }}", workflow)
        self.assertIn('npx playwright install --with-deps chromium', workflow)

    def test_first_report_failed_process_never_prints_raw_output_or_validates_success(self):
        marker = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD'
        def process(args, **kwargs):
            kwargs['stdout'].write(marker.encode())
            return SimpleNamespace(returncode=1 if args == ['node', p.FLOWS['first-report']] else 0)
        output = io.StringIO()
        with patch.object(p.subprocess, 'run', side_effect=process), patch.object(p, 'browser_report') as report, redirect_stdout(output):
            with self.assertRaises(ValueError):
                p.browser_checks({'flows': ['first-report'], 'sha': SHA})
        self.assertIn('FAIL stage: browser-first-report', output.getvalue())
        self.assertNotIn(marker, output.getvalue()); report.assert_not_called()

    def test_exact_retirement_fixture_selects_its_existing_update_owner(self):
        expected = {'tests/e2e-review/windows-update-retirement-browser.mjs',
                    'tests/e2e-review/windows-update-retirement-fixtures.test.mjs',
                    'tests/e2e-review/windows-update-download-browser.mjs',
                    'tests/e2e-review/windows-update-download-fixtures.test.mjs',
                    'web/scripts/capture-windows-complete-service-health.mjs',
                    'web/scripts/check-windows-complete-service-health-evidence.mjs',
                    'web/scripts/windows-complete-service-health-contract.mjs',
                    'web/scripts/windows-complete-service-health-contract.node.mjs',
                    'web/scripts/windows-complete-service-health-scenes.json',
                    }
        self.assertEqual({path for path, flows in p.DOMAIN_SCRIPTS.items()
                          if flows == {'windows-service-actions'}}, expected)
        for path in expected:
            self.assertTrue((ROOT / path).is_file())
            for status in ['A', 'M']:
                plan = self.select((status, path))
                self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
                self.assertEqual(plan['flows'], ['windows-service-actions'])
                with patch.object(p, 'run') as run:
                    p.web_checks(plan)
                self.assertIn(['node', '--test', 'tests/e2e-review/windows-update-retirement-fixtures.test.mjs'],
                              [call.args[0] for call in run.call_args_list])
        # A new caller must be reviewed before narrowing this exact dependency.
        consumers = set()
        for directory in ['web/scripts', 'web/src', 'tests/e2e-review']:
            for source in (ROOT / directory).rglob('*'):
                if source.suffix in {'.js', '.mjs', '.ts', '.tsx', '.mts'} and 'windows-update-retirement-browser.mjs' in source.read_text():
                    consumers.add(source.relative_to(ROOT).as_posix())
        self.assertEqual(consumers, {'tests/e2e-review/windows-service-actions-runner.mjs',
                                     'tests/e2e-review/windows-update-retirement-fixtures.test.mjs',
                                     'tests/e2e-review/paused-windows-routes.test.mjs'})

    def test_paused_windows_route_regression_selects_exact_owners_and_runs_once(self):
        path = 'tests/e2e-review/paused-windows-routes.test.mjs'
        flows = {'windows-managed-msi', 'windows-mutation-coexistence', 'windows-storage-io', 'windows-service-actions'}
        self.assertEqual(p.DOMAIN_SCRIPTS[path], flows)
        for status in ['A', 'M']:
            plan = self.select((status, path))
            self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
            self.assertEqual(set(plan['flows']), flows)
        for selected in [*([flow] for flow in sorted(flows)), sorted(flows), ['lan'], ['shell'], []]:
            with patch.object(p, 'run') as run, patch.object(p, 'run_vitest'):
                p.web_checks({'flows': selected, 'broadWeb': False, 'web': []})
            calls = [call for call in run.call_args_list if call.args[0] == ['node', '--test', path]]
            self.assertEqual(len(calls), int(bool(flows & set(selected))))
            if calls: self.assertEqual(calls[0].kwargs['stage'], 'ui-paused-windows-routes-contract')
        for status, other in [('D', path), ('T', path), ('M', 'tests/e2e-review/paused-detail-route.mjs'),
                              ('M', 'tests/e2e-review/paused-windows-new.test.mjs')]:
            plan = self.select((status, other))
            self.assertTrue(plan['broadGo']); self.assertTrue(plan['broadWeb'])
            self.assertEqual(set(plan['flows']), set(p.FLOWS))

    def test_retirement_browser_report_uses_the_canonical_source_validator(self):
        plan = self.select(('M', 'tests/e2e-review/windows-update-retirement-browser.mjs'))
        with patch.object(p, 'run') as run, patch.object(p, 'browser_report') as report:
            p.browser_checks(plan)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'],
            ['node', 'tests/e2e-review/windows-service-actions-runner.mjs'],
            ['node', 'tests/e2e-review/windows-update-retirement-browser.mjs', '--check-evidence', SHA],
            ['node', 'tests/e2e-review/windows-update-download-browser.mjs', '--check-evidence', SHA],
            ['node', 'web/scripts/check-windows-complete-service-health-evidence.mjs', SHA],
        ])
        report.assert_called_once_with('windows-service-actions', SHA)

    def test_exact_fleet_group_helpers_select_existing_owner_and_inert_contract(self):
        expected = {'tests/e2e-review/fleet-groups-browser.mjs',
                    'tests/e2e-review/fleet-groups-evidence.mjs',
                    'tests/e2e-review/fleet-groups-fixtures.test.mjs'}
        self.assertEqual({path for path, flows in p.DOMAIN_SCRIPTS.items() if flows == {'fleet-groups'}}, expected)
        for path in expected:
            for status in ['A', 'M']:
                plan = self.select((status, path))
                self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
                self.assertEqual(plan['flows'], ['fleet-groups'])
                with patch.object(p, 'run') as run:
                    p.web_checks(plan)
                self.assertEqual([call.args[0] for call in run.call_args_list].count(
                    ['node', '--test', 'tests/e2e-review/fleet-groups-fixtures.test.mjs']), 1)
                with patch.object(p, 'run') as run, patch.object(p, 'browser_report') as report:
                    p.browser_checks(plan)
                self.assertEqual([call.args[0] for call in run.call_args_list], [
                    ['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'],
                    ['node', 'tests/e2e-review/fleet-groups-runner.mjs']])
                report.assert_called_once_with('fleet-groups', SHA)
        # Only these checked-in consumers may support this exact narrowing.
        consumers = {name: set() for name in ['fleet-groups-browser.mjs', 'fleet-groups-evidence.mjs', 'fleet-groups-fixtures.test.mjs']}
        for directory in ['web/scripts', 'web/src', 'tests/e2e-review']:
            for source in (ROOT / directory).rglob('*'):
                if source.suffix in {'.js', '.mjs', '.ts', '.tsx', '.mts'}:
                    text = source.read_text()
                    for name in consumers:
                        if name in text: consumers[name].add(source.relative_to(ROOT).as_posix())
        self.assertEqual(consumers, {
            'fleet-groups-browser.mjs': {'tests/e2e-review/fleet-groups-runner.mjs', 'tests/e2e-review/fleet-groups-fixtures.test.mjs'},
            'fleet-groups-evidence.mjs': {'tests/e2e-review/fleet-groups-browser.mjs'},
            'fleet-groups-fixtures.test.mjs': {'tests/e2e-review/fleet-groups-fixtures.test.mjs'},
        })
        runner = (ROOT / 'tests/e2e-review/fleet-groups-runner.mjs').read_text()
        self.assertIn('fleetGroupsBrowserCase({page,expect,base,login,shot})', runner)
        self.assertIn('requireFleetGroupsEvidence(screenshots,sourceSha)', runner)
        self.assertIn('if(routes.failures!==0||routes.pending!==0)passed=false', runner)
        for path in ['tests/e2e-review/fleet-groups-new-helper.mjs', 'tests/e2e-review/fleet-groups-runner.mjs',
                     'web/src/windows-complete-service-health-go-fixture.json', 'web/src/windows-complete-group-service-go-fixture.json']:
            plan = self.select(('M', path)); self.assertTrue(plan['broadGo']); self.assertTrue(plan['broadWeb'])

    def test_complete_service_component_capture_selection_and_artifacts(self):
        for filename in ['windows-service-health-complete.tsx', 'windows-service-health-complete-resource.ts',
                         'windows-service-health-complete-types.ts', 'windows-service-health-complete-fixture.ts',
                         'fleet-group-service-checks-complete.tsx', 'fleet-group-service-checks-complete-workflow.ts',
                         'windows-full-services-picker.tsx', 'fleet-groups.tsx']:
            plan = self.select(('M', 'web/src/' + filename))
            self.assertIn('windows-service-actions', plan['flows'])
            self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
        self.assertIn('windows-service-actions', p.flow_names('internal/windowsservicehealth'))
        with patch.object(p, 'run') as run:
            p.web_checks(plan)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands.count(['node', 'web/scripts/capture-windows-complete-service-health.mjs', '--check']), 1)
        self.assertEqual(commands.count(['node', '--test', 'web/scripts/windows-complete-service-health-contract.node.mjs']), 1)
        for workflow in ['pr-checks.yml', 'validate.yml']:
            text = (ROOT / '.github/workflows' / workflow).read_text()
            for filename in ['windows-complete-service-health-manifest.json', 'complete-service-single-beyond-preview-en-1440.png']:
                self.assertIn(filename, text)
        full = (ROOT / '.github/workflows/validate.yml').read_text()
        self.assertIn('node --test web/scripts/windows-complete-service-health-contract.node.mjs', full)
        self.assertIn('node web/scripts/check-windows-complete-service-health-evidence.mjs "$TRACEBOLT_SOURCE_SHA"', full)

    def test_fleet_software_owns_focused_node_and_hosted_evidence_contracts(self):
        for filename in ['check-windows-fleet-software-evidence.mjs', 'capture-windows-fleet-software.mjs',
                         'run-windows-fleet-software-ci.mjs', 'windows-fleet-software-contract.mjs',
                         'windows-fleet-software-scenes.json', 'windows-fleet-software-contract.node.mjs']:
            plan = self.select(('M', 'web/scripts/' + filename))
            self.assertEqual(plan['flows'], ['windows-fleet-software'])
            self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
        plan = self.select(('M', 'web/src/windows-fleet-software.tsx'))
        self.assertEqual(plan['flows'], ['windows-fleet-software'])
        self.assertEqual(p.flow_names('internal/windowsfullsoftware/fleet.go'), set())
        self.assertEqual(p.flow_names('internal/windowsfullsoftware'), {'windows-full-software', 'windows-fleet-software'})
        with patch.object(p, 'run') as run:
            p.web_checks(plan)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands.count(['node', 'web/scripts/capture-windows-fleet-software.mjs', '--check']), 1)
        self.assertEqual(commands.count(['node', '--test', 'web/scripts/windows-fleet-software-contract.node.mjs']), 1)
        for workflow in ['pr-checks.yml', 'validate.yml']:
            text = (ROOT / '.github/workflows' / workflow).read_text()
            for filename in ['windows-fleet-software-results.json', 'windows-fleet-software-manifest.json', 'synthetic-windows-fleet-software-*.png']:
                self.assertIn(filename, text)
        self.assertIn('node --test web/scripts/windows-fleet-software-contract.node.mjs', (ROOT / '.github/workflows/validate.yml').read_text())
        self.assertFalse((ROOT / 'web/scripts/windows-fleet-software-contract.test.mjs').exists())
        runner = (ROOT / 'web/scripts/run-windows-fleet-software-ci.mjs').read_text()
        self.assertIn("RUNNER_ENVIRONMENT === 'github-hosted'", runner)
        self.assertIn('await validateEvidence(output, sourceSha)', runner)

    def test_cve_bridge_owns_one_changed_flow_and_shared_evidence_validator(self):
        for filename in ['check-linux-cve-update-review-evidence.mjs', 'capture-linux-cve-update-review.mjs', 'run-linux-cve-update-review-ci.mjs',
                         'linux-cve-update-review-contract.mjs', 'linux-cve-update-review-scenes.json',
                         'linux-cve-update-review-contract.node.mjs']:
            plan = self.select(('M', 'web/scripts/' + filename))
            self.assertEqual(plan['flows'], ['linux-cve-update-review'])
            self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
        plan = self.select(('M', 'web/src/linux-cve-update-review.ts'))
        self.assertEqual(plan['flows'], ['linux-cve-update-review'])
        with patch.object(p, 'run') as run:
            p.web_checks(plan)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands.count(['node', 'web/scripts/capture-linux-cve-update-review.mjs', '--check']), 1)
        self.assertEqual(commands.count(['node', '--test', 'web/scripts/linux-cve-update-review-contract.node.mjs']), 1)
        for name in ['linux-cve-update-review-results.json', 'linux-cve-update-review-manifest.json', 'synthetic-linux-cve-update-review-*.png']:
            self.assertIn(name, (ROOT / '.github/workflows/pr-checks.yml').read_text())
        node_contract = ROOT / 'web/scripts/linux-cve-update-review-contract.node.mjs'
        self.assertTrue(node_contract.is_file())
        self.assertFalse(node_contract.with_name('linux-cve-update-review-contract.test.mjs').exists())
        self.assertIn('node --test web/scripts/linux-cve-update-review-contract.node.mjs', (ROOT / '.github/workflows/validate.yml').read_text())
        runner = (ROOT / 'web/scripts/run-linux-cve-update-review-ci.mjs').read_text()
        self.assertIn("RUNNER_ENVIRONMENT === 'github-hosted'", runner)
        self.assertIn('await validateEvidence(output, sourceSha)', runner)

    def test_owned_script_selection_unions_with_go_dependencies_and_other_flows(self):
        edits = [('M', 'internal/api/windows_maintenance.go'), ('M', 'web/src/windows-maintenance.test.tsx')]
        expected = self.select(*edits)
        changes = edits + [('M', path) for path in p.DOMAIN_SCRIPTS] + [('M', p.GENERATED_ALLOWLIST)]
        plan = p.select(changes, self.packages, self.files, SHA, generated_allowlist_verified=True)
        self.assertEqual(plan['packages'], expected['packages'])
        self.assertEqual(plan['web'], expected['web'])
        self.assertEqual(plan['flows'], ['first-report', 'fleet-groups', 'linux-cve-update-review', 'windows-fleet-msi', 'windows-fleet-software', 'windows-maintenance',
                                        'windows-managed-msi', 'windows-mutation-coexistence', 'windows-service-actions', 'windows-storage-io'])
        self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
        self.assertEqual(plan, p.select(list(reversed(changes)), self.packages, self.files, SHA,
                                      generated_allowlist_verified=True))

    def test_exact_msi_ui_owners_keep_changed_and_related_interaction_checks(self):
        self.assertEqual({path for path, flows in p.DOMAIN_UI.items() if flows == {'windows-fleet-msi'}}, {
            'web/src/windows-fleet-managed-msi.css',
            'web/src/windows-fleet-managed-msi.test.tsx',
            'web/src/windows-reusable-managed-msi.test.tsx',
        })
        for path, flows in p.DOMAIN_UI.items():
            if flows != {'windows-fleet-msi'}:
                continue
            with self.subTest(path=path):
                self.assertEqual(flows, {'windows-fleet-msi'})
                self.assertTrue((ROOT / path).is_file())
                plan = self.select(('M', path))
                self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
                self.assertEqual(plan['flows'], ['windows-fleet-msi'])
                self.assertEqual(plan['web'], [path.removeprefix('web/')])
                with patch.object(p, 'run') as run:
                    p.web_checks(plan)
                calls = [call.args[0] for call in run.call_args_list]
                self.assertIn(['node', 'web/scripts/capture-windows-msi-catalogue-fixtures.mjs', '--check'], calls)
                self.assertTrue(any('related' in call and path.removeprefix('web/') in call for call in calls))
                for config in ['vitest.config.mts', 'v3-dom.config.mts']:
                    self.assertTrue(any('related' in call and 'tests/e2e-review/' + config in call and path in call
                                        for call in calls))
                if '.test.' in path:
                    self.assertTrue(any('run' in call and path.removeprefix('web/') in call for call in calls))
                for status in ['D', 'R100', 'T']:
                    deleted = self.select((status, path))
                    self.assertTrue(deleted['broadGo']); self.assertTrue(deleted['broadWeb'])
        for path in ['web/src/windows-fleet-managed-msi-new-helper.ts',
                     'web/src/windows-reusable-managed-msi-new.test.tsx']:
            self.assertTrue(self.select(('M', path))['broadWeb'])

    def test_owned_script_map_never_exempts_unknown_shared_security_or_deleted_paths(self):
        for change in [
            ('M', 'web/scripts/capture-windows-new-msi-fixtures.mjs'),
            ('M', 'web/scripts/run-windows-new-msi-ci.mjs'),
            ('M', 'web/scripts/windows-msi-new-scenes.json'),
            ('M', 'web/scripts/capture-screenshots.mjs'),
            ('M', 'web/scripts/check-test-environments.mjs'),
            ('M', 'web/scripts/windows-updates-fixtures.go'),
            ('M', 'tests/e2e-review/windows-maintenance-runner.mjs'),
            ('M', 'tests/fixtures/windows-maintenance-view.json'),
            ('M', 'internal/windowsstorageio/testdata/snapshot.json'),
            ('M', 'tests/security/pr_checks.py'),
            ('M', 'tests/security/report_go_failure.py'),
            ('M', p.GENERATED_ALLOWLIST),
            ('M', 'web/scripts/../scripts/run-windows-fleet-msi-ci.mjs'),
            *[(status, path) for path in p.DOMAIN_SCRIPTS for status in ['D', 'R100', 'T']],
        ]:
            with self.subTest(change=change):
                plan = self.select(('M', 'web/scripts/run-windows-fleet-msi-ci.mjs'), change)
                self.assertTrue(plan['broadGo']); self.assertTrue(plan['broadWeb'])
                self.assertEqual(plan['packages'], sorted(self.packages))
                self.assertEqual(plan['flows'], sorted(p.FLOWS))
        plan = self.select(('M', 'web/scripts/run-windows-fleet-msi-ci.mjs'), ('M', 'web/src/api.ts'))
        self.assertFalse(plan['broadGo']); self.assertTrue(plan['broadWeb'])
        self.assertEqual(plan['flows'], sorted(p.FLOWS))

    def test_msi_script_dependency_ownership_and_complete_capture_calls(self):
        # Fail closed on new direct source consumers: an exact script must never
        # become a cross-domain helper while retaining only its old flow mapping.
        # This bounded literal-reference contract supplements the reviewed map;
        # it is not a JavaScript dependency resolver or a prefix-based exemption.
        names = {Path(path).name for path, flows in p.DOMAIN_SCRIPTS.items() if flows == {'windows-fleet-msi'}}
        for directory in ['web/scripts', 'web/src', 'tests/e2e-review']:
            for source in (ROOT / directory).rglob('*'):
                if source.suffix not in {'.js', '.cjs', '.mjs', '.ts', '.tsx', '.mts', '.cts'}:
                    continue
                text = source.read_text()
                if any(name in text for name in names):
                    relative = source.relative_to(ROOT).as_posix()
                    self.assertIn(relative, p.DOMAIN_SCRIPTS, relative)
        runner = (ROOT / p.FLOWS['windows-fleet-msi']).read_text()
        for name, function, producer, result in [
            ('capture-windows-fleet-msi-fixtures.mjs', 'captureWindowsFleetMSIFixtures', 'fleet', 'manifest'),
            ('capture-windows-fleet-msi-fixtures.mjs', 'captureWindowsSavedMSIFixtures', 'saved', 'saved'),
            ('capture-windows-reusable-msi-fixtures.mjs', 'captureWindowsReusableMSIFixtures', 'reusable', 'reusable'),
            ('capture-windows-scheduled-msi-fixtures.mjs', 'captureWindowsScheduledMSIFixtures', 'scheduled', 'scheduled'),
            ('capture-windows-software-catalogue-fixtures.mjs', 'captureSoftwareCatalogueFixtures', 'recent-package', 'catalogue'),
        ]:
            self.assertIn("from './" + name + "'", runner)
            # Pin the full producer call and its matching closed diagnostic
            # coordinate, between the same producer's capture/validate phases.
            self.assertIn("phase('" + producer + "','capture');\n  const " + result
                          + '=await ' + function + "({browser,expect,output,onCase:currentCase('"
                          + producer + "')});\n  phase('" + producer + "','validate');", runner)
        companion = (ROOT / 'web/scripts/run-windows-msi-catalogue-ci.mjs').read_text()
        self.assertIn("from './capture-windows-msi-catalogue-fixtures.mjs'", companion)
        self.assertIn('await captureWindowsMSICatalogueFixtures({browser,expect,output})', companion)

    def test_ordinary_domain_test_fixtures_keep_exact_owners_or_conservative_fallback(self):
        package = 'localrmm/internal/windowsmaintenance'
        packages, files = p.graph([
            {'ImportPath': package, 'GoFiles': ['maintenance.go'], 'TestGoFiles': ['fixtures_test.go'],
             'TestEmbedFiles': ['testdata/fixture.json']},
            {'ImportPath': 'localrmm/internal/api', 'Imports': [package]},
            {'ImportPath': 'localrmm/tests/domain', 'TestImports': [package]},
            {'ImportPath': 'localrmm/internal/independent'},
        ])
        for path in ['internal/windowsmaintenance/fixtures_test.go', 'internal/windowsmaintenance/testdata/fixture.json']:
            with self.subTest(path=path):
                plan = p.select([('M', path)], packages, files, SHA)
                self.assertFalse(plan['broadGo'])
                self.assertEqual(plan['packages'], sorted(set(packages) - {'localrmm/internal/independent'}))
                # The generic nested embed name has a Go owner, but no explicit
                # browser-domain name; its API dependents therefore broaden web.
                nested_embed = path.endswith('.json')
                self.assertEqual(plan['broadWeb'], nested_embed)
                self.assertEqual(plan['flows'], sorted(p.FLOWS) if nested_embed else ['windows-maintenance'])
        for path in ['web/src/windows-maintenance-fixture.ts', 'web/src/windows-maintenance.test.tsx']:
            with self.subTest(path=path):
                plan = self.select(('M', path))
                self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
                self.assertEqual(plan['packages'], []); self.assertEqual(plan['web'], [path.removeprefix('web/')])
                self.assertEqual(plan['flows'], ['windows-maintenance'])

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

    def test_fleet_failure_reports_only_bounded_same_source_recipe_location(self):
        failure = {'phase': 'capture', 'producer': 'scheduled', 'scene': 'fleet-shared-window-unchecked', 'locale': 'de', 'width': 390}
        report = {'sourceSha': SHA, 'status': 'FAIL', 'browserAcceptance': False, 'variants': 0,
                  'screenshots': 0, 'requestsToRealAPI': 0, 'nativeAcceptance': False,
                  'disclosure': 'synthetic fixture', 'failure': failure}
        marker = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD'
        cases = [('valid', report, True)]
        for producer, scenes in p.FLEET_MSI_FAILURE_SCENES.items():
            for scene in scenes:
                cases.append(('coordinate', {**report, 'failure': {**failure, 'producer': producer, 'scene': scene}}, True))
        for phase in ['launch', 'close']:
            cases.append((phase, {**report, 'failure': dict.fromkeys(failure, None) | {'phase': phase}}, True))
        for producer in p.FLEET_MSI_FAILURE_SCENES:
            for phase in ['capture', 'validate']:
                cases.append((phase, {**report, 'failure': dict.fromkeys(failure, None) | {'phase': phase, 'producer': producer}}, True))
        for key, value in [('sourceSha', 'b' * 40), ('status', 'PASS'), ('screenshots', True), ('nativeAcceptance', True), ('raw', marker)]:
            cases.append((key, {**report, key: value}, False))
        for key, value in [('phase', marker), ('producer', marker), ('scene', marker), ('locale', marker), ('width', marker), ('raw', marker), ('scene', ['scheduled'])]:
            cases.append((key, {**report, 'failure': {**failure, key: value}}, False))
        cases.extend([('malformed', marker.encode(), False), ('oversized', b' ' * 4097, False),
                      ('duplicate', json.dumps(report).replace('"phase": "capture"', '"phase": "capture", "phase": "capture"').encode(), False),
                      ('missing', None, False), ('symlink', report, False)])
        for name, value, admitted in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); target = root / 'artifacts/review/windows-fleet-msi-results.json'
                target.parent.mkdir(parents=True)
                calls = []
                def process(args, **kwargs):
                    calls.append(args)
                    kwargs['stdout'].write(marker.encode())
                    if args == ['node', p.FLOWS['windows-fleet-msi']]:
                        if value is not None:
                            raw = value if isinstance(value, bytes) else json.dumps(value).encode()
                            if name == 'symlink':
                                backing = root / 'untrusted.json'; backing.write_bytes(raw); target.symlink_to(backing)
                            else:
                                target.write_bytes(raw)
                        return SimpleNamespace(returncode=1)
                    return SimpleNamespace(returncode=0)
                output = io.StringIO()
                with patch.object(p, 'ROOT', root), patch.object(p.subprocess, 'run', side_effect=process), redirect_stdout(output):
                    with self.assertRaises(ValueError):
                        p.browser_checks({'flows': ['windows-fleet-msi'], 'sha': SHA})
                text = output.getvalue()
                self.assertIn('FAIL stage: browser-windows-fleet-msi', text)
                self.assertEqual('FAIL fleet MSI location:' in text, admitted)
                self.assertNotIn(marker, text)
                self.assertNotIn(['node', 'web/scripts/run-windows-msi-catalogue-ci.mjs'], calls)
        runner = (ROOT / p.FLOWS['windows-fleet-msi']).read_text()
        for producer in p.FLEET_MSI_FAILURE_SCENES:
            self.assertIn("onCase:currentCase('" + producer + "')", runner)
        self.assertIn('failureRecorded={...failure}', runner)
        self.assertIn('process.exitCode=passed?0:1', runner)

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
                  'scenes': 5, 'screenshots': 20, 'requestsToRealAPI': 0,
                  'actualMutationRequests': 0, 'nativeAcceptance': False,
                  'sceneManifestSHA256': p.catalogue_scene_contract()[1]}
        p.validate_catalogue_browser_report(report, SHA)
        for key, value in [('sourceSha', 'b' * 40), ('status', 'FAIL'), ('browserAcceptance', False), ('scenes', 4), ('scenes', 3),
                           ('screenshots', 19), ('screenshots', 12), ('scenes', 6), ('screenshots', 21),
                           ('scenes', 5.0), ('screenshots', 20.0), ('sceneManifestSHA256', ''),
                           ('sceneManifestSHA256', 'b' * 64), ('requestsToRealAPI', 1),
                           ('actualMutationRequests', 1), ('nativeAcceptance', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.validate_catalogue_browser_report({**report, key: value}, SHA)
        alternate = {**report, 'results': [{'name': 'generic result', 'status': 'PASS'}],
                     'summary': {'passed': 1, 'failed': 0}}
        del alternate['browserAcceptance']
        with self.assertRaises(ValueError):
            p.validate_catalogue_browser_report(alternate, SHA)

    def test_catalogue_producer_and_gate_share_exact_required_scene_contract(self):
        contract, digest = p.catalogue_scene_contract()
        self.assertEqual(contract['scenes'], ['catalogue-storage-limit', 'selected-package-worklist',
                         'retained-outcome-after-reuse', 'guided-review-missing', 'guided-review-ready'])
        self.assertEqual(contract['viewports'], [
            {'locale': locale, 'width': width, 'height': 844 if width == 390 else 1100}
            for locale in ['en', 'de'] for width in [1440, 390]])
        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        fixture = (ROOT / 'web/scripts/capture-windows-msi-catalogue-fixtures.mjs').read_text()
        runner = (ROOT / 'web/scripts/run-windows-msi-catalogue-ci.mjs').read_text()
        self.assertIn("readFile(new URL('./windows-msi-catalogue-scenes.json',import.meta.url))", fixture)
        self.assertIn('msiCatalogueScenes=Object.freeze([...sceneManifest.scenes])', fixture)
        self.assertIn('msiCatalogueScenes.flatMap(scene=>msiCatalogueViewports.map', fixture)
        self.assertIn('scenes:passed?msiCatalogueScenes.length:0', runner)
        self.assertIn('screenshots:passed?msiCatalogueCaptureMatrix.length:0', runner)
        self.assertIn('sceneManifestSHA256:msiCatalogueSceneManifestSHA256', runner)
        self.assertIn("'windows-msi-catalogue-scenes.json'", (ROOT / 'web/scripts/capture-windows-fleet-msi-fixtures.mjs').read_text())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); path = root / 'web/scripts/windows-msi-catalogue-scenes.json'
            path.parent.mkdir(parents=True)
            invalid = [None, [], {}, {**contract, 'schemaVersion': True}, {**contract, 'schemaVersion': 2},
                       {**contract, 'extra': 1}, {**contract, 'scenes': []},
                       {**contract, 'scenes': contract['scenes'] + [contract['scenes'][0]]},
                       {**contract, 'scenes': ['../outside']}, {**contract, 'scenes': [1]},
                       {**contract, 'viewports': contract['viewports'][:-1]},
                       {**contract, 'viewports': [*contract['viewports'], contract['viewports'][0]]},
                       {**contract, 'viewports': [{**contract['viewports'][0], 'width': 1440.0}, *contract['viewports'][1:]]}]
            with patch.object(p, 'ROOT', root):
                for value in invalid:
                    path.write_text(json.dumps(value, indent=2) + '\n')
                    with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                        p.catalogue_scene_contract()
                for raw in ['', '{', 'x' * 8193,
                            '{"schemaVersion":1,"schemaVersion":1,"scenes":[],"viewports":[]}']:
                    path.write_text(raw)
                    with self.assertRaises(ValueError): p.catalogue_scene_contract()
                path.unlink()
                with self.assertRaises(OSError): p.catalogue_scene_contract()
                target = root / 'target.json'; target.write_text(json.dumps(contract)); path.symlink_to(target)
                with self.assertRaises(OSError): p.catalogue_scene_contract()

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


class LANFailureTests(unittest.TestCase):
    def report(self, failures=()):
        rows = []
        for name, code in p.LAN_FAILURE_CASES.items():
            row = {'name': name, 'status': 'PASS', 'durationMs': 1}
            if code in failures:
                row.update(status='FAIL', error='Assertion failed; raw state and credential-bearing diagnostics intentionally withheld.')
                if code in p.LAN_STAGE_CASES:
                    row['stage'] = next(iter(p.LAN_FAILURE_STAGES.get(code, {'setup': 'setup'})))
                if code == 'journal-browse': row['journalDiagnostics'] = None
                if code in ['alarm-status', 'alarm-settings']: row['alarmDiagnostics'] = {}
            rows.append(row)
        return {'sourceSha': SHA, 'createdAt': '2026-10-12T00:00:00Z', 'scope': 'synthetic',
                'faultInjection': 'synthetic', 'credentialMaterial': 'synthetic', 'screenshots': 'synthetic',
                'runtimeErrorCount': 0, 'results': rows,
                'summary': {'passed': len(rows) - len(failures), 'failed': len(failures), 'setupFailure': False}}

    def test_lan_codes_match_existing_case_order_and_cve_stages(self):
        runner = (ROOT / p.FLOWS['lan']).read_text()
        route_source = (ROOT / 'tests/e2e-review/route-loading-browser.mjs').read_text()
        route_names = re.search(r'export const routeLoadingCaseNames = Object.freeze\(\[(.*?)\]\);', route_source, re.S)[1]
        names = re.findall(r"'([^']+)'", route_names)
        self.assertEqual(len(names), 4)
        self.assertLess(runner.index('await runRouteLoadingChecks('), runner.index('await check('))
        for literal, symbol in re.findall(r"await check\((?:'([^']+)'|([A-Za-z][A-Za-z0-9_]+)),", runner):
            if literal:
                names.append(literal)
            else:
                module = next(filename for imports, filename in re.findall(r"import \{([^}]+)\} from './([^']+)';", runner)
                              if symbol in imports.split(','))
                source = (ROOT / 'tests/e2e-review' / module).read_text()
                names.append(re.search(r'export const ' + symbol + r"\s*=\s*'([^']+)'", source)[1])
        self.assertEqual(list(p.LAN_FAILURE_CASES), names)
        self.assertEqual(len(names), 31)
        self.assertEqual(len(set(p.LAN_FAILURE_CASES.values())), len(names))
        for code in p.LAN_FAILURE_CASES.values(): self.assertRegex(code, r'^[a-z][a-z0-9-]{0,70}$')
        self.assertLessEqual(set(p.LAN_FAILURE_STAGES), set(p.LAN_FAILURE_CASES.values()))
        for stages in p.LAN_FAILURE_STAGES.values():
            self.assertEqual(len(set(stages.values())), len(stages))
            for code in stages.values(): self.assertRegex(code, r'^[a-z][a-z0-9-]{0,70}$')
        source = (ROOT / 'tests/e2e-review/cve-detail-pages-browser.mjs').read_text()
        self.assertEqual(set(p.LAN_FAILURE_STAGES['cve-detail-pages']),
                         {
                             'fixture setup', 'mobile layout', 'desktop layout', 'real login', 'initial summary',
                             'initial warning navigation', 'omitted warning navigation', 'warning return navigation',
                             'mapped binary navigation', 'advancing empty scan', 'changed binding',
                             'expired retained input', 'device navigation isolation', 'session loss isolation',
                             'fresh login isolation', 'final guards'})
        for stage in p.LAN_FAILURE_STAGES['cve-detail-pages']: self.assertIn("'" + stage + "'", source)

    def test_route_loading_stages_remain_closed_and_unknown_coordinates_are_rejected(self):
        source = (ROOT / 'tests/e2e-review/route-loading-browser.mjs').read_text()
        expected = {
            'route-loading': {'setup', 'loading-captures', 'blurred-route-replacement'},
            'route-loading-resume': {'setup', 'pending-pagehide', 'auth-revalidation'},
            'route-loading-auth': {'setup', 'pending-logout', 'pending-auth-loss'},
            'route-loading-recovery': {'setup', 'module-failure', 'failure-captures', 'deliberate-reload'},
        }
        for code, stages in expected.items():
            self.assertEqual(p.LAN_FAILURE_STAGES[code], {stage: stage for stage in stages})
            for stage in stages: self.assertIn("'" + stage + "'", source)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'artifacts/review/lan-browser-results.json'
            target.parent.mkdir(parents=True)
            with patch.object(p, 'ROOT', root):
                for code in expected:
                    for key, value in [('name', 'Unknown route case'), ('stage', 'unreviewed-stage'),
                                       ('stage', 'PRIVATE_RAW_STATE_MUST_STAY_WITHHELD'), ('raw', 'private'),
                                       ('stage', 'sparse-search')]:
                        report = self.report([code])
                        next(row for row in report['results'] if row['status'] == 'FAIL')[key] = value
                        target.write_text(json.dumps(report))
                        with self.subTest(code=code, key=key, value=value):
                            self.assertIsNone(p.lan_failure_location(SHA))

    def test_paused_detail_cases_expose_only_complete_fixed_source_stage_sets(self):
        directory = ROOT / 'tests/e2e-review'
        def literals(*names):
            return {stage for name in names for stage in re.findall(
                r"(?:mark|capture)\('([^']+)'", (directory / name).read_text())}
        health = (directory / 'health-dashboard-browser.mjs').read_text()
        phases = re.findall(r"'([^']+)'", re.search(r'healthDashboardPhases=\[(.*?)\]', health)[1])
        package = (directory / 'package-updates-browser.mjs').read_text()
        expected = {
            'service-action-display': literals('service-action-display-browser.mjs', 'service-action-display-navigation.mjs'),
            'package-updates': set(re.findall(r"'([^']+)'", re.search(r'const stages=new Set\(\[(.*?)\]\)', package)[1])),
            'investigations': literals('investigations-browser.mjs', 'health-dashboard-browser.mjs')
                | {f'health-{phase}-{point}' for phase in phases for point in ['detail-route-readiness', 'assertions']}
                | {f'{prefix}-{part}' for prefix in ['health-layout', 'health-mobile-de-settings-layout']
                   for part in ['viewport', 'cards', 'issues', 'summaries']},
        }
        for code, stages in expected.items():
            self.assertEqual(p.LAN_FAILURE_STAGES[code], {stage: stage for stage in stages})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'artifacts/review/lan-browser-results.json'
            target.parent.mkdir(parents=True)
            with patch.object(p, 'ROOT', root):
                for code in expected:
                    other_case_stage = {'service-action-display': 'consent', 'package-updates': 'inventory-tab',
                                        'investigations': 'consent'}[code]
                    for stage in ['unreviewed-stage', 'PRIVATE_RAW_STATE_MUST_STAY_WITHHELD',
                                  other_case_stage, '::error::injected', '', None, 300, True]:
                        report = self.report([code])
                        next(row for row in report['results'] if row['status'] == 'FAIL')['stage'] = stage
                        target.write_text(json.dumps(report))
                        with self.subTest(code=code, stage=stage):
                            self.assertIsNone(p.lan_failure_location(SHA))

    def test_windows_inventory_service_stages_are_closed_source_vocabulary(self):
        source = (ROOT / 'tests/e2e-review/windows-service-health-browser.mjs').read_text()
        expected = {'services-source', 'services-disabled', 'services-pending', 'services-attention',
                    'services-unknown', 'services-recovered', 'services-policy-changed'}
        self.assertEqual(p.LAN_FAILURE_STAGES['windows-inventory'], {name: name for name in expected})
        for name in expected: self.assertIn("'" + name + "'", source)

    def test_lan_all_reviewed_case_stage_coordinates_and_generic_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'artifacts/review/lan-browser-results.json'
            target.parent.mkdir(parents=True)
            with patch.object(p, 'ROOT', root):
                for name, code in p.LAN_FAILURE_CASES.items():
                    for stage, label in p.LAN_FAILURE_STAGES.get(code, {None: 'unavailable'}).items():
                        value = self.report([code])
                        row = next(row for row in value['results'] if row['name'] == name)
                        if stage is not None: row['stage'] = stage
                        target.write_text(json.dumps(value))
                        with self.subTest(case=code, stage=stage):
                            self.assertEqual(p.lan_failure_location(SHA), 'case=' + code + ' stage=' + label)
                value = self.report(['cve-detail-pages', 'journal-browse', 'alarm-status'])
                marker = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD'
                for row in value['results']:
                    for key in ['journalDiagnostics', 'alarmDiagnostics']:
                        if key in row: row[key] = {'raw': marker, 'stage': marker, 'nested': {'error': marker}}
                next(row for row in value['results'] if 'journalDiagnostics' in row)['stage'] = marker
                value['runtimeErrorCount'] = 7
                value['summary']['setupFailure'] = True
                target.write_text(json.dumps(value))
                result = p.lan_failure_location(SHA)
                self.assertEqual(result.count('case='), 3)
                self.assertTrue(result.endswith('; setup-failure; runtime-errors'))
                self.assertNotIn(marker, result)
                value = self.report(); target.write_text(json.dumps(value))
                self.assertIsNone(p.lan_failure_location(SHA))
                value['runtimeErrorCount'] = 1; target.write_text(json.dumps(value))
                self.assertEqual(p.lan_failure_location(SHA), 'runtime-errors')
                value['results'] = value['results'][:3]
                value['summary'] = {'passed': 3, 'failed': 0, 'setupFailure': True}
                target.write_text(json.dumps(value))
                self.assertEqual(p.lan_failure_location(SHA), 'setup-failure; runtime-errors')

    def test_lan_rejects_malformed_types_shapes_counts_duplicates_and_raw_labels(self):
        good = self.report(['cve-detail-pages'])
        marker = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD\n::error::injected'
        cases = []
        for key, value in [('sourceSha', 'b' * 40), ('sourceSha', None), ('sourceSha', True),
                           ('runtimeErrorCount', True), ('runtimeErrorCount', 0.0), ('runtimeErrorCount', -1),
                           ('runtimeErrorCount', 1000001), ('runtimeErrorCount', '1'), ('runtimeErrorCount', []),
                           ('results', {}), ('results', None), ('results', good['results'][:-1]),
                           ('results', good['results'] + [good['results'][0]]),
                           ('summary', []), ('createdAt', 1), ('scope', {}), ('faultInjection', []),
                           ('credentialMaterial', None), ('screenshots', []), ('raw', marker)]:
            cases.append({**good, key: value})
        for key, value in [('passed', len(p.LAN_FAILURE_CASES)), ('failed', 0), ('passed', float(len(p.LAN_FAILURE_CASES) - 1)), ('failed', True),
                           ('setupFailure', 0), ('setupFailure', 'false'), ('passed', -1), ('failed', len(p.LAN_FAILURE_CASES) + 1), ('raw', marker)]:
            cases.append({**good, 'summary': {**good['summary'], key: value}})
        index = next(i for i, row in enumerate(good['results']) if row['status'] == 'FAIL')
        for key, value in [('name', marker), ('name', []), ('status', True), ('status', marker),
                           ('durationMs', True), ('durationMs', 1.0), ('durationMs', -1),
                           ('durationMs', 9007199254740992), ('stage', marker), ('stage', []),
                           ('stage', 'sparse-search'), ('stage', None), ('error', marker), ('error', {}),
                           ('raw', marker), ('alarmDiagnostics', {})]:
            changed = deepcopy(good); changed['results'][index][key] = value; cases.append(changed)
        for key in ['name', 'status', 'durationMs', 'stage', 'error']:
            changed = deepcopy(good); del changed['results'][index][key]; cases.append(changed)
        for key in good:
            changed = deepcopy(good); del changed[key]; cases.append(changed)
        for index in [0, 10, len(p.LAN_FAILURE_CASES) - 1]:
            changed = deepcopy(good); changed['results'][index] = changed['results'][1]; cases.append(changed)
        changed = deepcopy(good); changed['results'].reverse(); cases.append(changed)
        changed = deepcopy(good); changed['results'][0]['stage'] = 'setup'; cases.append(changed)
        for code, key in [('journal-browse', 'journalDiagnostics'), ('alarm-status', 'alarmDiagnostics')]:
            for value in [[], True, marker]:
                changed = self.report([code])
                next(row for row in changed['results'] if row['status'] == 'FAIL')[key] = value
                cases.append(changed)
        cases += [None, [], 1, True]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'artifacts/review/lan-browser-results.json'
            target.parent.mkdir(parents=True)
            with patch.object(p, 'ROOT', root):
                for index, value in enumerate(cases):
                    target.write_text(json.dumps(value))
                    with self.subTest(index=index): self.assertIsNone(p.lan_failure_location(SHA))
                target.write_text(json.dumps(good))
                for sha in [None, '', SHA.upper(), 'b' * 40, True, [], marker]:
                    self.assertIsNone(p.lan_failure_location(sha))

    def test_lan_report_file_guards_and_strict_json(self):
        good = json.dumps(self.report(['cve-detail-pages'])).encode()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'artifacts/review/lan-browser-results.json'
            target.parent.mkdir(parents=True)
            with patch.object(p, 'ROOT', root):
                self.assertIsNone(p.lan_failure_location(SHA))
                for raw in [b'{', b'[]', b'\xff', b' ' * ((64 << 10) + 1), good + b'{}',
                            good.replace(b'"runtimeErrorCount": 0', b'"runtimeErrorCount": NaN'),
                            good.replace(b'"runtimeErrorCount": 0', b'"runtimeErrorCount": Infinity'),
                            good.replace(b'"sourceSha":', b'"sourceSha": "' + SHA.encode() + b'", "sourceSha":'),
                            good.replace(b'"failed": 1', b'"failed": 1, "failed": 1'),
                            good.replace(b'"stage":', b'"stage": "real login", "stage":')]:
                    target.write_bytes(raw); self.assertIsNone(p.lan_failure_location(SHA))
                target.unlink(); target.mkdir(); self.assertIsNone(p.lan_failure_location(SHA)); target.rmdir()
                backing = root / 'backing.json'; backing.write_bytes(good)
                target.symlink_to(backing); self.assertIsNone(p.lan_failure_location(SHA)); target.unlink()
                target.parent.rmdir(); target.parent.symlink_to(root, target_is_directory=True)
                (root / target.name).write_bytes(good); self.assertIsNone(p.lan_failure_location(SHA))

    def test_lan_diagnostics_do_not_run_for_smoke_other_flows_or_success(self):
        with patch.object(p, 'run', side_effect=ValueError('private')), patch.object(p, 'lan_failure_location') as location:
            with self.assertRaises(ValueError): p.browser_checks({'flows': ['lan'], 'sha': SHA})
            location.assert_not_called()
        with patch.object(p, 'run', side_effect=[None, ValueError('private')]), patch.object(p, 'lan_failure_location') as location:
            with self.assertRaises(ValueError): p.browser_checks({'flows': ['shell'], 'sha': SHA})
            location.assert_not_called()
        with patch.object(p, 'run'), patch.object(p, 'browser_report'), patch.object(p, 'lan_failure_location') as location:
            p.browser_checks({'flows': ['lan'], 'sha': SHA})
            location.assert_not_called()

    def test_lan_failure_emits_only_fixed_setup_flag_and_still_fails(self):
        marker = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD'
        report = {'sourceSha': SHA, 'createdAt': marker, 'scope': marker,
                  'faultInjection': marker, 'credentialMaterial': marker, 'screenshots': marker,
                  'runtimeErrorCount': 0, 'results': [],
                  'summary': {'passed': 0, 'failed': 0, 'setupFailure': True}}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'artifacts/review/lan-browser-results.json'
            target.parent.mkdir(parents=True)
            def process(args, **kwargs):
                kwargs['stdout'].write(marker.encode())
                if args == ['node', p.FLOWS['lan']]:
                    target.write_text(json.dumps(report))
                    return SimpleNamespace(returncode=1)
                return SimpleNamespace(returncode=0)
            output = io.StringIO()
            with patch.object(p, 'ROOT', root), patch.object(p.subprocess, 'run', side_effect=process), \
                 patch.object(p, 'browser_report') as validate, redirect_stdout(output):
                with self.assertRaises(ValueError):
                    p.browser_checks({'flows': ['lan'], 'sha': SHA})
            self.assertIn('FAIL stage: browser-lan', output.getvalue())
            self.assertIn('FAIL LAN location: setup-failure', output.getvalue())
            self.assertNotIn(marker, output.getvalue())
            validate.assert_not_called()


class WindowsDetailFailureTests(unittest.TestCase):
    MARKER = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD\n::error::injected'

    def report(self, flow, stage='detail-route-readiness'):
        value = {'name': p.WINDOWS_DETAIL_FAILURE_CASES[flow], 'status': 'FAIL', 'stage': stage,
                 'sourceSha': SHA, 'createdAt': '2026-10-14T00:00:00.000Z', 'runtimeErrorCount': 0,
                 'browserAcceptance': False, 'nativeAcceptance': False}
        if flow == 'windows-storage-io':
            value.update(sourceState='sourceSha identifies checkout HEAD; source and compiled bundle hashes identify the tested bytes',
                         uiSourceSha256='b' * 64, compiledBundleSha256='c' * 64, browserVersion='139.0.7258.5',
                         customPreinstalledBrowser=False, fixtureDisclosure='Synthetic fixture only', details=None,
                         liveAuthenticationAcceptance=False, liveStoreAcceptance=False)
        else:
            value.update(scope='Synthetic fixture only', variants=[], requestsToRealAPI=0,
                         durableStoreAcceptance=False, secretsExported=False, realTelemetryExported=False)
        return value

    def target(self, root, flow):
        path = root / 'artifacts/review' / p.BROWSER_REPORTS[flow]
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def test_exact_selected_case_membership_and_stages_match_driver_source(self):
        fixtures = {
            'windows-managed-msi': ('windowsManagedMSI', 'exerciseWindowsManagedMSI'),
            'windows-mutation-coexistence': ('windowsMutationCoexistence', 'exerciseWindowsMutationCoexistence'),
            'windows-storage-io': ('windowsStorageIO', 'windowsStorageIOBrowserCase'),
        }
        self.assertEqual(set(p.WINDOWS_DETAIL_FAILURE_CASES), set(fixtures))
        self.assertEqual(set(p.WINDOWS_DETAIL_FAILURE_STAGES), set(fixtures))
        for flow, (prefix, function) in fixtures.items():
            with self.subTest(flow=flow):
                source = (ROOT / ('tests/e2e-review/' + flow + '-browser.mjs')).read_text()
                self.assertEqual(p.WINDOWS_DETAIL_FAILURE_CASES[flow],
                                 re.search(r'export const ' + prefix + r"CaseName='([^']+)'", source)[1])
                body = source.split('export async function ' + function + '(', 1)[1].split('\nexport ', 1)[0]
                stages = {'setup'} | set(re.findall(r"\bstage\s*=\s*'([^']+)'", body))
                if flow == 'windows-storage-io':
                    # The only dynamic stage comes from this fixed source tuple.
                    self.assertIn("for(const [mode,en,deText] of [['denied','Access denied','Zugriff verweigert'],['unsupported','Source unsupported','Quelle nicht unterstützt']]){stage=mode;", body)
                    stages.update(['denied', 'unsupported'])
                else:
                    declared = re.search(r'const stages=new Set\(\[(.*?)\]\)', source)[1]
                    self.assertEqual(set(re.findall(r"'([^']+)'", declared)), stages)
                self.assertEqual(set(p.WINDOWS_DETAIL_FAILURE_STAGES[flow]), stages)
                self.assertEqual(len(p.WINDOWS_DETAIL_FAILURE_STAGES[flow]), len(stages))
                self.assertIn("import {settlePausedDetailRoute} from './paused-detail-route.mjs';", source)
                helper_labels = re.findall(r"stage='([^']+)';await settlePausedDetailRoute\(page,expect,", body)
                self.assertCountEqual(helper_labels, [stage for stage in stages if stage.endswith('detail-route-readiness')])
                self.assertIn("page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));", body)
                runner = (ROOT / p.FLOWS[flow]).read_text()
                self.assertIn('name:' + prefix + 'CaseName', runner)
                self.assertIn('stage:' + prefix + 'FailureStage()', runner)
                self.assertIn("'" + Path(p.BROWSER_REPORTS[flow]).name + "'", runner)

    def test_all_closed_source_stages_and_ignored_private_prose(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(p, 'ROOT', root):
                for flow, stages in p.WINDOWS_DETAIL_FAILURE_STAGES.items():
                    target = self.target(root, flow)
                    for stage in stages:
                        report = self.report(flow, stage)
                        report['fixtureDisclosure' if flow == 'windows-storage-io' else 'scope'] = self.MARKER
                        if flow == 'windows-storage-io': report['browserVersion'] = self.MARKER
                        target.write_text(json.dumps(report))
                        with self.subTest(flow=flow, stage=stage):
                            self.assertEqual(p.windows_detail_failure_location(flow, SHA),
                                             'case=%s stage=%s' % (flow, stage))

    def test_rejects_unknown_wrong_case_stages_and_raw_payloads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(p, 'ROOT', root):
                for flow, stages in p.WINDOWS_DETAIL_FAILURE_STAGES.items():
                    target = self.target(root, flow); good = self.report(flow)
                    foreign_stages = set().union(*map(set, p.WINDOWS_DETAIL_FAILURE_STAGES.values())) - set(stages)
                    for stage in [None, True, 1, [], {}, 'unknown', 'DETAIL-ROUTE-READINESS',
                                  'detail-route-readiness\n', self.MARKER, 'x' * 8193, *sorted(foreign_stages)]:
                        target.write_text(json.dumps({**good, 'stage': stage}))
                        with self.subTest(flow=flow, stage=stage):
                            self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    for other, name in p.WINDOWS_DETAIL_FAILURE_CASES.items():
                        if other == flow: continue
                        target.write_text(json.dumps({**good, 'name': name}))
                        self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    for key in ['error', 'raw', 'case', 'runtimeErrors', 'dto']:
                        target.write_text(json.dumps({**good, key: self.MARKER}))
                        self.assertIsNone(p.windows_detail_failure_location(flow, SHA))

    def test_rejects_malformed_shapes_types_counts_success_and_foreign_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(p, 'ROOT', root):
                for flow in p.WINDOWS_DETAIL_FAILURE_CASES:
                    good = self.report(flow); target = self.target(root, flow); cases = []
                    for key in good:
                        missing = dict(good); del missing[key]; cases.append(missing)
                        for value in [None, True, False, 0, 1, [], {}]:
                            if type(value) is type(good[key]) and value == good[key]: continue
                            if key == 'browserVersion' and value is None: continue
                            if key == 'customPreinstalledBrowser' and value is True: continue
                            if key == 'runtimeErrorCount' and type(value) is int and value in [0, 1]: continue
                            cases.append({**good, key: value})
                    cases.extend({**good, key: value} for key, value in [
                        ('sourceSha', SHA.upper()), ('sourceSha', SHA + '\n'), ('sourceSha', 'b' * 40),
                        ('status', 'PASS'), ('status', 'fail'), ('runtimeErrorCount', -1),
                        ('runtimeErrorCount', 1000001), ('runtimeErrorCount', 1.5), ('createdAt', ''),
                        ('createdAt', 'x' * 65), ('name', self.MARKER)])
                    prose = 'fixtureDisclosure' if flow == 'windows-storage-io' else 'scope'
                    cases.extend([{**good, prose: ''}, {**good, prose: 'x' * 4097}])
                    if flow == 'windows-storage-io':
                        cases.extend([{**good, 'browserVersion': ''}, {**good, 'browserVersion': 'x' * 129},
                                      {**good, 'sourceState': self.MARKER}])
                        for key in ['uiSourceSha256', 'compiledBundleSha256']:
                            cases.extend({**good, key: value} for value in ['b' * 63, 'B' * 64, 'b' * 64 + '\n', self.MARKER])
                    else:
                        cases.extend([{**good, 'variants': [self.MARKER]}, {**good, 'requestsToRealAPI': 1}])
                    cases.extend([None, [], True, 1, self.MARKER])
                    for index, value in enumerate(cases):
                        target.write_text(json.dumps(value))
                        with self.subTest(flow=flow, index=index):
                            self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    target.write_text(json.dumps(good))
                    for sha in [None, True, 1, [], {}, '', SHA.upper(), SHA + '\n', 'b' * 40, self.MARKER]:
                        self.assertIsNone(p.windows_detail_failure_location(flow, sha))
                for flow in [None, True, 1, [], {}, '', 'windows-service-actions', '../windows-managed-msi', self.MARKER]:
                    self.assertIsNone(p.windows_detail_failure_location(flow, SHA))

    def test_strict_json_bounds_regular_file_and_nofollow_guards(self):
        for flow in p.WINDOWS_DETAIL_FAILURE_CASES:
            with self.subTest(flow=flow), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); target = self.target(root, flow)
                report = self.report(flow); good = json.dumps(report).encode()
                raw_values = [b'', b'{', b'\xff', b'[]', good + b'{}', b' ' * 8193]
                for key, value in report.items():
                    member = json.dumps(key).encode() + b': ' + json.dumps(value).encode()
                    raw_values.append(good.replace(member, member + b', ' + member, 1))
                raw_values.extend(good.replace(b'"runtimeErrorCount": 0', b'"runtimeErrorCount": ' + value)
                                  for value in [b'NaN', b'Infinity', b'-Infinity'])
                with patch.object(p, 'ROOT', root):
                    self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    for raw in raw_values:
                        target.write_bytes(raw); self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    target.write_bytes(good + b' ' * (8192 - len(good)))
                    self.assertIsNotNone(p.windows_detail_failure_location(flow, SHA))
                    target.write_bytes(good + b' ' * (8193 - len(good)))
                    self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    with patch.object(p.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600, st_size=1)):
                        self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    target.unlink(); target.mkdir()
                    self.assertIsNone(p.windows_detail_failure_location(flow, SHA)); target.rmdir()
                    backing = root / 'backing.json'; backing.write_bytes(good); target.symlink_to(backing)
                    self.assertIsNone(p.windows_detail_failure_location(flow, SHA)); target.unlink()
                    target.parent.rmdir(); target.parent.symlink_to(root, target_is_directory=True)
                    (root / target.name).write_bytes(good)
                    self.assertIsNone(p.windows_detail_failure_location(flow, SHA))
                    with patch.object(p.reporter, 'open_log', side_effect=PermissionError(self.MARKER)):
                        self.assertIsNone(p.windows_detail_failure_location(flow, SHA))

    def test_failed_process_emits_only_closed_location_and_preserves_failure(self):
        for flow in p.WINDOWS_DETAIL_FAILURE_CASES:
            with self.subTest(flow=flow), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); target = self.target(root, flow); report = self.report(flow)
                report['fixtureDisclosure' if flow == 'windows-storage-io' else 'scope'] = self.MARKER
                def process(args, **kwargs):
                    kwargs['stdout'].write(self.MARKER.encode())
                    if args == ['node', p.FLOWS[flow]]:
                        target.write_text(json.dumps(report))
                    return SimpleNamespace(returncode=int(args == ['node', p.FLOWS[flow]]))
                output = io.StringIO()
                with patch.object(p, 'ROOT', root), patch.object(p.subprocess, 'run', side_effect=process), \
                     patch.object(p, 'browser_report') as validate, redirect_stdout(output):
                    with self.assertRaisesRegex(ValueError, 'raw fixture output withheld'):
                        p.browser_checks({'flows': [flow], 'sha': SHA})
                self.assertIn('FAIL Windows detail location: case=%s stage=detail-route-readiness' % flow, output.getvalue())
                self.assertIn('FAIL stage: browser-' + flow, output.getvalue())
                for text in [self.MARKER, SHA, 'PASS:']: self.assertNotIn(text, output.getvalue())
                validate.assert_not_called()

    def test_old_same_source_result_is_removed_before_launch_and_cannot_supply_failure(self):
        for flow in p.WINDOWS_DETAIL_FAILURE_CASES:
            with self.subTest(flow=flow), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); target = self.target(root, flow)
                target.write_text(json.dumps(self.report(flow)))
                unrelated = target.parent / 'manifest.json'; unrelated.write_text('preserved')
                original = ValueError(self.MARKER)
                def run(args, **kwargs):
                    if args == ['node', p.FLOWS[flow]]:
                        self.assertFalse(target.exists())
                        raise original
                output = io.StringIO()
                with patch.object(p, 'ROOT', root), patch.object(p, 'run', side_effect=run), \
                     patch.object(p, 'browser_report') as validate, redirect_stdout(output):
                    with self.assertRaises(ValueError) as failure: p.browser_checks({'flows': [flow], 'sha': SHA})
                self.assertIs(failure.exception, original)
                self.assertEqual(unrelated.read_text(), 'preserved')
                self.assertNotIn('FAIL Windows detail location:', output.getvalue())
                self.assertNotIn(self.MARKER, output.getvalue()); validate.assert_not_called()

    def test_report_reset_is_bounded_nofollow_and_failure_never_launches_or_decodes(self):
        for flow in p.WINDOWS_DETAIL_FAILURE_CASES:
            with self.subTest(flow=flow), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with patch.object(p, 'ROOT', root):
                    p.clear_windows_detail_failure_report(flow)  # Missing parent is safe.
                    target = self.target(root, flow)
                    p.clear_windows_detail_failure_report(flow)  # Missing report is safe.
                    backing = root / 'unrelated.json'; backing.write_text(self.MARKER)
                    target.symlink_to(backing)
                    p.clear_windows_detail_failure_report(flow)
                    self.assertFalse(target.is_symlink()); self.assertEqual(backing.read_text(), self.MARKER)
                    target.mkdir()
                    with self.assertRaisesRegex(ValueError, 'could not prepare fresh'):
                        p.clear_windows_detail_failure_report(flow)
                    self.assertTrue(target.is_dir()); target.rmdir()
                    target.parent.rmdir(); target.parent.symlink_to(root, target_is_directory=True)
                    stale = root / target.name; stale.write_text(json.dumps(self.report(flow)))
                    with patch.object(p, 'run') as run, patch.object(p, 'windows_detail_failure_location') as location, \
                         patch.object(p, 'browser_report') as validate:
                        with self.assertRaisesRegex(ValueError, 'could not prepare fresh'):
                            p.browser_checks({'flows': [flow], 'sha': SHA})
                        run.assert_called_once_with(['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'], stage='browser-auth-smoke')
                        location.assert_not_called(); validate.assert_not_called()
                    self.assertTrue(stale.is_file())
                    with patch.object(p.reporter, 'open_log', side_effect=PermissionError(self.MARKER)):
                        with self.assertRaisesRegex(ValueError, '^could not prepare fresh Windows detail diagnostics$'):
                            p.clear_windows_detail_failure_report(flow)
                    with patch.object(p.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600)), \
                         patch.object(p.reporter, 'open_log', return_value=os.open(backing, os.O_RDONLY)):
                        with self.assertRaisesRegex(ValueError, 'invalid Windows detail diagnostic directory'):
                            p.clear_windows_detail_failure_report(flow)

    def test_diagnostics_preserve_exception_and_skip_smoke_other_flows_success_and_validation(self):
        for flow in p.WINDOWS_DETAIL_FAILURE_CASES:
            original = ValueError(self.MARKER)
            with patch.object(p, 'run', side_effect=[None, original]), \
                 patch.object(p, 'windows_detail_failure_location', return_value=None) as location, \
                 patch.object(p, 'browser_report') as validate:
                with self.assertRaises(ValueError) as failure: p.browser_checks({'flows': [flow], 'sha': SHA})
                self.assertIs(failure.exception, original); location.assert_called_once_with(flow, SHA)
                validate.assert_not_called()
            with patch.object(p, 'run'), patch.object(p, 'browser_report') as validate, \
                 patch.object(p, 'windows_detail_failure_location') as location:
                p.browser_checks({'flows': [flow], 'sha': SHA})
                location.assert_not_called(); validate.assert_called_once_with(flow, SHA)
            with patch.object(p, 'run'), patch.object(p, 'browser_report', side_effect=original), \
                 patch.object(p, 'windows_detail_failure_location') as location:
                with self.assertRaises(ValueError): p.browser_checks({'flows': [flow], 'sha': SHA})
                location.assert_not_called()
        for flow, effects in [('windows-managed-msi', [ValueError('smoke')]), ('shell', [None, ValueError('other')])]:
            with patch.object(p, 'run', side_effect=effects), patch.object(p, 'windows_detail_failure_location') as location:
                with self.assertRaises(ValueError): p.browser_checks({'flows': [flow], 'sha': SHA})
                location.assert_not_called()


class WindowsActionFailureTests(unittest.TestCase):
    TOKEN = 'b' * 32
    MARKER = 'PRIVATE_RAW_EXCEPTION_URL_DTO_MUST_STAY_WITHHELD\n::error::injected'

    def report(self, case=None, step=None, locale='en', width=1440):
        cases = p.windows_action_diagnostic_contract()
        case = case or next(name for name in cases if name != 'runner')
        step = step or cases[case][0]
        return {'schemaVersion': p.WINDOWS_ACTION_DIAGNOSTICS_SCHEMA, 'sourceSha': SHA,
                'invocation': self.TOKEN, 'status': 'FAIL', 'browserAcceptance': False,
                'nativeAcceptance': False, 'case': case, 'step': step, 'locale': locale, 'width': width}

    def target(self, root):
        target = root / 'artifacts/review/windows-service-actions-failure.json'
        target.parent.mkdir(parents=True)
        return target

    def test_all_closed_source_coordinates_and_viewports(self):
        cases = p.windows_action_diagnostic_contract()
        source = ROOT / 'tests/e2e-review/windows-service-actions-diagnostics.json'
        self.assertEqual(p.WINDOWS_ACTION_DIAGNOSTICS_SOURCE, source)
        self.assertEqual(cases, json.loads(source.read_bytes())['cases'])
        self.assertIn('service-actions', cases)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = self.target(root)
            with patch.object(p, 'ROOT', root):
                for case, steps in cases.items():
                    for step in steps:
                        viewports = [(None, None)] if case == 'runner' else [
                            (locale, width) for locale in ['en', 'de'] for width in [1440, 390]]
                        for locale, width in viewports:
                            target.write_text(json.dumps(self.report(case, step, locale, width)))
                            with self.subTest(case=case, step=step, locale=locale, width=width):
                                expected = 'case=%s step=%s locale=%s width=%s' % (case, step, locale or '-', width or '-')
                                self.assertEqual(p.windows_action_failure_location(SHA, self.TOKEN), expected)

    def test_detail_readiness_labels_belong_only_to_reviewed_detail_cases(self):
        cases = p.windows_action_diagnostic_contract()
        detail = {'service-actions', 'action-history', 'update-jobs', 'update-download',
                  'update-retirement', 'update-schedule', 'background-schedule', 'software-jobs'}
        self.assertEqual({case for case, steps in cases.items() if 'detail-route-readiness' in steps}, detail)
        self.assertEqual({case for case, steps in cases.items() if 'reload-detail-route-readiness' in steps},
                         detail - {'action-history'})
        self.assertEqual(set(cases), detail | {'runner', 'fleet-schedule'})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = self.target(root)
            with patch.object(p, 'ROOT', root):
                for case in cases:
                    for step in ['detail-route-readiness', 'reload-detail-route-readiness', 'mount-detail-route-readiness']:
                        report = self.report(case, step, None if case == 'runner' else 'de', None if case == 'runner' else 390)
                        target.write_text(json.dumps(report))
                        with self.subTest(case=case, step=step):
                            result = p.windows_action_failure_location(SHA, self.TOKEN)
                            if step in cases[case]:
                                self.assertEqual(result, 'case=%s step=%s locale=de width=390' % (case, step))
                            else:
                                self.assertIsNone(result)

    def test_javascript_producer_and_python_projection_share_the_source_vocabulary(self):
        cases = p.windows_action_diagnostic_contract()
        helper = (ROOT / 'tests/e2e-review/windows-service-actions-diagnostics.mjs').read_text()
        runner = (ROOT / p.FLOWS['windows-service-actions']).read_text()
        self.assertIn("import contract from './windows-service-actions-diagnostics.json' with {type:'json'}", helper)
        self.assertIn("import {createWindowsActionDiagnostic} from './windows-service-actions-diagnostics.mjs'", runner)
        self.assertIn('process.env.TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN', runner)
        self.assertIn("'windows-service-actions-failure.json'", runner)
        fixtures = {
            'service-actions': ('windows-service-actions-browser.mjs', 'exerciseWindowsServiceActions', 'windowsServiceActionsFailureStage', 'stage'),
            'action-history': ('windows-service-action-history-browser.mjs', 'exerciseWindowsServiceActionHistory', 'windowsServiceActionHistoryFailureStage', 'stage'),
            'update-jobs': ('windows-update-jobs-browser.mjs', 'exerciseWindowsUpdateJobs', 'windowsUpdateJobsFailureStage', 'stage'),
            'update-download': ('windows-update-download-browser.mjs', 'exerciseWindowsUpdateDownload', 'windowsUpdateDownloadFailureStage', 'stage'),
            'update-retirement': ('windows-update-retirement-browser.mjs', 'exerciseWindowsUpdateRetirement', 'windowsUpdateRetirementFailureStage', 'stage'),
            'update-schedule': ('windows-update-schedule-browser.mjs', 'exerciseWindowsUpdateSchedule', 'windowsUpdateScheduleFailureStage', 'stage'),
            'background-schedule': ('windows-update-schedule-browser.mjs', 'exerciseWindowsUpdateSchedule', 'windowsUpdateScheduleFailureStage', 'stage'),
            'fleet-schedule': ('windows-update-schedule-browser.mjs', 'exerciseWindowsFleetUpdateSchedule', 'windowsFleetUpdateScheduleFailureStep', 'fleetStep'),
            'software-jobs': ('windows-software-jobs-browser.mjs', 'exerciseWindowsSoftwareJobs', 'windowsSoftwareJobsFailureStage', 'stage'),
        }
        self.assertEqual(set(cases), {'runner'} | set(fixtures))
        wrappers = {'fixture', 'context', 'guards', 'close', 'screenshot'}
        for case, (filename, function, getter, variable) in fixtures.items():
            with self.subTest(case=case):
                source = (ROOT / 'tests/e2e-review' / filename).read_text()
                body = source.split('export async function ' + function + '(', 1)[1].split('\nexport ', 1)[0]
                stages = set(re.findall(r'\b' + variable + r"\s*=\s*'([^']+)'", body))
                self.assertTrue(stages)
                self.assertEqual(set(cases[case]), wrappers | stages)
                helper_labels = re.findall(r"stage='([^']+)';await settlePausedDetailRoute\(page,expect,", body)
                self.assertCountEqual(helper_labels, [step for step in cases[case] if step.endswith('detail-route-readiness')])
                if helper_labels:
                    self.assertIn("import {settlePausedDetailRoute} from './paused-detail-route.mjs';", source)
                    self.assertIn("page.getByRole('tab',{name:locale==='de'?'Inventar':'Inventory',exact:true}));", body)
                self.assertIn("'" + case + "'", runner)
                self.assertIn('diagnostic.track(' + getter + ')', runner)
                self.assertIn('await ' + function + '(', runner)
                self.assertIn('export const ' + getter + '=', source)
        runner_steps = set(re.findall(r"diagnostic.begin\('runner',null,null,'([^']+)'\)", runner))
        runner_steps.update(re.findall(r"await bootstrap\('([^']+)'", runner))
        runner_steps.update(re.findall(r"diagnostic.set\('([^']+)'\)", runner.split("for(const locale of ['en','de'])", 1)[0]))
        self.assertLessEqual({'setup'} | runner_steps, set(cases['runner']))

    def test_rejects_noncanonical_types_shapes_coordinates_and_private_values(self):
        good = self.report()
        cases = []
        for key in good:
            for value in [None, True, False, 0, 1, 1440.0, [], {}, self.MARKER]:
                if type(value) is type(good[key]) and value == good[key]:
                    continue
                cases.append((key, {**good, key: value}))
            missing = dict(good); del missing[key]; cases.append(('missing-' + key, missing))
        for key, value in [('schemaVersion', 'tracebolt.windows-action-browser-failure.v2'),
                           ('sourceSha', 'c' * 40), ('sourceSha', SHA.upper()), ('sourceSha', SHA + '\n'),
                           ('invocation', 'c' * 32), ('invocation', self.TOKEN.upper()),
                           ('invocation', self.TOKEN + '\n'), ('status', 'PASS'), ('status', 'fail'),
                           ('case', 'unknown'), ('case', good['case'] + '\n'), ('step', 'unknown'),
                           ('step', good['step'] + '\n'), ('locale', 'fr'), ('locale', 'EN'), ('locale', 'en\n'),
                           ('width', 1440.0), ('width', 390.0), ('width', 0), ('width', 1441), ('width', '1440'),
                           ('extra', self.MARKER), ('error', {'raw': self.MARKER})]:
            cases.append((key, {**good, key: value}))
        runner = self.report('runner', locale=None, width=None)
        for locale, width in [('en', 1440), ('en', None), (None, 390), ('', None), (None, False)]:
            cases.append(('runner-viewport', {**runner, 'locale': locale, 'width': width}))
        vocabulary = p.windows_action_diagnostic_contract()
        for case, steps in vocabulary.items():
            for other, other_steps in vocabulary.items():
                if case == other: continue
                for step in set(other_steps) - set(steps):
                    base = runner if case == 'runner' else good
                    cases.append(('foreign-step', {**base, 'case': case, 'step': step}))
        cases.extend(('root', value) for value in [None, [], True, 1, self.MARKER])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = self.target(root)
            with patch.object(p, 'ROOT', root):
                for index, (label, value) in enumerate(cases):
                    target.write_text(json.dumps(value))
                    with self.subTest(index=index, field=label):
                        self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                target.write_text(json.dumps(good))
                for sha in [None, True, 1, [], {}, '', SHA.upper(), SHA + '\n', 'c' * 40, self.MARKER]:
                    self.assertIsNone(p.windows_action_failure_location(sha, self.TOKEN))
                for token in [None, True, 1, [], {}, '', self.TOKEN.upper(), self.TOKEN + '\n', 'c' * 32, self.MARKER]:
                    self.assertIsNone(p.windows_action_failure_location(SHA, token))

    def test_strict_json_size_regular_file_and_nofollow_guards(self):
        report = self.report(); good = json.dumps(report).encode()
        raw_values = [b'', b'{', b'\xff', b'[]', good + b'{}', b' ' * 4097,
                      good.replace(b'1440', b'NaN'), good.replace(b'1440', b'Infinity'),
                      good.replace(b'1440', b'-Infinity')]
        for key, value in report.items():
            member = json.dumps(key).encode() + b': ' + json.dumps(value).encode()
            raw_values.append(good.replace(member, member + b', ' + member, 1))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = self.target(root)
            with patch.object(p, 'ROOT', root):
                self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                for raw in raw_values:
                    target.write_bytes(raw)
                    self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                target.write_bytes(good + b' ' * (4096 - len(good)))
                self.assertIsNotNone(p.windows_action_failure_location(SHA, self.TOKEN))
                target.write_bytes(good + b' ' * (4097 - len(good)))
                self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                # Size growth after fstat cannot escape the bounded read guard.
                with patch.object(p.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600, st_size=1)):
                    self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                target.unlink(); target.mkdir()
                self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN)); target.rmdir()
                backing = root / 'backing.json'; backing.write_bytes(good)
                target.symlink_to(backing)
                self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN)); target.unlink()
                target.parent.rmdir(); target.parent.symlink_to(root, target_is_directory=True)
                (root / target.name).write_bytes(good)
                self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                with patch.object(p.reporter, 'open_log', side_effect=PermissionError(self.MARKER)):
                    self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))

    def test_contract_is_source_relative_bounded_and_fail_closed(self):
        good = self.report()
        source_contract = p.WINDOWS_ACTION_DIAGNOSTICS_SOURCE
        contract = json.loads(source_contract.read_bytes())
        malformed = [None, [], {}, {**contract, 'schemaVersion': 1}, {**contract, 'extra': self.MARKER},
                     {**contract, 'cases': {}}, {**contract, 'cases': []},
                     {**contract, 'cases': {'private': ['step']}},
                     {**contract, 'cases': {'runner': []}},
                     {**contract, 'cases': {'runner': ['step', 'step']}},
                     {**contract, 'cases': {'runner': [self.MARKER]}},
                     {**contract, 'cases': {'runner': [True]}},
                     {**contract, 'cases': {'runner': 'step'}},
                     {**contract, 'cases': {'runner': ['step'], self.MARKER: ['step']}},
                     {**contract, 'cases': {'runner': ['step'], 'other': ['x' * 65]}},
                     {**contract, 'cases': {'runner': ['step'] * 129}},
                     {**contract, 'cases': {'runner': ['step'], **{'case-%d' % i: ['step'] for i in range(32)}}}]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = self.target(root)
            target.write_text(json.dumps(good))
            forged = root / 'tests/e2e-review/windows-service-actions-diagnostics.json'
            forged.parent.mkdir(parents=True)
            forged.write_text(json.dumps({**contract, 'cases': {'runner': ['step'], 'forged': ['private']}}))
            with patch.object(p, 'ROOT', root):
                self.assertIsNotNone(p.windows_action_failure_location(SHA, self.TOKEN))
                target.write_text(json.dumps({**good, 'case': 'forged', 'step': 'private'}))
                self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                target.write_text(json.dumps(good))
                with patch.object(p, 'WINDOWS_ACTION_DIAGNOSTICS_SOURCE', forged):
                    for value in malformed:
                        forged.write_text(json.dumps(value))
                        self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                    for raw in [b'{', b'\xff', b'x' * 16385,
                                json.dumps(contract).replace('"cases":', '"cases": {}, "cases":').encode()]:
                        forged.write_bytes(raw)
                        self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                    forged.unlink()
                    self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))
                    forged.symlink_to(source_contract)
                    self.assertIsNone(p.windows_action_failure_location(SHA, self.TOKEN))

    def test_failure_projection_preserves_original_exception_and_never_validates_pass(self):
        original = ValueError(self.MARKER)
        plan = {'flows': ['windows-service-actions'], 'sha': SHA}
        output = io.StringIO()
        with patch.object(p, 'run', side_effect=[None, original]) as run, \
             patch.object(p.secrets, 'token_hex', return_value=self.TOKEN) as token, \
             patch.object(p, 'windows_action_failure_location', return_value='case=runner step=launch locale=- width=-') as location, \
             patch.object(p, 'browser_report') as report, redirect_stdout(output):
            with self.assertRaises(ValueError) as failure: p.browser_checks(plan)
        self.assertIs(failure.exception, original)
        token.assert_called_once_with(16)
        location.assert_called_once_with(SHA, self.TOKEN)
        self.assertEqual(run.call_args_list[1].kwargs['env']['TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN'], self.TOKEN)
        self.assertEqual(run.call_count, 2); report.assert_not_called()
        self.assertIn('FAIL Windows action location: case=runner step=launch locale=- width=-', output.getvalue())
        self.assertNotIn(self.MARKER, output.getvalue()); self.assertNotIn(self.TOKEN, output.getvalue())
        self.assertNotIn('PASS:', output.getvalue())

    def test_real_projection_withholds_process_output_and_rejects_same_head_previous_invocation(self):
        report = self.report()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = self.target(root)
            def process(args, **kwargs):
                kwargs['stdout'].write(self.MARKER.encode())
                if args == ['node', p.FLOWS['windows-service-actions']]:
                    if not target.exists():
                        target.write_text(json.dumps({**report, 'invocation': kwargs['env']['TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN']}))
                    return SimpleNamespace(returncode=1)
                return SimpleNamespace(returncode=0)
            with patch.object(p, 'ROOT', root), patch.object(p.subprocess, 'run', side_effect=process), \
                 patch.object(p.secrets, 'token_hex', side_effect=[self.TOKEN, 'c' * 32]), \
                 patch.object(p, 'browser_report') as validate:
                for index in range(2):
                    output = io.StringIO()
                    with redirect_stdout(output), self.assertRaisesRegex(ValueError, 'raw fixture output withheld'):
                        p.browser_checks({'flows': ['windows-service-actions'], 'sha': SHA})
                    self.assertIn('FAIL stage: browser-windows-service-actions', output.getvalue())
                    self.assertEqual('FAIL Windows action location:' in output.getvalue(), index == 0)
                    self.assertNotIn(self.MARKER, output.getvalue()); self.assertNotIn(self.TOKEN, output.getvalue())
                    self.assertNotIn(SHA, output.getvalue()); self.assertNotIn('PASS:', output.getvalue())
                validate.assert_not_called()

    def test_diagnostics_skip_smoke_other_flows_success_and_evidence_validation(self):
        for flow, failures, expected_tokens in [
                ('windows-service-actions', [ValueError('smoke')], 0),
                ('shell', [None, ValueError('other')], 0),
                ('windows-service-actions', [None, None, ValueError('evidence')], 1)]:
            with self.subTest(flow=flow, failures=len(failures)), \
                 patch.object(p, 'run', side_effect=failures), patch.object(p.secrets, 'token_hex') as token, \
                 patch.object(p, 'windows_action_failure_location') as location:
                with self.assertRaises(ValueError): p.browser_checks({'flows': [flow], 'sha': SHA})
                location.assert_not_called(); self.assertEqual(token.call_count, expected_tokens)
        for flow in ['windows-service-actions', 'shell']:
            with patch.object(p, 'run') as run, patch.object(p, 'browser_report') as report, \
                 patch.object(p.secrets, 'token_hex', return_value=self.TOKEN) as token, \
                 patch.object(p, 'windows_action_failure_location') as location, \
                 patch.dict(os.environ, {'TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN': 'stale'}):
                p.browser_checks({'flows': [flow], 'sha': SHA})
            location.assert_not_called(); report.assert_called_once_with(flow, SHA)
            if flow == 'windows-service-actions':
                token.assert_called_once_with(16)
                self.assertEqual(run.call_args_list[1].kwargs['env']['TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN'], self.TOKEN)
            else:
                token.assert_not_called()
                self.assertNotIn('TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN', run.call_args_list[1].kwargs['env'])


class VitestFailureTests(unittest.TestCase):
    def fixture(self, root, marker='PRIVATE_RAW_VALUE'):
        source = root / 'web/src/exact.test.tsx'; source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('source fixture')
        return {'testResults': [{'name': str(source), 'status': 'failed', 'message': marker,
                'assertionResults': [{'status': 'passed'}, {'status': 'failed', 'fullName': marker, 'failureMessages': [marker]}]}]}

    def route_fixture(self, root, phase='blocked-mount'):
        source = root / 'web/src/route-details.test.tsx'; source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('source fixture')
        assertions = [{'status': 'passed'} for _ in range(19)]
        assertions[10] = {'status': 'failed', 'title': p.ROUTE_FIRST_COMMIT_TITLE,
                          'ancestorTitles': [p.ROUTE_FIRST_COMMIT_SUITE],
                          'fullName': p.ROUTE_FIRST_COMMIT_SUITE + ' ' + p.ROUTE_FIRST_COMMIT_TITLE,
                          'failureMessages': ['PRIVATE_RAW_VALUE'],
                          'meta': {'routeFirstCommitPhase': phase}}
        return {'testResults': [{'name': str(source), 'status': 'failed', 'message': 'PRIVATE_RAW_VALUE',
                                'assertionResults': assertions}]}

    def test_route_phase_is_a_closed_enum_for_the_exact_source_known_case(self):
        phases = {'bootstrap', 'suspend-import', 'blocked-mount', 'blocked-dom', 'resume-dom', 'resumed-mount'}
        self.assertEqual(p.ROUTE_FIRST_COMMIT_PHASES, phases)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = root / 'private.json'
            with patch.object(p, 'ROOT', root):
                for phase in sorted(phases):
                    report.write_text(json.dumps(self.route_fixture(root, phase)))
                    self.assertEqual(p.vitest_failure_location(report),
                                     'web/src/route-details.test.tsx assertions=11 route-first-commit=11:' + phase)

    def test_route_phase_rejects_unknown_extra_and_malformed_metadata(self):
        bad = [None, {}, [], 'PRIVATE_RAW_VALUE', {'other': 'blocked-mount'},
               {'routeFirstCommitPhase': 'blocked-mount', 'extra': 'PRIVATE_RAW_VALUE'}]
        bad += [{'routeFirstCommitPhase': value} for value in [
            None, True, 11, [], {}, 'PRIVATE_RAW_VALUE', 'blocked-mount\nPRIVATE_RAW_VALUE',
            'blocked-mount ', 'prefix-blocked-mount', 'x' * 10000,
        ]]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = root / 'private.json'; value = self.route_fixture(root)
            with patch.object(p, 'ROOT', root):
                for meta in bad:
                    value['testResults'][0]['assertionResults'][10]['meta'] = meta
                    report.write_text(json.dumps(value))
                    self.assertEqual(p.vitest_failure_location(report), 'web/src/route-details.test.tsx assertions=11')
                value['testResults'][0]['assertionResults'][10]['meta'] = {'routeFirstCommitPhase': 'blocked-mount'}
                raw = json.dumps(value).replace('"routeFirstCommitPhase": "blocked-mount"',
                    '"routeFirstCommitPhase": "blocked-mount", "routeFirstCommitPhase": "PRIVATE_RAW_VALUE"')
                report.write_text(raw); self.assertIsNone(p.vitest_failure_location(report))

    def test_route_phase_is_withheld_for_other_files_positions_cases_and_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = root / 'private.json'
            with patch.object(p, 'ROOT', root):
                for field, invalid in [('title', 'PRIVATE_RAW_VALUE'), ('fullName', 'PRIVATE_RAW_VALUE'),
                                       ('ancestorTitles', ['PRIVATE_RAW_VALUE'])]:
                    value = self.route_fixture(root); value['testResults'][0]['assertionResults'][10][field] = invalid
                    report.write_text(json.dumps(value))
                    self.assertEqual(p.vitest_failure_location(report), 'web/src/route-details.test.tsx assertions=11')
                value = self.route_fixture(root); row = value['testResults'][0]
                other = root / 'web/src/other.test.tsx'; other.write_text('source fixture'); row['name'] = str(other)
                report.write_text(json.dumps(value))
                self.assertEqual(p.vitest_failure_location(report), 'web/src/other.test.tsx assertions=11')
                for position in [0, 9, 11, 18]:
                    value = self.route_fixture(root); assertions = value['testResults'][0]['assertionResults']
                    assertions[position], assertions[10] = assertions[10], assertions[position]
                    report.write_text(json.dumps(value))
                    self.assertEqual(p.vitest_failure_location(report),
                                     'web/src/route-details.test.tsx assertions=' + str(position + 1))
                value = self.route_fixture(root); row = value['testResults'][0]
                row['status'] = 'passed'; row['assertionResults'][10]['status'] = 'passed'
                report.write_text(json.dumps(value)); self.assertIsNone(p.vitest_failure_location(report))

    def test_route_phase_preserves_failed_process_and_private_report_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); value = self.route_fixture(root, 'resumed-mount'); reports = []; output = io.StringIO()
            def failure(args, cwd, stage):
                report = Path(next(a.split('=', 1)[1] for a in args if a.startswith('--outputFile=')))
                self.assertNotIn('artifacts', report.parts); reports.append(report)
                report.write_text(json.dumps(value)); raise ValueError('original failure')
            with patch.object(p, 'ROOT', root), patch.object(p, 'run', side_effect=failure), redirect_stdout(output):
                with self.assertRaisesRegex(ValueError, 'original failure'):
                    p.run_vitest(['vitest', 'run', '--maxWorkers=1'], root / 'web', stage='ui-test')
            self.assertEqual(output.getvalue(),
                             'FAIL UI location: web/src/route-details.test.tsx assertions=11 route-first-commit=11:resumed-mount\n')
            self.assertFalse(reports[0].exists())

    def test_only_source_file_and_numeric_coordinates_are_released(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = root / 'private.json'; value = self.fixture(root)
            with patch.object(p, 'ROOT', root):
                report.write_text(json.dumps(value))
                self.assertEqual(p.vitest_failure_location(report), 'web/src/exact.test.tsx assertions=2')
                value['testResults'][0]['assertionResults'] = []
                report.write_text(json.dumps(value))
                self.assertEqual(p.vitest_failure_location(report), 'web/src/exact.test.tsx assertions=runner-or-hook')

    def test_unknown_paths_duplicates_invalid_status_and_symlinks_are_withheld(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); report = root / 'private.json'; value = self.fixture(root)
            bad = [dict(testResults=[dict(value['testResults'][0], name='/PRIVATE_RAW_PATH')]),
                   dict(testResults=value['testResults'] * 2),
                   dict(testResults=[dict(value['testResults'][0], status='PRIVATE_STATUS')]),
                   dict(testResults=[dict(value['testResults'][0], assertionResults=[{'status': 'PRIVATE_STATUS'}])]),
                   dict(testResults=[dict(value['testResults'][0], status='passed')])]
            with patch.object(p, 'ROOT', root):
                for malformed in bad:
                    report.write_text(json.dumps(malformed)); self.assertIsNone(p.vitest_failure_location(report))
                report.write_text('{"testResults":[],"testResults":[]}'); self.assertIsNone(p.vitest_failure_location(report))
                report.write_text(json.dumps(value)); link = root/'link.json'; link.symlink_to(report)
                self.assertIsNone(p.vitest_failure_location(link))
                report.write_bytes(b'x' * ((16 << 20) + 1)); self.assertIsNone(p.vitest_failure_location(report))

    def test_failed_process_stays_failed_and_private_json_is_not_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); value = self.fixture(root); seen = []; output = io.StringIO()
            def failure(args, cwd, stage):
                seen.append((args, cwd, stage))
                report = Path(next(a.split('=',1)[1] for a in args if a.startswith('--outputFile=')))
                self.assertNotIn('artifacts', report.parts); report.write_text(json.dumps(value))
                raise ValueError('original failure')
            with patch.object(p, 'ROOT', root), patch.object(p, 'run', side_effect=failure), redirect_stdout(output):
                with self.assertRaisesRegex(ValueError, 'original failure'):
                    p.run_vitest(['vitest', 'run', '--maxWorkers=1'], root/'web', stage='ui-test')
            self.assertEqual(seen[0][0][:3], ['vitest', 'run', '--maxWorkers=1'])
            self.assertEqual(seen[0][1:], (root/'web', 'ui-test'))
            self.assertEqual(output.getvalue(), 'FAIL UI location: web/src/exact.test.tsx assertions=2\n')
            self.assertFalse(Path(seen[0][0][-1].split('=',1)[1]).exists())


class CVEReviewFailureTests(unittest.TestCase):
    def report(self, stage='review-focus', index=0):
        return {'sourceSha': SHA, 'status': 'FAIL', 'browserAcceptance': False,
                'sceneManifestSHA256': 'b' * 64, 'scenes': 0, 'screenshots': 0,
                'requestsToRealAPI': 0, 'actualMutationRequests': 0,
                'nativeAcceptance': False, 'disclosure': 'private fixture prose is never emitted',
                'failure': {'stage': stage, 'captureIndex': index}}

    def test_all_closed_stages_and_source_contract(self):
        capture = (ROOT / 'web/scripts/capture-linux-cve-update-review.mjs').read_text()
        driver = (ROOT / 'web/scripts/run-linux-cve-update-review-ci.mjs').read_text()
        self.assertEqual(set(re.findall(r"stage\('([^']+)'\)", capture)), p.CVE_CAPTURE_STAGES)
        self.assertEqual({'launch'} | set(re.findall(r"onStage\('([^']+)'", capture + driver)), p.CVE_RUNNER_STAGES)
        self.assertIn('120000', driver)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'artifacts/review/linux-cve-update-review-results.json'
            target.parent.mkdir(parents=True)
            with patch.object(p, 'ROOT', root):
                for stage in p.CVE_RUNNER_STAGES:
                    target.write_text(json.dumps(self.report(stage, None)))
                    self.assertEqual(p.cve_review_failure_location(SHA), 'stage=' + stage)
                for stage in p.CVE_CAPTURE_STAGES:
                    for index, (locale, width) in enumerate([('en', 1440), ('en', 390), ('de', 1440), ('de', 390)]):
                        target.write_text(json.dumps(self.report(stage, index)))
                        self.assertEqual(p.cve_review_failure_location(SHA), f'stage={stage} locale={locale} width={width}')

    def test_rejects_unsafe_or_malformed_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / 'artifacts/review/linux-cve-update-review-results.json'
            target.parent.mkdir(parents=True)
            with patch.object(p, 'ROOT', root):
                values = []
                for key, value in [('sourceSha', 'c'*40), ('status', 'PASS'), ('browserAcceptance', True),
                                   ('nativeAcceptance', True), ('sceneManifestSHA256', 'runtime text'),
                                   ('disclosure', 'x'*1025), ('screenshots', True), ('scenes', 1),
                                   ('requestsToRealAPI', 1), ('actualMutationRequests', 1), ('extra', 'private')]:
                    report = self.report(); report[key] = value; values.append(report)
                for failure in [None, [], {}, {'stage': 'private secret', 'captureIndex': 0},
                                {'stage': 'review-focus', 'captureIndex': -1}, {'stage': 'review-focus', 'captureIndex': 4},
                                {'stage': 'review-focus', 'captureIndex': True}, {'stage': 'review-focus', 'captureIndex': None},
                                {'stage': 'launch', 'captureIndex': 0}, {'stage': [], 'captureIndex': 0},
                                {'stage': 'review-focus', 'captureIndex': 0, 'error': 'private'}]:
                    report = self.report(); report['failure'] = failure; values.append(report)
                for value in values:
                    target.write_text(json.dumps(value)); self.assertIsNone(p.cve_review_failure_location(SHA))
                for raw in [b'{"status":"FAIL","status":"PASS"}', b'x'*8193, b'\xff']:
                    target.write_bytes(raw); self.assertIsNone(p.cve_review_failure_location(SHA))
                target.unlink(); self.assertIsNone(p.cve_review_failure_location(SHA))
                target.mkdir(); self.assertIsNone(p.cve_review_failure_location(SHA)); target.rmdir()
                other = root / 'other.json'; other.write_text(json.dumps(self.report())); target.symlink_to(other)
                self.assertIsNone(p.cve_review_failure_location(SHA))

    def test_diagnostics_preserve_failure_and_skip_other_flows(self):
        plan = {'flows': ['linux-cve-update-review'], 'sha': SHA}
        output = io.StringIO()
        with patch.object(p, 'run', side_effect=[None, ValueError('private')]), \
             patch.object(p, 'cve_review_failure_location', return_value='stage=review-focus locale=en width=1440') as location, \
             redirect_stdout(output):
            with self.assertRaisesRegex(ValueError, 'private'): p.browser_checks(plan)
        location.assert_called_once_with(SHA)
        self.assertIn('FAIL CVE review location: stage=review-focus locale=en width=1440', output.getvalue())
        self.assertNotIn('private', output.getvalue())
        with patch.object(p, 'run'), patch.object(p, 'browser_report'), \
             patch.object(p, 'cve_review_failure_location') as location:
            p.browser_checks(plan)
        location.assert_not_called()


JOURNAL_MARKER = 'PRIVATE_MARKER_MUST_NOT_ESCAPE'


def journal_diagnostic_report():
    return {'schemaVersion': 'tracebolt.journal-browser-failure.v1', 'sourceSha': SHA,
            'failures': [{'case': 1, 'checkpoint': 5}], 'setupFailure': False,
            'runtimeFailure': False, 'finalCheckpoint': 8}


class JournalDiagnosticTests(unittest.TestCase):
    def test_exact_numeric_only_projection_and_failure_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'record.json'
            for extra, expected in [({}, 'case=1 checkpoint=5'),
                                    ({'setupFailure': True}, 'case=1 checkpoint=5; setup-checkpoint=8'),
                                    ({'failures': [], 'runtimeFailure': True}, 'runtime-errors')]:
                path.write_text(json.dumps({**journal_diagnostic_report(), **extra}))
                self.assertEqual(p.journal_failure_location(path, SHA), expected)

    def test_tampered_unknown_oversized_and_duplicate_records_are_withheld(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'record.json'
            invalid = [{'sourceSha': 'b' * 40}, {'schemaVersion': JOURNAL_MARKER}, {'private': JOURNAL_MARKER},
                       {'failures': []}, {'setupFailure': 1}, {'runtimeFailure': 0},
                       {'finalCheckpoint': True}, {'finalCheckpoint': -1}, {'finalCheckpoint': 128},
                       {'failures': [{'case': 1, 'checkpoint': 128}]},
                       {'failures': [{'case': 0, 'checkpoint': 5}]},
                       {'failures': [{'case': 8, 'checkpoint': 5}]},
                       {'failures': [{'case': True, 'checkpoint': 5}]},
                       {'failures': [{'case': 1, 'checkpoint': False}]},
                       {'failures': [{'case': 1, 'checkpoint': 5, 'error': JOURNAL_MARKER}]},
                       {'failures': [{'case': 2, 'checkpoint': 5}, {'case': 1, 'checkpoint': 5}]},
                       {'failures': [{'case': 1, 'checkpoint': 5}] * 2},
                       {'failures': [{'case': 1, 'checkpoint': 5}] * 8}]
            for extra in invalid:
                path.write_text(json.dumps({**journal_diagnostic_report(), **extra}))
                self.assertIsNone(p.journal_failure_location(path, SHA), extra)
            for raw in [b'{', b'\xff', b'x' * 8193,
                        json.dumps(journal_diagnostic_report()).replace('"failures":', '"failures": [], "failures":').encode(),
                        json.dumps(journal_diagnostic_report()).replace('"finalCheckpoint": 8', '"finalCheckpoint": NaN').encode()]:
                path.write_bytes(raw)
                self.assertIsNone(p.journal_failure_location(path, SHA))

    def test_nonregular_files_symlinks_and_untrusted_contract_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'record.json'; path.write_text(json.dumps(journal_diagnostic_report()))
            link = root / 'link.json'; link.symlink_to(path)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            for unsafe in [link, fifo, root]:
                self.assertIsNone(p.journal_failure_location(unsafe, SHA))
            alias = root / 'alias'; alias.symlink_to(root, target_is_directory=True)
            self.assertIsNone(p.journal_failure_location(alias / 'record.json', SHA))
            contract = root / 'contract.json'
            for raw in [b'{}', b'x' * 16385]:
                contract.write_bytes(raw)
                with patch.object(p, 'JOURNAL_COORDINATES_SOURCE', contract):
                    self.assertIsNone(p.journal_failure_location(path, SHA))

    def test_one_invocation_private_lifetime_original_failure_and_no_raw_output(self):
        paths, output = [], io.StringIO()
        def process(args, **kwargs):
            kwargs['stdout'].write(JOURNAL_MARKER.encode())
            path = Path(kwargs['env']['TRACEBOLT_JOURNAL_DIAGNOSTICS_PATH'])
            self.assertFalse(path.exists()); self.assertNotIn('artifacts', path.parts)
            paths.append(path)
            if len(paths) == 1:
                path.write_text(json.dumps(journal_diagnostic_report()))
            return SimpleNamespace(returncode=1)
        with patch.object(p.subprocess, 'run', side_effect=process), redirect_stdout(output):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, 'raw fixture output withheld'):
                    p.run_journal_browser({'TRACEBOLT_JOURNAL_DIAGNOSTICS_PATH': '/not-used'}, SHA)
        self.assertNotEqual(paths[0], paths[1])
        self.assertTrue(all(not path.parent.exists() for path in paths))
        self.assertEqual(output.getvalue().count('FAIL journal location: case=1 checkpoint=5'), 1)
        for forbidden in [JOURNAL_MARKER, SHA, 'PASS:', *map(str, paths)]:
            self.assertNotIn(forbidden, output.getvalue())

    def test_original_exception_identity_and_success_skip_projection(self):
        original = ValueError(JOURNAL_MARKER)
        with patch.object(p, 'run', side_effect=original), patch.object(p, 'journal_failure_location', return_value=None):
            with self.assertRaises(ValueError) as caught:
                p.run_journal_browser({}, SHA)
        self.assertIs(caught.exception, original)
        with patch.object(p, 'run'), patch.object(p, 'journal_failure_location') as projection:
            p.run_journal_browser({}, SHA)
        projection.assert_not_called()

    def test_only_journal_failure_uses_projection_and_browser_failure_stays_failed(self):
        original = ValueError(JOURNAL_MARKER)
        with patch.object(p, 'run'), patch.object(p, 'run_journal_browser', side_effect=original) as journal, \
                patch.object(p, 'browser_report') as acceptance:
            with self.assertRaises(ValueError) as caught:
                p.browser_checks({'flows': ['journal'], 'sha': SHA})
        self.assertIs(caught.exception, original); journal.assert_called_once(); acceptance.assert_not_called()
        with patch.object(p, 'run'), patch.object(p, 'run_journal_browser') as journal, patch.object(p, 'browser_report'):
            p.browser_checks({'flows': ['shell'], 'sha': SHA})
        journal.assert_not_called()


class ShellRouteLoadingDiagnosticTests(unittest.TestCase):
    def report(self, **extra):
        return {'schema': 1, 'sourceSha': SHA, 'status': 'FAIL', 'stage': 'cold-navigation', 'runtimeError': False, **extra}

    def test_every_closed_stage_and_producer_contract_match(self):
        source = (ROOT / 'tests/e2e-review/route-loading-browser.mjs').read_text()
        stages = re.search(r'routeLoadingDevelopmentStages = Object.freeze\(\[(.*?)\]\)', source, re.S)
        self.assertIsNotNone(stages)
        self.assertEqual(tuple(re.findall(r"'([^']+)'", stages[1])), p.ROUTE_LOADING_STAGES)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'
            for stage in p.ROUTE_LOADING_STAGES:
                path.write_text(json.dumps(self.report(stage=stage)))
                self.assertEqual(p.shell_route_loading_location(path, SHA), 'case=direct-case status=fail stage=' + stage)
            for extra, expected in [({'status': 'PASS', 'stage': 'complete'}, 'status=pass stage=complete'),
                                    ({'status': 'NOT_RUN', 'stage': 'fixture'}, 'status=not_run stage=fixture'),
                                    ({'runtimeError': True}, 'status=fail stage=cold-navigation runtime-errors')]:
                path.write_text(json.dumps(self.report(**extra)))
                self.assertEqual(p.shell_route_loading_location(path, SHA), 'case=direct-case ' + expected)

    def test_unknown_raw_stale_malformed_and_oversized_records_are_withheld(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'
            for extra in [{'schema': True}, {'schema': 2}, {'sourceSha': 'b' * 40}, {'status': 'raw-private-marker'},
                          {'stage': 'raw-private-marker'}, {'stage': []}, {'runtimeError': 1}, {'error': 'raw-private-marker'},
                          {'status': 'PASS'}, {'status': 'NOT_RUN'}, {'status': 'NOT_RUN', 'stage': 'fixture', 'runtimeError': True}]:
                path.write_text(json.dumps(self.report(**extra)))
                self.assertIsNone(p.shell_route_loading_location(path, SHA), extra)
            for raw in [b'{', b'\xff', b'x' * 2049,
                        json.dumps(self.report()).replace('"schema": 1', '"schema": 1, "schema": 1').encode(),
                        json.dumps(self.report()).replace('"schema": 1', '"schema": NaN').encode()]:
                path.write_bytes(raw)
                self.assertIsNone(p.shell_route_loading_location(path, SHA))
            path.write_text(json.dumps(self.report()))
            self.assertIsNone(p.shell_route_loading_location(path, 'not-a-sha'))

    def test_nonregular_and_symlink_files_are_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); path = root / 'record.json'; path.write_text(json.dumps(self.report()))
            link = root / 'link'; link.symlink_to(path)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            alias = root / 'alias'; alias.symlink_to(root, target_is_directory=True)
            for unsafe in [link, fifo, root, alias / 'record.json', root / 'missing']:
                self.assertIsNone(p.shell_route_loading_location(unsafe, SHA))

    def test_invocation_is_private_fresh_removed_and_never_releases_raw_output(self):
        paths, output = [], io.StringIO()
        def process(args, **kwargs):
            self.assertEqual(args, ['node', p.FLOWS['shell']])
            kwargs['stdout'].write(b'raw-private-marker')
            path = Path(kwargs['env']['TRACEBOLT_ROUTE_LOADING_DIAGNOSTIC'])
            self.assertFalse(path.exists()); self.assertNotIn('artifacts', path.parts)
            paths.append(path)
            if len(paths) == 1:
                path.write_text(json.dumps(self.report()))
            return SimpleNamespace(returncode=1)
        with patch.object(p.subprocess, 'run', side_effect=process), redirect_stdout(output):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, 'raw fixture output withheld'):
                    p.run_shell_browser({'TRACEBOLT_ROUTE_LOADING_DIAGNOSTIC': '/not-used'}, SHA)
        self.assertNotEqual(paths[0], paths[1]); self.assertTrue(all(not path.parent.exists() for path in paths))
        self.assertEqual(output.getvalue().count('FAIL shell route-load location: case=direct-case status=fail stage=cold-navigation'), 1)
        for forbidden in ['raw-private-marker', SHA, 'PASS:', *map(str, paths)]:
            self.assertNotIn(forbidden, output.getvalue())

    def test_original_failure_and_browser_acceptance_stay_unchanged(self):
        original = ValueError('inert failure')
        with patch.object(p, 'run', side_effect=original), patch.object(p, 'shell_route_loading_location', return_value=None):
            with self.assertRaises(ValueError) as caught:
                p.run_shell_browser({}, SHA)
        self.assertIs(caught.exception, original)
        with patch.object(p, 'run'), patch.object(p, 'shell_route_loading_location') as projection:
            p.run_shell_browser({}, SHA)
        projection.assert_not_called()
        with patch.object(p, 'run'), patch.object(p, 'run_shell_browser', side_effect=original) as shell, patch.object(p, 'browser_report') as acceptance:
            with self.assertRaises(ValueError) as caught:
                p.browser_checks({'flows': ['shell'], 'sha': SHA})
        self.assertIs(caught.exception, original); shell.assert_called_once(); acceptance.assert_not_called()


class ShellFailureDiagnosticTests(unittest.TestCase):
    def report(self, **extra):
        return {'schema': 1, 'sourceSha': SHA, 'failures': [{'case': 2, 'category': 'assertion'}], 'runtimeCases': [], 'unknownCase': False, **extra}

    def test_exact_closed_categories_ids_runtime_and_unknown_flag(self):
        source = (ROOT / 'tests/e2e-review/shell-browser-diagnostics.mjs').read_text()
        categories = re.search(r'shellFailureCategories = Object.freeze\(\[(.*?)\]\)', source, re.S)
        self.assertEqual(tuple(re.findall(r"'([^']+)'", categories[1])), p.SHELL_FAILURE_CATEGORIES)
        contract = json.loads(p.SHELL_CASES_SOURCE.read_text())
        self.assertEqual(len(contract['cases']), 45); self.assertEqual(len(set(contract['cases'])), 45)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'
            for category in p.SHELL_FAILURE_CATEGORIES:
                path.write_text(json.dumps(self.report(failures=[{'case': 45, 'category': category}], runtimeCases=[1, 45], unknownCase=True)))
                self.assertEqual(p.shell_failure_location(path, SHA), 'case=45 category=' + category + '; case=1 category=runtime; case=45 category=runtime; unknown-case')
            path.write_text(json.dumps(self.report(failures=[])))
            self.assertIsNone(p.shell_failure_location(path, SHA))

    def test_only_case36_accepts_each_closed_stage_and_rejects_unknown_or_misplaced_stage(self):
        source = (ROOT / 'tests/e2e-review/shell-scenarios.mjs').read_text()
        stages = re.search(r'shellKeyboardStages = Object.freeze\(\[(.*?)\]\)', source, re.S)
        self.assertEqual(tuple(re.findall(r"'([^']+)'", stages[1])), p.SHELL_KEYBOARD_STAGES)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'
            for stage in range(len(p.SHELL_KEYBOARD_STAGES)):
                path.write_text(json.dumps(self.report(failures=[{'case': 36, 'category': 'other', 'stage': stage}])))
                self.assertEqual(p.shell_failure_location(path, SHA), 'case=36 category=other stage=%d' % stage)
            for row in [{'case': 36, 'category': 'other'},
                        *[{'case': 36, 'category': 'other', 'stage': stage} for stage in [True, -1, 10, 'private-marker']],
                        {'case': 35, 'category': 'other', 'stage': 1}]:
                path.write_text(json.dumps(self.report(failures=[row])))
                self.assertIsNone(p.shell_failure_location(path, SHA), row)

    def test_gallery_source_domains_and_every_closed_coordinate(self):
        source = (ROOT / 'tests/e2e-review/concise-shell-gallery.mjs').read_text()
        for name, expected in [('shellGallerySurfaces', p.SHELL_GALLERY_SURFACES), ('shellGalleryPhases', p.SHELL_GALLERY_PHASES)]:
            domain = re.search(name + r' = Object.freeze\(\[(.*?)\]\)', source, re.S)
            self.assertEqual(tuple(re.findall(r"'([^']+)'", domain[1])), expected)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'
            for case in (28, 29, 30, 31):
                for surface, surface_name in enumerate(p.SHELL_GALLERY_SURFACES):
                    for phase, phase_name in enumerate(p.SHELL_GALLERY_PHASES):
                        row = {'case': case, 'category': 'assertion', 'surface': surface, 'phase': phase}
                        path.write_text(json.dumps(self.report(failures=[row])))
                        self.assertEqual(p.shell_failure_location(path, SHA), 'case=%d category=assertion surface=%s phase=%s' % (case, surface_name, phase_name))
            valid = {'case': 28, 'category': 'assertion', 'surface': 0, 'phase': 0}
            invalid = [{**valid, 'case': case} for case in (27, 32, 36)]
            invalid += [{key: value for key, value in valid.items() if key != omitted} for omitted in ('surface', 'phase')]
            invalid += [{**valid, key: value} for key, limit in [('surface', len(p.SHELL_GALLERY_SURFACES)), ('phase', len(p.SHELL_GALLERY_PHASES))] for value in (True, -1, limit, 'private-marker', [], {})]
            invalid += [{**valid, 'actual': 'private-marker'}, {**valid, 'stage': 0}]
            for row in invalid:
                path.write_text(json.dumps(self.report(failures=[row])))
                self.assertIsNone(p.shell_failure_location(path, SHA), row)

    def test_actual_gallery_producer_decodes_only_fixed_failure_coordinates(self):
        script = """
import { createShellFailureDiagnostic } from './tests/e2e-review/shell-browser-diagnostics.mjs';
import { shellGalleryCheckpoint } from './tests/e2e-review/concise-shell-gallery.mjs';
import contract from './tests/e2e-review/shell-browser-cases.json' with { type: 'json' };
const diagnostic = createShellFailureDiagnostic();
shellGalleryCheckpoint('source-head', 'summary');
diagnostic.failure(contract.cases[27], { matcherResult: { actual: 'private-marker' }, message: 'private-marker' });
shellGalleryCheckpoint('font-count', 'compact');
diagnostic.failure(contract.cases[30], { matcherResult: { actual: 'private-marker' } });
console.log(JSON.stringify(diagnostic.report('%s')));
""" % SHA
        result = subprocess.run(['node', '--input-type=module', '-e', script], cwd=ROOT, check=True, capture_output=True, text=True)
        self.assertNotIn('private-marker', result.stdout)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'; path.write_text(result.stdout)
            self.assertEqual(p.shell_failure_location(path, SHA), 'case=28 category=assertion surface=summary phase=source-head; case=31 category=assertion surface=compact phase=font-count')

    def test_unknown_names_categories_raw_fields_bad_types_stale_and_out_of_range_rejected(self):
        invalid = [{'sourceSha': 'b' * 40}, {'schema': True}, {'schema': 2}, {'unknownCase': 1}, {'error': 'private-marker'},
                   {'failures': [{'case': 2, 'category': 'private-marker'}]},
                   {'failures': [{'case': 'private-name', 'category': 'assertion'}]},
                   {'failures': [{'case': 2, 'category': 'assertion', 'name': 'private-name'}]},
                   {'failures': [{'case': True, 'category': 'assertion'}]},
                   {'failures': [{'case': 0, 'category': 'assertion'}]},
                   {'failures': [{'case': 46, 'category': 'assertion'}]},
                   {'failures': [{'case': 2, 'category': 'assertion'}] * 2},
                   {'failures': [{'case': 3, 'category': 'assertion'}, {'case': 2, 'category': 'timeout'}]},
                   {'failures': [{'case': 2, 'category': 'assertion'}] * 46},
                   {'runtimeCases': [True]}, {'runtimeCases': [0]}, {'runtimeCases': [46]},
                   {'runtimeCases': [2, 1]}, {'runtimeCases': [1, 1]}, {'runtimeCases': ['private-name']},
                   {'runtimeCases': list(range(1, 47))}, {'runtimeCases': {}}, {'failures': {}}]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'
            for extra in invalid:
                path.write_text(json.dumps(self.report(**extra)))
                self.assertIsNone(p.shell_failure_location(path, SHA), extra)
            for raw in [b'{', b'\xff', b'x' * 8193,
                        json.dumps(self.report()).replace('"schema": 1', '"schema": 1, "schema": 1').encode(),
                        json.dumps(self.report()).replace('"schema": 1', '"schema": NaN').encode()]:
                path.write_bytes(raw); self.assertIsNone(p.shell_failure_location(path, SHA))
            path.write_text(json.dumps(self.report()))
            self.assertIsNone(p.shell_failure_location(path, 'invalid-source'))

    def test_symlink_nonregular_and_invalid_source_manifest_withheld(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); path = root / 'record.json'; path.write_text(json.dumps(self.report()))
            link = root / 'link'; link.symlink_to(path)
            fifo = root / 'fifo'; os.mkfifo(fifo)
            alias = root / 'alias'; alias.symlink_to(root, target_is_directory=True)
            for unsafe in [link, fifo, root, alias / 'record.json', root / 'missing']:
                self.assertIsNone(p.shell_failure_location(unsafe, SHA))
            contract = root / 'contract.json'
            valid = json.loads(p.SHELL_CASES_SOURCE.read_text())
            for raw in [b'{}', b'x' * 16385, json.dumps({**valid, 'schema': True}).encode(),
                        json.dumps({**valid, 'cases': valid['cases'][:44]}).encode(),
                        json.dumps({**valid, 'cases': ['same'] * 45}).encode()]:
                contract.write_bytes(raw)
                with patch.object(p, 'SHELL_CASES_SOURCE', contract):
                    self.assertIsNone(p.shell_failure_location(path, SHA))

    def test_fresh_private_invocation_preserves_direct_case_diagnostic_and_original_failure(self):
        paths, output = [], io.StringIO()
        def process(args, **kwargs):
            self.assertEqual(args, ['node', p.FLOWS['shell']])
            kwargs['stdout'].write(b'private-marker')
            path = Path(kwargs['env']['TRACEBOLT_SHELL_DIAGNOSTIC'])
            direct = Path(kwargs['env']['TRACEBOLT_ROUTE_LOADING_DIAGNOSTIC'])
            self.assertEqual(path.parent, direct.parent); self.assertNotEqual(path, direct)
            self.assertFalse(path.exists()); self.assertFalse(direct.exists()); self.assertNotIn('artifacts', path.parts)
            paths.append(path)
            if len(paths) == 1:
                path.write_text(json.dumps(self.report()))
                direct.write_text(json.dumps({'schema': 1, 'sourceSha': SHA, 'status': 'PASS', 'stage': 'complete', 'runtimeError': False}))
            return SimpleNamespace(returncode=1)
        with patch.object(p.subprocess, 'run', side_effect=process), redirect_stdout(output):
            for _ in range(2):
                with self.assertRaisesRegex(ValueError, 'raw fixture output withheld'):
                    p.run_shell_browser({'TRACEBOLT_SHELL_DIAGNOSTIC': '/not-used'}, SHA)
        self.assertNotEqual(paths[0], paths[1]); self.assertTrue(all(not path.parent.exists() for path in paths))
        self.assertEqual(output.getvalue().count('FAIL shell location: case=2 category=assertion'), 1)
        self.assertEqual(output.getvalue().count('FAIL shell route-load location: case=direct-case status=pass stage=complete'), 1)
        for forbidden in ['private-marker', SHA, *map(str, paths)]:
            self.assertNotIn(forbidden, output.getvalue())

    def test_success_never_projects_and_failure_identity_remains(self):
        original = ValueError('inert failure')
        with patch.object(p, 'run', side_effect=original), patch.object(p, 'shell_failure_location', return_value=None):
            with self.assertRaises(ValueError) as caught:
                p.run_shell_browser({}, SHA)
        self.assertIs(caught.exception, original)
        with patch.object(p, 'run'), patch.object(p, 'shell_failure_location') as projection:
            p.run_shell_browser({}, SHA)
        projection.assert_not_called()


if __name__ == '__main__':
    unittest.main()
