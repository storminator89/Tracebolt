"""Inert selection/contract tests; no Go tests, browser, network, or host actions."""
import importlib.util
import io
from contextlib import redirect_stdout
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
            'windows-update-retirement.tsx': ['windows-mutation-coexistence', 'windows-service-actions'],
            'windows-update-retirement-resource.ts': ['windows-mutation-coexistence', 'windows-service-actions'],
            'windows-update-retirement.test.tsx': ['windows-mutation-coexistence', 'windows-service-actions'],
            'package-updates.tsx': ['conditional', 'lan'],
            'service-actions.tsx': ['service-action', 'service-action-v2'],
            'windows-managed-msi.tsx': ['windows-fleet-msi', 'windows-managed-msi', 'windows-mutation-coexistence'],
        }.items():
            with self.subTest(filename=filename):
                self.assertEqual(self.select(('M', 'web/src/' + filename))['flows'], flows)

    def test_shared_or_unknown_ui_broadens_instead_of_guessing(self):
        for path in ['web/src/App.tsx', 'web/src/api.ts', 'web/src/new-feature.tsx', 'web/package-lock.json']:
            self.assertTrue(self.select(('M', path))['broadWeb'])

    def test_exact_owned_scripts_select_the_existing_complete_fleet_flow(self):
        expected = {
            'capture-windows-fleet-msi-fixtures.mjs', 'capture-windows-msi-catalogue-fixtures.mjs',
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

    def test_exact_retirement_fixture_selects_its_existing_update_owner(self):
        expected = {'tests/e2e-review/windows-update-retirement-browser.mjs',
                    'tests/e2e-review/windows-update-retirement-fixtures.test.mjs'}
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
                                     'tests/e2e-review/windows-update-retirement-fixtures.test.mjs'})

    def test_retirement_browser_report_uses_the_canonical_source_validator(self):
        plan = self.select(('M', 'tests/e2e-review/windows-update-retirement-browser.mjs'))
        with patch.object(p, 'run') as run, patch.object(p, 'browser_report') as report:
            p.browser_checks(plan)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'],
            ['node', 'tests/e2e-review/windows-service-actions-runner.mjs'],
            ['node', 'tests/e2e-review/windows-update-retirement-browser.mjs', '--check-evidence', SHA],
        ])
        report.assert_called_once_with('windows-service-actions', SHA)

    def test_cve_bridge_owns_one_changed_flow_and_shared_evidence_validator(self):
        for filename in ['check-linux-cve-update-review-evidence.mjs', 'capture-linux-cve-update-review.mjs', 'run-linux-cve-update-review-ci.mjs',
                         'linux-cve-update-review-contract.mjs', 'linux-cve-update-review-scenes.json',
                         'linux-cve-update-review-contract.test.mjs']:
            plan = self.select(('M', 'web/scripts/' + filename))
            self.assertEqual(plan['flows'], ['linux-cve-update-review'])
            self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
        plan = self.select(('M', 'web/src/linux-cve-update-review.ts'))
        self.assertEqual(plan['flows'], ['linux-cve-update-review'])
        with patch.object(p, 'run') as run:
            p.web_checks(plan)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands.count(['node', 'web/scripts/capture-linux-cve-update-review.mjs', '--check']), 1)
        self.assertEqual(commands.count(['node', '--test', 'web/scripts/linux-cve-update-review-contract.test.mjs']), 1)
        for name in ['linux-cve-update-review-results.json', 'linux-cve-update-review-manifest.json', 'synthetic-linux-cve-update-review-*.png']:
            self.assertIn(name, (ROOT / '.github/workflows/pr-checks.yml').read_text())
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
        self.assertEqual(plan['flows'], ['linux-cve-update-review', 'windows-fleet-msi', 'windows-maintenance', 'windows-service-actions'])
        self.assertFalse(plan['broadGo']); self.assertFalse(plan['broadWeb'])
        self.assertEqual(plan, p.select(list(reversed(changes)), self.packages, self.files, SHA,
                                      generated_allowlist_verified=True))

    def test_exact_msi_ui_owners_keep_changed_and_related_interaction_checks(self):
        self.assertEqual(set(p.DOMAIN_UI), {
            'web/src/windows-fleet-managed-msi.css',
            'web/src/windows-fleet-managed-msi.test.tsx',
            'web/src/windows-reusable-managed-msi.test.tsx',
        })
        for path, flows in p.DOMAIN_UI.items():
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


if __name__ == '__main__':
    unittest.main()
