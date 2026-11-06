"""Inert focused-browser policy tests; no browser, subprocess or network use."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('pr_browser_execution_test', ROOT / 'tests/security/run_pr_browser_checks.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
SHA = 'a' * 40


class BrowserExecutionTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {'GITHUB_SHA': SHA})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.plan = {'schema': 1, 'sha': SHA, 'broadGo': False, 'broadWeb': False,
                     'packages': ['localrmm/internal/windowsusersoftware'],
                     'web': ['src/windows-user-software.tsx'],
                     'flows': ['enrollment', 'first-report', 'windows-user-software']}

    def test_only_the_retired_browser_flow_is_removed(self):
        original = json.dumps(self.plan, sort_keys=True)
        actual = runner.browser_plan(original)
        self.assertEqual(actual, {**self.plan, 'flows': ['enrollment', 'first-report']})
        self.assertEqual(json.dumps(self.plan, sort_keys=True), original)

    def test_broad_plan_keeps_every_other_flow_and_original_source_selection(self):
        self.plan.update(broadGo=True, broadWeb=True, flows=sorted(runner.checks.FLOWS))
        actual = runner.browser_plan(json.dumps(self.plan))
        self.assertEqual(actual['flows'], sorted(set(runner.checks.FLOWS) - {'windows-user-software'}))
        for key in set(self.plan) - {'flows'}:
            self.assertEqual(actual[key], self.plan[key])

    def test_unrelated_and_empty_plans_are_unchanged(self):
        for flows in [[], ['enrollment'], ['first-report'], ['enrollment', 'windows-full-software']]:
            self.plan['flows'] = flows
            with self.subTest(flows=flows):
                self.assertEqual(runner.browser_plan(json.dumps(self.plan)), self.plan)

    def test_invalid_or_incomplete_broad_plan_fails_before_execution(self):
        for changes in [{'sha': 'b' * 40}, {'schema': 2}, {'flows': ['unknown']},
                        {'flows': ['enrollment', 'enrollment']}, {'broadWeb': True},
                        {'web': ['src/../private']}, {'skip': ['enrollment']}]:
            with self.subTest(changes=changes), patch.dict(os.environ, {
                'TRACEBOLT_PR_PLAN': json.dumps({**self.plan, **changes})
            }), patch.object(runner.checks, 'browser_checks') as execute:
                with self.assertRaises((ValueError, TypeError)):
                    runner.main()
                execute.assert_not_called()

    def test_dispatch_preserves_smoke_and_other_flow_evidence_gates(self):
        plan = runner.browser_plan(json.dumps(self.plan))
        with patch.object(runner.checks, 'run') as run, patch.object(runner.checks, 'browser_report') as report:
            runner.checks.browser_checks(plan)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(calls, [
            ['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'],
            ['node', runner.checks.FLOWS['enrollment']],
            ['node', runner.checks.FLOWS['first-report']],
        ])
        self.assertEqual([call.args for call in report.call_args_list], [('enrollment', SHA), ('first-report', SHA)])

    def test_retired_only_plan_keeps_auth_smoke_without_fabricating_evidence(self):
        self.plan['flows'] = ['windows-user-software']
        with patch.dict(os.environ, {'TRACEBOLT_PR_PLAN': json.dumps(self.plan)}), \
             patch.object(runner.checks, 'run') as run, \
             patch.object(runner.checks, 'browser_report') as report:
            runner.main()
        run.assert_called_once_with(['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'], stage='browser-auth-smoke')
        report.assert_not_called()

    def test_other_browser_failures_still_fail(self):
        with patch.dict(os.environ, {'TRACEBOLT_PR_PLAN': json.dumps(self.plan)}), \
             patch.object(runner.checks, 'browser_checks', side_effect=ValueError('inert failure')):
            with self.assertRaises(ValueError):
                runner.main()

    def test_workflow_wiring_keeps_contracts_and_enrollment_checks(self):
        focused = (ROOT / '.github/workflows/pr-checks.yml').read_text()
        full = (ROOT / '.github/workflows/validate.yml').read_text()
        self.assertEqual(focused.count('run: python3 -I -B tests/security/run_pr_browser_checks.py\n'), 1)
        self.assertIn('python3 -I -B tests/security/test_pr_browser_execution.py\n', focused)
        for workflow in [focused, full]:
            self.assertNotIn('windows-user-software-runner.mjs', workflow)
            self.assertNotIn('windows-user-software-results.json', workflow)
            self.assertNotIn('windows-user-software-manifest.json', workflow)
            self.assertEqual(workflow.count('node --test tests/e2e-review/windows-user-software-fixtures.test.mjs\n'), 1)
        self.assertIn('node web/scripts/run-windows-enrollment-ci.mjs', focused)
        self.assertIn('node --test web/scripts/windows-enrollment-capture.node.mjs', focused)
        self.assertIn('python3 -I -B tests/security/test_pr_checks.py', focused)
        self.assertIn('node tests/e2e-review/enrollment-browser.mjs', full)


if __name__ == '__main__':
    unittest.main()
