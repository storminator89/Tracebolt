"""Inert API fixtures only. No network reads, Actions dispatch, or release mutation."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('full_gate_test', ROOT / 'tests/security/check_full_validation.py')
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
SHA = 'a' * 40


class GateTests(unittest.TestCase):
    def setUp(self):
        self.run = {'id': 123, 'head_sha': SHA, 'head_branch': 'main', 'path': g.WORKFLOW,
                    'name': 'Validate', 'workflow_id': 42, 'event': 'workflow_dispatch',
                    'status': 'completed', 'conclusion': 'success', 'run_attempt': 1,
                    'repository': {'id': g.REPO_ID}, 'head_repository': {'id': g.REPO_ID},
                    'html_url': f'https://github.com/{g.REPOSITORY}/actions/runs/123'}
        self.jobs = {'total_count': len(g.JOBS), 'jobs': [
            {'id': i + 1, 'name': name, 'run_id': 123, 'run_attempt': 1, 'head_sha': SHA,
             'workflow_name': 'Validate', 'status': 'completed', 'conclusion': 'success',
             'steps': [{'name': step, 'status': 'completed', 'conclusion': 'success'} for step in sorted(g.AGGREGATE_STEPS)]}
            for i, name in enumerate(sorted(g.JOBS))]}
        self.routes = {
            g.PREFIX + '/actions/workflows/validate.yml': {'id': 42, 'path': g.WORKFLOW, 'name': 'Validate'},
            g.PREFIX + '/actions/runs/123': self.run,
            g.PREFIX + '/actions/runs/123/attempts/1': copy.deepcopy(self.run),
            g.PREFIX + '/actions/runs/123/attempts/1/jobs?per_page=100': self.jobs,
        }

    def check(self):
        g.check(SHA, '123', self.routes.__getitem__)

    def test_exact_main_source_full_run_succeeds(self):
        self.check()

    def test_focused_pr_fork_foreign_source_and_nonterminal_runs_fail(self):
        for key, value in [('head_sha', 'b' * 40), ('path', '.github/workflows/pr-checks.yml'),
                           ('name', 'Focused source checks'), ('head_branch', 'feature'),
                           ('event', 'pull_request'), ('status', 'in_progress'), ('conclusion', 'failure'),
                           ('conclusion', 'cancelled'), ('head_repository', {'id': 1}), ('run_attempt', True)]:
            original = copy.deepcopy(self.run)
            self.run[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check()
            self.run.clear(); self.run.update(original)

    def test_missing_duplicate_skipped_failed_or_wrong_attempt_job_fails(self):
        for key, value in [('name', 'PR build and affected-flow checks'), ('head_sha', 'b' * 40),
                           ('run_attempt', 2), ('conclusion', 'skipped'), ('conclusion', 'failure'),
                           ('conclusion', 'cancelled'), ('workflow_name', 'Focused source checks')]:
            old = copy.deepcopy(self.jobs['jobs'][0]); self.jobs['jobs'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()
            self.jobs['jobs'][0] = old
        self.jobs['jobs'].pop()
        with self.assertRaises(ValueError): self.check()

    def test_aggregate_cannot_pass_without_actual_coverage_verification(self):
        aggregate = next(row for row in self.jobs['jobs'] if row['name'] == 'Go tests and build-only platform checks')
        for step in aggregate['steps']:
            step['conclusion'] = 'skipped'
            with self.assertRaises(ValueError): self.check()
            step['conclusion'] = 'success'
        aggregate['steps'].append(copy.deepcopy(aggregate['steps'][0]))
        with self.assertRaises(ValueError): self.check()

    def test_all_full_jobs_including_debian_are_available_on_manual_and_schedule(self):
        full = (ROOT / '.github/workflows/validate.yml').read_text()
        feed = full.split('  debian-security-feed:', 1)[1].split('  native-agent:', 1)[0]
        self.assertNotIn('    if:', feed)
        self.assertIn('Official Debian security feed compatibility', g.JOBS)
        for event in ['push', 'workflow_dispatch', 'schedule']:
            self.run['event'] = event
            self.routes[g.PREFIX + '/actions/runs/123/attempts/1']['event'] = event
            self.check()

    def test_every_release_rechecks_exact_source_before_publication(self):
        for name in ['linux-release-candidate.yml', 'windows-prerelease.yml', 'windows-current-prerelease.yml']:
            text = (ROOT / '.github/workflows' / name).read_text()
            self.assertIn('      full_validation_run_id:', text)
            self.assertEqual(text.count('python3 -I -B tests/security/check_full_validation.py'), 2)
            self.assertIn('FULL_RUN_ID: ${{ inputs.full_validation_run_id }}', text)
            self.assertIn('FULL_SOURCE_SHA: ${{ github.sha }}' if name.startswith('linux') else
                          'FULL_SOURCE_SHA: ${{ inputs.expected_source_sha }}', text)
            self.assertIn('actions: read', text)
            self.assertNotIn('workflow_call:', text)
            self.assertNotIn('schedule:', text)

    def test_new_run_or_invalid_id_is_never_selected_implicitly(self):
        for run_id in ['latest', '', '../1', '0', '1?query=2']:
            with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                g.check(SHA, run_id, lambda _: self.fail('must reject before API'))


if __name__ == '__main__':
    unittest.main()
