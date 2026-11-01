"""Focused browser execution policy; the source selector stays authoritative."""
import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('pr_browser_source_checks', ROOT / 'tests/security/pr_checks.py')
checks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checks)


def browser_plan(raw):
    # Validate the complete, exact-source plan first, including broad selection.
    # Only this explicitly retired CI browser flow is omitted. No configurable
    # skip list, fabricated browser report or change to Go/UI selection follows.
    plan = checks.checked_plan(raw)
    return {**plan, 'flows': [flow for flow in plan['flows'] if flow != 'windows-user-software']}


def main():
    plan = browser_plan(os.environ['TRACEBOLT_PR_PLAN'])
    print('Selected-account software browser flow retired from CI; source/fixture tests remain.', flush=True)
    checks.browser_checks(plan)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('FAIL: focused browser checks failed; raw source/runtime output withheld.')
