"""Bounded PR/main source checks. This is never full-race or native evidence."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('pr_reporter', ROOT / 'tests/security/report_go_failure.py')
reporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporter)
HEX = re.compile(r'[0-9a-f]{40}\Z')
PATH = re.compile(r'[A-Za-z0-9_./-]{1,240}\Z')
# Exact, small, always-run safety net. Missing or skipped roots fail, even on docs PRs.
CRITICAL = {
    'localrmm/internal/operatorauth': ['TestNamedUnknownUserAndWrongModeCannotFallback', 'TestNamedCapabilityRevocationWaitsForAdmittedWork'],
    'localrmm/internal/enrollmentstore': ['TestTelemetryRejectsWrongCertificateAndPartialActivation', 'TestTelemetryReplayFloorAndExactReceiptSurviveRestart', 'TestJournalClaimRollbackNeverReturnsGrant', 'TestWindowsEventMissingUsedAuthorityRowsNeverReset'],
    'localrmm/internal/mutationfence': ['TestUncertainIntentAndMissingStateNeverReset'],
    'localrmm/internal/windowsmutationfence': ['TestMissingReplacedPendingAndRollbackRemainBlocked'],
    'localrmm/internal/journalstate': ['TestDurabilityBarriersBeforePermission'],
    'localrmm/internal/windowsstate': ['TestFixtureUsedStateLossAndTampering'],
}
# Dedicated native/dense roots remain in full Validate unchanged, not in this tier.
SLOW = '^(TestIndependentPackageStoreDenseCapacityAndActualIngress|TestGuidedThreeBinaryEnrollmentAndForeground)$'
SHARED = ('go.mod', 'go.sum', 'Makefile', 'Dockerfile', '.github/', 'tests/security/', 'deploy/',
          'internal/operatorauth/', 'internal/enrollmentcrypto/', 'internal/enrollmentissuer/',
          'internal/enrollmenttransport/', 'internal/signedhttp/', 'internal/keyvalidation/',
          'internal/mutationfence/', 'internal/windowsmutationfence/', 'internal/model/',
          'internal/windowsstate/', 'internal/journalstate/', 'internal/actionstate/', 'internal/enrollmentstate/',
          'internal/enrollmentstore/authorize', 'internal/enrollmentstore/credential_authority',
          'internal/enrollmentstore/store.go', 'internal/enrollmentstore/schema')
UI_SHARED = ('web/src/App.tsx', 'web/src/api.ts', 'web/src/types.ts', 'web/src/auth',
             'web/src/index', 'web/src/main', 'web/src/i18n', 'web/src/styles',
             'web/src/windows-inventory.tsx', 'web/src/windows-inventory-types.ts', 'web/src/windows-inventory-resource.ts',
             'web/package', 'web/vite', 'web/tsconfig', 'web/test-environments',
             'tests/e2e-review/', 'tests/fixtures/', 'web/scripts/')
# Use existing bounded browser entry points, never dynamically supplied commands.
# Longest prefixes first avoid software/history, MSI and service/action ambiguity.
FLOWS = {
    'lan': 'tests/e2e-review/lan-browser.mjs',
    'shell': 'tests/e2e-review/run.mjs',
    'windows-mutation-coexistence': 'tests/e2e-review/windows-mutation-coexistence-runner.mjs',
    'windows-software-history': 'tests/e2e-review/windows-software-history-runner.mjs',
    'windows-user-software': 'tests/e2e-review/windows-user-software-runner.mjs',
    'windows-full-software': 'tests/e2e-review/windows-full-software-runner.mjs',
    'windows-full-services': 'tests/e2e-review/windows-full-services-runner.mjs',
    'windows-full-processes': 'tests/e2e-review/windows-full-processes-runner.mjs',
    'windows-network-context': 'tests/e2e-review/windows-network-context-runner.mjs',
    'windows-storage-io': 'tests/e2e-review/windows-storage-io-runner.mjs',
    'windows-event-history': 'tests/e2e-review/windows-event-history-runner.mjs',
    'windows-incident-inbox': 'tests/e2e-review/windows-incident-inbox-runner.mjs',
    'windows-maintenance': 'tests/e2e-review/windows-maintenance-runner.mjs',
    'windows-managed-msi': 'tests/e2e-review/windows-managed-msi-runner.mjs',
    'windows-service-actions': 'tests/e2e-review/windows-service-actions-runner.mjs',
    'windows-fleet-msi': 'web/scripts/run-windows-fleet-msi-ci.mjs',
    'fleet-groups': 'tests/e2e-review/fleet-groups-runner.mjs',
    'fleet-identity': 'tests/e2e-review/fleet-identity-browser.mjs',
    'endpoint-identity': 'tests/e2e-review/endpoint-identity-browser.mjs',
    'complete-overview': 'tests/e2e-review/complete-overview-browser.mjs',
    'service-action-v2': 'tests/e2e-review/service-action-v2-browser.mjs',
    'service-action': 'tests/e2e-review/service-action-browser.mjs',
    'enrollment': 'tests/e2e-review/enrollment-browser.mjs',
    'journal': 'tests/e2e-review/journal-browser.mjs',
    'conditional': 'tests/e2e-review/conditional-browser.mjs',
    'v3': 'tests/e2e-review/v3-mvp-browser.mjs',
    'managed': 'tests/e2e-review/managed-preview.mjs',
}
ALIASES = {'windowsmanagedmsiworklist': ['windows-fleet-msi'],
           'windowsmanagedmsireusable': ['windows-fleet-msi'],
           'windowsmanagedmsisaved': ['windows-fleet-msi'],
           # Paired setup filenames do not carry the windowsmanagedmsi prefix.
           # Retain their existing managed/LAN/enrollment flow while adding exact
           # package scheduling and, for the shared pair, WUA coexistence views.
           'scheduledmsi': ['lan', 'windows-managed-msi', 'windows-fleet-msi', 'windows-mutation-coexistence'],
           'managedmsiprovision': ['managed', 'windows-managed-msi', 'windows-fleet-msi', 'windows-mutation-coexistence'],
           'mutationprovision': ['lan', 'windows-managed-msi', 'windows-fleet-msi', 'windows-mutation-coexistence', 'windows-service-actions'],
           'windowsmutationpair': ['enrollment', 'windows-managed-msi', 'windows-fleet-msi', 'windows-mutation-coexistence', 'windows-service-actions'],
           'windowsreusablemsi': ['windows-fleet-msi'], 'windowssavedmsi': ['windows-fleet-msi'],
           'windowssoftwarecatalogue': ['windows-fleet-msi'],
           'journalai': ['lan'], 'journalbrowse': ['lan'],
           'packageupdate': ['lan', 'conditional'], 'serviceactiondisplay': ['lan'],
           'serviceaction': ['service-action', 'service-action-v2'],
           'windowscapacity': ['lan'], 'windowsresource': ['lan'], 'windowscontact': ['lan'],
           'windowsmonitoring': ['fleet-groups', 'windows-incident-inbox', 'windows-maintenance', 'lan'],
           'windowshealth': ['lan'], 'windowsnetwork': ['lan'], 'windowsinventory': ['lan'],
           'windowssecurity': ['lan'], 'windowspatch': ['lan'], 'windowsstorage': ['lan'],
           'windowshardware': ['lan'], 'windowssession': ['lan'], 'windowsadapter': ['lan'],
           'windowsserviceaction': ['windows-service-actions'], 'windowsservicehealth': ['lan'], 'windowsservice': ['lan'], 'proactive': ['lan'],
           'applicationcheck': ['lan'], 'alarm': ['lan'], 'certificate': ['lan'], 'resourcehistory': ['lan'],
           'linuxcve': ['lan'], 'investigation': ['lan'],'windowsmanagedmsi': ['windows-managed-msi', 'windows-fleet-msi', 'windows-mutation-coexistence'],
           'windowsmutationfence': ['windows-mutation-coexistence'],
           'windowsaction': ['windows-service-actions'], 'windowssoftware': ['windows-service-actions'],
           'windowsuser': ['windows-user-software'], 'windowshistory': ['windows-event-history'],
           'windowsevent': ['windows-event-history'], 'windowsupdate': ['windows-service-actions', 'windows-mutation-coexistence'],
           'operatorauth': list(FLOWS), 'package': ['conditional'], 'linuxpackages': ['conditional'],
           'cachedupdates': ['conditional'], 'systeminventory': ['v3'], 'operational': ['conditional'],
           'lanclient': ['v3', 'enrollment'], 'lanstore': ['v3'], 'enrollment': ['enrollment']}


def capture(args, env=None):
    result = subprocess.run(args, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode or len(result.stdout) > 32 << 20:
        raise ValueError('source discovery failed')
    return result.stdout


def objects(raw):
    decoder, result, text = json.JSONDecoder(), [], raw.decode()
    while text.strip():
        obj, end = decoder.raw_decode(text.lstrip())
        result.append(obj)
        text = text.lstrip()[end:]
    return result


def graph(rows):
    packages, files = {}, {}
    for row in rows:
        name = row.get('ImportPath', '')
        if not reporter.PACKAGE.fullmatch(name) or row.get('Error') or row.get('DepsErrors'):
            raise ValueError('invalid package graph')
        packages.setdefault(name, set()).update(row.get('Imports', []) + row.get('TestImports', []) + row.get('XTestImports', []))
        directory = name.removeprefix('localrmm').lstrip('/')
        for key in ('GoFiles', 'CgoFiles', 'TestGoFiles', 'XTestGoFiles', 'IgnoredGoFiles',
                    'EmbedFiles', 'TestEmbedFiles', 'XTestEmbedFiles', 'OtherFiles'):
            for name_in_package in row.get(key, []):
                path = '/'.join(filter(None, (directory, name_in_package)))
                files.setdefault(path, set()).add(name)
    if not packages:
        raise ValueError('empty package graph')
    return packages, files


def affected(packages, seeds):
    selected = set(seeds)
    while True:
        expanded = selected | {name for name, imports in packages.items() if imports & selected}
        if expanded == selected:
            return selected
        selected = expanded


def flow_names(path):
    name = Path(path).stem.replace('_', '-').lower()
    compact = name.replace('-', '')
    # One longest-prefix table: a richer domain alias must win over a shorter
    # generic flow ('journal-ai' is exercised in LAN, not journal-browser).
    mapping = {key.replace('-', ''): [key] for key in FLOWS}
    mapping.update(ALIASES)
    for key in sorted(mapping, key=lambda key: (-len(key), key)):
        if compact.startswith(key):
            return set(mapping[key])
    # UI mapping is a conservative hint only; unknown files broaden the tier.
    return set()


def select(changes, packages, files, sha, runnable=None):
    broad, broad_web, seeds, web, flows = False, False, set(), set(), set()
    unmapped = set()
    for status, path in changes:
        if (status not in {'A', 'M'} or not PATH.fullmatch(path) or '..' in Path(path).parts):
            broad = broad_web = True
            continue
        if path.startswith(SHARED):
            broad = broad_web = True
        if path.startswith(UI_SHARED):
            broad_web = True
        if path in files:
            seeds |= files[path]
            # API handlers are one package; route by exact domain filename rather
            # than sending every ordinary handler change to the full race suite.
            domain = flow_names(path) or flow_names(str(Path(path).parent))
            flows |= domain
            if not domain:
                unmapped |= files[path]
        elif path.startswith('web/src/') and Path(path).suffix in {'.ts', '.tsx', '.css'}:
            web.add(path.removeprefix('web/'))
            domain = flow_names(path)
            flows |= domain
            if not domain:
                broad_web = True
        elif (path.startswith('docs/') and path.endswith('.md')) or path in {'README.md', 'CHANGELOG.md', 'LICENSE', 'AGENTS.md'}:
            pass
        else:
            broad = broad_web = True  # Deleted, generated, embed and unknown paths never disappear.
    selected = set(packages) if broad else affected(packages, seeds)
    if affected(packages, unmapped) & {'localrmm/internal/api', 'localrmm/cmd/manager', 'localrmm/cmd/lan-manager'}:
        broad_web = True
    # Integration/security packages are dependents too; never drop them silently.
    return {'schema': 1, 'sha': sha, 'broadGo': broad, 'broadWeb': broad_web,
            'packages': sorted(selected & (set(packages) if runnable is None else runnable)), 'web': sorted(web),
            'flows': sorted(FLOWS if broad_web else flows)}


def discover():
    sha = os.environ.get('GITHUB_SHA', '')
    if not HEX.fullmatch(sha) or capture(['git', 'rev-parse', 'HEAD']).decode().strip() != sha:
        raise ValueError('wrong source')
    rows = objects(capture(['go', 'list', '-json', '-buildvcs=false', './...']))
    runnable = {row['ImportPath'] for row in rows}
    rows += objects(capture(['go', 'list', '-json', '-buildvcs=false', './...'],
                            env={**os.environ, 'GOOS': 'windows', 'GOARCH': 'amd64', 'CGO_ENABLED': '0'}))
    packages, files = graph(rows)
    before = os.environ.get('TRACEBOLT_BASE_SHA', '')
    # Missing/zero/truncated history is broad coverage, never empty selection.
    changes = [('D', 'unknown')]
    if HEX.fullmatch(before) and before != '0' * 40:
        try:
            raw = capture(['git', 'diff', '--name-status', '--no-renames', '-z', before, sha, '--'])
            fields = raw.decode().split('\0')
            if fields[-1] != '' or len(fields) % 2 != 1:
                raise ValueError('invalid diff')
            changes = list(zip(fields[:-1:2], fields[1::2]))
        except (ValueError, UnicodeError):
            pass
    return select(changes, packages, files, sha, runnable)


def checked_plan(raw):
    plan = reporter.decode(raw)
    if (set(plan) != {'schema', 'sha', 'broadGo', 'broadWeb', 'packages', 'web', 'flows'} or plan['schema'] != 1
            or plan['sha'] != os.environ.get('GITHUB_SHA') or not HEX.fullmatch(plan['sha'])
            or type(plan['broadGo']) is not bool or type(plan['broadWeb']) is not bool):
        raise ValueError('invalid plan')
    for key in ('packages', 'web', 'flows'):
        if not isinstance(plan[key], list) or len(plan[key]) > 2048 or plan[key] != sorted(set(plan[key])):
            raise ValueError('invalid plan')
    if (any(not reporter.PACKAGE.fullmatch(p) for p in plan['packages'])
            or any(not PATH.fullmatch(p) or not p.startswith('src/') or '..' in Path(p).parts for p in plan['web'])
            or any(p not in FLOWS for p in plan['flows'])
            or (plan['broadWeb'] and plan['flows'] != sorted(FLOWS))):
        raise ValueError('invalid plan')
    return plan


def run(args, cwd=ROOT, stage='selected-check', env=None):
    print('Running stage: ' + stage, flush=True)
    # Raw fixture output never enters Actions logs or artifacts, including failures.
    with tempfile.TemporaryFile() as out:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=out, stderr=out, check=False)
    if result.returncode:
        print('FAIL stage: ' + stage, flush=True)
        raise ValueError('selected check failed; raw fixture output withheld')


def go_checks(plan):
    allowed = reporter.load_allowlist()
    for package, roots in CRITICAL.items():
        print('Running critical package: ' + package, flush=True)
        if not set(roots) <= set(allowed.get(package, [])):
            raise ValueError('critical roots missing from source')
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result = subprocess.run(['go', 'test', '-json', '-buildvcs=false', '-count=1', '-timeout=4m',
                                     '-run', '^(' + '|'.join(roots) + ')$', package], cwd=ROOT, stdout=out, stderr=err)
            out.seek(0)
            raw = out.read(reporter.MAX_FILE + 1)
        if result.returncode or len(raw) > reporter.MAX_FILE:
            print('GO_TEST_DIAGNOSTIC ' + json.dumps(reporter.project(raw, allowed), separators=(',', ':')))
            raise ValueError('critical check failed')
        passed = []
        for line in raw.splitlines():
            event = reporter.decode(line)
            if event.get('Action') == 'pass' and event.get('Package') == package and event.get('Test') in roots:
                passed.append(event['Test'])
            if event.get('Action') in {'fail', 'build-fail'}:
                raise ValueError('critical check failed')
        if sorted(passed) != sorted(roots):
            raise ValueError('critical check missing, duplicated or skipped')
    if plan['packages']:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            result = subprocess.run(['go', 'test', '-json', '-p', '1', '-buildvcs=false', '-count=1', '-timeout=10m', '-skip', SLOW, *plan['packages']], cwd=ROOT, stdout=out, stderr=err)
            out.seek(0); raw = out.read(reporter.MAX_FILE + 1)
        if result.returncode or len(raw) > reporter.MAX_FILE:
            print('GO_TEST_DIAGNOSTIC ' + json.dumps(reporter.project(raw, allowed), separators=(',', ':')))
            raise ValueError('affected Go check failed')
    print('PASS: fixed authorization/durability roots and selected non-race source packages; not full/native evidence.')


def web_checks(plan):
    run(['npm', 'run', 'test:environments'], ROOT / 'web', stage='ui-environment-contract')
    if plan['broadWeb']:
        run(['./node_modules/.bin/vitest', 'run', '--maxWorkers=1'], ROOT / 'web', stage='ui-all-interactions')
        run(['./web/node_modules/.bin/vitest', 'run', '--config', 'tests/e2e-review/vitest.config.mts'], stage='ui-independent-interactions')
        run(['./web/node_modules/.bin/vitest', 'run', '--config', 'tests/e2e-review/v3-dom.config.mts'], stage='ui-v3-dom')
    else:
        run(['./node_modules/.bin/vitest', 'run', 'src/auth.test.tsx', '--maxWorkers=1'], ROOT / 'web', stage='ui-authorization')
        if plan['web']:
            changed_tests = [path for path in plan['web'] if '.test.' in path]
            if changed_tests:
                run(['./node_modules/.bin/vitest', 'run', '--maxWorkers=1', *changed_tests], ROOT / 'web', stage='ui-changed-tests')
            # Vite resolves actual imports and dependent tests (not filename guesses).
            run(['./node_modules/.bin/vitest', 'related', '--run', '--passWithNoTests', '--maxWorkers=1', *plan['web']], ROOT / 'web', stage='ui-related-interactions')
            for config, stage in [('vitest.config.mts', 'ui-related-independent'), ('v3-dom.config.mts', 'ui-related-v3-dom')]:
                run(['./web/node_modules/.bin/vitest', 'related', '--run', '--passWithNoTests',
                     '--config', 'tests/e2e-review/' + config, *['web/' + path for path in plan['web']]], stage=stage)
    print('PASS: UI authorization and affected interaction checks; not full browser evidence.')


# Existing full gate validators are reused where available. Other executable
# runners enforce exact captures internally; require their positive report too.
BROWSER_REPORTS = {name: name + '-results.json' for name in FLOWS if name.startswith('windows-') or name == 'fleet-groups'}
BROWSER_REPORTS.update({'lan': 'lan-browser-results.json', 'shell': 'results.json',
    'managed': 'managed-preview-result.json', 'enrollment': 'enrollment-browser-results.json',
    'conditional': 'conditional-browser-results.json', 'v3': 'v3-mvp-browser-results.json',
    'fleet-identity': 'fleet-identity-browser-results.json', 'endpoint-identity': 'endpoint-browser-results.json',
    'journal': 'journal-browser-results.json', 'complete-overview': 'complete-overview-browser-results.json',
    'service-action': 'service-action-browser-results.json', 'service-action-v2': 'service-action-v2-browser-results.json',
    'windows-storage-io': 'windows-storage-io/windows-storage-io-results.json'})
BROWSER_GATES = {'endpoint-identity': 'endpoint', 'journal': 'journal', 'complete-overview': 'complete_overview',
                 'service-action': 'service_action', 'service-action-v2': 'service_action_v2'}
SUMMARY_COUNTS = {'enrollment': 13, 'conditional': 19, 'v3': 10, 'fleet-identity': 6, 'managed': 6}


def validate_browser_report(flow, value, sha):
    if not isinstance(value, dict) or value.get('sourceSha') != sha:
        raise ValueError('missing or wrong browser source')
    if value.get('runtimeErrorCount', 0) != 0 or value.get('runtimeErrors', []) != []:
        raise ValueError('browser runtime errors')
    if 'browserAcceptance' in value:
        if value.get('browserAcceptance') is not True or value.get('status') != 'PASS':
            raise ValueError('browser did not execute successfully')
    else:
        rows, summary = value.get('results', value.get('checks')), value.get('summary', {})
        if (not isinstance(rows, list) or not rows or summary.get('passed') != len(rows)
                or summary.get('failed') != 0 or summary.get('skipped', 0) != 0
                or summary.get('setupFailure', False) is not False
                or summary.get('setupOrRuntimeFailure', False) is not False
                or summary.get('runtimeErrorCount', 0) != 0
                or any(row.get('status') != 'PASS' or not isinstance(row.get('name'), str) or not row['name'] for row in rows)
                or len({row['name'] for row in rows}) != len(rows)
                or (flow in SUMMARY_COUNTS and len(rows) != SUMMARY_COUNTS[flow])):
            raise ValueError('missing, duplicate or incomplete browser cases')
        if flow == 'enrollment' and (value.get('quarantine', {}).get('active') is not False
                                      or summary.get('fullEnrollmentAcceptance') is not True):
            raise ValueError('incomplete enrollment browser cases')


def browser_report(flow, sha):
    path = ROOT / 'artifacts/review' / BROWSER_REPORTS[flow]
    if path.is_symlink() or path.stat().st_size > 2 << 20:
        raise ValueError('invalid browser report')
    value = reporter.decode(path.read_bytes())
    validate_browser_report(flow, value, sha)
    if flow in BROWSER_GATES:
        run(['python3', 'tests/security/check_' + BROWSER_GATES[flow] + '_browser_gate.py', str(path)],
            stage='browser-evidence-' + flow)


def browser_checks(plan):
    run(['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'], stage='browser-auth-smoke')
    # The existing shell runner clears its screenshot folder on startup. Run it
    # first, so it cannot delete subsequently captured affected-flow evidence.
    for flow in sorted(plan['flows'], key=lambda value: (value != 'shell', value)):
        print('Running selected browser flow: ' + flow, flush=True)
        env = {**os.environ, 'TRACEBOLT_REVIEW_QUARANTINED': '1', 'TRACEBOLT_REVIEW_LIFECYCLE_REPEATS': '5', 'TRACEBOLT_REVIEW_AI': '1'}
        if flow == 'fleet-identity':
            # This legacy runner otherwise guesses /usr/bin/chromium. Bind only
            # this invocation to the locked Playwright browser installed by CI.
            executable = capture(['node', '-e', "console.log(require('./web/node_modules/@playwright/test').chromium.executablePath())"]).decode().strip()
            if not Path(executable).is_absolute() or not Path(executable).is_file():
                raise ValueError('installed browser unavailable')
            env['CHROMIUM_PATH'] = executable
        run(['node', FLOWS[flow]], stage='browser-' + flow, env=env)
        browser_report(flow, plan['sha'])
    print('PASS: authenticated browser smoke and selected existing flows; synthetic fixtures, not native acceptance.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['select', 'go', 'web', 'browser'])
    args = parser.parse_args()
    if args.mode == 'select':
        plan = discover()
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write('plan=' + json.dumps(plan, separators=(',', ':')) + '\n')
        print('PASS: deterministic source selection; packages=%d, browser flows=%d, broad=%s/%s.' %
              (len(plan['packages']), len(plan['flows']), plan['broadGo'], plan['broadWeb']))
    else:
        plan = checked_plan(os.environ['TRACEBOLT_PR_PLAN'])
        {'go': go_checks, 'web': web_checks, 'browser': browser_checks}[args.mode](plan)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('FAIL: source selection or selected checks failed; raw source/runtime output withheld.')
