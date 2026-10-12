"""Bounded PR/main source checks. This is never full-race or native evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('pr_reporter', ROOT / 'tests/security/report_go_failure.py')
reporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporter)
HEX = re.compile(r'[0-9a-f]{40}\Z')
PATH = re.compile(r'[A-Za-z0-9_./-]{1,240}\Z')
GENERATED_ALLOWLIST = 'tests/security/go_failure_allowlist.json'
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
# Exact reviewed script dependencies, not filename/prefix guesses. The fleet
# entry point exercises fleet/saved/reusable/scheduled/recent-package captures;
# browser_checks also runs its multi-package catalogue companion. The shared
# compiler/router below is owned by these same flows. Unknown scripts, general
# helpers, generators and independent test fixtures retain the broad fallback.
DOMAIN_SCRIPTS = {
    'web/scripts/capture-windows-fleet-msi-fixtures.mjs': {'windows-fleet-msi'},
    'web/scripts/capture-windows-msi-catalogue-fixtures.mjs': {'windows-fleet-msi'},
    'web/scripts/capture-windows-reusable-msi-fixtures.mjs': {'windows-fleet-msi'},
    'web/scripts/capture-windows-scheduled-msi-fixtures.mjs': {'windows-fleet-msi'},
    'web/scripts/capture-windows-software-catalogue-fixtures.mjs': {'windows-fleet-msi'},
    'web/scripts/run-windows-fleet-msi-ci.mjs': {'windows-fleet-msi'},
    'web/scripts/run-windows-msi-catalogue-ci.mjs': {'windows-fleet-msi'},
    'web/scripts/windows-msi-catalogue-scenes.json': {'windows-fleet-msi'},
}
# These existing UI names do not match the older domain aliases. Keep them in
# the normal changed/related Vitest path while selecting their verified owner.
DOMAIN_UI = {
    'web/src/windows-fleet-managed-msi.css': {'windows-fleet-msi'},
    'web/src/windows-fleet-managed-msi.test.tsx': {'windows-fleet-msi'},
    'web/src/windows-reusable-managed-msi.test.tsx': {'windows-fleet-msi'},
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



def verified_generated_allowlist(before, sha):
    """Only exact canonical generated bytes with unchanged regular Git mode qualify.

    Derivation reads all current Go bytes and root names without compiling or
    executing them. Any uncertainty keeps the ordinary broad security fallback.
    The original runtime reporter.load_allowlist() guard is unchanged.
    """
    try:
        if not HEX.fullmatch(before) or not HEX.fullmatch(sha):
            return False
        raw_diff = capture(['git', 'diff', '--raw', '--no-abbrev', '--no-renames', '-z',
                            before, sha, '--', GENERATED_ALLOWLIST])
        pattern = rb':100644 100644 [0-9a-f]{40} [0-9a-f]{40} M\x00' + re.escape(GENERATED_ALLOWLIST.encode()) + rb'\x00'
        if re.fullmatch(pattern, raw_diff) is None:
            return False  # Added/deleted/renamed/type/mode changes never qualify.
        path = ROOT / GENERATED_ALLOWLIST
        # Existing no-follow opener checks every directory component too.
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o644 or metadata.st_size > 8 << 20:
                return False
            raw = stream.read((8 << 20) + 1)
            after = os.fstat(stream.fileno())
        expected = (json.dumps(reporter.derive_allowlist(ROOT), indent=2) + '\n').encode()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        rebound = path.lstat()
        return (raw == expected and len(raw) <= 8 << 20
                and all(getattr(metadata, field) == getattr(after, field) == getattr(rebound, field) for field in fields))
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return False


def select(changes, packages, files, sha, runnable=None, generated_allowlist_verified=False):
    broad, broad_web, seeds, web, flows = False, False, set(), set(), set()
    unmapped = set()
    for status, path in changes:
        if (status not in {'A', 'M'} or not PATH.fullmatch(path) or '..' in Path(path).parts):
            broad = broad_web = True
            continue
        if path == GENERATED_ALLOWLIST and status == 'M' and generated_allowlist_verified:
            continue  # Generated vocabulary only; actual Go edits remain in the diff.
        if path.startswith(SHARED):
            broad = broad_web = True
        if path in DOMAIN_SCRIPTS:
            flows |= DOMAIN_SCRIPTS[path]
            continue  # Existing full domain flows cover these exact non-Go files.
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
            domain = DOMAIN_UI.get(path, set()) or flow_names(path)
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
    allowlist_verified = (('M', GENERATED_ALLOWLIST) in changes
                          and verified_generated_allowlist(before, sha))
    return select(changes, packages, files, sha, runnable, allowlist_verified)


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
    if 'lan' in plan.get('flows', []):
        # This Node fixture extracts LAN's real completion wrapper; Vitest's
        # related-test graph does not discover these inert .test.mjs contracts.
        run(['node', '--test', 'tests/e2e-review/windows-health-fixtures.test.mjs'], stage='ui-windows-health-contract')
    if 'windows-fleet-msi' in plan.get('flows', []):
        run(['node', 'web/scripts/capture-windows-msi-catalogue-fixtures.mjs', '--check'], stage='ui-msi-catalogue-contract')
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


def catalogue_scene_contract():
    """Read the same bounded, domain-owned scene/viewport source as the producer."""
    path = ROOT / 'web/scripts/windows-msi-catalogue-scenes.json'
    with os.fdopen(reporter.open_log(path), 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8192:
            raise ValueError('invalid catalogue scene contract')
        raw = stream.read(8193)
    if not raw or len(raw) > 8192:
        raise ValueError('invalid catalogue scene contract')
    value = reporter.decode(raw)
    if raw != (json.dumps(value, indent=2) + '\n').encode():
        raise ValueError('noncanonical catalogue scene contract')
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'scenes', 'viewports'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or not isinstance(value['scenes'], list) or not 0 < len(value['scenes']) <= 8
            or any(not isinstance(scene, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', scene)
                   for scene in value['scenes']) or len(set(value['scenes'])) != len(value['scenes'])):
        raise ValueError('invalid catalogue scene contract')
    expected_viewports = [{'locale': locale, 'width': width, 'height': 844 if width == 390 else 1100}
                          for locale in ['en', 'de'] for width in [1440, 390]]
    if (value['viewports'] != expected_viewports
            or any(type(row['width']) is not int or type(row['height']) is not int
                   for row in value['viewports'])):
        raise ValueError('invalid catalogue viewport contract')
    return value, hashlib.sha256(raw).hexdigest()


def validate_catalogue_browser_report(value, sha):
    validate_browser_report('windows-fleet-msi', value, sha)
    contract, digest = catalogue_scene_contract()
    if (value.get('browserAcceptance') is not True or value.get('status') != 'PASS'
            or value.get('sceneManifestSHA256') != digest
            or type(value.get('scenes')) is not int or value['scenes'] != len(contract['scenes'])
            or type(value.get('screenshots')) is not int
            or value['screenshots'] != len(contract['scenes']) * len(contract['viewports'])
            or value.get('requestsToRealAPI') != 0 or value.get('actualMutationRequests') != 0
            or value.get('nativeAcceptance') is not False):
        raise ValueError('incomplete catalogue changed-flow captures')


def browser_report(flow, sha):
    path = ROOT / 'artifacts/review' / BROWSER_REPORTS[flow]
    if path.is_symlink() or path.stat().st_size > 2 << 20:
        raise ValueError('invalid browser report')
    value = reporter.decode(path.read_bytes())
    validate_browser_report(flow, value, sha)
    if flow == 'windows-fleet-msi':
        catalogue = ROOT / 'artifacts/review/windows-msi-catalogue-results.json'
        if catalogue.is_symlink() or catalogue.stat().st_size > 2 << 20:
            raise ValueError('invalid catalogue browser report')
        validate_catalogue_browser_report(reporter.decode(catalogue.read_bytes()), sha)
    if flow in BROWSER_GATES:
        run(['python3', 'tests/security/check_' + BROWSER_GATES[flow] + '_browser_gate.py', str(path)],
            stage='browser-evidence-' + flow)



# Closed recipe coordinates for this one runner. No exception text or fixture data
# is admitted, even if a failed process writes it into its report.
FLEET_MSI_FAILURE_SCENES = {
    'fleet': {'uploaded-artifact', 'delivery-unchecked', 'saved-3010-shared-owner', 'saved-3010-owner-refreshed'},
    'saved': {'compact-summary', 'expanded-evidence', 'delivery-unchecked', 'review-unchecked', 'approval-unchecked', 'retirement-unchecked', 'retired-outcomes'},
    'reusable': {'retirement-review', 'retired', 'next-package', 'intervention'},
    'scheduled': {'approval-unchecked', 'scheduled', 'permit-issued', 'canceled', 'blocked', 'fleet-shared-window-unchecked', 'fleet-mixed-scheduled-unsent'},
    'recent-package': {'ready-and-blocked', 'upload-required'},
}


def fleet_msi_failure_location(sha):
    """Read only a bounded, same-source, finite-location failed-run report."""
    try:
        path = ROOT / 'artifacts/review/windows-fleet-msi-results.json'
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
                return None
            raw = stream.read(4097)
        if len(raw) > 4096:
            return None
        value = reporter.decode(raw)
        if (not HEX.fullmatch(sha) or not isinstance(value, dict)
                or set(value) != {'sourceSha', 'status', 'browserAcceptance', 'variants', 'screenshots', 'requestsToRealAPI', 'nativeAcceptance', 'disclosure', 'failure'}
                or value['sourceSha'] != sha or value['status'] != 'FAIL'
                or value['browserAcceptance'] is not False or value['nativeAcceptance'] is not False
                or any(type(value[key]) is not int or value[key] != 0 for key in ['variants', 'screenshots', 'requestsToRealAPI'])):
            return None
        failure = value['failure']
        if not isinstance(failure, dict) or set(failure) != {'phase', 'producer', 'scene', 'locale', 'width'}:
            return None
        phase, producer, scene, locale, width = (failure[key] for key in ['phase', 'producer', 'scene', 'locale', 'width'])
        if phase in ['launch', 'close']:
            if any(item is not None for item in [producer, scene, locale, width]):
                return None
        elif phase in ['capture', 'validate'] and isinstance(producer, str) and producer in FLEET_MSI_FAILURE_SCENES:
            if scene is None:
                if locale is not None or width is not None:
                    return None
            elif (phase != 'capture' or not isinstance(scene, str) or scene not in FLEET_MSI_FAILURE_SCENES[producer]
                  or locale not in ['en', 'de'] or type(width) is not int or width not in [390, 1440]):
                return None
        else:
            return None
        return 'phase=%s producer=%s scene=%s locale=%s width=%s' % (phase, producer or '-', scene or '-', locale or '-', width or '-')
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


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
        try:
            run(['node', FLOWS[flow]], stage='browser-' + flow, env=env)
        except ValueError:
            if flow == 'windows-fleet-msi':
                location = fleet_msi_failure_location(plan['sha'])
                if location is not None:
                    print('FAIL fleet MSI location: ' + location, flush=True)
            raise  # Diagnostics never turn a failed browser flow into success.
        if flow == 'windows-fleet-msi':
            # Three bounded changed flows accompany the existing MSI selection;
            # no new broad-flow mapping or older screenshot expansion.
            run(['node', 'web/scripts/run-windows-msi-catalogue-ci.mjs'], stage='browser-msi-catalogue', env=env)
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
