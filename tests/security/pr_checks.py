"""Bounded PR/main source checks. This is never full-race or native evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
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
    'first-report': 'web/scripts/run-first-report-ci.mjs',
    'lan': 'tests/e2e-review/lan-browser.mjs',
    'linux-cve-update-review': 'web/scripts/run-linux-cve-update-review-ci.mjs',
    'windows-fleet-software': 'web/scripts/run-windows-fleet-software-ci.mjs',
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
    'tests/e2e-review/paused-windows-routes.test.mjs': {
        'windows-managed-msi', 'windows-mutation-coexistence', 'windows-storage-io', 'windows-service-actions',
    },
    'web/scripts/capture-first-report-fixtures.mjs': {'first-report'},
    'web/scripts/run-first-report-ci.mjs': {'first-report'},
    'web/scripts/check-first-report-evidence.mjs': {'first-report'},
    'web/scripts/first-report-contract.mjs': {'first-report'},
    'web/scripts/first-report-contract.node.mjs': {'first-report'},
    'tests/e2e-review/fleet-groups-browser.mjs': {'fleet-groups'},
    'tests/e2e-review/fleet-groups-evidence.mjs': {'fleet-groups'},
    'tests/e2e-review/fleet-groups-fixtures.test.mjs': {'fleet-groups'},
    'web/scripts/capture-windows-complete-service-health.mjs': {'windows-service-actions'},
    'web/scripts/check-windows-complete-service-health-evidence.mjs': {'windows-service-actions'},
    'web/scripts/windows-complete-service-health-contract.mjs': {'windows-service-actions'},
    'web/scripts/windows-complete-service-health-contract.node.mjs': {'windows-service-actions'},
    'web/scripts/windows-complete-service-health-scenes.json': {'windows-service-actions'},
    'web/scripts/check-windows-fleet-software-evidence.mjs': {'windows-fleet-software'},
    'web/scripts/capture-windows-fleet-software.mjs': {'windows-fleet-software'},
    'web/scripts/run-windows-fleet-software-ci.mjs': {'windows-fleet-software'},
    'web/scripts/windows-fleet-software-contract.mjs': {'windows-fleet-software'},
    'web/scripts/windows-fleet-software-scenes.json': {'windows-fleet-software'},
    'web/scripts/windows-fleet-software-contract.node.mjs': {'windows-fleet-software'},
    'web/scripts/check-linux-cve-update-review-evidence.mjs': {'linux-cve-update-review'},
    'web/scripts/capture-linux-cve-update-review.mjs': {'linux-cve-update-review'},
    'web/scripts/run-linux-cve-update-review-ci.mjs': {'linux-cve-update-review'},
    'web/scripts/linux-cve-update-review-contract.mjs': {'linux-cve-update-review'},
    'web/scripts/linux-cve-update-review-scenes.json': {'linux-cve-update-review'},
    'web/scripts/linux-cve-update-review-contract.node.mjs': {'linux-cve-update-review'},

    'tests/e2e-review/windows-update-download-browser.mjs': {'windows-service-actions'},
    'tests/e2e-review/windows-update-download-fixtures.test.mjs': {'windows-service-actions'},
    'tests/e2e-review/windows-update-retirement-browser.mjs': {'windows-service-actions'},
    'tests/e2e-review/windows-update-retirement-fixtures.test.mjs': {'windows-service-actions'},
    'web/scripts/capture-windows-fleet-msi-fixtures.mjs': {'windows-fleet-msi', 'first-report'},
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
    'web/src/enrollment.tsx': {'enrollment', 'first-report'},
    'web/src/enrollment-types.ts': {'enrollment', 'first-report'},
    'web/src/enrollment-report.tsx': {'enrollment', 'first-report'},
    'web/src/windows-fleet-managed-msi.css': {'windows-fleet-msi'},
    'web/src/windows-fleet-managed-msi.test.tsx': {'windows-fleet-msi'},
    'web/src/windows-reusable-managed-msi.test.tsx': {'windows-fleet-msi'},
}
ALIASES = {'windowsfullservices': ['windows-full-services', 'windows-service-actions'],
           'fleetgroups': ['fleet-groups', 'windows-service-actions'],
           'windowsfullsoftware': ['windows-full-software', 'windows-fleet-software'],
           'windowsmanagedmsiworklist': ['windows-fleet-msi'],
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
           'windowsserviceaction': ['windows-service-actions'],
           'windowsservicehealthcomplete': ['lan', 'windows-service-actions'],
           'windowscompleteservice': ['lan', 'windows-service-actions'],
           'windowscompletegroupservice': ['fleet-groups', 'windows-service-actions'],
           'fleetgroupservicecheckscomplete': ['fleet-groups', 'windows-service-actions'],
           'windowsservicehealth': ['lan', 'windows-service-actions'], 'windowsservice': ['lan'], 'proactive': ['lan'],
           'applicationcheck': ['lan'], 'alarm': ['lan'], 'certificate': ['lan'], 'resourcehistory': ['lan'],
           'linuxcve': ['lan', 'linux-cve-update-review'], 'investigation': ['lan'],'windowsmanagedmsi': ['windows-managed-msi', 'windows-fleet-msi', 'windows-mutation-coexistence'],
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



ROUTE_FIRST_COMMIT_PHASES = frozenset({
    'bootstrap', 'suspend-import', 'blocked-mount', 'blocked-dom', 'resume-dom', 'resumed-mount',
})
ROUTE_FIRST_COMMIT_TITLE = 'blocks first commit for same-task pagehide and import completion (event-first)'
ROUTE_FIRST_COMMIT_SUITE = 'route-local deferred detail lifecycle'


def route_first_commit_failure_phase(source, index, assertion):
    """Accept one fixed test's closed phase only, never arbitrary reporter metadata."""
    if (source != 'web/src/route-details.test.tsx' or index != 11
            or assertion.get('status') != 'failed'
            or assertion.get('title') != ROUTE_FIRST_COMMIT_TITLE
            or assertion.get('ancestorTitles') != [ROUTE_FIRST_COMMIT_SUITE]
            or assertion.get('fullName') != ROUTE_FIRST_COMMIT_SUITE + ' ' + ROUTE_FIRST_COMMIT_TITLE):
        return None
    meta = assertion.get('meta')
    if type(meta) is not dict or set(meta) != {'routeFirstCommitPhase'}:
        return None
    phase = meta['routeFirstCommitPhase']
    return phase if type(phase) is str and phase in ROUTE_FIRST_COMMIT_PHASES else None


def vitest_failure_location(path):
    """Release source coordinates and one allowlisted route test's fixed phase."""
    try:
        allowed = {str(file.resolve()): file.relative_to(ROOT).as_posix()
                   for directory in ['web/src', 'web/scripts', 'tests/e2e-review']
                   for file in (ROOT / directory).rglob('*.test.*')
                   if file.is_file() and not file.is_symlink()
                   and PATH.fullmatch(file.relative_to(ROOT).as_posix())}
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            if os.fstat(stream.fileno()).st_size > 16 << 20:
                return None
            raw = stream.read((16 << 20) + 1)
        if len(raw) > 16 << 20:
            return None
        value = reporter.decode(raw)
        rows = value.get('testResults') if type(value) is dict else None
        if type(rows) is not list or not 0 < len(rows) <= 2048:
            return None
        seen, failed = set(), []
        for row in rows:
            if (type(row) is not dict or row.get('name') not in allowed
                    or row['name'] in seen or row.get('status') not in ['passed', 'failed']
                    or type(row.get('assertionResults')) is not list
                    or len(row['assertionResults']) > 50000):
                return None
            seen.add(row['name'])
            indices, route_phase = [], None
            for i, assertion in enumerate(row['assertionResults'], 1):
                if type(assertion) is not dict or assertion.get('status') not in ['passed', 'failed', 'pending', 'todo', 'skipped', 'disabled']:
                    return None
                if assertion['status'] == 'failed':
                    indices.append(i)
                    phase = route_first_commit_failure_phase(allowed[row['name']], i, assertion)
                    if phase is not None:
                        route_phase = phase
            if row['status'] == 'failed':
                coordinates = ','.join(map(str, indices[:10])) or 'runner-or-hook'
                location = allowed[row['name']] + ' assertions=' + coordinates
                if route_phase is not None:
                    location += ' route-first-commit=11:' + route_phase
                failed.append(location)
            elif indices:
                return None
        return '; '.join(sorted(failed)[:20]) or None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


def run_vitest(args, cwd=ROOT, stage='selected-ui-check'):
    # Reporter output may contain raw values. Keep it outside artifact directories
    # and never upload/print it. Existing process exit status remains authoritative.
    with tempfile.TemporaryDirectory(prefix='tracebolt-private-vitest-') as private:
        report = Path(private) / 'results.json'
        try:
            run([*args, '--reporter=json', '--outputFile=' + str(report)], cwd, stage=stage)
        except ValueError:
            location = vitest_failure_location(report)
            if location is not None:
                print('FAIL UI location: ' + location, flush=True)
            raise


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
    if {'windows-managed-msi', 'windows-mutation-coexistence', 'windows-storage-io', 'windows-service-actions'} & set(plan.get('flows', [])):
        run(['node', '--test', 'tests/e2e-review/paused-windows-routes.test.mjs'], stage='ui-paused-windows-routes-contract')
    if 'first-report' in plan.get('flows', []):
        run(['node', 'web/scripts/capture-first-report-fixtures.mjs', '--check'], stage='ui-first-report-contract')
        run(['node', '--test', '--test-concurrency=1', 'web/scripts/first-report-contract.node.mjs'], stage='ui-first-report-evidence-contract')
    if 'shell' in plan.get('flows', []):
        run(['node', '--test', 'tests/e2e-review/route-loading-fixtures.test.mjs'], stage='ui-route-loading-contract')
        run(['node', '--test', 'tests/e2e-review/shell-browser-diagnostics.test.mjs'], stage='ui-shell-diagnostic-contract')
    if 'fleet-groups' in plan.get('flows', []):
        run(['node', '--test', 'tests/e2e-review/fleet-groups-fixtures.test.mjs'], stage='ui-fleet-groups-contract')
    if 'windows-fleet-software' in plan.get('flows', []):
        run(['node', 'web/scripts/capture-windows-fleet-software.mjs', '--check'], stage='ui-fleet-software-contract')
        run(['node', '--test', 'web/scripts/windows-fleet-software-contract.node.mjs'], stage='ui-fleet-software-evidence-contract')
    if 'linux-cve-update-review' in plan.get('flows', []):
        run(['node', 'web/scripts/capture-linux-cve-update-review.mjs', '--check'], stage='ui-cve-review-contract')
        run(['node', '--test', 'web/scripts/linux-cve-update-review-contract.node.mjs'], stage='ui-cve-review-evidence-contract')
    if 'windows-service-actions' in plan.get('flows', []):
        run(['node', 'web/scripts/capture-windows-complete-service-health.mjs', '--check'], stage='ui-complete-service-contract')
        run(['node', '--test', 'web/scripts/windows-complete-service-health-contract.node.mjs'], stage='ui-complete-service-evidence-contract')
        run(['node', '--test', 'tests/e2e-review/windows-update-download-fixtures.test.mjs'], stage='ui-windows-update-download-contract')
        run(['node', '--test', 'tests/e2e-review/windows-update-retirement-fixtures.test.mjs'], stage='ui-windows-update-retirement-contract')
    if 'windows-fleet-msi' in plan.get('flows', []):
        run(['node', 'web/scripts/capture-windows-msi-catalogue-fixtures.mjs', '--check'], stage='ui-msi-catalogue-contract')
    run(['npm', 'run', 'test:environments'], ROOT / 'web', stage='ui-environment-contract')
    if plan['broadWeb']:
        run_vitest(['./node_modules/.bin/vitest', 'run', '--maxWorkers=1'], ROOT / 'web', stage='ui-all-interactions')
        run_vitest(['./web/node_modules/.bin/vitest', 'run', '--config', 'tests/e2e-review/vitest.config.mts'], stage='ui-independent-interactions')
        run_vitest(['./web/node_modules/.bin/vitest', 'run', '--config', 'tests/e2e-review/v3-dom.config.mts'], stage='ui-v3-dom')
    else:
        run_vitest(['./node_modules/.bin/vitest', 'run', 'src/auth.test.tsx', '--maxWorkers=1'], ROOT / 'web', stage='ui-authorization')
        if plan['web']:
            changed_tests = [path for path in plan['web'] if '.test.' in path]
            if changed_tests:
                run_vitest(['./node_modules/.bin/vitest', 'run', '--maxWorkers=1', *changed_tests], ROOT / 'web', stage='ui-changed-tests')
            # Vite resolves actual imports and dependent tests (not filename guesses).
            run_vitest(['./node_modules/.bin/vitest', 'related', '--run', '--passWithNoTests', '--maxWorkers=1', *plan['web']], ROOT / 'web', stage='ui-related-interactions')
            for config, stage in [('vitest.config.mts', 'ui-related-independent'), ('v3-dom.config.mts', 'ui-related-v3-dom')]:
                run_vitest(['./web/node_modules/.bin/vitest', 'related', '--run', '--passWithNoTests',
                     '--config', 'tests/e2e-review/' + config, *['web/' + path for path in plan['web']]], stage=stage)
    print('PASS: UI authorization and affected interaction checks; not full browser evidence.')


# Existing full gate validators are reused where available. Other executable
# runners enforce exact captures internally; require their positive report too.
BROWSER_REPORTS = {name: name + '-results.json' for name in FLOWS if name.startswith('windows-') or name == 'fleet-groups'}
BROWSER_REPORTS.update({'first-report': 'first-report-results.json', 'linux-cve-update-review': 'linux-cve-update-review-results.json', 'lan': 'lan-browser-results.json', 'shell': 'results.json',
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
    if flow == 'first-report':
        run(['node', 'web/scripts/check-first-report-evidence.mjs', sha], stage='browser-first-report-evidence')
    if flow == 'windows-fleet-software':
        run(['node', 'web/scripts/check-windows-fleet-software-evidence.mjs', sha], stage='browser-fleet-software-evidence')
    if flow == 'linux-cve-update-review':
        run(['node', 'web/scripts/check-linux-cve-update-review-evidence.mjs', sha], stage='browser-cve-review-evidence')
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


# Closed coordinates from lan-browser.mjs and its reviewed case modules. These
# literals, never report prose or nested diagnostics, are the only output labels.
LAN_FAILURE_CASES = {
    'Deferred details stay absent on login and overview, and respect blurred route replacement': 'route-loading',
    'Deferred details wait through pagehide and completed auth revalidation': 'route-loading-resume',
    'Deferred details cannot mount after logout or protected auth loss': 'route-loading-auth',
    'Rejected detail module is contained and deliberate reload retries without mutation replay': 'route-loading-recovery',
    'Automatic certificate renewal metadata remains explicit and bounded': 'certificate-renewal',
    'Synthetic presentation-only service actions show exact review and uncertain outcomes without approval or execution': 'service-action-display',
    'Real HTTP-test login defaults to English, blocks protected data and retains a localized transport warning': 'login-warning',
    'Malformed or unavailable bootstrap fails closed and explicit retry recovers without fake access': 'bootstrap',
    'Actual password rejection and repeated login clear the draft, use one request and keep session cookies out of script storage': 'password-rejection',
    'Authenticated LAN contract shows unknown awaiting-agent data with no demo fleet or healthy empty-state claim': 'awaiting-agent',
    'Visible device tabs refresh synthetic metadata without remounts, preserve sample time and stop at access loss': 'live-metadata',
    'Read-only application status separates retained HTTP and verified-leaf expiry, ages samples and clears access loss': 'application-status',
    'Synthetic read-only alarm status preserves snapshot meaning and clears interrupted access without replay': 'alarm-status',
    'Synthetic alarm setup renders explicit configuration and test consent with intercepted fake sender states': 'alarm-settings',
    'Synthetic application check setup saves inert drafts and requires exact manager-origin enable consent': 'application-settings',
    'Synthetic Windows inventory shares device charts and explicit enrollment consent without Linux reads': 'windows-inventory',
    'Synthetic 24-hour resource charts preserve real sample times, missing intervals and protected access': 'resource-history',
    'Synthetic capability source states preserve denied, failed and stale reads without profile-only warnings': 'capabilities',
    'Synthetic retained journal browsing opens approved services directly and pages sparse searches without export': 'journal-browse',
    'Synthetic service-log AI requires independent capture/export scope and expires cited findings without real collection': 'journal-ai',
    'Synthetic selected package updates retain unavailable scope, exact simulation review and unknown outcomes without host changes': 'package-updates',
    'Synthetic proactive AI setup requires scoped approval and reads durable unconfirmed results without running a provider': 'proactive-ai',
    'Synthetic read-only Investigations distinguish retained warnings, unknown assessment and expired current evidence': 'investigations',
    'Synthetic CVE continuation retains bounded warnings, stops changed or blocked work and rejects late scope responses': 'cve-continuation',
    'Synthetic CVE detail pages reach omitted warnings and exact binaries, preserve bindings and reject late scope responses': 'cve-detail-pages',
    'Real CSRF-protected logout removes private content and rejects later protected API reads': 'logout',
    'Actual short session expiry locks the browser and backend using server-relative TTL': 'session-expiry',
    'Protected 401 unmounts provider drafts and a fresh login never replays the interrupted write': 'provider-access-loss',
    'Unconfirmed logout stays locked across reload and explicit retry performs real logout': 'logout-retry',
    'Logout from another tab clears its private view and prevents authenticated restoration': 'cross-tab-logout',
    'Mobile HTTP-test login and shell keep the warning visible with no horizontal overflow': 'mobile-login',
}
# Other existing cases may report stages, but only the detail-page coordinates
# needed for this failure investigation are promoted to public output here.
LAN_STAGE_CASES = {
    'route-loading', 'route-loading-resume', 'route-loading-auth', 'route-loading-recovery',
    'service-action-display', 'application-status', 'application-settings', 'windows-inventory',
    'resource-history', 'capabilities', 'journal-browse', 'journal-ai', 'package-updates',
    'proactive-ai', 'investigations', 'cve-detail-pages',
}
LAN_FAILURE_STAGES = {
    'service-action-display': {stage: stage for stage in (
        'agent-reported-result',
        'detail-route-readiness',
        'final-no-action-guards',
        'fixture-document',
        'inventory-tab',
        'services-tab',
        'setup',
        'stale-helper',
        'synthetic-display-service-action-consent-mobile-de',
        'synthetic-display-service-action-preview-desktop-en',
        'synthetic-display-service-action-preview-mobile-de',
        'synthetic-display-service-action-result-desktop-en',
        'synthetic-display-service-action-result-mobile-en',
        'synthetic-display-service-action-stale-mobile-de',
        'synthetic-display-service-action-unknown-mobile-de',
        'unapproved-review',
        'unknown-result',
    )},
    'package-updates': {stage: stage for stage in (
        'consent',
        'detail-route-readiness',
        'guards',
        'login',
        'review',
        'selection',
        'setup',
        'unavailable',
        'unknown',
    )},
    'investigations': {stage: stage for stage in (
        'browser-back',
        'expired-current-evidence',
        'final-read-only-guards',
        'health-awaiting-assertions',
        'health-awaiting-detail-route-readiness',
        'health-clear-assertions',
        'health-clear-detail-route-readiness',
        'health-dashboard-clear',
        'health-dashboard-healthy-services',
        'health-dashboard-issues',
        'health-healthy-services-assertions',
        'health-healthy-services-detail-route-readiness',
        'health-issue-assertions',
        'health-issue-detail-route-readiness',
        'health-layout-cards',
        'health-layout-issues',
        'health-layout-summaries',
        'health-layout-viewport',
        'health-mobile-de-clear-reading',
        'health-mobile-de-clear-reload',
        'health-mobile-de-clear-summary',
        'health-mobile-de-settings-layout-cards',
        'health-mobile-de-settings-layout-issues',
        'health-mobile-de-settings-layout-summaries',
        'health-mobile-de-settings-layout-viewport',
        'health-mobile-de-settings-open',
        'health-mobile-de-settings-scroll',
        'health-mobile-de-settings-visible',
        'health-stale-assertions',
        'health-stale-detail-route-readiness',
        'health-unavailable-assertions',
        'health-unavailable-detail-route-readiness',
        'issue',
        'mobile-issue',
        'no-current-assessment',
        'setup',
        'stable-device-navigation',
        'synthetic-http-test-health-clear-desktop-de',
        'synthetic-http-test-health-clear-desktop-en',
        'synthetic-http-test-health-clear-mobile-de',
        'synthetic-http-test-health-controls-mobile-de',
        'synthetic-http-test-health-desktop-en',
        'synthetic-http-test-health-issue-mobile-en',
        'synthetic-http-test-health-mobile-de',
        'synthetic-http-test-health-services-desktop-en',
        'synthetic-http-test-health-stale-mobile-en',
        'synthetic-http-test-health-unavailable-mobile-en',
        'synthetic-http-test-health-unknown-mobile-en',
        'synthetic-http-test-investigations-issue-desktop-en',
        'synthetic-http-test-investigations-issue-mobile-de',
        'synthetic-http-test-investigations-issue-mobile-en',
        'synthetic-http-test-investigations-stale-desktop-en',
        'synthetic-http-test-investigations-unknown-mobile-en',
    )},
    'route-loading': {stage: stage for stage in ('setup', 'loading-captures', 'blurred-route-replacement')},
    'route-loading-resume': {stage: stage for stage in ('setup', 'pending-pagehide', 'auth-revalidation')},
    'route-loading-auth': {stage: stage for stage in ('setup', 'pending-logout', 'pending-auth-loss')},
    'route-loading-recovery': {stage: stage for stage in ('setup', 'module-failure', 'failure-captures', 'deliberate-reload')},
    'windows-inventory': {stage: stage for stage in (
        'services-source', 'services-disabled', 'services-pending', 'services-attention',
        'services-unknown', 'services-recovered', 'services-policy-changed',
    )},
    'cve-detail-pages': {stage: stage.replace(' ', '-') for stage in (
        'advancing empty scan', 'changed binding', 'desktop layout', 'device navigation isolation',
        'expired retained input', 'final guards', 'fixture setup', 'fresh login isolation',
        'initial summary', 'initial warning navigation', 'mapped binary navigation', 'mobile layout',
        'omitted warning navigation', 'real login', 'session loss isolation', 'warning return navigation',
    )},
}


def lan_failure_location(sha):
    """Decode the existing failed report; emit only closed source case/stage codes."""
    try:
        path = ROOT / 'artifacts/review/lan-browser-results.json'
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 << 10:
                return None
            raw = stream.read((64 << 10) + 1)
        if len(raw) > 64 << 10:
            return None
        value = reporter.decode(raw)
        prose = {'createdAt', 'scope', 'faultInjection', 'credentialMaterial', 'screenshots'}
        if (not HEX.fullmatch(sha) or type(value) is not dict
                or set(value) != prose | {'sourceSha', 'runtimeErrorCount', 'results', 'summary'}
                or value['sourceSha'] != sha or any(type(value[key]) is not str for key in prose)
                or type(value['runtimeErrorCount']) is not int or not 0 <= value['runtimeErrorCount'] <= 1000000
                or type(value['results']) is not list or len(value['results']) > len(LAN_FAILURE_CASES)):
            return None
        summary, rows = value['summary'], value['results']
        if (type(summary) is not dict or set(summary) != {'passed', 'failed', 'setupFailure'}
                or type(summary['setupFailure']) is not bool
                or any(type(summary[key]) is not int or not 0 <= summary[key] <= len(LAN_FAILURE_CASES)
                       for key in ['passed', 'failed'])
                or (not summary['setupFailure'] and len(rows) != len(LAN_FAILURE_CASES))):
            return None
        failed, locations = 0, []
        # The producer runs in a fixed order, possibly stopping on a fatal setup
        # or cleanup failure. Exact prefix matching also rejects duplicate cases.
        for row, name in zip(rows, LAN_FAILURE_CASES):
            if (type(row) is not dict or row.get('name') != name or row.get('status') not in ['PASS', 'FAIL']
                    or type(row.get('durationMs')) is not int or not 0 <= row['durationMs'] <= 9007199254740991):
                return None
            keys = {'name', 'status', 'durationMs'}
            if row['status'] == 'FAIL':
                failed += 1
                code, stage = LAN_FAILURE_CASES[name], 'unavailable'
                keys.add('error')
                if row.get('error') != 'Assertion failed; raw state and credential-bearing diagnostics intentionally withheld.':
                    return None
                if code in LAN_STAGE_CASES:
                    keys.add('stage')
                    if type(row.get('stage')) is not str or len(row['stage']) > 128:
                        return None
                    if code in LAN_FAILURE_STAGES:
                        if row['stage'] not in LAN_FAILURE_STAGES[code]:
                            return None
                        stage = LAN_FAILURE_STAGES[code][row['stage']]
                diagnostic = ('journalDiagnostics' if code == 'journal-browse' else
                              'alarmDiagnostics' if code in ['alarm-status', 'alarm-settings'] else None)
                if diagnostic:
                    keys.add(diagnostic)
                    if diagnostic not in row or (row[diagnostic] is not None and type(row[diagnostic]) is not dict):
                        return None
                locations.append('case=' + code + ' stage=' + stage)
            if set(row) != keys:
                return None
        if summary['failed'] != failed or summary['passed'] != len(rows) - failed:
            return None
        if summary['setupFailure']:
            locations.append('setup-failure')
        if value['runtimeErrorCount']:
            locations.append('runtime-errors')
        return '; '.join(locations) or None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


# Finite recipe steps; failed reports never admit exception text or runtime values.
CVE_CAPTURE_STAGES = {
    'fixture', 'context', 'navigate', 'open-warning', 'open-binaries', 'review-focus',
    'review-enter', 'candidate', 'updates-focus', 'matched-row', 'unchecked-row',
    'capture-times', 'layout', 'screenshot', 'final-guards',
}
CVE_RUNNER_STAGES = {'launch', 'compile', 'manifest', 'close', 'evidence'}


def cve_review_failure_location(sha):
    try:
        path = ROOT / 'artifacts/review/linux-cve-update-review-results.json'
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8192:
                return None
            raw = stream.read(8193)
        if len(raw) > 8192:
            return None
        value = reporter.decode(raw)
        keys = {'sourceSha', 'status', 'browserAcceptance', 'sceneManifestSHA256', 'scenes', 'screenshots',
                'requestsToRealAPI', 'actualMutationRequests', 'nativeAcceptance', 'disclosure', 'failure'}
        if (not HEX.fullmatch(sha) or type(value) is not dict or set(value) != keys
                or value['sourceSha'] != sha or value['status'] != 'FAIL'
                or value['browserAcceptance'] is not False or value['nativeAcceptance'] is not False
                or type(value['sceneManifestSHA256']) is not str
                or not re.fullmatch(r'[a-f0-9]{64}', value['sceneManifestSHA256'])
                or type(value['disclosure']) is not str or len(value['disclosure']) > 1024
                or any(type(value[key]) is not int or value[key] != 0
                       for key in ['scenes', 'screenshots', 'requestsToRealAPI', 'actualMutationRequests'])):
            return None
        failure = value['failure']
        if type(failure) is not dict or set(failure) != {'stage', 'captureIndex'}:
            return None
        stage, index = failure['stage'], failure['captureIndex']
        if type(stage) is not str:
            return None
        if stage in CVE_RUNNER_STAGES and index is None:
            return 'stage=' + stage
        if stage in CVE_CAPTURE_STAGES and type(index) is int and 0 <= index < 4:
            locale, width = [('en', 1440), ('en', 390), ('de', 1440), ('de', 390)][index]
            return 'stage=%s locale=%s width=%d' % (stage, locale, width)
        return None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None



# Closed coordinates for the selected single-case Windows detail runners. The
# report's prose, source hashes, browser version and fixture values never leave
# this decoder. These diagnostics do not participate in acceptance validation.
WINDOWS_DETAIL_FAILURE_CASES = {
    'windows-managed-msi': 'Synthetic central MSI bounded upload, separate delivery, unchecked exact approval and durable outcome',
    'windows-mutation-coexistence': 'Synthetic shared MSI and WUA blocking, exact recovery details and released status in both compiled views',
    'windows-storage-io': 'Private Windows PerfDisk aggregate with invented transport',
}
WINDOWS_DETAIL_FAILURE_STAGES = {
    'windows-managed-msi': (
        'setup', 'document', 'detail-route-readiness', 'upload', 'deliver', 'imported',
        'review', 'ready', 'approve', 'outcome', 'reload', 'reload-detail-route-readiness', 'complete',
    ),
    'windows-mutation-coexistence': (
        'setup', 'document', 'detail-route-readiness', 'blocked', 'released', 'reload',
        'reload-detail-route-readiness', 'complete',
    ),
    'windows-storage-io': (
        'setup', 'mount', 'detail-route-readiness', 'mount-detail-route-readiness',
        'summary', 'details', 'navigation', 'idle', 'partial', 'denied', 'unsupported',
        'retained', 'retained-age', 'legacy', 'expiry', 'focus', 'revoked', 'session', 'complete',
    ),
}


def clear_windows_detail_failure_report(flow):
    """Remove only this runner's old result through a no-follow directory FD."""
    directory = None
    try:
        if type(flow) is not str or flow not in WINDOWS_DETAIL_FAILURE_CASES:
            raise ValueError('invalid Windows detail diagnostic flow')
        path = ROOT / 'artifacts/review' / BROWSER_REPORTS[flow]
        directory = reporter.open_log(path.parent)
        if not stat.S_ISDIR(os.fstat(directory).st_mode):
            raise ValueError('invalid Windows detail diagnostic directory')
        os.unlink(path.name, dir_fd=directory)
    except FileNotFoundError:
        pass  # A missing result or parent cannot contribute a stale coordinate.
    except OSError:
        raise ValueError('could not prepare fresh Windows detail diagnostics') from None
    finally:
        if directory is not None:
            os.close(directory)


def windows_detail_failure_location(flow, sha):
    """Project only same-source, exact-case labels from bounded failed reports."""
    try:
        if (type(flow) is not str or flow not in WINDOWS_DETAIL_FAILURE_CASES
                or type(sha) is not str or not HEX.fullmatch(sha)):
            return None
        path = ROOT / 'artifacts/review' / BROWSER_REPORTS[flow]
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8192:
                return None
            raw = stream.read(8193)
        if len(raw) > 8192:
            return None
        value = reporter.decode(raw)
        common = {'name', 'status', 'stage', 'sourceSha', 'createdAt', 'runtimeErrorCount',
                  'browserAcceptance', 'nativeAcceptance'}
        storage = flow == 'windows-storage-io'
        extra = ({'sourceState', 'uiSourceSha256', 'compiledBundleSha256', 'browserVersion',
                  'customPreinstalledBrowser', 'fixtureDisclosure', 'details',
                  'liveAuthenticationAcceptance', 'liveStoreAcceptance'} if storage else
                 {'scope', 'variants', 'requestsToRealAPI', 'durableStoreAcceptance',
                  'secretsExported', 'realTelemetryExported'})
        if (type(value) is not dict or set(value) != common | extra
                or value['sourceSha'] != sha or value['name'] != WINDOWS_DETAIL_FAILURE_CASES[flow]
                or value['status'] != 'FAIL' or value['browserAcceptance'] is not False
                or value['nativeAcceptance'] is not False
                or type(value['stage']) is not str or value['stage'] not in WINDOWS_DETAIL_FAILURE_STAGES[flow]
                or type(value['createdAt']) is not str or not 1 <= len(value['createdAt']) <= 64
                or type(value['runtimeErrorCount']) is not int or not 0 <= value['runtimeErrorCount'] <= 1000000):
            return None
        prose = 'fixtureDisclosure' if storage else 'scope'
        if type(value[prose]) is not str or not 1 <= len(value[prose]) <= 4096:
            return None
        if storage:
            if (value['sourceState'] != 'sourceSha identifies checkout HEAD; source and compiled bundle hashes identify the tested bytes'
                    or any(type(value[key]) is not str or not re.fullmatch(r'[a-f0-9]{64}', value[key])
                           for key in ['uiSourceSha256', 'compiledBundleSha256'])
                    or (value['browserVersion'] is not None and
                        (type(value['browserVersion']) is not str or not 1 <= len(value['browserVersion']) <= 128))
                    or type(value['customPreinstalledBrowser']) is not bool or value['details'] is not None
                    or value['liveAuthenticationAcceptance'] is not False or value['liveStoreAcceptance'] is not False):
                return None
        elif (type(value['variants']) is not list or value['variants'] != []
              or type(value['requestsToRealAPI']) is not int or value['requestsToRealAPI'] != 0
              or any(value[key] is not False for key in ['durableStoreAcceptance', 'secretsExported', 'realTelemetryExported'])):
            return None
        # Select emitted labels from source, never from report strings.
        case = next(name for name in WINDOWS_DETAIL_FAILURE_CASES if name == flow)
        stage = next(name for name in WINDOWS_DETAIL_FAILURE_STAGES[case] if name == value['stage'])
        return 'case=%s stage=%s' % (case, stage)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


# This source vocabulary is shared with the Windows producer, never loaded from
# the runtime report directory (including when ROOT points at captured artifacts).
WINDOWS_ACTION_DIAGNOSTICS_SOURCE = Path(__file__).resolve().parents[1] / 'e2e-review/windows-service-actions-diagnostics.json'
WINDOWS_ACTION_DIAGNOSTICS_SCHEMA = 'tracebolt.windows-action-browser-failure.v1'
WINDOWS_ACTION_INVOCATION = re.compile(r'[0-9a-f]{32}\Z')


def windows_action_diagnostic_contract():
    """Admit only bounded source-owned labels, shared with the runner."""
    with os.fdopen(reporter.open_log(WINDOWS_ACTION_DIAGNOSTICS_SOURCE), 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16384:
            raise ValueError('invalid Windows action diagnostic contract')
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('invalid Windows action diagnostic contract')
    value = reporter.decode(raw)
    if (type(value) is not dict or set(value) != {'schemaVersion', 'cases'}
            or value['schemaVersion'] != WINDOWS_ACTION_DIAGNOSTICS_SCHEMA
            or type(value['cases']) is not dict or not 1 <= len(value['cases']) <= 32
            or 'runner' not in value['cases']):
        raise ValueError('invalid Windows action diagnostic contract')
    for case, steps in value['cases'].items():
        if (type(case) is not str or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', case)
                or type(steps) is not list or not 1 <= len(steps) <= 128
                or any(type(step) is not str or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', step)
                       for step in steps) or len(set(steps)) != len(steps)):
            raise ValueError('invalid Windows action diagnostic contract')
    return value['cases']


def windows_action_failure_location(sha, invocation):
    """Project only finite labels from this exact source and runner invocation."""
    try:
        if (type(sha) is not str or not HEX.fullmatch(sha)
                or type(invocation) is not str or not WINDOWS_ACTION_INVOCATION.fullmatch(invocation)):
            return None
        path = ROOT / 'artifacts/review/windows-service-actions-failure.json'
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
                return None
            raw = stream.read(4097)
        if len(raw) > 4096:
            return None
        value = reporter.decode(raw)
        keys = {'schemaVersion', 'sourceSha', 'invocation', 'status', 'browserAcceptance',
                'nativeAcceptance', 'case', 'locale', 'width', 'step'}
        if (type(value) is not dict or set(value) != keys
                or value['schemaVersion'] != WINDOWS_ACTION_DIAGNOSTICS_SCHEMA
                or type(value['sourceSha']) is not str or value['sourceSha'] != sha
                or type(value['invocation']) is not str or value['invocation'] != invocation
                or value['status'] != 'FAIL' or value['browserAcceptance'] is not False
                or value['nativeAcceptance'] is not False
                or type(value['case']) is not str or type(value['step']) is not str):
            return None
        cases = windows_action_diagnostic_contract()
        if value['case'] not in cases or value['step'] not in cases[value['case']]:
            return None
        # Select the emitted strings from source, not from report values.
        case = next(name for name in cases if name == value['case'])
        step = next(name for name in cases[case] if name == value['step'])
        locale, width = value['locale'], value['width']
        if case == 'runner':
            if locale is not None or width is not None:
                return None
            return 'case=runner step=%s locale=- width=-' % step
        if type(locale) is not str or locale not in ['en', 'de'] or type(width) is not int or width not in [1440, 390]:
            return None
        locale = next(name for name in ['en', 'de'] if name == locale)
        width = next(size for size in [1440, 390] if size == width)
        return 'case=%s step=%s locale=%s width=%d' % (case, step, locale, width)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


JOURNAL_COORDINATES_SOURCE = Path(__file__).resolve().parents[1] / 'e2e-review/journal-browser-coordinates.json'


def journal_failure_location(path, sha):
    """Release fixed numeric coordinates only from this invocation's private file."""
    try:
        with os.fdopen(reporter.open_log(JOURNAL_COORDINATES_SOURCE), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 16384:
                return None
            contract_raw = stream.read(16385)
        if len(contract_raw) > 16384:
            return None
        contract = reporter.decode(contract_raw)
        if (type(contract) is not dict or set(contract) != {'schemaVersion', 'cases', 'stages'}
                or contract['schemaVersion'] != 'tracebolt.journal-browser-coordinates.v1'
                or type(contract['cases']) is not list or len(contract['cases']) != 7
                or type(contract['stages']) is not list or not 0 < len(contract['stages']) <= 128):
            return None
        for values in [contract['cases'], contract['stages']]:
            if any(type(item) is not str or not 0 < len(item) <= 160 for item in values) or len(set(values)) != len(values):
                return None
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 8192:
                return None
            raw = stream.read(8193)
        if len(raw) > 8192:
            return None
        value = reporter.decode(raw)
        if (not HEX.fullmatch(sha) or type(value) is not dict
                or set(value) != {'schemaVersion', 'sourceSha', 'failures', 'setupFailure', 'runtimeFailure', 'finalCheckpoint'}
                or value['schemaVersion'] != 'tracebolt.journal-browser-failure.v1' or value['sourceSha'] != sha
                or any(type(value[key]) is not bool for key in ['setupFailure', 'runtimeFailure'])
                or type(value['finalCheckpoint']) is not int or not 0 <= value['finalCheckpoint'] < len(contract['stages'])
                or type(value['failures']) is not list or len(value['failures']) > len(contract['cases'])):
            return None
        previous, locations = 0, []
        for row in value['failures']:
            if (type(row) is not dict or set(row) != {'case', 'checkpoint'}
                    or type(row['case']) is not int or not previous < row['case'] <= len(contract['cases'])
                    or type(row['checkpoint']) is not int or not 0 <= row['checkpoint'] < len(contract['stages'])):
                return None
            previous = row['case']
            locations.append('case=%d checkpoint=%d' % (row['case'], row['checkpoint']))
        if value['setupFailure']:
            locations.append('setup-checkpoint=%d' % value['finalCheckpoint'])
        if value['runtimeFailure']:
            locations.append('runtime-errors')
        return '; '.join(locations) or None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


ROUTE_LOADING_STAGES = (
    'fixture', 'overview-navigation', 'initial-deferral', 'interception-setup',
    'cold-navigation', 'module-interception', 'loading-fallback', 'module-transfer',
    'module-evaluation', 'final-render', 'final-counts', 'complete',
)


def shell_route_loading_location(path, sha):
    """Read only a closed direct-case coordinate from this invocation's private file."""
    try:
        with os.fdopen(reporter.open_log(path), 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 2048:
                return None
            raw = stream.read(2049)
        if len(raw) > 2048:
            return None
        value = reporter.decode(raw)
        if (type(sha) is not str or not HEX.fullmatch(sha) or type(value) is not dict
                or set(value) != {'schema', 'sourceSha', 'status', 'stage', 'runtimeError'}
                or type(value['schema']) is not int or value['schema'] != 1 or value['sourceSha'] != sha
                or type(value['status']) is not str or value['status'] not in ('PASS', 'FAIL', 'NOT_RUN')
                or type(value['stage']) is not str or value['stage'] not in ROUTE_LOADING_STAGES
                or type(value['runtimeError']) is not bool
                or (value['status'] == 'PASS' and value['stage'] != 'complete')
                or (value['status'] == 'NOT_RUN' and (value['stage'] != 'fixture' or value['runtimeError']))):
            return None
        # Reconstruct from source literals, never echo an arbitrary report string.
        status = next(name.lower() for name in ('PASS', 'FAIL', 'NOT_RUN') if name == value['status'])
        stage = next(name for name in ROUTE_LOADING_STAGES if name == value['stage'])
        return 'case=direct-case status=%s stage=%s%s' % (status, stage, ' runtime-errors' if value['runtimeError'] else '')
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


SHELL_CASES_SOURCE = Path(__file__).resolve().parents[1] / 'e2e-review/shell-browser-cases.json'
SHELL_FAILURE_CATEGORIES = ('assertion', 'timeout', 'other')
SHELL_KEYBOARD_STAGES = ('navigation', 'case-content', 'initial-bounds', 'skip-focus', 'main-focus',
                         'page-scroll', 'scrolled-bounds', 'menu-navigation', 'final-bounds', 'complete')


def shell_failure_location(path, sha):
    """Project source-bound numeric IDs and closed categories, never report names."""
    try:
        def read_bounded(path, limit):
            with os.fdopen(reporter.open_log(path), 'rb') as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
                    raise ValueError('invalid')
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('invalid')
            return reporter.decode(raw)
        contract = read_bounded(SHELL_CASES_SOURCE, 16384)
        if (type(contract) is not dict or set(contract) != {'schema', 'cases'}
                or type(contract['schema']) is not int or contract['schema'] != 1
                or type(contract['cases']) is not list or len(contract['cases']) != 45
                or any(type(name) is not str or not 0 < len(name) <= 200 for name in contract['cases'])
                or len(set(contract['cases'])) != 45):
            return None
        value = read_bounded(path, 8192)
        if (type(sha) is not str or not HEX.fullmatch(sha) or type(value) is not dict
                or set(value) != {'schema', 'sourceSha', 'failures', 'runtimeCases', 'unknownCase'}
                or type(value['schema']) is not int or value['schema'] != 1 or value['sourceSha'] != sha
                or type(value['unknownCase']) is not bool
                or type(value['failures']) is not list or len(value['failures']) > 45
                or type(value['runtimeCases']) is not list or len(value['runtimeCases']) > 45):
            return None
        previous, locations = 0, []
        for row in value['failures']:
            if (type(row) is not dict or set(row) != ({'case', 'category', 'stage'} if row.get('case') == 36 else {'case', 'category'})
                    or type(row['case']) is not int or not previous < row['case'] <= 45
                    or type(row['category']) is not str or row['category'] not in SHELL_FAILURE_CATEGORIES
                    or (row['case'] == 36 and (type(row['stage']) is not int or not 0 <= row['stage'] < len(SHELL_KEYBOARD_STAGES)))):
                return None
            previous = row['case']
            category = next(name for name in SHELL_FAILURE_CATEGORIES if name == row['category'])
            locations.append('case=%d category=%s%s' % (row['case'], category, ' stage=%d' % row['stage'] if row['case'] == 36 else ''))
        previous = 0
        for case in value['runtimeCases']:
            if type(case) is not int or not previous < case <= 45:
                return None
            previous = case
            locations.append('case=%d category=runtime' % case)
        if value['unknownCase']:
            locations.append('unknown-case')
        return '; '.join(locations) or None
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        return None


def run_shell_browser(env, sha):
    # A fresh private path prevents stale same-head results and is removed on
    # every exit. No raw errors, fixture values or browser logs are released.
    with tempfile.TemporaryDirectory(prefix='tracebolt-private-route-loading-') as private:
        path = Path(private) / 'coordinates.json'
        shell_path = Path(private) / 'shell-coordinates.json'
        try:
            run(['node', FLOWS['shell']], stage='browser-shell',
                env={**env, 'TRACEBOLT_ROUTE_LOADING_DIAGNOSTIC': str(path), 'TRACEBOLT_SHELL_DIAGNOSTIC': str(shell_path)})
        except ValueError:
            location = shell_route_loading_location(path, sha)
            if location is not None:
                print('FAIL shell route-load location: ' + location, flush=True)
            location = shell_failure_location(shell_path, sha)
            if location is not None:
                print('FAIL shell location: ' + location, flush=True)
            raise


def run_journal_browser(env, sha):
    # Fresh exclusive path per invocation, never under artifacts and always
    # removed. A previous same-head run cannot supply this run's diagnostic.
    with tempfile.TemporaryDirectory(prefix='tracebolt-private-journal-') as private:
        path = Path(private) / 'coordinates.json'
        try:
            run(['node', FLOWS['journal']], stage='browser-journal',
                env={**env, 'TRACEBOLT_JOURNAL_DIAGNOSTICS_PATH': str(path)})
        except ValueError:
            location = journal_failure_location(path, sha)
            if location is not None:
                print('FAIL journal location: ' + location, flush=True)
            raise  # Original failure and withheld raw process output stay intact.


def browser_checks(plan):
    run(['node', 'tests/e2e-review/lan-browser.mjs', '--pr-smoke'], stage='browser-auth-smoke')
    # The existing shell runner clears its screenshot folder on startup. Run it
    # first, so it cannot delete subsequently captured affected-flow evidence.
    for flow in sorted(plan['flows'], key=lambda value: (value != 'shell', value)):
        print('Running selected browser flow: ' + flow, flush=True)
        env = {**os.environ, 'TRACEBOLT_REVIEW_QUARANTINED': '1', 'TRACEBOLT_REVIEW_LIFECYCLE_REPEATS': '5', 'TRACEBOLT_REVIEW_AI': '1'}
        # A same-head report from an earlier run must never describe this run.
        env.pop('TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN', None)
        if flow == 'windows-service-actions':
            invocation = secrets.token_hex(16)
            env['TRACEBOLT_WINDOWS_DIAGNOSTICS_TOKEN'] = invocation
        if flow in WINDOWS_DETAIL_FAILURE_CASES:
            # Before the failure handler: a cleanup error must never decode the
            # old file, and a failed launch without a new report stays generic.
            clear_windows_detail_failure_report(flow)
        if flow == 'fleet-identity':
            # This legacy runner otherwise guesses /usr/bin/chromium. Bind only
            # this invocation to the locked Playwright browser installed by CI.
            executable = capture(['node', '-e', "console.log(require('./web/node_modules/@playwright/test').chromium.executablePath())"]).decode().strip()
            if not Path(executable).is_absolute() or not Path(executable).is_file():
                raise ValueError('installed browser unavailable')
            env['CHROMIUM_PATH'] = executable
        try:
            if flow == 'shell':
                run_shell_browser(env, plan['sha'])
            elif flow == 'journal':
                run_journal_browser(env, plan['sha'])
            else:
                run(['node', FLOWS[flow]], stage='browser-' + flow, env=env)
        except ValueError:
            if flow == 'linux-cve-update-review':
                location = cve_review_failure_location(plan['sha'])
                if location is not None:
                    print('FAIL CVE review location: ' + location, flush=True)
            if flow == 'lan':
                location = lan_failure_location(plan['sha'])
                if location is not None:
                    print('FAIL LAN location: ' + location, flush=True)
            if flow == 'windows-fleet-msi':
                location = fleet_msi_failure_location(plan['sha'])
                if location is not None:
                    print('FAIL fleet MSI location: ' + location, flush=True)
            if flow == 'windows-service-actions':
                location = windows_action_failure_location(plan['sha'], invocation)
                if location is not None:
                    print('FAIL Windows action location: ' + location, flush=True)
            if flow in WINDOWS_DETAIL_FAILURE_CASES:
                location = windows_detail_failure_location(flow, plan['sha'])
                if location is not None:
                    print('FAIL Windows detail location: ' + location, flush=True)
            raise  # Diagnostics never turn a failed browser flow into success.
        if flow == 'windows-fleet-msi':
            # Three bounded changed flows accompany the existing MSI selection;
            # no new broad-flow mapping or older screenshot expansion.
            run(['node', 'web/scripts/run-windows-msi-catalogue-ci.mjs'], stage='browser-msi-catalogue', env=env)
        if flow == 'windows-service-actions':
            run(['node', 'tests/e2e-review/windows-update-retirement-browser.mjs', '--check-evidence', plan['sha']],
                stage='browser-update-retirement-evidence', env=env)
            run(['node', 'tests/e2e-review/windows-update-download-browser.mjs', '--check-evidence', plan['sha']],
                stage='browser-update-download-evidence', env=env)
            run(['node', 'web/scripts/check-windows-complete-service-health-evidence.mjs', plan['sha']],
                stage='browser-complete-service-evidence', env=env)
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
