"""Require exact, bounded, source-matched synthetic service-action browser evidence."""
import hashlib
from pathlib import Path
import json
import os
import re
import stat
import sys
from datetime import datetime

from report_complete_mvp import reject_constant, unique_object

MAX_BYTES = 32768
CASES = {
    'Named operator preview binds the selected service and cancellation leaves zero jobs and helper calls',
    'Explicit interruption approval commits one job and held helper execution remains unconfirmed',
    'Agent-reported completion survives reload without automatic approval or execution replay',
    'Repeating the exact approved preview is idempotent and cannot execute again',
    'V2 complete impact, exclusions and authority warning remain reviewable with fresh consent in English and German on desktop and mobile',
}
TRUE_FLAGS = {
    'builtReactUI', 'namedOperatorAuth', 'realManagerAPI', 'durableEnrollmentStore',
    'realAgentIngress', 'realFramedHelperIPC', 'fakeBackend',
    'injectedHelperAuthorityAndPeer', 'syntheticProtocolDriver',
}
FALSE_FLAGS = {
    'secretsExported', 'realTelemetryExported', 'nativeHelperExecuted',
    'realSystemctlExecuted', 'hostGrantChanged', 'userVmAccessed',
    'productionActionSenderExecuted', 'apiMocked',
}
FIXTURE = ('Disposable loopback HTTP test with invented inventory and a synthetic protocol-driving agent; '
           'real framed net.Pipe helper ServeConn uses injected fixture authority/peer and a fake Backend. '
           'This does not establish native root/helper/systemd isolation, production actionSender '
           'acceptance or mTLS browser acceptance.')
KEYS = {'schemaVersion', 'sourceSha', 'createdAt', 'transportProfile', 'fixture',
        'scope', 'runtimeErrorCount', 'results', 'summary', 'screenshots'}


def validate(value, source_sha):
    if not isinstance(source_sha, str) or re.fullmatch(r'[a-f0-9]{40}', source_sha) is None:
        raise ValueError('invalid expected source')
    if not isinstance(value, dict) or set(value) != KEYS or value['sourceSha'] != source_sha:
        raise ValueError('invalid identity or shape')
    if value['schemaVersion'] != 'tracebolt.service-action-browser.v2' or value['transportProfile'] != 'disposable-http-test' or value['fixture'] != FIXTURE:
        raise ValueError('invalid scope disclosure')
    created = value['createdAt']
    if not isinstance(created, str) or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', created) is None:
        raise ValueError('invalid timestamp')
    datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.%fZ')
    scope = value['scope']
    if not isinstance(scope, dict) or set(scope) != TRUE_FLAGS | FALSE_FLAGS:
        raise ValueError('invalid scope shape')
    if any(scope[key] is not True for key in TRUE_FLAGS) or any(scope[key] is not False for key in FALSE_FLAGS):
        raise ValueError('unsafe or incomplete scope')
    if type(value['runtimeErrorCount']) is not int or value['runtimeErrorCount'] != 0:
        raise ValueError('runtime errors')
    summary = value['summary']
    if not isinstance(summary, dict) or set(summary) != {'passed', 'failed', 'setupFailure'}:
        raise ValueError('invalid summary')
    if type(summary['passed']) is not int or summary['passed'] != len(CASES) or type(summary['failed']) is not int or summary['failed'] != 0 or summary['setupFailure'] is not False:
        raise ValueError('incomplete summary')
    results = value['results']
    if not isinstance(results, list) or len(results) != len(CASES):
        raise ValueError('wrong case count')
    names = set()
    for result in results:
        if not isinstance(result, dict) or set(result) != {'name', 'status', 'durationMs'}:
            raise ValueError('invalid result shape')
        name = result['name']
        if not isinstance(name, str) or name not in CASES or name in names or result['status'] != 'PASS':
            raise ValueError('invalid or duplicate case')
        if type(result['durationMs']) is not int or not 0 <= result['durationMs'] <= 600000:
            raise ValueError('invalid duration')
        names.add(name)
    shots = value['screenshots']
    expected = {(locale, width) for locale in ('en', 'de') for width in (1440, 390)}
    if not isinstance(shots, list) or len(shots) != 4:
        raise ValueError('missing screenshots')
    for shot in shots:
        if not isinstance(shot, dict) or set(shot) != {'file', 'locale', 'viewportWidth', 'sha256'}:
            raise ValueError('invalid screenshot shape')
        locale, width = shot['locale'], shot['viewportWidth']
        if not isinstance(locale, str) or type(width) is not int or (locale, width) not in expected:
            raise ValueError('unexpected screenshot')
        expected.remove((locale, width))
        if shot['file'] != f'service-action-v2-{locale}-{width}.png' or not isinstance(shot['sha256'], str) or re.fullmatch(r'[a-f0-9]{64}', shot['sha256']) is None:
            raise ValueError('invalid screenshot identity')
    if names != CASES:
        raise ValueError('missing case')


def read_report(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            raise ValueError('invalid report file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        if not 0 < len(raw) <= MAX_BYTES:
            raise ValueError('invalid report bounds')
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    finally:
        os.close(fd)


def verify_screenshots(value, directory):
    for shot in value['screenshots']:
        fd = os.open(Path(directory) / shot['file'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 24 <= info.st_size <= 10 * 1024 * 1024:
                raise ValueError('invalid screenshot file')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(10 * 1024 * 1024 + 1)
            if len(data) != info.st_size or hashlib.sha256(data).hexdigest() != shot['sha256'] or data[:8] != b'\x89PNG\r\n\x1a\n' or data[12:16] != b'IHDR':
                raise ValueError('invalid screenshot bytes')
            if int.from_bytes(data[16:20], 'big') != shot['viewportWidth'] or not 1000 <= int.from_bytes(data[20:24], 'big') <= 20000:
                raise ValueError('invalid screenshot dimensions')
        finally:
            os.close(fd)


def main(argv):
    try:
        if len(argv) != 2:
            raise ValueError('invalid arguments')
        value = read_report(argv[1])
        validate(value, os.environ.get('TRACEBOLT_SOURCE_SHA'))
        verify_screenshots(value, Path(argv[1]).parent)
    except Exception:
        print('FAIL: missing, partial, mismatched or unsafe service-action browser evidence.')
        return 1
    print('PASS: five exact service-action-v2 browser cases plus EN/DE desktop/mobile review screenshots on the selected source; synthetic agent, injected helper authority/peer and fake backend, with no native root/helper/systemd or production actionSender acceptance.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
