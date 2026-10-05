"""Require exact, bounded, source-matched synthetic service-action browser evidence."""
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
        'scope', 'runtimeErrorCount', 'results', 'summary'}


def validate(value, source_sha):
    if not isinstance(source_sha, str) or re.fullmatch(r'[a-f0-9]{40}', source_sha) is None:
        raise ValueError('invalid expected source')
    if not isinstance(value, dict) or set(value) != KEYS or value['sourceSha'] != source_sha:
        raise ValueError('invalid identity or shape')
    if value['schemaVersion'] != 'tracebolt.service-action-browser.v1' or value['transportProfile'] != 'disposable-http-test' or value['fixture'] != FIXTURE:
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


def main(argv):
    try:
        if len(argv) != 2:
            raise ValueError('invalid arguments')
        validate(read_report(argv[1]), os.environ.get('TRACEBOLT_SOURCE_SHA'))
    except Exception:
        print('FAIL: missing, partial, mismatched or unsafe service-action browser evidence.')
        return 1
    print('PASS: four exact service-action browser cases on the selected source; synthetic agent, injected helper authority/peer and fake backend, with no native root/helper/systemd or production actionSender acceptance.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
