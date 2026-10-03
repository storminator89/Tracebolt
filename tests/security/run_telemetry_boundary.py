#!/usr/bin/env python3
"""Independent managed-preview checks against two owned disposable managers.
One manager must be default-off; the other must use --managed-preview.
Only own-built local agent binaries and literal loopback endpoints are accepted.
"""
import argparse
from datetime import datetime, timedelta, timezone
import http.client
import json
import pathlib
import subprocess
import time
from urllib.parse import urlsplit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base-url', required=True)
parser.add_argument('--disabled-url', required=True)
parser.add_argument('--agent', required=True)
parser.add_argument('--dev-agent', required=True)
args = parser.parse_args()
for value in (args.base_url, args.disabled_url):
    parsed = urlsplit(value)
    if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port or parsed.path or parsed.username or parsed.query or parsed.fragment:
        parser.error('Use explicit http://127.0.0.1:PORT origins only')
for value in (args.agent, args.dev_agent):
    if not pathlib.Path(value).is_file():
        parser.error('Agent binary is unavailable')


def request(base, method, path, body=None, token=None, origin=True):
    url = urlsplit(base)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=5)
    headers = {}
    if body is not None:
        body = json.dumps(body).encode() if not isinstance(body, bytes) else body
        headers['Content-Type'] = 'application/json'
    if token:
        headers['X-CSRF-Token'] = token
    if origin:
        headers['Origin'] = base
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw)
    finally:
        connection.close()


def session(base):
    status, result = request(base, 'GET', '/api/session')
    assert status == 200
    return result['csrfToken']


def status():
    code, result = request(args.base_url, 'GET', '/api/dev/telemetry/status')
    assert code == 200, (code, result)
    return result


def post(body, *, origin=True):
    return request(args.base_url, 'POST', '/api/dev/telemetry', body, session(args.base_url), origin)


# Default-off ingress remains disabled even with otherwise valid write guards.
disabled_token = session(args.disabled_url)
assert request(args.disabled_url, 'GET', '/api/dev/telemetry/status')[0] == 404
assert request(args.disabled_url, 'POST', '/api/dev/telemetry', {}, disabled_token)[0] == 404
print('PASS: telemetry ingress is default-off')

initial = status()
assert initial['state'] == 'awaiting' and initial['acceptedSamples'] == 0
_, device = request(args.base_url, 'GET', '/api/devices/sandbox-local')
assert device['status'] == 'unknown' and device['cpu']['value'] is None
assert device['memory']['value'] is None and device['disk']['value'] is None
assert device['lastSeen'].startswith('0001-')
print('PASS: no startup fallback or fabricated reading')

assert post({}, origin=False)[0] == 403
assert post(b' ' * 65537)[0] == 413
assert status()['acceptedSamples'] == 0
print('PASS: ingress guard and raw byte cap')

for expected in (1, 2):
    command = subprocess.run([args.dev_agent, '--manager', args.base_url], check=True, capture_output=True, timeout=10)
    receipt = json.loads(command.stdout)
    assert receipt['sequence'] == expected and receipt['deviceId'] == 'sandbox-local'
    live = status()
    assert live['acceptedSamples'] == expected and live['state'] == 'fresh'
_, device = request(args.base_url, 'GET', '/api/devices/sandbox-local')
assert device['source'] == 'sandbox' and device['synthetic'] is False and device['status'] == 'unknown'
assert device['ip'] is None
print('PASS: two real separate one-shot Linux agent deliveries, explicit unknown health')

# A mixed-age but valid bundle must age out without receiving another sample.
command = subprocess.run([args.agent, '--support-bundle'], check=True, capture_output=True, timeout=10)
bundle = json.loads(command.stdout)
bundle['observation']['cpu']['collectedAt'] = (datetime.now(timezone.utc) - timedelta(seconds=119)).isoformat().replace('+00:00', 'Z')
code, receipt = post(bundle)
assert code == 200 and receipt['sequence'] == 3, (code, receipt)
assert status()['state'] == 'fresh'
code, _ = post(bundle)
assert code == 409
unchanged = status()
assert unchanged['acceptedSamples'] == 3 and unchanged['receivedAt'] == receipt['receivedAt']
print('PASS: replay rejected without refreshing receipt')

time.sleep(2.1)
aged = status()
assert aged['state'] == 'stale' and aged['acceptedSamples'] == 3
_, device = request(args.base_url, 'GET', '/api/devices/sandbox-local')
assert device['status'] == 'unknown'
assert all(device[name]['quality'] != 'healthy' for name in ('cpu', 'memory', 'disk'))
assert device['lastSeen'] == bundle['observation']['lastSeen']
print('PASS: oldest field ages out through real API, no refreshed/fallback sample')

bundle['observation']['name'] = 'forged-host-identifier'
assert post(bundle)[0] == 400
assert status()['acceptedSamples'] == 3
print('PASS: fixed role identity enforced atomically')
print('Managed-preview independent checks: 7 groups PASS')
