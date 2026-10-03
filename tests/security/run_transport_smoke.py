#!/usr/bin/env python3
"""Real two-process Linux transport smoke, entirely within one exec/network namespace.

Uses disposable binaries/database and literal loopback; no installation, enrollment,
credential persistence, external requests, or target-OS claims. --wait-stale observes
real expiry after the one-shot sender exits instead of simulating manager time.
"""
import argparse
import datetime
import http.client
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]

def request(port, path, data=None, token=None, origin=True, with_hash=False):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    headers = {}
    if origin:
        headers['Origin'] = f'http://127.0.0.1:{port}'
    if data is not None:
        headers['Content-Type'] = 'application/json'
    if token:
        headers['X-CSRF-Token'] = token
    try:
        conn.request('GET' if data is None else 'POST', path, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read(128 * 1024 + 1)
        assert len(raw) <= 128 * 1024
        if with_hash:
            return response.status, json.loads(raw), hashlib.sha256(raw).hexdigest()
        return response.status, json.loads(raw)
    finally:
        conn.close()

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait-stale', action='store_true')
    parser.add_argument('--report', type=Path, help='sanitized validation/hash report suitable for review artifacts')
    parser.add_argument('--private-report', type=Path, help='optional local-only sample proof; keep outside published source/artifacts')
    args = parser.parse_args()
    if args.private_report and (args.private_report.resolve() == ROOT or ROOT in args.private_report.resolve().parents):
        parser.error('--private-report must be outside the repository/publication tree')
    checks = []
    source_files = sorted(p for d in ('cmd/manager', 'cmd/dev-agent', 'cmd/agent', 'internal/telemetry', 'internal/api', 'internal/collector', 'internal/bundle', 'internal/model') for p in (ROOT / d).glob('*.go'))
    source_files += [ROOT / 'go.mod', ROOT / 'go.sum', Path(__file__).resolve()]
    source_hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    source_snapshot_hash = hashlib.sha256(json.dumps(source_hashes,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    def passed(name):
        checks.append(name)
        print('PASS ' + name, flush=True)
    with tempfile.TemporaryDirectory(prefix='tracebolt-transport-') as directory:
        work = Path(directory)
        for command in ('manager', 'dev-agent', 'agent'):
            subprocess.run([os.environ.get('GO_BIN', 'go'), 'build', '-buildvcs=false', '-o', str(work / command), './cmd/' + command], cwd=ROOT, check=True)
        assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name,digest in source_hashes.items()), 'source changed during build; retry against a stable snapshot'
        binary_hashes = {name: hashlib.sha256((work / name).read_bytes()).hexdigest() for name in ('manager', 'dev-agent', 'agent')}
        port = free_port()
        base = f'http://127.0.0.1:{port}'
        with (work / 'manager.log').open('wb') as log:
            manager = subprocess.Popen([str(work / 'manager'), '--managed-preview', '--port', str(port), '--db', str(work / 'state.db'), '--web', str(ROOT / 'web/dist')], cwd=ROOT, stdout=log, stderr=log)
            try:
                for _ in range(60):
                    if manager.poll() is not None:
                        raise RuntimeError('manager exited before ready')
                    try:
                        if request(port, '/api/health')[0] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(.05)
                else:
                    raise RuntimeError('manager did not start')
                status, initial = request(port, '/api/dev/telemetry/status')
                assert status == 200 and initial['state'] == 'awaiting' and initial['acceptedSamples'] == 0
                _, before = request(port, '/api/devices/sandbox-local')
                assert before['cpu']['value'] is None and before['lastSeen'].startswith('0001-')
                assert before['evidence'] == []
                passed('managed preview starts awaiting; no manager-generated observation')
                # Build an older authentic stdout bundle for live out-of-order checks.
                older = subprocess.check_output([str(work / 'agent'), '--support-bundle'], cwd=ROOT)
                sender = subprocess.Popen([str(work / 'dev-agent'), '--manager', base], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                assert sender.pid != manager.pid
                stdout, stderr = sender.communicate(timeout=12)
                assert sender.returncode == 0, stderr.decode()
                receipt = json.loads(stdout)
                assert receipt['sequence'] == 1 and receipt['deviceId'] == 'sandbox-local'
                _, observed, observation_raw_hash = request(port, '/api/devices/sandbox-local', with_hash=True)
                _, fresh = request(port, '/api/dev/telemetry/status')
                assert fresh['state'] == 'fresh' and fresh['acceptedSamples'] == 1
                assert observed['lastSeen'] == receipt['collectedAt'] and observed['status'] == 'unknown'
                assert observed['platform'] == 'linux' and not observed['synthetic'] and observed['ip'] is None
                assert any(e['id'] == 'local-agent-transport' for e in observed['evidence'])
                assert all(next(c for c in observed['capabilities'] if c['id'] == capability)['status'] == 'unsupported' for capability in ('systemd', 'journal', 'remote_actions'))
                _, devices = request(port, '/api/devices')
                assert len(devices['items']) == 8 and sum(d['synthetic'] for d in devices['items']) == 7
                passed('separate Linux dev-agent exits after delivering sample; API exposes collection time and seven separate demos')
                print(json.dumps({'acceptedSamples':1, 'metricQuality': {key: observed[key]['quality'] for key in ('cpu','memory','disk')}}), flush=True)
                _, session = request(port, '/api/session')
                token = session['csrfToken']
                def reject(name, raw, expected, supplied_token=token, use_origin=True):
                    code, body = request(port, '/api/dev/telemetry', raw, supplied_token, use_origin)
                    assert code == expected, (name, code, body)
                    _, current = request(port, '/api/dev/telemetry/status')
                    assert current['acceptedSamples'] == 1 and current['receivedAt'] == receipt['receivedAt']
                    passed(name)
                reject('live out-of-order observation rejected without refreshing receipt', older, 409)
                reject('missing same-origin guard rejected', older, 403, use_origin=False)
                reject('missing CSRF token rejected', older, 403, supplied_token=None)
                reject('malformed JSON rejected', b'{', 400)
                reject('oversize body rejected', b' ' * 65537, 413)
                bundle = json.loads(older)
                duplicate = older.replace(b'"product": "Tracebolt"', b'"product": "Tracebolt", "product": "Tracebolt"', 1)
                assert duplicate != older
                reject('duplicate JSON key rejected', duplicate, 400)
                bad = dict(bundle); bad['hostname'] = 'not-collected'
                reject('unknown identifier field rejected', json.dumps(bad).encode(), 400)
                bad = json.loads(older); bad['generatedAt'] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
                reject('future timestamp rejected', json.dumps(bad).encode(), 400)
                bad = json.loads(older); bad['generatedAt'] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
                reject('stale timestamp rejected', json.dumps(bad).encode(), 409)
                unsafe = subprocess.run([str(work / 'dev-agent'), '--manager', 'http://example.invalid:8787'], capture_output=True, timeout=2)
                assert unsafe.returncode == 2 and not unsafe.stdout
                passed('non-loopback sender destination rejected before collection or network')
                if args.wait_stale:
                    # Bound by the manager's declared expiry, not an arbitrary retry count.
                    received = datetime.datetime.fromisoformat(receipt['receivedAt'].replace('Z', '+00:00'))
                    deadline = received.timestamp() + fresh['maxAgeSeconds'] + 1
                    print('WAIT observing real timestamp expiry after sender exit', flush=True)
                    while time.time() < deadline:
                        time.sleep(min(5, max(0, deadline - time.time())))
                        _, current = request(port, '/api/dev/telemetry/status')
                        assert current['acceptedSamples'] == 1 and current['receivedAt'] == receipt['receivedAt']
                    _, current = request(port, '/api/dev/telemetry/status')
                    _, aged = request(port, '/api/devices/sandbox-local')
                    assert current['state'] == 'stale' and aged['lastSeen'] == observed['lastSeen']
                    assert all(aged[key]['quality'] != 'healthy' for key in ('cpu','memory','disk'))
                    assert aged['evidence'][-1]['quality'] == 'stale'
                    passed('real two-minute expiry: sender remains exited, sample stale, no periodic manager fallback')
                report = {'status':'PASS','createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'real separate Linux processes, one exec namespace, literal loopback development preview','checks':checks,'receiptSummary':{'deviceId':receipt['deviceId'],'sequence':receipt['sequence']},'sourceSnapshotSha256':source_snapshot_hash,'sourceFileSha256':source_hashes,'observationResponseSha256':observation_raw_hash,'binarySha256':binary_hashes,'observationCanonicalSha256':hashlib.sha256(json.dumps(observed,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'metricQuality':{key:observed[key]['quality'] for key in ('cpu','memory','disk')},'acceptedCountTransitions':[0,1],'freshnessTransitions':['awaiting','fresh']+(['stale'] if args.wait_stale else []),'realExpiryObserved':args.wait_stale,'limitations':['No persistent agent, enrolled identity, or production authentication.','No service/systemd, logs, remote actions, full-host attribution or target-Windows/macOS acceptance.','Replay state is memory-only and resets on manager restart.']}
            finally:
                if manager.poll() is None:
                    manager.send_signal(signal.SIGTERM)
                    try:
                        manager.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        manager.kill();manager.wait(timeout=3)
            # A stopped real manager is a hard failure, not a silently cached success.
            offline = subprocess.run([str(work / 'dev-agent'), '--manager', base, '--timeout', '500ms'],capture_output=True,timeout=3)
            assert offline.returncode == 1 and not offline.stdout
            passed('real stopped-manager delivery fails closed')
            report['sourceUnchangedDuringRun'] = all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name,digest in source_hashes.items())
            if args.private_report:
                args.private_report.parent.mkdir(parents=True,exist_ok=True)
                args.private_report.write_text(json.dumps({'report':report,'receipt':receipt,'observation':observed},indent=2)+'\n')
                args.private_report.chmod(0o600)
            if args.report:
                args.report.parent.mkdir(parents=True,exist_ok=True)
                args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS {len(checks)} transport checks; all child processes stopped', flush=True)

if __name__ == '__main__':
    main()
