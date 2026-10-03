#!/usr/bin/env python3
"""Fake-provider-only AI API regressions; use an owned disposable manager.
No real credentials or external model services are used.
"""
import argparse
import concurrent.futures
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import unittest
from urllib.parse import urlsplit

import run_boundary as boundary

BASE_URL = ""
FAKE_KEY = "test-only-not-a-real-key-api-boundary-sentinel"


class FakeProvider:
    def __init__(self, *, fail=False, delay=False):
        self.requests = []
        self.started = threading.Event()
        self.release = threading.Event()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                owner.requests.append((self.path, self.headers.get('Authorization'), body))
                owner.started.set()
                if delay:
                    owner.release.wait(5)
                self.send_response(500 if fail else 200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                payload = {'error': FAKE_KEY} if fail else {'choices': [{'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': json.dumps({'observedEvidenceIDs': [], 'hypotheses': [], 'counterevidence': [], 'missingData': ['Synthetic test fixture; no real inference performed.'], 'nextCheck': 'none'})}}]}
                try:
                    self.wfile.write(json.dumps(payload).encode())
                except (BrokenPipeError, ConnectionResetError):
                    pass
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class AIBoundaryTests(unittest.TestCase):
    request = classmethod(boundary.BoundaryTests.request.__func__)
    @classmethod
    def setUpClass(cls):
        cls.url = urlsplit(BASE_URL)
        cls.authority = cls.url.netloc
        cls.origin = 'http://' + cls.authority
        status, _, body = cls.request('GET', '/api/session')
        if status != 200:
            raise RuntimeError('Manager session unavailable')
        cls.token = json.loads(body)['csrfToken']
        status, _, body = cls.request('GET', '/api/cases')
        if status != 200:
            raise RuntimeError('Seeded case unavailable')
        cls.case_id = json.loads(body)['items'][0]['id']
        cls.analyze_path = '/api/cases/' + cls.case_id + '/analyze'
    def headers(self):
        return {'Origin': self.origin, 'X-CSRF-Token': self.token, 'Content-Type': 'application/json'}
    def config(self):
        status, _, body = self.request('GET', '/api/ai/config')
        self.assertEqual(status, 200, body[:250])
        self.assertNotIn(FAKE_KEY.encode(), body)
        return json.loads(body)
    def save(self, provider):
        body = {'expectedRevision': self.config()['revision'], 'baseURL': provider.origin + '/v1', 'model': 'synthetic-test-model', 'apiKey': FAKE_KEY, 'approvedOrigin': provider.origin, 'allowRemoteEvidence': False, 'useLegacyMaxTokens': False}
        status, _, response = self.request('POST', '/api/ai/config', body, self.headers())
        self.assertEqual(status, 200, response[:250])
        self.assertNotIn(FAKE_KEY.encode(), response)
        result = json.loads(response)
        self.assertTrue(result['configured'])
        self.assertTrue(result['keyConfigured'])
        self.assertEqual(result['storage'], 'memory-only')
        return result
    def clear(self):
        revision = self.config()['revision']
        status, _, body = self.request('POST', '/api/ai/config/clear', {'expectedRevision': revision}, self.headers())
        self.assertEqual(status, 200, body[:250])
        result = json.loads(body)
        self.assertFalse(result['configured'])
        self.assertFalse(result['keyConfigured'])
        return result
    def test_01_unconfigured_is_honest(self):
        cfg = self.config()
        self.assertFalse(cfg['configured'], 'Use a fresh disposable manager')
        status, _, body = self.request('POST', self.analyze_path, {'configRevision': cfg['revision']}, self.headers())
        self.assertEqual(status, 200, body[:250])
        result = json.loads(body)
        self.assertEqual(result['ai']['status'], 'not_configured')
        self.assertFalse(result['rootCauseConfirmed'])
        self.assertIsNone(result['ai']['findings'])
    def test_02_all_mutations_require_guards(self):
        before = self.config()['revision']
        for path in ('/api/ai/config', '/api/ai/config/clear', self.analyze_path):
            for headers in ({'Content-Type': 'application/json'}, {**self.headers(), 'Origin': 'https://evil.invalid'}, {**self.headers(), 'X-CSRF-Token': 'invalid'}):
                with self.subTest(path=path, headers=list(headers)):
                    status, _, body = self.request('POST', path, {}, headers)
                    self.assertIn(status, (400, 403), body[:250])
        self.assertEqual(self.config()['revision'], before)
    def test_03_config_rejection_is_atomic(self):
        before = self.config()['revision']
        for body in (b'{', b'[]', b'{"expectedRevision":"first","expectedRevision":"second"}', {'expectedRevision': before, 'apiKey': FAKE_KEY}, b' ' * 8200):
            status, _, response = self.request('POST', '/api/ai/config', body, self.headers())
            self.assertIn(status, (400, 413), response[:250])
            self.assertNotIn(FAKE_KEY.encode(), response)
        for base in ('https://169.254.169.254/v1', 'https://168.63.129.16/v1', 'http://192.168.1.1/v1'):
            body = {'expectedRevision': before, 'baseURL': base, 'model': 'test', 'apiKey': FAKE_KEY, 'approvedOrigin': base[:-3], 'allowRemoteEvidence': True, 'useLegacyMaxTokens': False}
            status, _, response = self.request('POST', '/api/ai/config', body, self.headers())
            self.assertEqual(status, 400, response[:250])
            self.assertNotIn(FAKE_KEY.encode(), response)
        self.assertEqual(self.config()['revision'], before)
    def test_04_explicit_fake_analysis_and_no_save_time_call(self):
        provider = FakeProvider()
        try:
            cfg = self.save(provider)
            self.assertEqual(provider.requests, [])
            self.config()
            self.assertEqual(provider.requests, [])
            status, _, body = self.request('POST', self.analyze_path, {'configRevision': cfg['revision']}, self.headers())
            self.assertEqual(status, 200, body[:250])
            self.assertNotIn(FAKE_KEY.encode(), body)
            result = json.loads(body)
            self.assertEqual(result['ai']['status'], 'completed')
            self.assertFalse(result['rootCauseConfirmed'])
            self.assertFalse(result['superseded'])
            self.assertEqual(len(provider.requests), 1)
            path, authorization, raw = provider.requests[0]
            self.assertEqual(path, '/v1/chat/completions')
            self.assertEqual(authorization, 'Bearer ' + FAKE_KEY)
            self.assertNotIn(FAKE_KEY.encode(), raw)
            packet = json.loads(json.loads(raw)['messages'][1]['content'])
            self.assertNotIn('notes', packet['case'])
            self.assertNotIn('deviceName', packet['case'])
            self.assertNotIn('deviceId', packet['case'])
            self.assertNotIn('timeline', packet['case'])
            new_config = self.clear()
            status, _, _ = self.request('POST', self.analyze_path, {'configRevision': cfg['revision']}, self.headers())
            self.assertEqual(status, 409)
            self.assertNotEqual(new_config['revision'], cfg['revision'])
            self.assertEqual(len(provider.requests), 1)
        finally:
            self.clear()
            provider.close()
    def test_05_upstream_errors_do_not_echo_secrets(self):
        provider = FakeProvider(fail=True)
        try:
            cfg = self.save(provider)
            status, _, body = self.request('POST', self.analyze_path, {'configRevision': cfg['revision']}, self.headers())
            self.assertEqual(status, 200, body[:250])
            self.assertNotIn(FAKE_KEY.encode(), body)
            result = json.loads(body)
            self.assertEqual(result['ai']['status'], 'unavailable')
            self.assertIsNone(result['ai']['findings'])
            self.assertEqual(len(provider.requests), 1)
        finally:
            self.clear()
            provider.close()
    def test_06_clear_cancels_inflight_and_prevents_stale_result(self):
        provider = FakeProvider(delay=True)
        try:
            cfg = self.save(provider)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(self.request, 'POST', self.analyze_path, {'configRevision': cfg['revision']}, self.headers())
                self.assertTrue(provider.started.wait(2), 'Fake provider did not receive request')
                status, _, _ = self.request('POST', self.analyze_path, {'configRevision': cfg['revision']}, self.headers())
                self.assertEqual(status, 409)
                self.clear()
                status, _, body = pending.result(timeout=3)
                self.assertEqual(status, 200, body[:250])
                result = json.loads(body)
                self.assertTrue(result['superseded'])
                self.assertEqual(result['ai']['status'], 'canceled')
                self.assertIsNone(result['ai']['findings'])
            self.assertEqual(len(provider.requests), 1)
        finally:
            provider.release.set()
            self.clear()
            provider.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--allow-mutations', action='store_true')
    args = parser.parse_args()
    url = urlsplit(args.base_url)
    if url.scheme != 'http' or url.hostname != '127.0.0.1' or not url.port or url.path not in ('', '/') or url.username or url.query or url.fragment:
        parser.error('Only explicit http://127.0.0.1:PORT is allowed')
    if not args.allow_mutations:
        parser.error('Use a disposable manager and explicitly pass --allow-mutations')
    BASE_URL = args.base_url.rstrip('/')
    unittest.main(argv=['run_ai_boundary.py'], verbosity=2)
