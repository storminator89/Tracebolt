#!/usr/bin/env python3
"""Independent local-only boundary checks. Use a disposable seeded database.

Run: python3 tests/security/run_boundary.py --base-url http://127.0.0.1:18787 --allow-mutations
The explicit mutation flag acknowledges that up to 100 diagnostic notes are retained.
This is a focused regression test, not a security certification.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import uuid
import http.client
import json
import sys
import unittest
from urllib.parse import quote, urlsplit

BASE_URL = ""


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url = urlsplit(BASE_URL)
        cls.authority = cls.url.netloc
        cls.origin = f"http://{cls.authority}"
        status, _, session = cls.request("GET", "/api/session")
        if status != 200:
            raise RuntimeError(f"session endpoint failed: {status}: {session!r}")
        cls.token = json.loads(session)["csrfToken"]
        status, _, data = cls.request("GET", "/api/cases")
        if status != 200:
            raise RuntimeError(f"cases endpoint failed: {status}")
        cases = json.loads(data)["items"]
        if not cases:
            raise RuntimeError("Use a disposable seeded database containing a case")
        cls.case_id = cases[0]["id"]
        cls.note_path = f"/api/cases/{quote(cls.case_id, safe='')}/notes"
        cls.status_path = f"/api/cases/{quote(cls.case_id, safe='')}/status"

    @classmethod
    def request(cls, method, path, body=None, headers=None, raw_headers=None):
        conn = http.client.HTTPConnection(cls.url.hostname, cls.url.port, timeout=4)
        try:
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            if raw_headers is not None:
                conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
                for key, value in raw_headers:
                    conn.putheader(key, value)
                conn.endheaders(body)
            else:
                conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict((k.lower(), v) for k, v in response.getheaders()), response.read()
        finally:
            conn.close()

    def write_headers(self, **updates):
        result = {"Origin": self.origin, "X-CSRF-Token": self.token, "Content-Type": "application/json"}
        result.update(updates)
        return result

    def case(self):
        status, _, data = self.request("GET", f"/api/cases/{quote(self.case_id, safe='')}")
        self.assertEqual(status, 200)
        return json.loads(data)

    def assert_denied(self, response, expected=(400, 403, 404, 405, 413, 415, 422)):
        status, headers, body = response
        self.assertIn(status, expected, (status, body[:300]))
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertNotIn(b"Traceback", body)
        self.assertNotIn(b"sqlite3.", body)

    def test_01_read_contract_and_capability_truth(self):
        for path in ("/api/overview", "/api/devices", "/api/cases", "/api/runbooks", "/api/capabilities"):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200, body[:300])
                self.assertIn("application/json", headers.get("content-type", ""))
                self.assertNotIn("access-control-allow-origin", headers)
                self.assertIn("no-store", headers.get("cache-control", ""))
                json.loads(body)
        _, _, body = self.request("GET", "/api/capabilities")
        capabilities = json.loads(body)
        for key in ("remoteEnrollment", "shellExecution", "aiConnected"):
            self.assertIs(capabilities[key], False)
        self.assertEqual(capabilities["mode"], "local-development")

    def test_02_host_guards_reads_and_writes(self):
        bad_hosts = ["evil.invalid", f"127.0.0.1.evil.invalid:{self.url.port}",
                     f"localhost.evil.invalid:{self.url.port}", f"127.0.0.1:{self.url.port + 1}",
                     f"evil.invalid@{self.authority}", f"{self.authority},evil.invalid"]
        for host in bad_hosts:
            for method, path in (("GET", "/api/session"), ("POST", self.note_path), ("GET", "/")):
                with self.subTest(host=host, method=method, path=path):
                    headers = self.write_headers(Host=host)
                    self.assert_denied(self.request(method, path, {"text": "must-not-persist"} if method == "POST" else None, headers), (400, 403, 421))
        # The manager intentionally supports these two loopback names only.
        status, _, body = self.request("GET", "/api/session", headers={"Host": f"localhost:{self.url.port}"})
        self.assertEqual(status, 200, body[:300])
        for hosts in ([], [("Host", self.authority), ("Host", "evil.invalid")],
                      [("Host", "evil.invalid"), ("Host", self.authority)]):
            with self.subTest(raw_hosts=hosts):
                self.assert_denied(self.request("GET", "/api/session", raw_headers=hosts), (400, 403, 421))

    def test_03_origin_and_token_guards(self):
        before = self.case()
        for origin in (None, "null", "https://evil.invalid", f"{self.origin}.evil.invalid", f"http://localhost:{self.url.port}", f"{self.origin}/", f"http://127.0.0.1:{self.url.port + 1}"):
            headers = self.write_headers()
            if origin is None:
                headers.pop("Origin")
            else:
                headers["Origin"] = origin
            for path, body in ((self.note_path, {"text": "must-not-persist"}), (self.status_path, {"status": "resolved"})):
                with self.subTest(origin=origin, path=path):
                    self.assert_denied(self.request("POST", path, body, headers), (400, 403))
        for token in (None, "", "invalid", self.token[:-1]):
            headers = self.write_headers()
            if token is None:
                headers.pop("X-CSRF-Token")
            else:
                headers["X-CSRF-Token"] = token
            with self.subTest(token=token):
                self.assert_denied(self.request("POST", self.note_path, {"text": "must-not-persist"}, headers), (400, 403))
        after = self.case()
        self.assertEqual(after["notes"], before["notes"])
        self.assertEqual(after["status"], before["status"])

    def test_04_no_cors_or_method_bypass(self):
        before = self.case()
        for method in ("OPTIONS", "PUT", "PATCH", "DELETE", "TRACE"):
            with self.subTest(method=method):
                response = self.request(method, self.note_path, {"text": "must-not-persist"}, self.write_headers(Origin="https://evil.invalid"))
                self.assert_denied(response, (400, 403, 404, 405, 501))
        for path in (self.note_path, self.status_path):
            self.assert_denied(self.request("GET", path), (404, 405))
        self.assertEqual(self.case()["notes"], before["notes"])
        self.assertEqual(self.case()["status"], before["status"])

    def test_05_strict_notes_validation_and_atomic_rejection(self):
        before = self.case()
        bad_bodies = [b"", b"{", b"null", b"[]", b'"text"', b"\xff", {"text": ""},
                      {"text": "   "}, {"text": None}, {"text": 1}, {"text": True},
                      {"text": ["a"]}, {"text": "a" * 2001}, {"text": "good", "extra": "bad"},
                      b'{"text":"first","text":"second"}', b'{"text":NaN}',
                      b'{"text":Infinity}', b'{"text":"\\ud800"}']
        for body in bad_bodies:
            with self.subTest(body=str(body)[:80]):
                self.assert_denied(self.request("POST", self.note_path, body, self.write_headers()), (400, 413, 422))
        self.assertEqual(self.case()["notes"], before["notes"])

    def test_06_byte_cap_and_content_type(self):
        before = self.case()
        for body in (b'{"text":"' + b"a" * 5000 + b'"}', '{"text":"' + "😀" * 1500 + '"}'):
            self.assert_denied(self.request("POST", self.note_path, body, self.write_headers()), (400, 413))
        for content_type in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""):
            with self.subTest(content_type=content_type):
                self.assert_denied(self.request("POST", self.note_path, {"text": "must-not-persist"}, self.write_headers(**{"Content-Type": content_type})), (400, 415))
        self.assertEqual(self.case()["notes"], before["notes"])

    def test_07_status_validation(self):
        before = self.case()
        for body in ({}, {"status": "deleted"}, {"status": None}, {"status": []},
                     {"status": "resolved", "role": "admin"}, {"status": True}):
            with self.subTest(body=body):
                self.assert_denied(self.request("POST", self.status_path, body, self.write_headers()), (400, 422))
        self.assertEqual(self.case()["status"], before["status"])

    def test_08_path_boundary(self):
        paths = ["/.env", "/.git/config", "/../.env", "/%2e%2e/.env", "/%2e%2e%2f.env",
                 "/web/../../.env", "/escape.txt", "/rmm.sqlite", "/data/rmm.sqlite", "/api/unknown",
                 "/api/cases/%27%20OR%201%3D1--", "/api/devices/%00", "/api/cases/..%2f..%2f.env"]
        for path in paths:
            with self.subTest(path=path):
                self.assert_denied(self.request("GET", path), (400, 403, 404))
        for path in ("/" + self.note_path, self.note_path + "/", self.note_path.replace("/api/", "/api//"), self.note_path.replace("/notes", "/%6eotes")):
            with self.subTest(mutation_path=path):
                # A path alias may be valid, but it must never bypass the write guard.
                self.assert_denied(self.request("POST", path, {"text": "must-not-persist"}, {"Content-Type": "application/json"}), (400, 403, 404, 405))

    def test_09_inert_string_roundtrip_and_sql_values(self):
        payloads = ["<img src=x onerror=alert('rmm-review')><script>alert(1)</script>", "Review: '); DROP TABLE cases; --"]
        for payload in payloads:
            with self.subTest(payload=payload):
                status, _, body = self.request("POST", self.note_path, {"text": payload}, self.write_headers())
                self.assertIn(status, (200, 201), body[:300])
                notes = self.case()["notes"]
                self.assertTrue(any(note["text"] == payload for note in notes))
        status, _, body = self.request("GET", "/api/cases")
        self.assertEqual(status, 200, body[:300])
        self.assertTrue(json.loads(body)["items"])

    def test_10_valid_status_write(self):
        before = self.case()["status"]
        target = "investigating" if before != "investigating" else "open"
        try:
            status, _, body = self.request("POST", self.status_path, {"status": target}, self.write_headers())
            self.assertEqual(status, 200, body[:300])
            self.assertEqual(self.case()["status"], target)
        finally:
            self.request("POST", self.status_path, {"status": before}, self.write_headers())

    def test_11_ambiguous_framing_and_duplicate_guard_headers(self):
        before = self.case()["notes"]
        body = b'{"text":"must-not-persist"}'
        standard = [("Host", self.authority), ("Content-Type", "application/json"),
                    ("Origin", self.origin), ("X-CSRF-Token", self.token)]
        header_sets = [
            standard + [("Origin", "https://evil.invalid"), ("Content-Length", str(len(body)))],
            standard + [("X-CSRF-Token", "invalid"), ("Content-Length", str(len(body)))],
            standard + [("Content-Length", str(len(body))), ("Content-Length", "1")],
            standard + [("Transfer-Encoding", "chunked")],
        ]
        for headers in header_sets:
            with self.subTest(headers=[k for k, _ in headers]):
                encoded = (f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n") if any(k == "Transfer-Encoding" for k, _ in headers) else body
                self.assert_denied(self.request("POST", self.note_path, encoded, raw_headers=headers), (400, 403, 411, 413, 501))
        self.assertEqual(self.case()["notes"], before)

    def test_12_concurrent_writes_are_not_lost(self):
        before = len(self.case()["notes"])
        prefix = "concurrency-check-" + uuid.uuid4().hex + "-"
        payloads = [prefix + str(i) for i in range(8)]
        def save(text):
            return self.request("POST", self.note_path, {"text": text}, self.write_headers())
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(executor.map(save, payloads))
        for status, _, body in responses:
            self.assertEqual(status, 200, body[:300])
        notes = self.case()["notes"]
        self.assertEqual(len(notes), before + len(payloads))
        self.assertEqual(sorted(note["text"] for note in notes if note["text"].startswith(prefix)), sorted(payloads))
        self.assertEqual(len({note["id"] for note in notes}), len(notes))

    def test_13_case_note_limit_is_enforced(self):
        notes = self.case()["notes"]
        for index in range(len(notes), 100):
            status, _, body = self.request("POST", self.note_path, {"text": f"bounded-storage-check-{index}"}, self.write_headers())
            self.assertEqual(status, 200, body[:300])
        before = self.case()
        self.assertEqual(len(before["notes"]), 100)
        self.assert_denied(self.request("POST", self.note_path, {"text": "one-too-many"}, self.write_headers()), (409,))
        after = self.case()
        self.assertEqual(after["notes"], before["notes"])
        self.assertEqual(after["timeline"], before["timeline"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--allow-mutations", action="store_true")
    args = parser.parse_args()
    parsed = urlsplit(args.base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username:
        parser.error("Only an explicit http://127.0.0.1:PORT disposable local service is supported")
    if not args.allow_mutations:
        parser.error("Use a disposable seeded database and explicitly pass --allow-mutations")
    BASE_URL = args.base_url.rstrip("/")
    unittest.main(argv=[sys.argv[0]], verbosity=2)
