#!/usr/bin/env python3
"""Transport-reader regressions; no server, credentials or mutations."""
import http.client
import unittest

from run_boundary import read_response_body


class Response:
    def __init__(self, status, pieces):
        self.status = status
        self.pieces = iter(pieces)

    def read1(self, _limit):
        piece = next(self.pieces, b"")
        if isinstance(piece, Exception):
            raise piece
        return piece

    def read(self):
        return self.read1(0)


class FramingTransportTests(unittest.TestCase):
    def test_explicit_denial_preserves_fragmented_body_before_reset(self):
        response = Response(400, [b"bad ", b"request", ConnectionResetError()])
        self.assertEqual(read_response_body(response, True), b"bad request")

    def test_incomplete_rejection_preserves_available_bytes(self):
        response = Response(403, [b"denied:", http.client.IncompleteRead(b"detail", 2)])
        self.assertEqual(read_response_body(response, True), b"denied:detail")

    def test_reset_is_not_a_successful_rejection_without_expected_status(self):
        for status in (200, 301, 404, 500):
            with self.subTest(status=status), self.assertRaises(ConnectionResetError):
                read_response_body(Response(status, [ConnectionResetError()]), True)

    def test_normal_requests_and_timeouts_remain_strict(self):
        with self.assertRaises(ConnectionResetError):
            read_response_body(Response(400, [ConnectionResetError()]))
        with self.assertRaises(TimeoutError):
            read_response_body(Response(400, [TimeoutError()]), True)

    def test_rejection_body_still_has_a_resource_bound(self):
        with self.assertRaises(AssertionError):
            read_response_body(Response(400, [b"x" * (64 * 1024 + 1)]), True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
