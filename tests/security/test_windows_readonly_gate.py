import importlib.util
import copy
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("windows_gate", Path(__file__).with_name("run_windows_readonly.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class NativeGateTests(unittest.TestCase):
    def test_requires_both_native_cases_without_skips(self):
        events = [{"Package": p, "Test": t, "Action": "pass"} for p, t in gate.REQUIRED]
        data = b"\n".join(json.dumps(e).encode() for e in events)
        gate.check_test_events(data)
        with self.assertRaises(gate.GateFailure):
            gate.check_test_events(json.dumps(events[0]).encode())
        events.append(dict(events[0], Action="skip"))
        with self.assertRaises(gate.GateFailure):
            gate.check_test_events(b"\n".join(json.dumps(e).encode() for e in events))

    def test_document_consent_and_completeness(self):
        section = {"quality": "healthy", "complete": True, "truncated": False, "rows": []}
        inventory = dict(schema="tracebolt.windows-readonly.v1", platform="windows", nativeVerification="installed-service-and-enrollment-unverified")
        inventory.update({k: dict(section) for k in ("hostname", "processes", "services", "software", "network")})
        inventory.update({k: {"quality": "healthy", "value": 25} for k in ("cpu", "memory", "disk")})
        value = {"inventory": inventory}
        gate.check_document(json.dumps(value).encode(), False)
        with self.assertRaises(gate.GateFailure):
            gate.check_document(json.dumps(value).encode(), True)
        inventory["software"]["truncated"] = True
        with self.assertRaises(gate.GateFailure):
            gate.check_document(json.dumps(value).encode(), False)

    def event_fixture(self):
        source = "windows-event-log-system-metadata"
        event = dict(record_id=1, event_id=23, level=4, provider="Synthetic fixture", timestamp="2026-10-07T00:00:00Z", channel="System")
        return dict(source=source, quality="observed", collected_at="2026-10-07T00:00:00Z", limit_per_channel=25, complete=True, truncated=False,
                    channels=[dict(source=source, channel="Application", quality="observed", complete=True, truncated=False, events=[]),
                              dict(source=source, channel="System", quality="observed", complete=True, truncated=False, events=[event])])

    def test_event_metadata_value_bounds_and_scope(self):
        valid = self.event_fixture()
        gate.check_events(valid)
        for invalid in (None, {}, [], dict(valid, channels=[]), dict(valid, limit_per_channel=100), dict(valid, complete=False)):
            with self.assertRaises(gate.GateFailure):
                gate.check_events(invalid)
        mutations = (
            lambda value: value["channels"][1].update(events=[]),
            lambda value: value["channels"][1].update(events=value["channels"][1]["events"] * 26),
            lambda value: value["channels"][1]["events"][0].update(message="unapproved content"),
            lambda value: value["channels"][1]["events"][0].update(channel="Security"),
            lambda value: value["channels"][1]["events"][0].update(record_id=True),
            lambda value: value["channels"][1]["events"][0].update(provider="bad\nprovider"),
            lambda value: value["channels"][1]["events"][0].update(timestamp="invalid"),
        )
        for mutate in mutations:
            value = copy.deepcopy(valid)
            mutate(value)
            with self.assertRaises(gate.GateFailure):
                gate.check_events(value)

    def test_rejects_malformed_and_oversized(self):
        with self.assertRaises(gate.GateFailure):
            gate.check_test_events(b"[]")
        for data in (b"not json", b"[]", b"{}", b" " * (gate.MAX_BYTES + 1)):
            with self.assertRaises(gate.GateFailure):
                gate.check_document(data, False)


if __name__ == "__main__":
    unittest.main()
