"""Inert complete-overview marker checks; no collection or privilege changes."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

import check_endpoint_identity_gate as gate
from test_endpoint_identity_gate import marker, valid_events as endpoint_events


def overview_payloads():
    fixed = {value: key for key, value in gate.OVERVIEW_FIXED.items()}
    return [fixed.get(stage) or (
        "complete overview observation: stage=first processes=complete countExact=true processRows=205"
        " volumes=complete countExact=true volumeRows=101 processPages=3 volumePages=2 manifest=validated"
    ) for stage in gate.OVERVIEW_ORDER]


def valid_events():
    result = []
    for event in endpoint_events():
        if event.get("Action") == "pass" and event.get("Test") in gate.LEAVES:
            result.extend(marker(payload, event["Test"]) for payload in overview_payloads())
        result.append(event)
    return result


class OverviewCompletionTests(unittest.TestCase):
    def test_complete_contract_and_legacy_default(self):
        self.assertIsNone(gate.validate(valid_events(), require_overview=True))
        self.assertIsNone(gate.validate(endpoint_events()))
        with self.assertRaises(ValueError):
            gate.validate(endpoint_events(), require_overview=True)

    def test_every_required_event_is_required(self):
        events = valid_events()
        for index in range(len(events)):
            with self.subTest(index=index), self.assertRaises(ValueError):
                gate.validate(events[:index] + events[index + 1:], require_overview=True)

    def test_duplicates_and_each_domain_reordering_reject(self):
        events = valid_events()
        for index in range(len(events)):
            with self.subTest(index=index), self.assertRaises(ValueError):
                gate.validate(events[:index] + [events[index]] + events[index:], require_overview=True)
        for one, two in ((0, 1), (6, 7), (8, 9), (10, 11)):
            changed = copy.deepcopy(events)
            changed[one], changed[two] = changed[two], changed[one]
            with self.assertRaises(ValueError):
                gate.validate(changed, require_overview=True)

    def test_exact_positive_counts_and_page_bounds(self):
        for old, new in (
            ("processRows=205", "processRows=0"), ("processRows=205", "processRows=32769"),
            ("volumeRows=101", "volumeRows=0"), ("volumeRows=101", "volumeRows=16385"),
            ("processRows=205", "processRows=0205"), ("volumeRows=101", "volumeRows=-1"),
            ("processPages=3", "processPages=0"), ("processPages=3", "processPages=2"),
            ("processPages=3", "processPages=206"), ("volumePages=2", "volumePages=1"),
            ("volumePages=2", "volumePages=102"), ("volumePages=2", "volumePages=02"),
            ("processes=complete", "processes=failed"), ("volumes=complete", "volumes=failed"),
            ("countExact=true", "countExact=false"), ("manifest=validated", "manifest=unknown"),
        ):
            events = valid_events()
            events[8]["Output"] = events[8]["Output"].replace(old, new)
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                gate.validate(events, require_overview=True)
        for processes, volumes, pp, vp in ((1, 1, 1, 1), (32768, 16384, 328, 164), (205, 101, 205, 101)):
            events = valid_events()
            events[8]["Output"] = marker(
                f"complete overview observation: stage=first processes=complete countExact=true processRows={processes}"
                f" volumes=complete countExact=true volumeRows={volumes} processPages={pp} volumePages={vp} manifest=validated",
                gate.ROOT + "/tls",
            )["Output"]
            self.assertIsNone(gate.validate(events, require_overview=True))

    def test_fixed_consent_retention_and_input_projection(self):
        for index in (6, 7, 9, 10, 11):
            for suffix in (" private-fixture", "\nprivate-fixture"):
                events = valid_events()
                events[index]["Output"] = events[index]["Output"].rstrip("\n") + suffix + "\n"
                with self.assertRaises(ValueError): gate.validate(events, require_overview=True)
        for old, new in (("enabled=false", "enabled=true"), ("existingState=unchanged", "existingState=changed"),
                         ("capture=original_age", "capture=refreshed"), ("ordinary=advanced", "ordinary=unchanged"),
                         ("rows=unchanged", "rows=changed"), ("generations=unchanged", "generations=changed")):
            events = valid_events()
            for event in events:
                if "complete overview " in event.get("Output", ""):
                    event["Output"] = event["Output"].replace(old, new)
            with self.subTest(old=old), self.assertRaises(ValueError): gate.validate(events, require_overview=True)

    def test_profile_source_and_completion_boundaries(self):
        for field, value in (("Package", "other"), ("Test", gate.ROOT), ("Test", gate.ROOT + "/tls/extra"),
                             ("Action", "pass"), ("Action", "skip"), ("Action", "fail")):
            events = valid_events(); events[6][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): gate.validate(events, require_overview=True)
        for filename in ("private.go", "complete_mvp_overview_test.go"):
            events = valid_events(); events[6]["Output"] = events[6]["Output"].replace("complete_mvp_process_test.go", filename)
            with self.assertRaises(ValueError): gate.validate(events, require_overview=True)
        events = valid_events()
        with self.assertRaises(ValueError): gate.validate(events + [events[6]], require_overview=True)
        with self.assertRaises(ValueError): gate.validate(events + [{"Action": "build-fail"}], require_overview=True)

    def test_cli_fixed_messages_and_exact_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "input.jsonl"
            p.write_text("".join(json.dumps(value) + "\n" for value in valid_events()))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = gate.main(["gate", "--require-complete-overview", str(p)])
            self.assertEqual(code, 0)
            for private in ("processRows", "volumeRows", "205", "101", temp):
                self.assertNotIn(private, out.getvalue())
            p.write_text("private-fixture\n"); out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = gate.main(["gate", "--require-complete-overview", str(p)])
            self.assertEqual(code, 1)
            self.assertEqual(out.getvalue(), "FAIL: missing, skipped, malformed or incomplete endpoint/complete-overview native evidence.\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out): code = gate.main(["gate", "--unknown", str(p)])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
