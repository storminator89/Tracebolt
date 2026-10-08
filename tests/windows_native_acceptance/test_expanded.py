"""Inert expanded admission/evidence fixtures; no process or host operation."""
import copy
import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_acceptance as gate
from test_runner import approved, pass_report, SOURCE, encode


def observation():
    counts = {"observed": 1, "denied": 1, "unavailable": 0, "firstSample": 0, "reset": 0}
    return dict(freshOrchestrationAcceptance=False, frames=1, v5Frames=1, eventApplication="observed", eventSystem="partial", volumes="observed", volumeCapacity="partial", processCPU="partial", processMemory="partial", network="partial", eventRows=0, volumeRows=2, processRows=2, networkRows=1, peerLoopbackRows=1, processCPUFirstSampleRows=0, volumeCapacityCounts=dict(counts), processCPUCounts=dict(counts), processMemoryCounts=dict(counts))


def expanded_report():
    r = pass_report()
    r.update(schema=gate.EXPANDED_SCHEMA, extensions=observation(), nativeInventorySenderExercised=True)
    r["selection"]["collectionProfile"] = "windows-inventory-v1"
    r["inventory"] = dict(frames=2, **{k: "healthy" for k in gate.QUALITIES})
    return r


class ExpandedTests(unittest.TestCase):
    def test_old_approvals_never_grant_extensions(self):
        self.assertFalse(gate.extension_approval(approved()))
        for bits in itertools.product(("true", "false"), repeat=4):
            for profile in ("basic-readonly-v1", "windows-inventory-v1"):
                env = dict(approved(), TRACEBOLT_COLLECTION_PROFILE=profile, **dict(zip(gate.EXTENSION_APPROVALS, bits)))
                allowed = all(b == "false" for b in bits) or all(b == "true" for b in bits) and profile == "windows-inventory-v1"
                if allowed:
                    self.assertEqual(gate.extension_approval(env), bits[0] == "true")
                else:
                    with mock.patch.object(gate.subprocess, "Popen") as process:
                        with self.assertRaises(gate.Rejected): gate.extension_approval(env)
                        process.assert_not_called()
        for value in (True, 1, None, "TRUE", " true", "true\n", [], {}):
            env = dict(approved(), TRACEBOLT_APPROVE_EVENT_HEADERS=value)
            with self.assertRaises(gate.Rejected): gate.extension_approval(env)

    def test_finite_partial_proof_keeps_denials(self):
        r = expanded_report()
        self.assertEqual(gate.validate_report(encode(r), SOURCE, expanded=True), r)
        self.assertEqual(gate.validate_report(gate.sanitized_bytes(r, SOURCE), SOURCE), r)
        with self.assertRaises(gate.Rejected): gate.validate_report(encode(r), SOURCE, expanded=False)
        with self.assertRaises(gate.Rejected): gate.validate_report(encode(pass_report()), SOURCE, expanded=True)

    def test_scope_schema_counts_raw_data_and_first_sample_rejected(self):
        r = expanded_report()
        mutations = [lambda r: r["extensions"].update(freshOrchestrationAcceptance=True),lambda r: r.update(schema=gate.SCHEMA), lambda r: r.pop("extensions"), lambda r: r["extensions"].update(raw="secret"), lambda r: r["extensions"].update(frames=True), lambda r: r["extensions"].update(v5Frames=0), lambda r: r["extensions"].update(networkRows=65), lambda r: r["extensions"].update(peerLoopbackRows=0), lambda r: r["extensions"].update(peerLoopbackRows=2), lambda r: r["extensions"].update(processCPU="observed"), lambda r: r["extensions"]["processCPUCounts"].update(observed=0), lambda r: r.update(productionManagerExercised=True)]
        for mutate in mutations:
            v=copy.deepcopy(r); mutate(v)
            with self.assertRaises(gate.Rejected): gate.validate_report(encode(v), SOURCE)
        for key in r["extensions"]:
            v=copy.deepcopy(r); del v["extensions"][key]
            with self.assertRaises(gate.Rejected): gate.validate_report(encode(v), SOURCE)
        v=copy.deepcopy(r)
        v["extensions"]["processCPUCounts"] = dict(observed=0, denied=0, unavailable=0, firstSample=2, reset=0)
        v["extensions"].update(processCPU="first-sample", processCPUFirstSampleRows=2)
        with self.assertRaises(gate.Rejected): gate.validate_report(encode(v), SOURCE)
        v["status"]="failed"
        gate.validate_report(encode(v), SOURCE)

    def test_extended_workflow_scopes_are_explicit(self):
        workflow=(gate.ROOT / ".github/workflows/windows-native-acceptance.yml").read_text()
        for name in gate.EXTENSION_APPROVALS: self.assertIn(name + ":", workflow)
        for disclosure in ("Security log", "volume GUIDs", "CPU deltas", "TCP/UDP", "all four extension approvals", "plaintext", "owned cleanup"):
            self.assertIn(disclosure, workflow)
