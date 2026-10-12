"""Current-profile synthetic fixtures only: no native execution or network writes.

Reuse the existing finite API/ZIP fixture. Synthetic pin and PE inspection are
injected only in tests; production current accepted tree remains UNSET.
"""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = load("_current_publisher_test", ROOT / "deploy/release/publish-windows-current-prerelease.py")
p = adapter.publisher
gate = adapter.gate
# A separate module instance keeps historical fixture/test globals unchanged.
f = load("_current_publisher_api_fixture", Path(__file__).with_name("test_publish_windows_prerelease.py"))
f.publisher, f.gate = p, gate
current = load("_current_report_fixture", ROOT / "tests/windows_native_acceptance/test_current_setup_gui.py")
TREE = "f" * 40


def current_api(*, cloned_machine=False):
    files, _ = f.fixtures.public_fixture()
    reports = {}
    for index, case in enumerate(gate.CHECKS):
        report = current.report(case, "8" if cloned_machine else hex(8 + index)[2:])
        report.update(setupSHA256=p.digest(files[gate.SETUP_NAME]), serviceSHA256=p.digest(files[gate.SERVICE_NAME]),
                      sourceInputsSHA256=p.digest(files["source-inputs.json"]))
        reports[case] = p.canonical(report)
    return f.FakeAPI(files=files, reports=reports)


class CurrentPublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        for name in p.GUIDES:
            (self.root / "docs" / name).write_text("Inert current fixture guide.\n")
        self.request = f.request_fixture()
        pin = mock.patch.object(p, "ACCEPTED_SOURCE_TREE", TREE)
        pin.start()
        self.addCleanup(pin.stop)
        self.api = current_api()

    def prepare(self, api=None, frozen=None):
        with mock.patch.object(gate.resources, "verify_pe", side_effect=f.fixtures.fake_pe):
            return p.prepare(api or self.api, self.request, frozen=frozen, root=self.root)

    def reject(self, call, *args, **kwargs):
        with self.assertRaises((p.Rejected, gate.shared.Rejected, gate.provenance.Rejected)):
            call(*args, **kwargs)

    def test_unset_pin_rejects_prepare_plan_publish_before_api_or_writes(self):
        self.assertIsNone(adapter.ACCEPTED_SOURCE_TREE)
        plan, files = self.prepare()
        for call, args in ((p.prepare, (self.api, self.request)),
                           (p.validate_plan, (plan, self.request)),
                           (p.publish, (self.api, self.request, plan, files))):
            self.api.calls.clear()
            with mock.patch.object(p, "ACCEPTED_SOURCE_TREE", None):
                self.reject(call, *args)
            self.assertEqual(self.api.calls, [])
        with mock.patch.object(p, "ACCEPTED_SOURCE_TREE", None), mock.patch.object(p, "verify_checkout") as checkout, mock.patch.object(p, "GitHubAPI") as api:
            self.reject(p.main, ["--verify"], dict(f.environment(), TRACEBOLT_ACCEPTED_SOURCE_TREE=TREE))
            self.reject(p.main, ["--publish"], f.environment(True))
            checkout.assert_not_called()
            api.assert_not_called()

    def test_current_prepare_freezes_three_cases_four_jobs_six_original_artifacts(self):
        plan, files = self.prepare()
        self.assertEqual(plan["schema"], "tracebolt.windows-current-prerelease-plan.v1")
        self.assertEqual((len(plan["native"]["jobs"]), len(plan["native"]["runners"]), len(plan["artifacts"])), (4, 3, 6))
        self.assertEqual(len(files), 10)
        self.assertEqual(p.BOUNDS[gate.REPORT_NAME], 32 << 10)
        self.assertEqual({name: files[name] for name in gate.PUBLIC_FILES}, self.api.files)
        evidence = json.loads(files[gate.AGGREGATE_REPORT])
        self.assertEqual(evidence["schema"], "tracebolt.windows-current-setup-native-subset.v1")
        self.assertEqual(evidence["status"], "three_case_current_packaged_gui_subset")
        self.assertEqual(evidence["distributionStatus"], "unsigned-current-source-candidate-native-subset")
        self.assertTrue(all(v is False for v in evidence["coverage"].values()))
        manifest = json.loads(files[p.RELEASE_MANIFEST])
        self.assertEqual(manifest["schema"], "tracebolt.windows-current-prerelease.v1")
        self.assertEqual(manifest["sourceTree"], TREE)
        self.assertEqual(manifest["executionProvenance"], evidence["executionProvenance"])
        self.assertEqual(self.prepare(frozen=plan), (plan, files))
        self.assertEqual(self.api.mutations, [])

    def test_cloned_machine_metadata_requires_distinct_authenticated_execution(self):
        api = current_api(cloned_machine=True)
        plan, files = self.prepare(api)
        evidence = json.loads(files[gate.AGGREGATE_REPORT])
        reports = evidence["reports"]
        self.assertEqual(len({r["machineIDSHA256"] for r in reports.values()}), 1)
        self.assertEqual(len({r["machine"] for r in reports.values()}), 1)
        proof = evidence["executionProvenance"]
        self.assertFalse(proof["vmIdentityAttested"])
        self.assertEqual(len({row["jobID"] for row in proof["cases"].values()}), 3)
        self.assertEqual(len({row["runnerID"] for row in proof["cases"].values()}), 3)
        self.assertEqual(gate._validated_reports(api.reports, f.SOURCE, "123", proof, api.files), reports)
        for missing in (None, {}):
            self.reject(gate._validated_reports, api.reports, f.SOURCE, "123", missing, api.files)
        for field in ("jobID", "runnerID"):
            bad = copy.deepcopy(proof)
            bad["cases"]["pending-transport"][field] = bad["cases"]["install-uninstall"][field]
            self.reject(gate.aggregate_reports, api.reports, f.SOURCE, "123", bad, api.files)
        bad = copy.deepcopy(proof)
        bad["source"] = "b" * 40
        self.reject(gate.aggregate_reports, api.reports, f.SOURCE, "123", bad, api.files)
        for stage in ("fresh-service", "fresh-program-files", "fresh-program-data", "hidden-input", *gate.HIDDEN_INPUT_FAILURE_STAGES):
            changed = dict(api.reports)
            value = json.loads(changed["pending-transport"])
            value.update(status="failed", stage=stage, reason="operation_failed", startup="inspection_required",
                         checks=dict.fromkeys(gate.CHECKS["pending-transport"], False))
            changed["pending-transport"] = gate.canonical(value)
            self.reject(gate.aggregate_reports, changed, f.SOURCE, "123", proof, api.files)
        self.assertEqual(api.mutations, [])
        for field in ("id", "runner_id"):
            changed = current_api(cloned_machine=True)
            changed.jobs[1][field] = changed.jobs[0][field]
            self.reject(self.prepare, changed)
            self.assertEqual(changed.mutations, [])

    def test_current_publish_reverifies_originals_before_writes_patch_and_readback(self):
        plan, files = self.prepare()
        with mock.patch.object(gate.resources, "verify_pe", side_effect=f.fixtures.fake_pe):
            p.publish(self.api, self.request, plan, files)
        self.assertFalse(self.api.release["draft"])
        self.assertEqual(len(self.api.mutations), 13)
        self.assertEqual(set(self.api.uploads), p.ASSETS)
        self.assertEqual({name for _, name, _ in self.api.public_reads}, p.ASSETS)
        route = gate.provenance.API_ROOT + "/actions/workflows/windows-current-setup-acceptance.yml"
        self.assertGreaterEqual(sum(url == route for url, _, _ in self.api.provenance_calls), 4)
        self.assertNotIn("http-test", self.api.release["body"])

    def test_wrong_source_tree_workflow_attempt_owner_or_runner_fails(self):
        changes = (lambda a: a.routes[f.P + "/git/commits/" + f.SOURCE]["tree"].update(sha="e" * 40),
                   lambda a: a.run.update(path=".github/workflows/windows-setup-acceptance.yml"),
                   lambda a: a.attempt.update(run_attempt=2),
                   lambda a: a.run["actor"].update(id=42),
                   lambda a: a.jobs[1].update(runner_id=a.jobs[0]["runner_id"]),
                   lambda a: a.jobs[0]["steps"][0].update(conclusion="skipped"))
        for change in changes:
            api = current_api()
            change(api)
            self.reject(self.prepare, api)
            self.assertEqual(api.mutations, [])

    def test_all_original_reports_and_input_package_are_mandatory_even_with_aggregate(self):
        for missing in (False, True):
            for name in p.artifact_names(f.SOURCE):
                if "gui-" not in name and "public-input-" not in name:
                    continue
                api = current_api()
                entry = next(item for item in api.artifact_listing["artifacts"] if item["name"] == name)
                if missing:
                    api.artifact_listing["artifacts"].remove(entry)
                    api.artifact_listing["total_count"] -= 1
                else:
                    entry["expired"] = True
                self.reject(self.prepare, api)
                self.assertEqual(api.mutations, [])

    def test_expiry_during_live_proof_blocks_first_write(self):
        plan, files = self.prepare()
        name = p.ARTIFACT_PREFIX + "public-input-" + f.SOURCE
        artifact_id = plan["artifacts"][name]["id"]
        def expire(url, headers, limit, result, api):
            if url == api.storage_url(artifact_id):
                next(item for item in api.artifact_listing["artifacts"] if item["id"] == artifact_id)["expired"] = True
            return result
        self.api.provenance_hook = expire
        with mock.patch.object(gate.resources, "verify_pe", side_effect=f.fixtures.fake_pe):
            self.reject(p.publish, self.api, self.request, plan, files)
        self.assertEqual(self.api.mutations, [])

    def test_source_tree_in_reports_cannot_be_self_asserted(self):
        reports = {case: p.canonical(dict(json.loads(raw), sourceTree="e" * 40)) for case, raw in self.api.reports.items()}
        self.api.refresh_evidence(reports=reports)
        self.reject(self.prepare)

    def test_historical_evidence_false_coverage_source_inputs_or_package_substitution_rejected(self):
        evidence = json.loads(self.api.evidence)
        for key, value in (("schema", "tracebolt.windows-setup-native-subset.v2"),
                           ("status", "four_case_packaged_gui_subset"),
                           ("distributionStatus", "unsigned-source-candidate-native-subset"),
                           ("coverage", dict(evidence["coverage"], windows11=True))):
            bad = dict(evidence, **{key: value})
            with mock.patch.object(gate.resources, "verify_pe", side_effect=f.fixtures.fake_pe):
                self.reject(p.validate_evidence, p.canonical(bad), self.api.files, self.api.reports, self.request)
        for name in (gate.SETUP_NAME, "source-inputs.json"):
            api = current_api()
            artifact_name = p.ARTIFACT_PREFIX + "native-subset-public-" + f.SOURCE
            artifact = next(item for item in api.artifact_listing["artifacts"] if item["name"] == artifact_name)
            bad = dict(api.files)
            bad[name] += b"changed"
            api.set_artifact(artifact["id"], artifact_name, bad)
            self.reject(self.prepare, api)

    def test_historical_plan_and_extra_job_artifact_cannot_enter_current_profile(self):
        plan, _ = self.prepare()
        bad = copy.deepcopy(plan)
        bad["schema"] = "tracebolt.windows-prerelease-plan.v2"
        self.reject(p.validate_plan, bad, self.request)
        bad = copy.deepcopy(plan)
        bad["native"]["jobs"]["Actual packaged GUI - http-test-install-uninstall"] = 222
        self.reject(p.validate_plan, bad, self.request)
        bad = copy.deepcopy(plan)
        key = next(iter(bad["artifacts"]))
        bad["artifacts"][key.replace("windows-current-setup", "windows-setup")] = bad["artifacts"].pop(key)
        self.reject(p.validate_plan, bad, self.request)

    def test_current_provenance_transport_allowlist_is_exact(self):
        client = p.GitHubAPI("INERT")
        current_route = f.P + "/actions/workflows/windows-current-setup-acceptance.yml"
        client._provenance_routes = {current_route}
        headers = {"Authorization": "Bearer INERT"}
        with mock.patch.object(client, "_request", return_value=(200, b"{}")) as request:
            client.provenance_transport("https://api.github.com" + current_route, headers, 1024)
            self.reject(client.provenance_transport, "https://api.github.com" + f.P + "/actions/workflows/windows-setup-acceptance.yml", headers, 1024)
            self.assertEqual(request.call_count, 1)

    def test_current_workflow_stays_manual_and_disabled_pin_has_no_override(self):
        source = (ROOT / p.PUBLISH_WORKFLOW).read_text()
        self.assertIn("three-case current21", source)
        self.assertEqual(source.count("default: false"), 1)
        self.assertIn("publish-windows-current-prerelease.py --verify", source)
        self.assertIn("publish-windows-current-prerelease.py --publish", source)
        self.assertNotIn("expected_tree", source)
        for event in ("push:", "pull_request:", "schedule:", "workflow_run:"):
            self.assertNotIn("\n  " + event, source)
        old = load("_historical_unchanged_profile", ROOT / "deploy/release/publish-windows-prerelease.py")
        self.assertEqual(old.ACCEPTED_SOURCE_TREE, "d2ec1451a0fb4332a48f0ee48b17c35eca807ad4")
        self.assertEqual(len(old.gate.CHECKS), 4)


if __name__ == "__main__":
    unittest.main()
