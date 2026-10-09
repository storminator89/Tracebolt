"""Inert authenticated-record/ZIP fixtures; never contact GitHub or a native host."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("_setup_provenance", Path(__file__).with_name("setup_job_provenance.py"))
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
SOURCE = "a" * 40
RUN_ID = "123"
TOKEN = "INERT_TOKEN_NEVER_EXPORT"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def zip_bytes(files, mode=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in files.items():
            if mode is None:
                archive.writestr(name, raw)
            else:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, raw)
    return output.getvalue()


class Fixture:
    def __init__(self, completed=False):
        self.reports = {case: encoded({"case": case, "machine": "same-cloned-hostname"}) + b"\n" for case in p.CASES}
        self.files = {name: ("INERT_PUBLIC_" + name).encode() for name in p.PUBLIC_BOUNDS}
        actor = {"login": p.OWNER, "id": p.OWNER_ID}
        repo = {"id": p.REPOSITORY_ID, "full_name": p.REPOSITORY, "owner": actor}
        self.run = {"id": 123, "head_sha": SOURCE, "run_attempt": 1, "event": "workflow_dispatch",
                    "name": p.WORKFLOW_NAME, "workflow_id": 456, "head_branch": "main", "path": p.WORKFLOW_PATH,
                    "repository": repo, "head_repository": copy.deepcopy(repo), "actor": actor,
                    "triggering_actor": copy.deepcopy(actor), "status": "completed" if completed else "in_progress",
                    "conclusion": "success" if completed else None}
        self.attempt = copy.deepcopy(self.run)
        self.workflow = {"id": 456, "path": p.WORKFLOW_PATH, "name": p.WORKFLOW_NAME}
        self.jobs = []
        for index, case in enumerate(p.CASES):
            self.jobs.append({"id": 1000 + index, "run_id": 123, "head_sha": SOURCE,
                "run_attempt": 1, "workflow_name": p.WORKFLOW_NAME,
                "name": "Actual packaged GUI - " + case, "status": "completed", "conclusion": "success",
                "labels": ["windows-2025"], "runner_id": 777 + index, "runner_group_id": 0,
                "steps": [{"name": name, "status": "completed", "conclusion": conclusion, "number": number}
                          for name, conclusion, number in ((p.NATIVE_STEP, "success", 7),
                            (p.REPORT_STEP, "success", 8),
                            (p.PACKAGE_STEP, "success" if case == "install-uninstall" else "skipped", 9))]})
        self.jobs.append({"id": 2000, "run_id": 123, "head_sha": SOURCE, "name": p.AGGREGATE_NAME,
                          "run_attempt": 1, "workflow_name": p.WORKFLOW_NAME,
                          "status": self.run["status"], "conclusion": self.run["conclusion"], "labels": ["ubuntu-24.04"]})
        self.artifacts = []
        self.archives = {}
        for index, case in enumerate(p.CASES):
            self.add_artifact(3000 + index, "windows-setup-gui-" + case + "-" + SOURCE,
                              {p.REPORT_NAME: self.reports[case]})
        self.add_artifact(4000, "windows-setup-public-input-" + SOURCE, self.files)
        self.calls = []
        self.overrides = {}

    def add_artifact(self, identity, name, files):
        raw = zip_bytes(files)
        self.archives[identity] = raw
        self.artifacts.append({"id": identity, "name": name, "expired": False, "size_in_bytes": len(raw),
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "workflow_run": {"id": 123, "repository_id": p.REPOSITORY_ID, "head_repository_id": p.REPOSITORY_ID,
                             "head_sha": SOURCE, "head_branch": "main"}})

    def set_zip(self, identity, raw, update_digest=True):
        self.archives[identity] = raw
        for artifact in self.artifacts:
            if artifact["id"] == identity and update_digest:
                artifact["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
                artifact["size_in_bytes"] = len(raw)

    def transport(self, url, headers, limit):
        self.calls.append((url, dict(headers), limit))
        if url in self.overrides:
            value = self.overrides[url]
            if isinstance(value, Exception):
                raise value
            return value
        prefix = p.API_ROOT + "/actions/runs/123"
        if url == prefix:
            return 200, {}, encoded(self.run)
        if url == prefix + "/attempts/1":
            return 200, {}, encoded(self.attempt)
        if url == p.API_ROOT + "/actions/workflows/windows-setup-acceptance.yml":
            return 200, {}, encoded(self.workflow)
        if url == prefix + "/attempts/1/jobs?per_page=100":
            return 200, {}, encoded({"total_count": len(self.jobs), "jobs": self.jobs})
        if url == prefix + "/artifacts?per_page=100":
            return 200, {}, encoded({"total_count": len(self.artifacts), "artifacts": self.artifacts})
        for identity, raw in self.archives.items():
            storage = "https://productionresultssa1.blob.core.windows.net/inert/" + str(identity) + "?sig=INERT_SECRET"
            if url == p.API_ROOT + "/actions/artifacts/" + str(identity):
                found = [artifact for artifact in self.artifacts if artifact["id"] == identity]
                return 200, {}, encoded(found[0])
            if url == p.API_ROOT + "/actions/artifacts/" + str(identity) + "/zip":
                return 302, {"Location": storage}, b""
            if url == storage:
                return 200, {}, raw
        raise AssertionError("unexpected fixture request")

    def verify(self, **kwargs):
        # Fail immediately if injection is lost and a fixture attempts a live read.
        with mock.patch.object(p, "_request", side_effect=AssertionError("live request forbidden")):
            return p.verify_run(SOURCE, RUN_ID, self.reports, self.files, TOKEN,
                                transport=self.transport, **kwargs)


def environment():
    return {"GITHUB_REPOSITORY": p.REPOSITORY, "GITHUB_REPOSITORY_OWNER": p.OWNER,
            "GITHUB_REPOSITORY_OWNER_ID": str(p.OWNER_ID), "GITHUB_ACTOR": p.OWNER,
            "GITHUB_ACTOR_ID": str(p.OWNER_ID), "GITHUB_TRIGGERING_ACTOR": p.OWNER,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTIONS": "true",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "accepted-public-package",
            "GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE, "GITHUB_RUN_ID": RUN_ID,
            "GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW_REF": p.REPOSITORY + "/" + p.WORKFLOW_PATH + "@refs/heads/main",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted", p.TOKEN_ENV: TOKEN}


class SetupJobProvenance(unittest.TestCase):
    def test_same_hostname_with_distinct_job_and_registration_evidence(self):
        fixture = Fixture()
        result = fixture.verify()
        self.assertEqual(len({row["jobID"] for row in result["cases"].values()}), 4)
        self.assertEqual({row["runnerID"] for row in result["cases"].values()}, {"777", "778", "779", "780"})
        self.assertEqual(result["proofBasis"], p.PROOF_BASIS)
        self.assertFalse(result["vmIdentityAttested"])
        self.assertEqual(result["documentationReviewedOn"], "2026-10-09")
        self.assertEqual(result["artifactJobBinding"], p.ARTIFACT_BINDING)
        self.assertEqual(p.validate_provenance(result, SOURCE, RUN_ID, fixture.reports, fixture.files), result)
        exported = encoded(result)
        for secret in (TOKEN.encode(), b"INERT_SECRET", b"blob.core.windows.net", b"same-cloned-hostname"):
            self.assertNotIn(secret, exported)
        for url, headers, _limit in fixture.calls:
            self.assertEqual("Authorization" in headers, url.startswith(p.API_ROOT))

    def test_publisher_refetches_same_evidence_and_requires_terminal_success(self):
        result = Fixture().verify()
        self.assertEqual(Fixture(completed=True).verify(expected_provenance=result, require_aggregate_success=True), result)
        with self.assertRaises(p.Rejected):
            Fixture().verify(expected_provenance=result, require_aggregate_success=True)
        fixture = Fixture(completed=True)
        fixture.jobs[-1]["conclusion"] = "failure"
        with self.assertRaises(p.Rejected):
            fixture.verify(expected_provenance=result, require_aggregate_success=True)
        stale = copy.deepcopy(result)
        stale["cases"]["install-uninstall"]["jobID"] = "5000"
        with self.assertRaises(p.Rejected):
            Fixture(completed=True).verify(expected_provenance=stale, require_aggregate_success=True)

    def test_aggregate_optional_runner_metadata_is_not_native_identity(self):
        fixture = Fixture()
        fixture.jobs[-1].update(runner_id=None, runner_group_id=None, runner_name=None, steps=[])
        fixture.verify()

    def test_current_ref_must_match_authenticated_run_branch(self):
        fixture = Fixture()
        env = environment()
        env["GITHUB_REF"] = "refs/heads/other"
        env["GITHUB_WORKFLOW_REF"] = p.REPOSITORY + "/" + p.WORKFLOW_PATH + "@refs/heads/other"
        with self.assertRaises(p.Rejected):
            p.verify_current_run(env, SOURCE, fixture.reports, fixture.files, transport=fixture.transport)
        for ref in ("refs/tags/main", "main", "refs/heads/Main", "refs/heads/main/", ""):
            env = environment()
            env["GITHUB_REF"] = ref
            env["GITHUB_WORKFLOW_REF"] = p.REPOSITORY + "/" + p.WORKFLOW_PATH + "@" + ref
            with self.subTest(ref=ref), self.assertRaises(p.Rejected):
                p.verify_current_run(env, SOURCE, fixture.reports, fixture.files, transport=fixture.transport)
        for ref in ("refs/tags/main", "refs/heads/other", "main", ""):
            with self.subTest(explicit_ref=ref), self.assertRaises(p.Rejected):
                fixture.verify(expected_ref=ref)

    def test_every_current_binding_fails_before_network(self):
        fixture = Fixture()
        env = environment()
        self.assertEqual(p.verify_current_run(env, SOURCE, fixture.reports, fixture.files,
                                            transport=fixture.transport)["runID"], RUN_ID)
        for key in env:
            with self.subTest(key=key):
                bad = dict(env)
                bad.pop(key)
                transport = mock.Mock(side_effect=AssertionError("request before authority"))
                with self.assertRaises(p.Rejected):
                    p.verify_current_run(bad, SOURCE, fixture.reports, fixture.files, transport=transport)
                transport.assert_not_called()

    def test_run_repository_owner_actor_source_attempt_workflow_guards(self):
        edits = [("id", 999), ("id", True), ("head_sha", "b" * 40), ("run_attempt", 2),
                 ("run_attempt", True), ("event", "push"), ("name", "foreign"),
                 ("path", p.WORKFLOW_PATH + "@foreign"), ("workflow_id", 999),
                 ("status", "queued"), ("conclusion", "success"), ("head_branch", "bad\nref")]
        for key, value in edits:
            with self.subTest(key=key, value=value):
                fixture = Fixture()
                fixture.run[key] = value
                with self.assertRaises(p.Rejected):
                    fixture.verify()
        for key in ("actor", "triggering_actor"):
            fixture = Fixture()
            fixture.run[key] = {"id": 1, "login": p.OWNER}
            with self.assertRaises(p.Rejected):
                fixture.verify()
        for key in ("repository", "head_repository"):
            for field, value in (("id", 99), ("full_name", "foreign/repo"), ("owner", {"id": 1, "login": p.OWNER})):
                with self.subTest(key=key, field=field):
                    fixture = Fixture()
                    fixture.run[key] = copy.deepcopy(fixture.run[key])
                    fixture.run[key][field] = value
                    with self.assertRaises(p.Rejected):
                        fixture.verify()
        fixture = Fixture()
        for record in (fixture.run, fixture.attempt):
            record["repository"]["id"] = 99
            record["head_repository"]["id"] = 99
        with self.assertRaises(p.Rejected):
            fixture.verify()

    def test_attempt_and_workflow_records_must_match(self):
        for target, field, value in (("attempt", "run_attempt", 2), ("attempt", "head_sha", "b" * 40),
             ("attempt", "workflow_id", 999), ("workflow", "id", 999), ("workflow", "path", ".github/workflows/other.yml"),
             ("workflow", "name", "foreign"), ("attempt", "head_branch", "other"),
             ("attempt", "status", "completed"), ("attempt", "conclusion", "failure")):
            with self.subTest(target=target, field=field):
                fixture = Fixture()
                getattr(fixture, target)[field] = value
                with self.assertRaises(p.Rejected):
                    fixture.verify()
        fixture = Fixture(completed=True)
        fixture.attempt["conclusion"] = "failure"
        with self.assertRaises(p.Rejected):
            fixture.verify(require_aggregate_success=True)

    def test_only_exact_four_unique_successful_jobs_are_accepted(self):
        edits = [("id", 1001), ("id", True), ("run_id", 999), ("head_sha", "b" * 40),
                 ("run_attempt", 2), ("run_attempt", True), ("workflow_name", "foreign workflow"),
                 ("name", "Actual packaged GUI - unknown"), ("name", "Actual packaged GUI - http-install-uninstall"),
                 ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "skipped"),
                 ("labels", ["self-hosted", "windows-2025"]), ("labels", ["windows-latest"]),
                 ("runner_id", True), ("runner_id", 0), ("runner_id", 778),
                 ("runner_id", None), ("runner_group_id", -1)]
        for key, value in edits:
            with self.subTest(key=key, value=value):
                fixture = Fixture()
                fixture.jobs[0][key] = value
                with self.assertRaises(p.Rejected):
                    fixture.verify()
        for remove in (True, False):
            fixture = Fixture()
            if remove:
                fixture.jobs.pop(0)
            else:
                fixture.jobs.append(copy.deepcopy(fixture.jobs[0]))
            with self.assertRaises(p.Rejected):
                fixture.verify()

    def test_native_and_upload_step_binding(self):
        for index in (0, 1, 2):
            for key, value in (("name", "foreign"), ("conclusion", "failure"), ("status", "in_progress"), ("number", True)):
                with self.subTest(index=index, key=key):
                    fixture = Fixture()
                    fixture.jobs[0]["steps"][index][key] = value
                    with self.assertRaises(p.Rejected):
                        fixture.verify()
        fixture = Fixture()
        fixture.jobs[0]["steps"][0]["number"] = 10
        with self.assertRaises(p.Rejected):
            fixture.verify()
        fixture = Fixture()
        fixture.jobs[1]["steps"][2]["conclusion"] = "success"
        with self.assertRaises(p.Rejected):
            fixture.verify()
        fixture = Fixture()
        fixture.jobs[0]["steps"].append(copy.deepcopy(fixture.jobs[0]["steps"][0]))
        with self.assertRaises(p.Rejected):
            fixture.verify()

    def test_exact_artifact_metadata_required(self):
        edits = [("id", 3001), ("id", True), ("name", "foreign"), ("expired", True),
                 ("expired", 0), ("size_in_bytes", 0), ("size_in_bytes", True),
                 ("size_in_bytes", 99999),
                 ("digest", "sha256:" + "f" * 64), ("digest", "invalid")]
        for key, value in edits:
            with self.subTest(key=key, value=value):
                fixture = Fixture()
                fixture.artifacts[0][key] = value
                with self.assertRaises(p.Rejected):
                    fixture.verify()
        for key, value in (("id", 999), ("repository_id", 99), ("head_repository_id", 99),
                           ("head_sha", "b" * 40), ("head_branch", "other")):
            fixture = Fixture()
            fixture.artifacts[0]["workflow_run"][key] = value
            with self.assertRaises(p.Rejected):
                fixture.verify()
        fixture = Fixture()
        fixture.artifacts.append(copy.deepcopy(fixture.artifacts[0]))
        with self.assertRaises(p.Rejected):
            fixture.verify()

    def test_individual_artifact_record_must_match_listing_before_download(self):
        for field, value in (("id", 3001), ("name", "foreign"), ("expired", True),
                             ("size_in_bytes", 42), ("digest", "sha256:" + "f" * 64)):
            fixture = Fixture()
            changed = copy.deepcopy(fixture.artifacts[0])
            changed[field] = value
            fixture.overrides[p.API_ROOT + "/actions/artifacts/3000"] = (200, {}, encoded(changed))
            with self.subTest(field=field), self.assertRaises(p.Rejected):
                fixture.verify()
            self.assertFalse(any(url.endswith("/3000/zip") for url, _headers, _limit in fixture.calls))

    def test_only_known_aggregate_outputs_may_also_exist(self):
        fixture = Fixture(completed=True)
        fixture.add_artifact(5000, "windows-setup-native-subset-public-" + SOURCE, {"inert": b"ignored here"})
        fixture.add_artifact(5001, "windows-setup-native-subset-evidence-" + SOURCE, {"inert": b"ignored here"})
        fixture.verify(require_aggregate_success=True)
        fixture.artifacts[-1]["name"] = "unreviewed-output"
        with self.assertRaises(p.Rejected):
            fixture.verify(require_aggregate_success=True)

    def test_zip_digest_and_exact_consumed_report_and_package_bytes(self):
        for identity, files in ((3000, {p.REPORT_NAME: b"different report"}),
                                (4000, dict(Fixture().files, SHA256SUMS=b"different package"))):
            for update_digest in (True, False):
                with self.subTest(identity=identity, update_digest=update_digest):
                    fixture = Fixture()
                    fixture.set_zip(identity, zip_bytes(files), update_digest)
                    with self.assertRaises(p.Rejected):
                        fixture.verify()

    def test_unsafe_zip_members_and_duplicates_fail_without_extracting(self):
        fixture = Fixture()
        expected = {p.REPORT_NAME: fixture.reports[p.CASES[0]]}
        for files in ({"../" + p.REPORT_NAME: b"x"}, {"/" + p.REPORT_NAME: b"x"},
                      dict(expected, extra=b"x"), {}, {"nested/" + p.REPORT_NAME: b"x"}):
            with self.subTest(files=list(files)), self.assertRaises(p.Rejected):
                p._verify_zip(zip_bytes(files), expected)
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755):
            with self.assertRaises(p.Rejected):
                p._verify_zip(zip_bytes(expected, mode), expected)
        duplicate = io.BytesIO()
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr(p.REPORT_NAME, expected[p.REPORT_NAME])
            with mock.patch("warnings.warn"):
                archive.writestr(p.REPORT_NAME, expected[p.REPORT_NAME])
        with self.assertRaises(p.Rejected):
            p._verify_zip(duplicate.getvalue(), expected)

    def test_zip_preflight_bounds_before_member_object_allocation(self):
        expected = {p.REPORT_NAME: b"inert"}
        original = zip_bytes(expected)
        variants = [original + b"trailing", original[:-22], b"invalid"]
        for position, format_, value in ((4, "H", 1), (6, "H", 1), (8, "H", 0xffff),
                                          (10, "H", 0xffff), (12, "L", 16385),
                                          (16, "L", 0xffffffff), (20, "H", 1)):
            bad = bytearray(original)
            struct.pack_into("<" + format_, bad, len(bad) - 22 + position, value)
            variants.append(bytes(bad))
        massive = zip_bytes({"file" + str(index): b"" for index in range(2000)})
        variants.append(massive)
        for raw in variants:
            with self.subTest(size=len(raw)), mock.patch.object(p.zipfile, "ZipFile") as parser:
                with self.assertRaises(p.Rejected):
                    p._verify_zip(raw, expected)
                parser.assert_not_called()

    def test_fixed_redirect_policy_and_no_token_forwarding(self):
        for target in ("http://productionresultssa1.blob.core.windows.net/x", "https://evil.example/x",
                       "https://productionresultssa1.blob.core.windows.net.evil.example/x",
                       "https://user:pass@productionresultssa1.blob.core.windows.net/x",
                       "https://productionresultssa1.blob.core.windows.net:444/x",
                       "https://productionresultssa1.blob.core.windows.net/x#fragment",
                       "https://productionresultssa1.blob.core.windows.net/x\nheader"):
            with self.subTest(target=target):
                fixture = Fixture()
                fixture.overrides[p.API_ROOT + "/actions/artifacts/3000/zip"] = (302, {"location": target}, b"")
                with self.assertRaises(p.Rejected):
                    fixture.verify()
                self.assertFalse(any(url == target for url, _headers, _limit in fixture.calls))
        fixture = Fixture()
        target = "https://productionresultssa1.blob.core.windows.net/inert/3000?sig=INERT_SECRET"
        fixture.overrides[target] = (302, {"Location": "https://evil.example/x"}, b"")
        with self.assertRaises(p.Rejected):
            fixture.verify()
        self.assertNotIn("Authorization", next(headers for url, headers, _limit in fixture.calls if url == target))

    def test_pagination_json_size_duplicate_keys_and_api_errors_are_redacted(self):
        prefix = p.API_ROOT + "/actions/runs/123"
        responses = [(200, {"Link": "https://evil.example/next"}, encoded(Fixture().run)),
                     (200, {}, b'{"id":123,"id":123}'), (200, {}, b'{"id":NaN}'),
                     (200, {}, b"x" * (p.JSON_LIMIT + 1)), (302, {"Location": "https://evil.example"}, b""),
                     (401, {}, b"PRIVATE_RESPONSE_" + TOKEN.encode()), RuntimeError("PRIVATE_ERROR_" + TOKEN)]
        for response in responses:
            fixture = Fixture()
            fixture.overrides[prefix] = response
            with self.subTest(response_type=type(response).__name__), self.assertRaises(p.Rejected) as caught:
                fixture.verify()
            self.assertEqual(str(caught.exception), "packaged Setup execution provenance rejected")
            self.assertEqual(len(fixture.calls), 1)
        fixture = Fixture()
        fixture.overrides[prefix + "/attempts/1/jobs?per_page=100"] = (
            200, {}, encoded({"total_count": 6, "jobs": fixture.jobs}))
        with self.assertRaises(p.Rejected):
            fixture.verify()

    def test_http_transport_is_bounded_no_proxy_no_automatic_redirect(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.code = 200
        response.headers.items.return_value = [("Content-Type", "application/json")]
        response.read.return_value = b"{}"
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(p.urllib.request, "build_opener", return_value=opener) as build:
            self.assertEqual(p._request(p.API_ROOT, {"Accept": "application/json"}, 10),
                             (200, {"Content-Type": "application/json"}, b"{}"))
            handlers = build.call_args.args
            self.assertIsInstance(handlers[0], p.urllib.request.ProxyHandler)
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsInstance(handlers[1], p._NoRedirect)
            self.assertIsNone(handlers[1].redirect_request(None, None, None, None, None, None))
            self.assertEqual(opener.open.call_args.kwargs, {"timeout": 30})
            self.assertEqual(opener.open.call_args.args[0].get_method(), "GET")
            response.read.assert_called_once_with(11)
        response.read.return_value = b"x" * 11
        with mock.patch.object(p.urllib.request, "build_opener", return_value=opener), self.assertRaises(p.Rejected):
            p._request(p.API_ROOT, {}, 10)
        opener.open.side_effect = RuntimeError("PRIVATE_NETWORK_ERROR_" + TOKEN)
        with mock.patch.object(p.urllib.request, "build_opener", return_value=opener), self.assertRaises(p.Rejected) as caught:
            p._request(p.API_ROOT, {}, 10)
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_projection_rejects_unknown_missing_forged_or_attested_claims(self):
        fixture = Fixture()
        result = fixture.verify()
        for key in result:
            bad = copy.deepcopy(result)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(p.Rejected):
                p.validate_provenance(bad, SOURCE, RUN_ID, fixture.reports, fixture.files)
        for key, value in (("vmIdentityAttested", True), ("runAttempt", True), ("rawResponse", TOKEN),
                           ("documentationReviewedOn", "2099-01-01"), ("proofBasis", "unique-hostname"),
                           ("repositoryID", "99")):
            bad = copy.deepcopy(result)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(p.Rejected):
                p.validate_provenance(bad, SOURCE, RUN_ID, fixture.reports, fixture.files)
        for key, value in (("jobID", result["cases"][p.CASES[1]]["jobID"]), ("reportSHA256", "f" * 64),
                           ("artifactID", result["cases"][p.CASES[1]]["artifactID"]), ("runnerID", True),
                           ("runnerID", "0"), ("runnerID", None),
                           ("runnerID", result["cases"][p.CASES[1]]["runnerID"])):
            bad = copy.deepcopy(result)
            bad["cases"][p.CASES[0]][key] = value
            with self.subTest(key=key), self.assertRaises(p.Rejected):
                p.validate_provenance(bad, SOURCE, RUN_ID, fixture.reports, fixture.files)

    def test_api_token_permission_are_aggregate_step_only(self):
        workflow = (ROOT / ".github/workflows/windows-setup-acceptance.yml").read_text()
        native, aggregate = workflow.split("  accepted-public-package:", 1)
        self.assertNotIn("actions: read", native)
        self.assertNotIn(p.TOKEN_ENV, native)
        self.assertEqual(aggregate.count("actions: read"), 1)
        self.assertEqual(aggregate.count(p.TOKEN_ENV), 1)
        step = aggregate.split("        id: aggregate\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("          TRACEBOLT_SETUP_API_TOKEN: ${{ github.token }}", step)
        self.assertIn("run_setup_gui.py --aggregate", step)


if __name__ == "__main__":
    unittest.main()
