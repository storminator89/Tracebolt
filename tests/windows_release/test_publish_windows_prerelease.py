"""Fixture-only publisher checks: no GitHub calls, writes or native execution.

The public package consists exclusively of the existing acceptance suite's
synthetic inert bytes. Only fixture preparation/evidence tests inject fake_pe;
the unpatched production verifier must reject those bytes as invalid PE files.
All publication mutations below happen in an in-memory FakeAPI state machine.
"""
import base64
import copy
import importlib.util
import io
import json
import re
import runpy
import sys
from pathlib import Path
import socket
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publisher = load("windows_prerelease_publisher", ROOT / "deploy/release/publish-windows-prerelease.py")
fixtures = load("windows_prerelease_native_fixtures", ROOT / "tests/windows_native_acceptance/test_setup_gui.py")
gate = publisher.gate
P = publisher.PREFIX
SOURCE = "a" * 40
PUBLISHER_SHA = "b" * 40
VERSION = "v0.1.0-windows-preview.1"


def request_fixture():
    return {"source": SOURCE, "acceptanceRunID": "123", "version": VERSION,
            "publisherSHA": PUBLISHER_SHA, "publisherRef": "refs/heads/windows-prerelease", "publisherRunID": "456"}


def environment(publish=False):
    return {"TRACEBOLT_RELEASE_SOURCE": SOURCE, "TRACEBOLT_ACCEPTANCE_RUN_ID": "123",
            "TRACEBOLT_RELEASE_VERSION": VERSION, "TRACEBOLT_PUBLISHER_SHA": PUBLISHER_SHA,
            "GITHUB_REF": "refs/heads/windows-prerelease", "GITHUB_RUN_ID": "456",
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": publisher.REPOSITORY, "GITHUB_REPOSITORY_ID": str(publisher.REPO_ID),
            "GITHUB_REPOSITORY_OWNER": publisher.OWNER, "GITHUB_REPOSITORY_OWNER_ID": str(publisher.OWNER_ID),
            "GITHUB_ACTOR": publisher.OWNER, "GITHUB_ACTOR_ID": str(publisher.OWNER_ID),
            "GITHUB_TRIGGERING_ACTOR": publisher.OWNER, "GITHUB_RUN_ATTEMPT": "1",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_SHA": PUBLISHER_SHA, "GITHUB_WORKFLOW_SHA": PUBLISHER_SHA,
            "GITHUB_JOB": "publish" if publish else "verify",
            "GITHUB_WORKFLOW_REF": publisher.REPOSITORY + "/" + publisher.PUBLISH_WORKFLOW + "@refs/heads/windows-prerelease",
            "TRACEBOLT_RELEASE_PUBLISH": "true" if publish else "false"}


def repository():
    return {"id": publisher.REPO_ID, "full_name": publisher.REPOSITORY, "private": False,
            "owner": {"id": publisher.OWNER_ID, "login": publisher.OWNER}}


def zip_bytes(files, *, comment=b"", compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    pairs = files.items() if isinstance(files, dict) else files
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            archive.comment = comment
            for name, raw in pairs:
                info = name if isinstance(name, zipfile.ZipInfo) else zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                info.compress_type = compression
                archive.writestr(info, raw)
    return output.getvalue()


def archive_entry(raw):
    return {"size": len(raw), "sha256": publisher.digest(raw)}


def evidence_fixture(files, raw_reports):
    reports = gate.aggregate_reports(raw_reports, SOURCE, "123")
    with mock.patch.object(gate.resources, "verify_pe", side_effect=fixtures.fake_pe):
        hashes = gate.validate_public_package(files, SOURCE, reports["install-uninstall"])
    return {"schema": "tracebolt.windows-setup-native-subset.v1", "source": SOURCE, "runID": "123",
            "status": "four_case_packaged_gui_subset", "distributionStatus": "unsigned-source-candidate-native-subset",
            "crossOSRebuildEquivalence": False, "coverage": dict.fromkeys(sorted(gate.FALSE_COVERAGE), False),
            "reports": reports, "publicFilesSHA256": hashes}


class FakeAPI:
    """Finite in-memory HTTP fixtures, including create-only mutation state."""
    def __init__(self):
        self.calls, self.downloads, self.public_reads = [], [], []
        self.hook = None
        self.public_hook = None
        self.tag = None
        self.release = None
        self.uploads = {}
        self.release_id = 701
        self.asset_serial = 800
        self.files, self.reports = fixtures.public_fixture()
        self.evidence = publisher.canonical(evidence_fixture(self.files, self.reports))
        actor = {"id": publisher.OWNER_ID, "login": publisher.OWNER}
        self.run = {"id": 123, "run_attempt": 1, "event": "workflow_dispatch", "status": "completed",
                    "conclusion": "success", "head_sha": SOURCE, "head_branch": "main", "path": publisher.NATIVE_WORKFLOW,
                    "html_url": "https://github.com/" + publisher.REPOSITORY + "/actions/runs/123",
                    "repository": repository(), "head_repository": repository(), "actor": actor,
                    "triggering_actor": copy.deepcopy(actor), "workflow_id": 61}
        jobs = [{"id": 100 + n, "name": "Actual packaged GUI - " + case, "run_id": 123,
                 "head_sha": SOURCE, "status": "completed", "conclusion": "success", "labels": ["windows-2025"]}
                for n, case in enumerate(gate.CHECKS)]
        jobs.append({"id": 104, "name": publisher.AGGREGATE_JOB, "run_id": 123, "head_sha": SOURCE,
                     "status": "completed", "conclusion": "success", "labels": ["ubuntu-24.04"]})
        self.artifact_listing = {"total_count": 7, "artifacts": []}
        self.archives = {}
        self.routes = {P: repository(), P + "/git/ref/heads/windows-prerelease":
                       {"ref": "refs/heads/windows-prerelease", "object": {"type": "commit", "sha": PUBLISHER_SHA}},
                       P + "/git/commits/" + SOURCE: {"sha": SOURCE, "tree": {"sha": publisher.ACCEPTED_SOURCE_TREE}},
                       P + "/actions/runs/123": self.run,
                       P + "/actions/workflows/61": {"id": 61, "path": publisher.NATIVE_WORKFLOW},
                       P + "/actions/runs/123/attempts/1/jobs?per_page=100": {"total_count": 5, "jobs": jobs},
                       P + "/actions/runs/123/artifacts?per_page=100": self.artifact_listing}
        for number, name in enumerate(sorted(publisher.artifact_names(SOURCE)), 200):
            if name.startswith("windows-setup-gui-"):
                case = name[len("windows-setup-gui-"):-(len(SOURCE) + 1)]
                contents = {gate.REPORT_NAME: self.reports[case]}
            elif name.startswith("windows-setup-native-subset-evidence-"):
                contents = {gate.AGGREGATE_REPORT: self.evidence}
            else:
                contents = self.files
            self.set_artifact(number, name, contents)

    @property
    def mutations(self):
        return [(method, path) for method, path, _, _ in self.calls if method != "GET"]

    def set_artifact(self, artifact_id, name, files):
        raw = zip_bytes(files)
        meta = {"id": artifact_id, "name": name, "expired": False, "size_in_bytes": len(raw),
                "digest": "sha256:" + publisher.digest(raw),
                "workflow_run": {"id": 123, "repository_id": publisher.REPO_ID,
                                 "head_repository_id": publisher.REPO_ID, "head_sha": SOURCE, "head_branch": "main"}}
        entries = self.artifact_listing["artifacts"]
        entries[:] = [item for item in entries if item["id"] != artifact_id]
        entries.append(meta)
        self.routes[P + "/actions/artifacts/" + str(artifact_id)] = copy.deepcopy(meta)
        self.archives[artifact_id] = raw

    def asset(self, name):
        raw, asset_id = self.uploads[name]
        download_tag = "untagged-" + "e" * 20 if self.release["draft"] else VERSION
        return {"id": asset_id, "name": name, "state": "uploaded", "size": len(raw),
                "digest": "sha256:" + publisher.digest(raw),
                "browser_download_url": "https://github.com/" + publisher.REPOSITORY + "/releases/download/" + download_tag + "/" + name}

    def request(self, method, path, payload=None, *, upload=None, missing=False):
        self.calls.append((method, path, copy.deepcopy(payload), upload))
        if method == "GET":
            if path in self.routes:
                result = self.routes[path]
            elif path == P + "/git/ref/tags/" + VERSION:
                result = self.tag
            elif path == P + "/releases/tags/" + VERSION:
                result = self.release if self.release and not self.release["draft"] else None
            elif path.startswith(P + "/releases?per_page=100&page="):
                result = [self.release] if self.release else []
            elif path == P + f"/releases/{self.release_id}/assets?per_page=100":
                result = [self.asset(name) for name in sorted(self.uploads)]
            elif path == P + f"/releases/{self.release_id}":
                result = self.release
            else:
                raise AssertionError("Unexpected fixture GET: " + path)
        elif method == "POST" and path == P + "/git/refs":
            if self.tag is not None:
                raise AssertionError("Fixture forbids replacing a tag")
            self.tag = {"ref": payload["ref"], "object": {"type": "commit", "sha": payload["sha"]}}
            result = self.tag
        elif method == "POST" and path == P + "/releases":
            if self.release is not None:
                raise AssertionError("Fixture forbids replacing a release")
            self.release = {**copy.deepcopy(payload), "id": self.release_id, "assets": [],
                            "html_url": "https://github.com/" + publisher.REPOSITORY + "/releases/tag/untagged-" + "e" * 20}
            result = self.release
        elif method == "POST" and path.startswith(P + f"/releases/{self.release_id}/assets?name="):
            name = path.split("?name=", 1)[1]
            if name in self.uploads:
                raise AssertionError("Fixture forbids asset replacement")
            self.asset_serial += 1
            self.uploads[name] = (upload, self.asset_serial)
            result = self.asset(name)
        elif method == "PATCH" and path == P + f"/releases/{self.release_id}":
            if self.release["draft"] is not True:
                raise AssertionError("Fixture forbids publishing twice")
            self.release.update(payload)
            self.release["html_url"] = "https://github.com/" + publisher.REPOSITORY + "/releases/tag/" + VERSION
            result = self.release
        else:
            raise AssertionError("Unexpected fixture mutation: " + method + " " + path)
        result = copy.deepcopy(result)
        return self.hook(method, path, result, self) if self.hook else result

    def artifact(self, artifact_id, limit):
        self.downloads.append((artifact_id, limit))
        return self.archives[artifact_id]

    def public_asset(self, version, name, size):
        self.public_reads.append((version, name, size))
        if self.release is None or self.release["draft"]:
            raise AssertionError("Public download attempted before publication")
        raw = self.uploads[name][0]
        return self.public_hook(name, raw) if self.public_hook else raw


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self.request = request_fixture()
        self.api = FakeAPI()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        for name in publisher.GUIDES:
            (self.root / "docs" / name).write_text("Synthetic fixture guide only.\n", encoding="utf-8")

    def prepare(self, api=None, frozen=None):
        with mock.patch.object(gate.resources, "verify_pe", side_effect=fixtures.fake_pe):
            return publisher.prepare(api or self.api, self.request, frozen=frozen, root=self.root)

    def reject(self, function, *args, **kwargs):
        with self.assertRaises((publisher.Rejected, gate.shared.Rejected)):
            function(*args, **kwargs)


class RequestAndLeaseTests(FixtureCase):
    def test_strict_request_accepts_only_exact_keys_strings_and_distinct_ids(self):
        self.assertEqual(publisher.validate_request(self.request), self.request)
        for key in self.request:
            bad = dict(self.request)
            bad.pop(key)
            with self.subTest(missing=key):
                self.reject(publisher.validate_request, bad)
            for value in (None, True, 1, [], ""):
                with self.subTest(key=key, value=value):
                    self.reject(publisher.validate_request, dict(self.request, **{key: value}))
        self.reject(publisher.validate_request, dict(self.request, extra="x"))
        self.reject(publisher.validate_request, dict(self.request, source=PUBLISHER_SHA))
        self.reject(publisher.validate_request, dict(self.request, acceptanceRunID="456"))

    def test_source_run_and_version_names_cannot_escape_or_alias(self):
        for field in ("source", "publisherSHA"):
            for value in ("A" * 40, "a" * 39, "a" * 41, SOURCE + "\n", "refs/heads/main"):
                with self.subTest(field=field, value=value):
                    self.reject(publisher.validate_request, dict(self.request, **{field: value}))
        for field in ("acceptanceRunID", "publisherRunID"):
            for value in ("0", "0123", "-1", "1.0", str(2**63), "123\n", "１２３"):
                with self.subTest(field=field, value=value):
                    self.reject(publisher.validate_request, dict(self.request, **{field: value}))
        for value in ("v0.1.0", "v0.1.0-rc.4", "v0.1.0-windows-preview.0", "v01.1.0-windows-preview.1",
                      "v0.1.0-windows-preview.01", VERSION + "\n", "../" + VERSION, "v" + "1" * 65):
            with self.subTest(version=value):
                self.reject(publisher.validate_request, dict(self.request, version=value))
        for value in ("refs/tags/foo", "refs/heads/../main", "refs/heads/a//b", "refs/heads/a.lock",
                      "refs/heads/a.", "refs/heads/a..b", "refs/heads/a\\b", "refs/heads/a\n"):
            with self.subTest(ref=value):
                self.reject(publisher.validate_request, dict(self.request, publisherRef=value))

    def test_every_environment_lease_is_required_for_both_modes(self):
        for publish in (False, True):
            env = environment(publish)
            self.assertEqual(publisher.authorize(env, publish), self.request)
            for key in env:
                bad = dict(env)
                bad.pop(key)
                with self.subTest(publish=publish, missing=key):
                    self.reject(publisher.authorize, bad, publish)
            for key in env:
                bad = dict(env, **{key: "incorrect"})
                with self.subTest(publish=publish, changed=key):
                    self.reject(publisher.authorize, bad, publish)
        self.reject(publisher.authorize, dict(environment(True), TRACEBOLT_RELEASE_PUBLISH="false"), True)
        self.assertEqual(publisher.authorize(dict(environment(), TRACEBOLT_RELEASE_PUBLISH="true"), False), self.request)

    def test_invalid_input_has_no_checkout_api_or_output_effects(self):
        with mock.patch.object(publisher, "verify_checkout") as checkout, mock.patch.object(publisher, "GitHubAPI") as api, mock.patch("builtins.open") as opened:
            self.reject(publisher.main, ["--publish"], {})
            checkout.assert_not_called()
            api.assert_not_called()
            opened.assert_not_called()

    def test_checkout_requires_exact_root_clean_tree_and_sha(self):
        outputs = [str(self.root).encode() + b"\n", PUBLISHER_SHA.encode() + b"\n", b""]
        def run(*_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=outputs.pop(0))
        with mock.patch.object(publisher.subprocess, "run", side_effect=run) as command:
            publisher.verify_checkout(self.request, self.root)
            self.assertEqual(command.call_count, 3)
            self.assertEqual(command.call_args.args[0], ["git", "status", "--porcelain", "--untracked-files=all"])
        for responses in ([b"/wrong\n"], [str(self.root).encode(), b"c" * 40],
                          [str(self.root).encode(), PUBLISHER_SHA.encode(), b"?? rogue"]):
            outputs[:] = responses
            with mock.patch.object(publisher.subprocess, "run", side_effect=run):
                self.reject(publisher.verify_checkout, self.request, self.root)

    def test_repository_owner_tree_and_publisher_ref_are_fixed(self):
        publisher.publisher_lease(self.api, self.request)
        variants = [(P, "id", publisher.REPO_ID + 1), (P, "private", True),
                    (P, "full_name", "attacker/Tracebolt"),
                    (P + "/git/commits/" + SOURCE, "sha", "c" * 40)]
        for path, key, value in variants:
            api = FakeAPI()
            api.routes[path][key] = value
            with self.subTest(path=path, key=key):
                self.reject(publisher.publisher_lease, api, self.request)
        for mutate in (lambda a: a.routes[P]["owner"].update(id=True),
                       lambda a: a.routes[P]["owner"].update(login="other"),
                       lambda a: a.routes[P + "/git/commits/" + SOURCE]["tree"].update(sha="c" * 40),
                       lambda a: a.routes[P + "/git/ref/heads/windows-prerelease"]["object"].update(type="tag"),
                       lambda a: a.routes[P + "/git/ref/heads/windows-prerelease"]["object"].update(sha="c" * 40)):
            api = FakeAPI()
            mutate(api)
            self.reject(publisher.publisher_lease, api, self.request)

    def test_run_requires_first_attempt_owner_exact_workflow_and_source(self):
        self.assertEqual(len(publisher.verify_native_run(self.api, self.request)["jobs"]), 5)
        for key, value in (("id", True), ("run_attempt", 2), ("run_attempt", True), ("event", "push"),
                           ("status", "in_progress"), ("conclusion", "failure"), ("head_sha", "c" * 40),
                           ("path", "other.yml"), ("html_url", "https://evil.invalid/run"), ("workflow_id", True)):
            api = FakeAPI()
            api.run[key] = value
            with self.subTest(key=key, value=value):
                self.reject(publisher.verify_native_run, api, self.request)
        for key in ("repository", "head_repository", "actor", "triggering_actor"):
            api = FakeAPI()
            api.run[key]["id"] += 1
            with self.subTest(key=key):
                self.reject(publisher.verify_native_run, api, self.request)
        for key, value in (("id", 62), ("path", ".github/workflows/fake.yml")):
            api = FakeAPI()
            api.routes[P + "/actions/workflows/61"][key] = value
            self.reject(publisher.verify_native_run, api, self.request)

    def test_native_run_requires_explicit_main_branch_without_constraining_publisher_branch(self):
        self.assertEqual(self.api.run["head_branch"], "main")
        self.assertNotEqual(self.request["publisherRef"], "refs/heads/main")
        publisher.verify_native_run(self.api, self.request)
        publisher.publisher_lease(self.api, self.request)
        for branch in (None, "", "feature/fixture", "Main", "refs/heads/main"):
            api = FakeAPI()
            if branch is None:
                api.run.pop("head_branch")
            else:
                api.run["head_branch"] = branch
            with self.subTest(branch=branch):
                self.reject(publisher.verify_native_run, api, self.request)
                self.assertFalse(api.downloads)
                self.assertFalse(api.mutations)

    def test_exactly_five_distinct_successful_jobs_on_expected_runners(self):
        path = P + "/actions/runs/123/attempts/1/jobs?per_page=100"
        for key, value in (("id", True), ("run_id", 124), ("head_sha", "c" * 40),
                           ("status", "queued"), ("conclusion", "cancelled"), ("name", "unknown"),
                           ("labels", ["windows-latest"]), ("labels", ["windows-2025", "SELF-HOSTED"]),
                           ("labels", ["windows-2025", 1])):
            api = FakeAPI()
            api.routes[path]["jobs"][0][key] = value
            with self.subTest(key=key, value=value):
                self.reject(publisher.verify_native_run, api, self.request)
        for mutate in (lambda jobs: jobs.pop(), lambda jobs: jobs.append(copy.deepcopy(jobs[0])),
                       lambda jobs: jobs[1].update(name=jobs[0]["name"]),
                       lambda jobs: jobs[1].update(id=jobs[0]["id"]),
                       lambda jobs: jobs[-1].update(labels=["windows-2025"])):
            api = FakeAPI()
            mutate(api.routes[path]["jobs"])
            self.reject(publisher.verify_native_run, api, self.request)
        self.api.routes[path]["total_count"] = 6
        self.reject(publisher.verify_native_run, self.api, self.request)


class ArtifactTests(FixtureCase):
    def test_exact_seven_named_immutable_artifacts_are_resolved_and_read_back(self):
        entries = publisher.resolve_artifacts(self.api, self.request)
        self.assertEqual(len(entries), 7)
        self.assertEqual(set(entries), set(publisher.artifact_names(SOURCE)))
        self.assertEqual(len(self.api.calls), 8)
        self.assertFalse(self.api.downloads)
        self.assertFalse(self.api.mutations)
        self.assertEqual(publisher.resolve_artifacts(self.api, self.request, entries), entries)

    def test_artifact_inventory_rejects_missing_extra_duplicate_names_and_ids(self):
        for mutate in (lambda a: a.pop(), lambda a: a.append(copy.deepcopy(a[0])),
                       lambda a: a[1].update(name=a[0]["name"]), lambda a: a[1].update(id=a[0]["id"]),
                       lambda a: a[0].update(name="other-source-artifact")):
            api = FakeAPI()
            mutate(api.artifact_listing["artifacts"])
            self.reject(publisher.resolve_artifacts, api, self.request)
        self.api.artifact_listing["total_count"] = 8
        self.reject(publisher.resolve_artifacts, self.api, self.request)

    def test_artifact_metadata_requires_id_digest_size_and_run_binding(self):
        original = self.api.artifact_listing["artifacts"][0]
        for key, value in (("id", True), ("id", 0), ("expired", True), ("expired", 0),
                           ("size_in_bytes", True), ("size_in_bytes", 0), ("size_in_bytes", publisher.MAX_ARCHIVE + 1),
                           ("digest", ""), ("digest", "sha256:" + "A" * 64), ("digest", "sha1:" + "a" * 40)):
            bad = copy.deepcopy(original)
            bad[key] = value
            with self.subTest(key=key, value=value):
                self.reject(publisher.artifact_identity, bad, original["name"], self.request)
        for key, value in (("id", 124), ("repository_id", 1), ("head_repository_id", 1), ("head_sha", "c" * 40)):
            bad = copy.deepcopy(original)
            bad["workflow_run"][key] = value
            self.reject(publisher.artifact_identity, bad, original["name"], self.request)

    def test_all_artifact_listings_and_readbacks_require_explicit_main_branch(self):
        for artifact_index in range(7):
            for scope in ("listing", "readback"):
                for branch in (None, "feature/fixture"):
                    api = FakeAPI()
                    listed = api.artifact_listing["artifacts"][artifact_index]
                    metadata = listed if scope == "listing" else api.routes[P + "/actions/artifacts/" + str(listed["id"])]
                    if branch is None:
                        metadata["workflow_run"].pop("head_branch")
                    else:
                        metadata["workflow_run"]["head_branch"] = branch
                    with self.subTest(name=listed["name"], scope=scope, branch=branch):
                        self.reject(publisher.resolve_artifacts, api, self.request)
                        self.assertFalse(api.downloads)
                        self.assertFalse(api.mutations)

    def test_artifact_readback_and_frozen_identity_changes_stop_downloads(self):
        entries = publisher.resolve_artifacts(self.api, self.request)
        changed = copy.deepcopy(entries)
        changed[next(iter(changed))]["sha256"] = "c" * 64
        self.reject(publisher.resolve_artifacts, self.api, self.request, changed)
        entry = self.api.artifact_listing["artifacts"][0]
        self.api.routes[P + "/actions/artifacts/" + str(entry["id"])]["digest"] = "sha256:" + "c" * 64
        self.reject(publisher.resolve_artifacts, self.api, self.request)
        self.assertFalse(self.api.downloads)

    def test_zip_stored_and_deflated_round_trip_without_extraction(self):
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raw = zip_bytes(self.api.files, compression=compression)
            self.assertEqual(publisher.unpack_archive(raw, archive_entry(raw), gate.PUBLIC_FILES), self.api.files)
        self.assertEqual(list(self.root.iterdir()), [self.root / "docs"])

    def test_zip_must_match_archive_size_and_digest_before_parsing(self):
        raw = zip_bytes({gate.REPORT_NAME: b"fixture"})
        for entry in ({"size": len(raw) + 1, "sha256": publisher.digest(raw)},
                      {"size": len(raw), "sha256": "c" * 64}):
            with mock.patch.object(publisher.zipfile, "ZipFile") as archive:
                self.reject(publisher.unpack_archive, raw, entry, {gate.REPORT_NAME})
                archive.assert_not_called()
        self.reject(publisher.unpack_archive, b"notzip", archive_entry(b"notzip"), {gate.REPORT_NAME})

    def test_zip_paths_duplicates_extra_members_comments_and_empty_are_rejected(self):
        names = {gate.REPORT_NAME}
        for name in ("../" + gate.REPORT_NAME, "/" + gate.REPORT_NAME, "dir/" + gate.REPORT_NAME,
                     "dir\\" + gate.REPORT_NAME, "C:" + gate.REPORT_NAME, gate.REPORT_NAME + "/", "OTHER.json"):
            raw = zip_bytes({name: b"fixture"})
            with self.subTest(name=name):
                self.reject(publisher.unpack_archive, raw, archive_entry(raw), names)
        for members in ([(gate.REPORT_NAME, b"a"), (gate.REPORT_NAME, b"b")],
                        [(gate.REPORT_NAME, b"a"), ("private.txt", b"b")], [(gate.REPORT_NAME, b"")]):
            raw = zip_bytes(members)
            self.reject(publisher.unpack_archive, raw, archive_entry(raw), names)
        raw = zip_bytes({gate.REPORT_NAME: b"fixture"}, comment=b"unreviewed metadata")
        self.reject(publisher.unpack_archive, raw, archive_entry(raw), names)

    def test_zip_duplicate_member_name_with_expected_count_is_rejected(self):
        members = list(self.api.files.items())
        members[1] = (members[0][0], members[1][1])
        raw = zip_bytes(members)
        self.reject(publisher.unpack_archive, raw, archive_entry(raw), gate.PUBLIC_FILES)

    def test_zip_links_special_files_and_dos_directories_are_rejected(self):
        for mode, dos in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFDIR | 0o755, 0),
                          (stat.S_IFIFO | 0o600, 0), (stat.S_IFREG | 0o600, 0x10)):
            info = zipfile.ZipInfo(gate.REPORT_NAME)
            info.create_system = 3
            info.external_attr = (mode << 16) | dos
            raw = zip_bytes([(info, b"target")])
            with self.subTest(mode=mode, dos=dos):
                self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})

    def test_zip_member_bounds_compression_flags_and_crc_are_checked(self):
        raw = zip_bytes({gate.REPORT_NAME: b"too large"})
        with mock.patch.dict(publisher.BOUNDS, {gate.REPORT_NAME: 3}):
            self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})
        raw = zip_bytes({gate.REPORT_NAME: b"fixture"}, compression=zipfile.ZIP_BZIP2)
        self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})
        original = zip_bytes({gate.REPORT_NAME: b"fixture"})
        central = original.index(b"PK\x01\x02")
        for flag in (1, 64, 8192):
            raw = bytearray(original)
            struct.pack_into("<H", raw, 6, flag)
            struct.pack_into("<H", raw, central + 8, flag)
            raw = bytes(raw)
            self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})
        raw = bytearray(original)
        raw[30 + len(gate.REPORT_NAME)] ^= 1
        raw = bytes(raw)
        with self.assertRaises(zipfile.BadZipFile):
            publisher.unpack_archive(raw, archive_entry(raw), {gate.REPORT_NAME})


    def test_zip_end_record_rejected_before_central_directory_allocation(self):
        original = zip_bytes({gate.REPORT_NAME: b"fixture"})
        edits = [(4, "H", 1), (6, "H", 1), (8, "H", 2), (10, "H", 2),
                 (8, "H", 65535), (10, "H", 65535), (12, "L", 513),
                 (12, "L", 0xffffffff), (16, "L", 0), (16, "L", 0xffffffff), (20, "H", 1)]
        for offset, kind, value in edits:
            raw = bytearray(original)
            struct.pack_into("<" + kind, raw, len(raw) - 22 + offset, value)
            raw = bytes(raw)
            with self.subTest(offset=offset, value=value), mock.patch.object(publisher.zipfile, "ZipFile") as parser:
                self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})
                parser.assert_not_called()
        for raw in (original + b"trailing-data", original[:-1],
                    original[:-22] + b"PK\x06\x07" + b"\x00" * 16 + original[-22:]):
            with mock.patch.object(publisher.zipfile, "ZipFile") as parser:
                self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})
                parser.assert_not_called()

    def test_each_artifact_has_allowlist_specific_archive_limit(self):
        for item in self.api.artifact_listing["artifacts"]:
            names = publisher.artifact_names(SOURCE)[item["name"]]
            limit = publisher.archive_bound(names)
            self.assertLessEqual(limit, publisher.MAX_ARCHIVE)
            oversized = dict(item, size_in_bytes=limit + 1)
            self.reject(publisher.artifact_identity, oversized, item["name"], self.request)
        raw = zip_bytes({gate.REPORT_NAME: b"fixture"})
        with mock.patch.object(publisher, "archive_bound", return_value=len(raw) - 1), mock.patch.object(publisher.zipfile, "ZipFile") as parser:
            self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})
            parser.assert_not_called()

    def test_zip_member_filename_nul_is_rejected_instead_of_truncated(self):
        raw = zip_bytes({gate.REPORT_NAME + "Xextra": b"fixture"})
        raw = raw.replace((gate.REPORT_NAME + "Xextra").encode(), (gate.REPORT_NAME + "\x00extra").encode())
        self.reject(publisher.unpack_archive, raw, archive_entry(raw), {gate.REPORT_NAME})


class EvidenceAndPlanTests(FixtureCase):
    def test_preparation_preserves_exact_six_package_bytes_and_builds_frozen_plan(self):
        plan, public = self.prepare()
        self.assertEqual(set(public), publisher.ASSETS)
        self.assertEqual({name: public[name] for name in gate.PUBLIC_FILES}, self.api.files)
        self.assertEqual(public[gate.AGGREGATE_REPORT], self.api.evidence)
        self.assertEqual(plan["assets"], publisher.file_entries(public))
        manifest = json.loads(public[publisher.RELEASE_MANIFEST])
        self.assertEqual(manifest["embeddedVersion"], gate.VERSION)
        self.assertEqual(manifest["sourceCommit"], SOURCE)
        self.assertEqual(manifest["publisherSourceCommit"], PUBLISHER_SHA)
        self.assertEqual(manifest["acceptanceBranch"], "main")
        self.assertFalse(manifest["cryptographicAttestation"])
        self.assertFalse(manifest["platformImmutabilityClaimed"])
        self.assertTrue(all(v is False for v in manifest["coverage"].values()))
        self.assertEqual(len(self.api.downloads), 7)
        self.assertFalse(self.api.mutations)
        frozen, rebuilt = self.prepare(FakeAPI(), plan)
        self.assertEqual(frozen, plan)
        self.assertEqual(rebuilt, public)

    def test_real_pe_verifier_rejects_synthetic_fixture_bytes(self):
        real_verifier = gate.resources.verify_pe
        with mock.patch.object(gate.resources, "verify_pe", wraps=real_verifier) as pe:
            with self.assertRaises(gate.resources.Rejected):
                publisher.validate_evidence(self.api.evidence, self.api.files, self.api.reports, self.request)
            pe.assert_called_once()

    def test_evidence_requires_exact_canonical_shape_false_coverage_and_hashes(self):
        evidence = json.loads(self.api.evidence)
        edits = [("source", "c" * 40), ("runID", "124"), ("status", "fully-accepted"),
                 ("distributionStatus", "signed"), ("crossOSRebuildEquivalence", True), ("extra", "private")]
        with mock.patch.object(gate.resources, "verify_pe", side_effect=fixtures.fake_pe):
            self.assertEqual(publisher.validate_evidence(self.api.evidence, self.api.files, self.api.reports, self.request), evidence)
            for key, value in edits:
                bad = copy.deepcopy(evidence)
                bad[key] = value
                with self.subTest(key=key):
                    self.reject(publisher.validate_evidence, publisher.canonical(bad), self.api.files, self.api.reports, self.request)
            for key in evidence["coverage"]:
                bad = copy.deepcopy(evidence)
                bad["coverage"][key] = True
                self.reject(publisher.validate_evidence, publisher.canonical(bad), self.api.files, self.api.reports, self.request)
            bad = copy.deepcopy(evidence)
            bad["publicFilesSHA256"][gate.SETUP_NAME] = "c" * 64
            self.reject(publisher.validate_evidence, publisher.canonical(bad), self.api.files, self.api.reports, self.request)
            self.reject(publisher.validate_evidence, json.dumps(evidence).encode(), self.api.files, self.api.reports, self.request)

    def test_four_distinct_canonical_passes_require_same_source_run_and_hashes(self):
        with mock.patch.object(gate.resources, "verify_pe", side_effect=fixtures.fake_pe):
            for key, value in (("source", "c" * 40), ("runID", "124"), ("setupSHA256", "c" * 64),
                               ("serviceSHA256", "c" * 64), ("driverSHA256", "c" * 64),
                               ("sourceInputsSHA256", "c" * 64), ("machine", "FRESH-VM-0"), ("status", "failed")):
                reports = dict(self.api.reports)
                changed = json.loads(reports["pending-transport"])
                changed[key] = value
                reports["pending-transport"] = publisher.canonical(changed)
                with self.subTest(key=key):
                    self.reject(publisher.validate_evidence, self.api.evidence, self.api.files, reports, self.request)
            for case in gate.CHECKS:
                reports = dict(self.api.reports)
                reports.pop(case)
                self.reject(publisher.validate_evidence, self.api.evidence, self.api.files, reports, self.request)
            reports = dict(self.api.reports)
            reports["install-uninstall"] = json.dumps(json.loads(reports["install-uninstall"])).encode()
            self.reject(publisher.validate_evidence, self.api.evidence, self.api.files, reports, self.request)

    def test_prepare_rejects_accepted_package_with_different_input_bytes(self):
        name = "windows-setup-public-input-" + SOURCE
        entry = next(item for item in self.api.artifact_listing["artifacts"] if item["name"] == name)
        files = dict(self.api.files)
        files[gate.SETUP_NAME] += b"changed"
        self.api.set_artifact(entry["id"], name, files)
        self.reject(self.prepare)
        self.assertFalse(self.api.mutations)

    def test_frozen_plan_reconstruction_detects_new_docs_native_jobs_and_artifacts(self):
        plan, _ = self.prepare()
        for name in publisher.GUIDES:
            path = self.root / "docs" / name
            original = path.read_bytes()
            path.write_bytes(original + b"changed\n")
            self.reject(self.prepare, FakeAPI(), plan)
            path.write_bytes(original)
        api = FakeAPI()
        api.routes[P + "/actions/runs/123/attempts/1/jobs?per_page=100"]["jobs"][0]["id"] += 999
        self.reject(self.prepare, api, plan)
        api = FakeAPI()
        api.artifact_listing["artifacts"][0]["id"] += 999
        self.reject(self.prepare, api, plan)

    def test_preparation_closes_source_native_and_artifact_read_races(self):
        for target in (P + "/git/ref/heads/windows-prerelease", P + "/actions/runs/123",
                       P + "/actions/runs/123/artifacts?per_page=100"):
            api = FakeAPI()
            seen = 0
            def hook(method, path, value, _api):
                nonlocal seen
                if path == target:
                    seen += 1
                    if seen == 2:
                        if "object" in value:
                            value["object"]["sha"] = "c" * 40
                        elif "run_attempt" in value:
                            value["run_attempt"] = 2
                        else:
                            value["artifacts"][0]["digest"] = "sha256:" + "c" * 64
                return value
            api.hook = hook
            with self.subTest(target=target):
                self.reject(self.prepare, api)
                self.assertFalse(api.mutations)

    def test_plan_schema_identity_asset_bounds_and_unique_ids_are_strict(self):
        plan, _ = self.prepare()
        mutations = [lambda p: p.update(extra=True), lambda p: p.update(sourceTree="c" * 40),
                     lambda p: p["request"].update(version="v0.1.0-windows-preview.2"),
                     lambda p: p["native"].update(workflowID=True), lambda p: p["assets"].pop(gate.SETUP_NAME),
                     lambda p: p["assets"][gate.SETUP_NAME].update(size=True),
                     lambda p: p["assets"][gate.SETUP_NAME].update(size=publisher.BOUNDS[gate.SETUP_NAME] + 1),
                     lambda p: p["assets"][gate.SETUP_NAME].update(sha256="A" * 64)]
        for mutate in mutations:
            bad = copy.deepcopy(plan)
            mutate(bad)
            self.reject(publisher.validate_plan, bad, self.request)
        bad = copy.deepcopy(plan)
        artifacts = list(bad["artifacts"].values())
        artifacts[1]["id"] = artifacts[0]["id"]
        self.reject(publisher.validate_plan, bad, self.request)
        bad = copy.deepcopy(plan)
        jobs = bad["native"]["jobs"]
        names = list(jobs)
        jobs[names[1]] = jobs[names[0]]
        self.reject(publisher.validate_plan, bad, self.request)

    def test_frozen_plan_base64_digest_canonical_and_size_are_checked(self):
        plan, _ = self.prepare()
        raw = publisher.canonical(plan)
        env = {"TRACEBOLT_VERIFIED_PLAN": base64.b64encode(raw).decode(), "TRACEBOLT_VERIFIED_PLAN_SHA256": publisher.digest(raw)}
        self.assertEqual(publisher.decode_plan(env, self.request), plan)
        for bad in ({}, dict(env, TRACEBOLT_VERIFIED_PLAN_SHA256="c" * 64),
                    dict(env, TRACEBOLT_VERIFIED_PLAN="A" * (4 * publisher.MAX_PLAN // 3 + 5))):
            self.reject(publisher.decode_plan, bad, self.request)
        raw = json.dumps(plan).encode()
        env.update(TRACEBOLT_VERIFIED_PLAN=base64.b64encode(raw).decode(), TRACEBOLT_VERIFIED_PLAN_SHA256=publisher.digest(raw))
        self.reject(publisher.decode_plan, env, self.request)

    def test_guides_reject_links_empty_crlf_and_nonregular_files(self):
        name = next(iter(publisher.GUIDES))
        path = self.root / "docs" / name
        for raw in (b"", b"line\r\n"):
            path.write_bytes(raw)
            self.reject(publisher.read_guides, self.root)
        path.unlink()
        path.symlink_to(self.root / "absent")
        self.reject(publisher.read_guides, self.root)
        path.unlink()
        path.mkdir()
        self.reject(publisher.read_guides, self.root)


class PublicationTests(FixtureCase):
    def test_create_tag_draft_upload_once_publish_and_read_all_public_bytes(self):
        plan, files = self.prepare()
        url = publisher.publish(self.api, self.request, plan, files)
        self.assertEqual(url, "https://github.com/" + publisher.REPOSITORY + "/releases/tag/" + VERSION)
        mutations = self.api.mutations
        self.assertEqual(mutations[:2], [("POST", P + "/git/refs"), ("POST", P + "/releases")])
        self.assertEqual(mutations[-1], ("PATCH", P + "/releases/701"))
        self.assertEqual(len(mutations), 3 + len(publisher.ASSETS))
        self.assertEqual(len(mutations), len(set(mutations)))
        self.assertEqual({name: item[0] for name, item in self.api.uploads.items()}, files)
        self.assertEqual({name for _, name, _ in self.api.public_reads}, publisher.ASSETS)
        self.assertFalse(self.api.release["draft"])
        self.assertTrue(self.api.release["prerelease"])
        self.assertEqual(self.api.release["make_latest"], "false")
        self.assertEqual(self.api.tag["object"]["sha"], SOURCE)

    def test_existing_tag_release_or_untagged_draft_never_gets_adopted(self):
        plan, files = self.prepare()
        for kind in ("tag", "published", "draft"):
            api = FakeAPI()
            if kind == "tag":
                api.tag = {"existing": True}
            else:
                api.release = {"draft": kind == "draft", "tag_name": VERSION}
            with self.subTest(kind=kind):
                self.reject(publisher.publish, api, self.request, plan, files)
                self.assertFalse(api.mutations)

    def test_freshness_inventory_is_bounded_and_checks_later_pages(self):
        self.api.routes[P + "/releases?per_page=100&page=1"] = [{"tag_name": "other-" + str(i)} for i in range(100)]
        self.api.routes[P + "/releases?per_page=100&page=2"] = [{"tag_name": VERSION, "draft": True}]
        self.reject(publisher.require_fresh_version, self.api, VERSION)
        api = FakeAPI()
        for page in range(1, 11):
            api.routes[P + f"/releases?per_page=100&page={page}"] = [{"tag_name": "other"}] * 100
        self.reject(publisher.require_fresh_version, api, VERSION)
        self.assertEqual(sum("/releases?" in call[1] for call in api.calls), 10)

    def test_changed_publication_bytes_and_prewrite_leases_stop_every_mutation(self):
        plan, files = self.prepare()
        for name in publisher.ASSETS:
            bad = dict(files)
            bad[name] += b"changed"
            api = FakeAPI()
            with self.subTest(name=name):
                self.reject(publisher.publish, api, self.request, plan, bad)
                self.assertFalse(api.mutations)
        api = FakeAPI()
        api.routes[P + "/git/ref/heads/windows-prerelease"]["object"]["sha"] = "c" * 40
        self.reject(publisher.publish, api, self.request, plan, files)
        self.assertFalse(api.mutations)

    def test_tag_race_or_ambiguous_create_is_not_retried_or_cleaned_up(self):
        plan, files = self.prepare()
        for failure in (publisher.Rejected("fixture 422"), TimeoutError("ambiguous fixture write")):
            api = FakeAPI()
            def hook(method, path, value, _api):
                if method == "POST" and path == P + "/git/refs":
                    raise failure
                return value
            api.hook = hook
            with self.subTest(failure=type(failure).__name__), self.assertRaises(type(failure)):
                publisher.publish(api, self.request, plan, files)
            self.assertEqual(api.mutations, [("POST", P + "/git/refs")])
            self.assertIsNotNone(api.tag)
            self.assertIsNone(api.release)

    def test_wrong_tag_creation_response_stops_before_creating_draft(self):
        plan, files = self.prepare()
        def hook(method, path, value, _api):
            if method == "POST" and path == P + "/git/refs":
                value["object"]["sha"] = "c" * 40
            return value
        self.api.hook = hook
        self.reject(publisher.publish, self.api, self.request, plan, files)
        self.assertEqual(self.api.mutations, [("POST", P + "/git/refs")])

    def test_new_draft_requires_exact_identity_and_empty_inventory(self):
        plan, files = self.prepare()
        for key, replacement in (("id", True), ("tag_name", "wrong"), ("target_commitish", PUBLISHER_SHA),
                                 ("draft", False), ("prerelease", False), ("name", "wrong"), ("body", "wrong"),
                                 ("assets", [{"name": "existing"}]), ("html_url", "https://evil.invalid/draft")):
            api = FakeAPI()
            def hook(method, path, value, _api):
                if method == "POST" and path == P + "/releases":
                    value[key] = replacement
                return value
            api.hook = hook
            with self.subTest(key=key):
                self.reject(publisher.publish, api, self.request, plan, files)
                self.assertEqual(len(api.mutations), 2)
                self.assertFalse(api.uploads)

    def test_upload_response_requires_new_id_exact_digest_size_name_and_url(self):
        plan, files = self.prepare()
        for key, replacement in (("id", True), ("name", "wrong.exe"), ("state", "new"), ("size", 1),
                                 ("digest", "sha256:" + "c" * 64), ("browser_download_url", "https://evil.invalid/asset")):
            api = FakeAPI()
            def hook(method, path, value, _api):
                if method == "POST" and "/assets?name=" in path:
                    value[key] = replacement
                return value
            api.hook = hook
            with self.subTest(key=key):
                self.reject(publisher.publish, api, self.request, plan, files)
                self.assertEqual(len(api.uploads), 1)
                self.assertEqual(len(api.mutations), 3)
                self.assertTrue(api.release["draft"])

    def test_reused_upload_id_is_rejected_without_further_upload_or_publish(self):
        plan, files = self.prepare()
        def hook(method, path, value, _api):
            if method == "POST" and "/assets?name=" in path:
                value["id"] = 999
            return value
        self.api.hook = hook
        self.reject(publisher.publish, self.api, self.request, plan, files)
        self.assertEqual(len(self.api.uploads), 2)
        self.assertTrue(self.api.release["draft"])
        self.assertFalse(any(method == "PATCH" for method, _ in self.api.mutations))

    def test_partial_upload_failure_preserves_draft_and_never_retries(self):
        plan, files = self.prepare()
        def hook(method, path, value, api):
            if method == "POST" and "/assets?name=" in path and len(api.uploads) == 3:
                raise TimeoutError("fixture ambiguous upload")
            return value
        self.api.hook = hook
        with self.assertRaises(TimeoutError):
            publisher.publish(self.api, self.request, plan, files)
        self.assertEqual(len(self.api.uploads), 3)
        self.assertTrue(self.api.release["draft"])
        self.assertEqual(len(self.api.mutations), len(set(self.api.mutations)))
        self.assertFalse(any(method == "PATCH" for method, _ in self.api.mutations))

    def test_asset_readback_missing_extra_duplicate_and_replaced_ids_stop_draft(self):
        plan, files = self.prepare()
        for change in (lambda v: v.pop(), lambda v: v.append(copy.deepcopy(v[0])),
                       lambda v: v[1].update(name=v[0]["name"]), lambda v: v[0].update(id=v[0]["id"] + 1),
                       lambda v: v[0].update(digest="sha256:" + "c" * 64)):
            api = FakeAPI()
            def hook(method, path, value, _api):
                if method == "GET" and path.endswith("/assets?per_page=100"):
                    change(value)
                return value
            api.hook = hook
            self.reject(publisher.publish, api, self.request, plan, files)
            self.assertTrue(api.release["draft"])
            self.assertFalse(any(method == "PATCH" for method, _ in api.mutations))

    def test_changed_tag_draft_publisher_and_artifact_lease_after_upload_stop_publish(self):
        plan, files = self.prepare()
        for target in ("tag", "draft", "publisher", "run", "artifacts"):
            api = FakeAPI()
            def hook(method, path, value, api):
                if len(api.uploads) == len(publisher.ASSETS) and method == "GET":
                    if target == "tag" and path == P + "/git/ref/tags/" + VERSION:
                        value["object"]["sha"] = "c" * 40
                    elif target == "draft" and path == P + "/releases/701":
                        value["id"] += 1
                    elif target == "publisher" and path == P + "/git/ref/heads/windows-prerelease":
                        value["object"]["sha"] = "c" * 40
                    elif target == "run" and path == P + "/actions/runs/123":
                        value["run_attempt"] = 2
                    elif target == "artifacts" and path.endswith("/artifacts?per_page=100"):
                        value["artifacts"][0]["digest"] = "sha256:" + "c" * 64
                return value
            api.hook = hook
            with self.subTest(target=target):
                self.reject(publisher.publish, api, self.request, plan, files)
                self.assertTrue(api.release["draft"])
                self.assertFalse(any(method == "PATCH" for method, _ in api.mutations))

    def test_uncertain_publish_patch_is_never_retried(self):
        plan, files = self.prepare()
        def hook(method, path, value, _api):
            if method == "PATCH":
                raise TimeoutError("fixture ambiguous publication")
            return value
        self.api.hook = hook
        with self.assertRaises(TimeoutError):
            publisher.publish(self.api, self.request, plan, files)
        self.assertFalse(self.api.release["draft"])
        self.assertEqual(sum(method == "PATCH" for method, _ in self.api.mutations), 1)
        self.assertFalse(self.api.public_reads)

    def test_public_download_wrong_bytes_or_unavailable_never_republish(self):
        plan, files = self.prepare()
        for failure in ("hash", "size", "network"):
            api = FakeAPI()
            def public_hook(_name, raw):
                if failure == "network":
                    raise TimeoutError("fixture unavailable public bytes")
                return bytes([raw[0] ^ 1]) + raw[1:] if failure == "hash" else raw + b"changed"
            api.public_hook = public_hook
            with self.subTest(failure=failure), self.assertRaises((publisher.Rejected, TimeoutError)):
                publisher.publish(api, self.request, plan, files)
            self.assertFalse(api.release["draft"])
            self.assertEqual(len(api.public_reads), 1)
            self.assertEqual(sum(method == "PATCH" for method, _ in api.mutations), 1)
            self.assertEqual(len(api.mutations), len(set(api.mutations)))

    def test_post_public_download_metadata_replacement_is_detected(self):
        plan, files = self.prepare()
        def hook(method, path, value, api):
            if method == "GET" and path.endswith("/assets?per_page=100") and len(api.public_reads) == len(publisher.ASSETS):
                value[0]["id"] += 1
            return value
        self.api.hook = hook
        self.reject(publisher.publish, self.api, self.request, plan, files)
        self.assertEqual(len(self.api.public_reads), len(publisher.ASSETS))
        self.assertEqual(sum(method == "PATCH" for method, _ in self.api.mutations), 1)

    def test_main_verify_produces_plan_with_readonly_client_only(self):
        env = environment()
        env.update(GITHUB_TOKEN="fixture-token", GITHUB_OUTPUT=str(self.root / "outputs"))
        actual_prepare = publisher.prepare
        def prepare(api, request, *, frozen=None):
            return actual_prepare(api, request, frozen=frozen, root=self.root)
        with mock.patch.object(publisher, "verify_checkout"), mock.patch.object(publisher, "GitHubAPI", return_value=self.api) as constructor, mock.patch.object(publisher, "prepare", side_effect=prepare), mock.patch.object(gate.resources, "verify_pe", side_effect=fixtures.fake_pe), mock.patch("builtins.print"):
            publisher.main(["--verify"], env)
        constructor.assert_called_once_with("fixture-token", write=False)
        outputs = dict(line.split("=", 1) for line in (self.root / "outputs").read_text().splitlines())
        plan = publisher.decode_plan({"TRACEBOLT_VERIFIED_PLAN": outputs["plan"], "TRACEBOLT_VERIFIED_PLAN_SHA256": outputs["plan_sha256"]}, self.request)
        self.assertEqual(set(plan["assets"]), publisher.ASSETS)
        self.assertFalse(self.api.mutations)

    def test_main_publish_requires_frozen_plan_before_creating_any_api_client(self):
        env = environment(True)
        with mock.patch.object(publisher, "verify_checkout"), mock.patch.object(publisher, "GitHubAPI") as constructor:
            self.reject(publisher.main, ["--publish"], env)
            constructor.assert_not_called()


    def test_release_identity_changes_during_public_reads_are_detected(self):
        plan, files = self.prepare()
        for key, value in (("prerelease", False), ("body", "changed public claims"), ("target_commitish", PUBLISHER_SHA)):
            api = FakeAPI()
            def change_release(_name, raw):
                api.release[key] = value
                return raw
            api.public_hook = change_release
            with self.subTest(key=key):
                self.reject(publisher.publish, api, self.request, plan, files)
                self.assertEqual(len(api.public_reads), len(publisher.ASSETS))
                self.assertEqual(sum(method == "PATCH" for method, _ in api.mutations), 1)
                self.assertEqual(len(api.mutations), len(set(api.mutations)))

    def test_publisher_branch_lease_moving_during_public_reads_stops_success(self):
        plan, files = self.prepare()
        def change_branch(_name, raw):
            self.api.routes[P + "/git/ref/heads/windows-prerelease"]["object"]["sha"] = "c" * 40
            return raw
        self.api.public_hook = change_branch
        self.reject(publisher.publish, self.api, self.request, plan, files)
        self.assertEqual(len(self.api.public_reads), len(publisher.ASSETS))
        self.assertEqual(sum(method == "PATCH" for method, _ in self.api.mutations), 1)
        self.assertEqual(len(self.api.mutations), len(set(self.api.mutations)))

    def test_public_tag_lookup_must_still_resolve_same_release_after_downloads(self):
        plan, files = self.prepare()
        def hook(method, path, value, api):
            if method == "GET" and path == P + "/releases/tags/" + VERSION and len(api.public_reads) == len(publisher.ASSETS):
                value["id"] += 1
            return value
        self.api.hook = hook
        self.reject(publisher.publish, self.api, self.request, plan, files)
        self.assertEqual(sum(method == "PATCH" for method, _ in self.api.mutations), 1)

    def test_main_publish_reconstructs_readonly_before_constructing_write_client(self):
        plan, files = self.prepare()
        raw = publisher.canonical(plan)
        env = environment(True)
        env.update(GITHUB_TOKEN="fixture-token", TRACEBOLT_VERIFIED_PLAN=base64.b64encode(raw).decode(),
                   TRACEBOLT_VERIFIED_PLAN_SHA256=publisher.digest(raw))
        readonly, writer = FakeAPI(), FakeAPI()
        actual_prepare = publisher.prepare
        def prepare(api, request, *, frozen=None):
            self.assertIs(api, readonly)
            return actual_prepare(api, request, frozen=frozen, root=self.root)
        clients = []
        def constructor(_token, *, write):
            clients.append(write)
            if write:
                self.assertEqual(len(readonly.downloads), 7)
                self.assertFalse(readonly.mutations)
                return writer
            return readonly
        with mock.patch.object(publisher, "verify_checkout"), mock.patch.object(publisher, "GitHubAPI", side_effect=constructor), mock.patch.object(publisher, "prepare", side_effect=prepare), mock.patch.object(gate.resources, "verify_pe", side_effect=fixtures.fake_pe), mock.patch("builtins.print"):
            publisher.main(["--publish"], env)
        self.assertEqual(clients, [False, True])
        self.assertFalse(readonly.mutations)
        self.assertEqual({name: entry[0] for name, entry in writer.uploads.items()}, files)

    def test_failed_readonly_reconstruction_never_constructs_write_client(self):
        plan, _ = self.prepare()
        raw = publisher.canonical(plan)
        env = environment(True)
        env.update(GITHUB_TOKEN="fixture-token", TRACEBOLT_VERIFIED_PLAN=base64.b64encode(raw).decode(),
                   TRACEBOLT_VERIFIED_PLAN_SHA256=publisher.digest(raw))
        with mock.patch.object(publisher, "verify_checkout"), mock.patch.object(publisher, "GitHubAPI", return_value=self.api) as constructor, mock.patch.object(publisher, "prepare", side_effect=publisher.Rejected("fixture stopped")):
            self.reject(publisher.main, ["--publish"], env)
        constructor.assert_called_once_with("fixture-token", write=False)
        self.assertFalse(self.api.mutations)


class FakeResponse:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status, self.stream = status, io.BytesIO(body)
        self.headers = [("Content-Length", str(len(body)))] if headers is None else headers
    def getheaders(self):
        return list(self.headers)
    def read(self, size):
        return self.stream.read(size)


class ConnectionFactory:
    def __init__(self, responses):
        self.responses, self.calls, self.closed = list(responses), [], 0
    def __call__(self, host, port, **kwargs):
        factory = self
        class Connection:
            def request(self, method, path, body=None, headers=None):
                factory.calls.append({"host": host, "port": port, "method": method, "path": path,
                                      "body": body, "headers": dict(headers), "kwargs": kwargs})
            def getresponse(self):
                if not factory.responses:
                    raise AssertionError("Unexpected fixture connection")
                result = factory.responses.pop(0)
                if isinstance(result, Exception):
                    raise result
                return result
            def close(self):
                factory.closed += 1
        return Connection()


class HTTPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tls = mock.patch.object(publisher, "tls_context", return_value=object())
        self.tls.start()
        self.addCleanup(self.tls.stop)

    def api(self, responses=(), write=False):
        factory = ConnectionFactory(responses)
        return publisher.GitHubAPI("fixture-token", write=write, connection=factory), factory

    def reject(self, fn, *args, **kwargs):
        with self.assertRaises(publisher.Rejected):
            fn(*args, **kwargs)

    def test_token_is_required_and_cannot_contain_whitespace(self):
        for token in (None, "", "with space", "with\nnewline", "a" * 10001):
            self.reject(publisher.GitHubAPI, token)

    def test_readonly_client_rejects_writes_and_wrong_routes_before_connecting(self):
        api, factory = self.api()
        for method, path in (("POST", P + "/git/refs"), ("PATCH", P + "/releases/1"),
                             ("DELETE", P + "/releases/1"), ("GET", "/repos/other/Tracebolt"),
                             ("GET", P + "-other")):
            self.reject(api.request, method, path)
        self.assertFalse(factory.calls)

    def test_write_client_allows_only_three_fixed_mutation_routes(self):
        api, factory = self.api(write=True)
        for method, path in (("POST", P + "/issues"), ("POST", P + "/actions/runs/1/rerun"),
                             ("PATCH", P + "/git/refs/tags/x"), ("PATCH", P + "/releases/1/assets/2"),
                             ("DELETE", P + "/releases/1"), ("POST", P + "/releases/1/assets?name=../bad")):
            self.reject(api.request, method, path)
        self.assertFalse(factory.calls)

    def test_api_requests_authenticate_only_to_fixed_api_or_upload_hosts(self):
        api, factory = self.api([FakeResponse(200), FakeResponse(201)], write=True)
        self.assertEqual(api.request("GET", P), {})
        self.assertEqual(api.request("POST", P + "/releases/1/assets?name=SHA256SUMS", upload=b"fixture"), {})
        self.assertEqual([c["host"] for c in factory.calls], ["api.github.com", "uploads.github.com"])
        for call in factory.calls:
            self.assertEqual(call["headers"]["Authorization"], "Bearer fixture-token")
            self.assertEqual(call["headers"]["Accept-Encoding"], "identity")
        self.assertEqual(factory.closed, 2)

    def test_artifact_redirect_is_one_hop_with_no_token_or_cookie_forwarded(self):
        location = "https://fixture123.blob.core.windows.net/container/archive.zip?sig=fixture"
        api, factory = self.api([FakeResponse(302, headers=[("Location", location)]), FakeResponse(200, b"ZIP")])
        self.assertEqual(api.artifact(123, 3), b"ZIP")
        self.assertIn("Authorization", factory.calls[0]["headers"])
        self.assertNotIn("Authorization", factory.calls[1]["headers"])
        self.assertNotIn("Cookie", factory.calls[1]["headers"])
        self.assertEqual(factory.calls[1]["host"], "fixture123.blob.core.windows.net")
        self.assertEqual(factory.calls[1]["path"], "/container/archive.zip?sig=fixture")

    def test_public_downloads_and_redirects_are_unauthenticated(self):
        location = "https://release-assets.githubusercontent.com/github-production-release-asset/1/fixture?sig=fixture"
        api, factory = self.api([FakeResponse(302, headers=[("Location", location)]), FakeResponse(200, b"123")])
        self.assertEqual(api.public_asset(VERSION, "SHA256SUMS", 3), b"123")
        self.assertEqual([c["host"] for c in factory.calls], ["github.com", "release-assets.githubusercontent.com"])
        self.assertTrue(all("Authorization" not in c["headers"] and "Cookie" not in c["headers"] for c in factory.calls))
        api, factory = self.api([FakeResponse(200, b"123")])
        self.assertEqual(api.public_asset(VERSION, "SHA256SUMS", 3), b"123")
        self.assertEqual(len(factory.calls), 1)

    def test_redirect_url_parser_rejects_untrusted_hosts_ports_credentials_and_paths(self):
        for artifact in (False, True):
            for value in ("http://fixture123.blob.core.windows.net/a", "https://evil.invalid/a", "https://127.0.0.1/a",
                          "https://fixture123.blob.core.windows.net:443/a", "https://user@fixture123.blob.core.windows.net/a",
                          "https://fixture123.blob.core.windows.net/a#fragment", "https://fixture123.blob.core.windows.net/../a",
                          "https://fixture123.blob.core.windows.net/a\\b", "https://fixture123.blob.core.windows.net/a\r\nHeader: bad",
                          "https://fixture123.blob.core.windows.net.evil.invalid/a", "https://api.github.com/a"):
                with self.subTest(artifact=artifact, value=value):
                    self.reject(publisher.redirect_target, value, artifact)
        self.reject(publisher.redirect_target, "https://release-assets.githubusercontent.com/wrong/route", False)

    def test_credentials_cannot_be_forwarded_even_to_approved_download_host(self):
        api, factory = self.api()
        for host in ("github.com", "release-assets.githubusercontent.com", "fixture123.blob.core.windows.net", "evil.invalid"):
            self.reject(api._request, host, "GET", "/fixture", token=True)
        self.assertFalse(factory.calls)

    def test_ambiguous_or_second_redirect_fails_without_retry(self):
        url = "https://fixture123.blob.core.windows.net/a"
        api, factory = self.api([FakeResponse(302, headers=[("Location", url), ("location", url)])])
        self.reject(api.artifact, 1, 100)
        self.assertEqual(len(factory.calls), 1)
        api, factory = self.api([FakeResponse(302, headers=[("Location", url)]), FakeResponse(302, headers=[("Location", url)])])
        self.reject(api.artifact, 1, 100)
        self.assertEqual(len(factory.calls), 2)
        self.assertEqual(factory.closed, 2)

    def test_http_errors_timeouts_and_invalid_json_never_retry(self):
        for response, error in ((FakeResponse(500), publisher.Rejected), (TimeoutError("fixture"), TimeoutError),
                                (FakeResponse(200, b'{"x":1,"x":2}'), publisher.Rejected)):
            api, factory = self.api([response])
            with self.assertRaises(error):
                api.request("GET", P)
            self.assertEqual(len(factory.calls), 1)
            self.assertEqual(factory.closed, 1)

    def test_bounded_response_rejects_duplicate_lengths_compression_truncation_and_overflow(self):
        for headers, body in (([("Content-Length", "3"), ("content-length", "3")], b"123"),
                              ([("Content-Length", "4")], b"123"), ([("Content-Length", "999")], b"123"),
                              ([("Content-Length", "-1")], b"123"), ([("Content-Encoding", "gzip")], b"123"),
                              ([("Content-Encoding", "identity"), ("Content-Encoding", "identity")], b"123"),
                              ([], b"1234")):
            with self.subTest(headers=headers):
                self.reject(publisher.response_bytes, FakeResponse(200, body, headers), 3)
        self.assertEqual(publisher.response_bytes(FakeResponse(200, b"123"), 3), b"123")

    def test_response_time_limit_is_enforced_without_sleeping(self):
        response = FakeResponse(200, b"fixture")
        with mock.patch.object(publisher.time, "monotonic", side_effect=[0, 601]):
            self.reject(publisher.response_bytes, response, 100)

    def test_dns_empty_large_mixed_or_non443_destinations_fail_before_connect(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443))
        for addresses in ([], [public] * 17, [public, private]):
            connection = publisher.OfficialConnection("api.github.com", 443)
            with mock.patch.object(publisher.socket, "getaddrinfo", return_value=addresses), mock.patch.object(publisher.socket, "socket") as sock:
                self.reject(connection.connect)
                sock.assert_not_called()
        connection = publisher.OfficialConnection("api.github.com", 8443)
        with mock.patch.object(publisher.socket, "getaddrinfo") as dns:
            self.reject(connection.connect)
            dns.assert_not_called()

    def test_json_duplicate_nonfinite_invalid_utf8_and_size_are_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}', b"\xff", b"", b"not json"):
            self.reject(publisher.strict_json, raw)
        self.reject(publisher.strict_json, b"{}", 1)
        self.assertEqual(publisher.strict_json(b'{"a":1}'), {"a": 1})

    def test_official_connection_rejects_private_dns_before_socket_creation(self):
        for host in ("api.github.com", "fixture123.blob.core.windows.net"):
            for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.0.1", "0.0.0.0", "224.0.0.1", "::1"):
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                connection = publisher.OfficialConnection(host, 443)
                result = [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))]
                with mock.patch.object(publisher.socket, "getaddrinfo", return_value=result), mock.patch.object(publisher.socket, "socket") as sock:
                    with self.subTest(host=host, address=address):
                        self.reject(connection.connect)
                        sock.assert_not_called()
        connection = publisher.OfficialConnection("evil.invalid", 443)
        with mock.patch.object(publisher.socket, "getaddrinfo") as resolve:
            self.reject(connection.connect)
            resolve.assert_not_called()


class SourceAndWorkflowPolicyTests(unittest.TestCase):
    def test_import_is_inert_without_network_processes_or_filesystem_writes(self):
        with mock.patch.object(sys, "dont_write_bytecode", True), mock.patch.object(publisher.socket, "getaddrinfo") as dns, mock.patch.object(publisher.socket, "socket") as sock, mock.patch.object(publisher.http.client.HTTPSConnection, "request") as http, mock.patch.object(publisher.subprocess, "run") as run, mock.patch.object(publisher.subprocess, "Popen") as popen, mock.patch.object(Path, "write_bytes") as write_bytes, mock.patch.object(Path, "write_text") as write_text, mock.patch.object(Path, "mkdir") as mkdir:
            fresh = load("windows_prerelease_import_inert", ROOT / "deploy/release/publish-windows-prerelease.py")
            self.assertEqual(fresh.REPOSITORY, publisher.REPOSITORY)
            for action in (dns, sock, http, run, popen, write_bytes, write_text, mkdir):
                action.assert_not_called()

    def test_cli_failure_is_fixed_sanitized_text_without_environment_or_exception_leak(self):
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["publish-windows-prerelease.py", "--verify"]), mock.patch.object(sys, "dont_write_bytecode", True), mock.patch.dict(publisher.os.environ, {"TRACEBOLT_RELEASE_SOURCE": "fixture-private-invalid-input", "GITHUB_TOKEN": "fixture-private-token"}, clear=True), mock.patch.object(sys, "stderr", stderr), mock.patch.object(publisher.socket, "getaddrinfo") as dns, mock.patch.object(publisher.subprocess, "run") as command:
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / "deploy/release/publish-windows-prerelease.py"), run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "Windows prerelease stopped. No automatic retry or cleanup was attempted; inspect the run and any partial tag/release before another publication.\n")
        dns.assert_not_called()
        command.assert_not_called()

    def test_workflow_is_manual_default_readonly_and_explicitly_publishes_after_verify(self):
        text = (ROOT / publisher.PUBLISH_WORKFLOW).read_text()
        self.assertIn("  workflow_dispatch:", text)
        for event in ("push:", "pull_request:", "pull_request_target:", "schedule:", "workflow_call:", "workflow_run:", "release:"):
            self.assertNotRegex(text, r"(?m)^  " + re.escape(event))
        self.assertEqual(text.count("default: false"), 1)
        self.assertIn("publish:\n", text)
        for name in ("expected_source_sha", "acceptance_run_id", "version", "expected_publisher_sha", "publish"):
            self.assertIn("      " + name + ":", text)
        top, jobs = text.split("jobs:\n", 1)
        self.assertIn("permissions:\n  contents: read\n  actions: read", top)
        self.assertNotIn("contents: write", top)
        verify, publish = jobs.split("  publish:\n", 1)
        self.assertIn("  verify:", verify)
        self.assertIn("contents: read", verify)
        self.assertNotIn("contents: write", verify)
        self.assertIn("--verify", verify)
        self.assertNotIn("--publish", verify)
        self.assertIn("needs: verify", publish)
        self.assertIn("inputs.publish == true", publish)
        self.assertIn("needs.verify.result == 'success'", publish)
        self.assertIn("contents: write", publish)
        self.assertIn("actions: read", publish)
        self.assertIn("--publish", publish)
        for output in ("TRACEBOLT_VERIFIED_PLAN: ${{ needs.verify.outputs.plan }}",
                       "TRACEBOLT_VERIFIED_PLAN_SHA256: ${{ needs.verify.outputs.plan_sha256 }}"):
            self.assertIn(output, publish)
        self.assertEqual(text.count("contents: write"), 1)
        self.assertIn("concurrency:\n  group: windows-prerelease-${{ inputs.version }}\n  cancel-in-progress: false", text)

    def test_workflow_is_owner_source_pinned_and_has_no_broad_write_or_build_authority(self):
        text = (ROOT / publisher.PUBLISH_WORKFLOW).read_text()
        for guard in ("github.repository == 'storminator89/Tracebolt'", "github.repository_id == '1403204207'",
                      "github.repository_owner == 'storminator89'", "github.repository_owner_id == '30489872'",
                      "github.actor == 'storminator89'", "github.actor_id == '30489872'",
                      "github.triggering_actor == 'storminator89'", "github.run_attempt == 1",
                      "github.sha == inputs.expected_publisher_sha", "github.workflow_sha == github.sha"):
            self.assertIn(guard, text)
        actions = re.findall(r"(?m)^\s+- uses: (\S+)", text)
        self.assertEqual(len(actions), 4)
        self.assertTrue(all(re.fullmatch(r"actions/(checkout|setup-python)@[a-f0-9]{40}", value) for value in actions))
        self.assertEqual(text.count("persist-credentials: false"), 2)
        self.assertEqual(text.count("ref: ${{ github.sha }}"), 2)
        self.assertEqual(text.count("runs-on: ubuntu-24.04"), 2)
        self.assertIn("python3 -I -B -m unittest discover -s tests/windows_release -v", text)
        self.assertIn("PYTHONDONTWRITEBYTECODE: '1'", text)
        for forbidden in ("write-all", "id-token:", "attestations:", "secrets.", "go build", "go test",
                          "--run-native", "--aggregate", "gh release", "git push", "workflow_dispatch --",
                          "delete-release", "signtool", "actions/upload-artifact", "actions/download-artifact"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
