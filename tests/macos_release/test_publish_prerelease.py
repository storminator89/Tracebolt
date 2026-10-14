"""Host-free adversarial checks for the default-off Mac publisher."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("macos_prerelease", ROOT / "deploy/macos-release/publish-prerelease.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class PublisherTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.run(["git", *args], cwd=root, check=True,
                              capture_output=True).stdout.decode("utf-8").strip()

    def temp_repo(self, root):
        self.git(root, "init", "-q")
        (root / "guide.md").write_bytes(b"reviewed guide\n")
        self.git(root, "add", "guide.md")
        self.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "Inert fixture")
        return self.git(root, "rev-parse", "HEAD"), self.git(root, "rev-parse", "HEAD^{tree}")

    def request(self):
        return {"source": publisher.REVIEWED_SOURCE_SHA, "sourceCIRunIDs": "101,102,103,104,105,106,107",
                "version": "v0.1.0-macos-preview.1", "publisherSHA": "a" * 40,
                "publisherRunID": "1235"}

    def env(self, publish=False):
        req = self.request()
        return {"TRACEBOLT_RELEASE_SOURCE": req["source"],
                "TRACEBOLT_SOURCE_CI_RUN_IDS": req["sourceCIRunIDs"],
                "TRACEBOLT_RELEASE_VERSION": req["version"],
                "TRACEBOLT_PUBLISHER_SHA": req["publisherSHA"],
                "TRACEBOLT_RELEASE_PUBLISH": "true" if publish else "false",
                "GITHUB_RUN_ID": req["publisherRunID"], "GITHUB_ACTIONS": "true",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": publisher.REPOSITORY,
                "GITHUB_REPOSITORY_ID": str(publisher.REPO_ID), "GITHUB_REPOSITORY_OWNER": publisher.OWNER,
                "GITHUB_REPOSITORY_OWNER_ID": str(publisher.OWNER_ID), "GITHUB_ACTOR": publisher.OWNER,
                "GITHUB_ACTOR_ID": str(publisher.OWNER_ID), "GITHUB_TRIGGERING_ACTOR": publisher.OWNER,
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REF": "refs/heads/main",
                "GITHUB_SHA": req["publisherSHA"], "GITHUB_WORKFLOW_SHA": req["publisherSHA"],
                "GITHUB_WORKFLOW_REF": publisher.REPOSITORY + "/" + publisher.WORKFLOW + "@refs/heads/main",
                "GITHUB_JOB": "publish" if publish else "verify", "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted"}

    def test_exact_owner_revision_and_explicit_publish(self):
        self.assertEqual(publisher.authorize(self.env(), False), self.request())
        self.assertEqual(publisher.authorize(self.env(True), True), self.request())
        for change in ({"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_ACTOR_ID": "1"},
                       {"GITHUB_SHA": "b" * 40}, {"GITHUB_REF": "refs/heads/other"},
                       {"RUNNER_OS": "macOS"}, {"TRACEBOLT_RELEASE_SOURCE": "b" * 40},
                       {"GITHUB_JOB": "publish"}):
            with self.subTest(change=change), self.assertRaises(publisher.Rejected):
                publisher.authorize(dict(self.env(), **change), False)
        with self.assertRaises(publisher.Rejected):
            publisher.authorize(self.env(), True)

    def test_version_and_json_closure(self):
        for version in ("v0.1.0", "v0.1.0-macos-preview.0", "v0.1.0-windows-preview.1",
                        "v01.1.0-macos-preview.1", "v0.1.0-macos-preview.1/x"):
            with self.subTest(version=version), self.assertRaises(publisher.Rejected):
                publisher.checked_request(dict(self.request(), version=version))
        with self.assertRaises(publisher.Rejected):
            publisher.strict_json(b'{"x":1,"x":2}')
        with self.assertRaises(publisher.Rejected):
            publisher.strict_json(b'{"x":NaN}')


    def test_seven_exact_source_push_runs_and_aggregate(self):
        request = self.request()
        routes = {}
        prefix = publisher.PREFIX
        for index, contract in enumerate(publisher.SOURCE_CI, 101):
            workflow_id, path, workflow_name, job_names = contract
            repository = {"id": publisher.REPO_ID, "full_name": publisher.REPOSITORY,
                          "private": False, "owner": {"id": publisher.OWNER_ID, "login": publisher.OWNER}}
            run = {"id": index, "workflow_id": workflow_id, "path": path,
                   "name": workflow_name, "head_sha": request["source"],
                   "head_branch": "main", "event": "push", "run_attempt": 1,
                   "status": "completed", "conclusion": "success",
                   "repository": repository,
                   "head_repository": dict(repository),
                   "html_url": f"https://github.com/{publisher.REPOSITORY}/actions/runs/{index}"}
            jobs = []
            for serial, job_name in enumerate(sorted(job_names), 1):
                job = {"id": 1000 * index + serial, "run_id": index,
                       "run_attempt": 1, "head_sha": request["source"],
                       "workflow_name": workflow_name, "name": job_name,
                       "status": "completed", "conclusion": "success"}
                if job_name == "PR build and affected-flow checks":
                    job["steps"] = [{"name": "Require every focused prerequisite, including selection",
                                     "status": "completed", "conclusion": "success"}]
                jobs.append(job)
            routes[prefix + f"/actions/workflows/{workflow_id}"] = {
                "id": workflow_id, "path": path, "name": workflow_name}
            route = prefix + f"/actions/runs/{index}"
            routes[route] = run
            routes[route + "/attempts/1"] = dict(run)
            routes[route + "/attempts/1/jobs?per_page=100"] = {
                "total_count": len(jobs), "jobs": jobs}
        class ReadOnlyAPI:
            def get(self, path):
                return routes[path]
        api = ReadOnlyAPI()
        publisher.exact_source_ci(api, request)
        first_run = prefix + "/actions/runs/101"
        class RerunAtFinalSweepAPI(ReadOnlyAPI):
            def __init__(self):
                self.first_reads = 0

            def get(self, path):
                value = super().get(path)
                if path == first_run:
                    self.first_reads += 1
                    if self.first_reads == 3:
                        return dict(value, run_attempt=2)
                return value
        with self.assertRaises(publisher.Rejected):
            publisher.exact_source_ci(RerunAtFinalSweepAPI(), request)
        run_path = prefix + "/actions/runs/103"
        for change in ({"head_sha": "b" * 40}, {"head_branch": "other"},
                       {"event": "workflow_dispatch"}, {"run_attempt": 2},
                       {"conclusion": "failure"}, {"workflow_id": 1}):
            with self.subTest(change=change):
                good = routes[run_path]
                routes[run_path] = dict(good, **change)
                with self.assertRaises(publisher.Rejected):
                    publisher.exact_source_ci(api, request)
                routes[run_path] = good
        jobs_path = prefix + "/actions/runs/104/attempts/1/jobs?per_page=100"
        good = routes[jobs_path]
        routes[jobs_path] = {"total_count": len(good["jobs"]), "jobs":
                            [dict(good["jobs"][0], conclusion="skipped")] + good["jobs"][1:]}
        with self.assertRaises(publisher.Rejected):
            publisher.exact_source_ci(api, request)
        routes[jobs_path] = good
        with self.assertRaises(publisher.Rejected):
            publisher.parse_source_ci_ids("101,102,103,104,105,106,106")
        with self.assertRaises(publisher.Rejected):
            publisher.parse_source_ci_ids("101,102,103,104,105,106")

    def test_redirects_fail_closed(self):
        good = "https://release-assets.githubusercontent.com/github-production-release-asset/123?sig=public"
        self.assertEqual(publisher.redirect_target(good).netloc, "release-assets.githubusercontent.com")
        for url in ("http://release-assets.githubusercontent.com/github-production-release-asset/123",
                    "https://evil.example/github-production-release-asset/123",
                    "https://release-assets.githubusercontent.com/../../private",
                    "https://user@release-assets.githubusercontent.com/github-production-release-asset/123",
                    good + "#fragment"):
            with self.subTest(url=url), self.assertRaises(publisher.Rejected):
                publisher.redirect_target(url)

    def test_public_file_and_plan_tampering(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            file = root / "asset"
            file.write_bytes(b"test")
            self.assertEqual(publisher.file_entry(file, 10), {"size": 4, "sha256": publisher.digest(b"test")})
            (root / "link").symlink_to(file)
            with self.assertRaises(publisher.Rejected):
                publisher.file_entry(root / "link", 10)
            (root / "hardlink").hardlink_to(file)
            with self.assertRaises(publisher.Rejected):
                publisher.file_entry(file, 10)
        entries = {name: {"size": 4, "sha256": "a" * 64}
                   for name in publisher.expected_assets(self.request()["version"])}
        plan = {"schema": publisher.PLAN_SCHEMA, "request": self.request(),
                "sourceTree": publisher.REVIEWED_SOURCE_TREE,
                "buildManifestSHA256": "a" * 64, "assets": entries}
        publisher.validate_plan(plan, self.request())
        for broken in (dict(plan, sourceTree="b" * 40), dict(plan, assets={}),
                       dict(plan, buildManifestSHA256="x" * 64)):
            with self.assertRaises(publisher.Rejected):
                publisher.validate_plan(broken, self.request())

    def test_real_git_hidden_tracked_edits_and_links_fail_closed(self):
        for flag in ("--skip-worktree", "--assume-unchanged"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch).resolve()
                commit, tree = self.temp_repo(root)
                publisher.checkout_lease(root, commit, tree)
                publisher.tracked_blob_lease(root, "guide.md")
                self.git(root, "update-index", flag, "guide.md")
                (root / "guide.md").write_bytes(b"unreviewed guide\n")
                self.assertEqual(self.git(root, "status", "--porcelain=v1"), "")
                with self.assertRaises(publisher.Rejected):
                    publisher.checkout_lease(root, commit, tree)
                with self.assertRaises(publisher.Rejected):
                    publisher.tracked_blob_lease(root, "guide.md")
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            self.temp_repo(root)
            (root / "link").symlink_to("guide.md")
            self.git(root, "add", "link")
            self.git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                     "commit", "-qm", "Track a symlink")
            with self.assertRaises(publisher.Rejected):
                publisher.checkout_lease(root, self.git(root, "rev-parse", "HEAD"))

    def test_existing_draft_blocks_before_writes(self):
        class ReadOnlyAPI:
            def get(self, path, missing=False):
                if path.endswith("/releases?per_page=100&page=1"):
                    return [{"tag_name": "v0.1.0-macos-preview.1"}]
                return None
        with self.assertRaises(publisher.Rejected):
            publisher.require_fresh(ReadOnlyAPI(), self.request())

    def test_asset_metadata_requires_exact_digest_size_url(self):
        req = self.request()
        name = "build-manifest.json"
        entry = {"size": 4, "sha256": "a" * 64}
        value = {"id": 12, "name": name, "size": 4, "digest": "sha256:" + "a" * 64,
                 "state": "uploaded", "browser_download_url":
                 f"https://github.com/{publisher.REPOSITORY}/releases/download/{req['version']}/{name}"}
        self.assertEqual(publisher.check_asset(value, name, entry, req["version"]), 12)
        draft_url = dict(value, browser_download_url=f"https://github.com/{publisher.REPOSITORY}/releases/download/untagged-" + "b" * 20 + f"/{name}")
        self.assertEqual(publisher.check_asset(draft_url, name, entry, {req["version"], "untagged-" + "b" * 20}), 12)
        with self.assertRaises(publisher.Rejected):
            publisher.check_asset(draft_url, name, entry, req["version"])
        for broken in (dict(value, size=3), dict(value, digest="sha256:" + "b" * 64),
                       dict(value, browser_download_url="https://evil.example/")):
            with self.assertRaises(publisher.Rejected):
                publisher.check_asset(broken, name, entry, req["version"])


if __name__ == "__main__":
    unittest.main()
