"""Publication fixtures. No token, live GitHub write, tag or Release is created."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("publisher", ROOT / "deploy/release/publish-linux-release.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
VERSION, SOURCE = "v0.1.0-fixture.1", "a" * 40
DRAFT_TAG = "untagged-5de35e2eadff66a24c09"


def reference(name, source=SOURCE):
    return {"ref": "refs/" + name, "object": {"type": "commit", "sha": source}}


class FakeAPI:
    def __init__(self, expected):
        self.expected, self.calls, self.assets = expected, [], []
        self.tag, self.release = None, None
        self.repo_id = p.REPO_ID
        self.main = SOURCE
        self.hidden_draft = False
        self.bad_upload = False
        self.fail_after_tag = False
        self.fail_after_draft = False
        self.change_main_after_upload = False
        self.change_tag_after_upload = False
        self.draft_download_tag = DRAFT_TAG
        self.upload_override = {}
        self.change_draft_url_after_upload = False
        self.keep_published_draft_url = False
        self.keep_published_draft_asset_urls = False

    def request(self, method, path, payload=None, upload=None, missing=False):
        self.calls.append((method, path, payload))
        if method == "GET" and path == p.PREFIX:
            return {"id": self.repo_id, "full_name": p.b.REPOSITORY, "private": False}
        if method == "GET" and path == p.PREFIX + "/git/ref/heads/main":
            return reference("heads/main", self.main)
        if method == "GET" and path == p.PREFIX + "/releases/tags/" + VERSION:
            return self.release
        if method == "GET" and path == p.PREFIX + "/git/ref/tags/" + VERSION:
            return self.tag
        if method == "GET" and "/releases?per_page=100&page=" in path:
            return [{"tag_name": VERSION}] if self.hidden_draft else []
        if method == "POST" and path == p.PREFIX + "/git/refs":
            self.tag = reference("tags/" + VERSION)
            if self.fail_after_tag:
                raise OSError("simulated lost tag response")
            return self.tag
        if method == "POST" and path == p.PREFIX + "/releases":
            self.release = dict(payload, id=17, assets=[], html_url=f"https://github.com/{p.b.REPOSITORY}/releases/tag/{self.draft_download_tag}")
            if self.fail_after_draft:
                raise OSError("simulated lost draft response")
            return dict(self.release)
        if method == "POST" and upload is not None:
            name = upload.name
            entry = self.expected[name]
            asset = {"id": 100 + len(self.assets), "name": name, "state": "uploaded", "size": entry["size"], "digest": "sha256:" + entry["sha256"],
                     "browser_download_url": f"https://github.com/{p.b.REPOSITORY}/releases/download/{self.draft_download_tag}/{name}"}
            asset.update(self.upload_override)
            self.assets.append(asset)
            if self.change_main_after_upload:
                self.main = "b" * 40
            if self.change_tag_after_upload:
                self.tag = reference("tags/" + VERSION, "b" * 40)
            if self.change_draft_url_after_upload:
                self.release["html_url"] = f"https://github.com/{p.b.REPOSITORY}/releases/tag/untagged-{'b' * 20}"
            return dict(asset, digest="sha256:" + "f" * 64) if self.bad_upload else asset
        if method == "GET" and path == p.PREFIX + "/releases/17/assets?per_page=100":
            return list(self.assets)
        if method == "GET" and path == p.PREFIX + "/releases/17":
            return dict(self.release)
        if method == "PATCH" and path == p.PREFIX + "/releases/17":
            self.release.update(payload)
            if not self.keep_published_draft_url:
                self.release["html_url"] = f"https://github.com/{p.b.REPOSITORY}/releases/tag/{VERSION}"
            if not self.keep_published_draft_asset_urls:
                for asset in self.assets:
                    asset["browser_download_url"] = f"https://github.com/{p.b.REPOSITORY}/releases/download/{VERSION}/{asset['name']}"
            return dict(self.release)
        raise AssertionError((method, path))


class Publication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.data = {name: ("inert " + name).encode() for name in p.b.asset_names(VERSION)}
        self.manifest = {"schema": p.b.SCHEMA, "repository": p.b.REPOSITORY, "version": VERSION, "sourceCommit": SOURCE, "runtimeTargets": ["linux-amd64"],
                         "assets": {name: {"size": len(data), "sha256": p.b.digest(data)} for name, data in self.data.items()}}
        raw = (json.dumps(self.manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        bundle = b"inert local attestation policy fixture"
        pin = {"version": VERSION, "sourceCommit": SOURCE, "manifestSHA256": p.b.digest(raw), "bundleSHA256": p.b.digest(bundle)}
        bootstrap = (ROOT / "deploy/release/linux-bootstrap.py").read_text().replace("RELEASE_PIN = None", "RELEASE_PIN = " + repr(pin)).encode()
        self.data.update({"manifest.json": raw, "manifest.sigstore.json": bundle, "bootstrap.py": bootstrap})
        for name, data in self.data.items():
            with p.b.open_private(self.artifacts / name) as stream:
                stream.write(data)
        self.expected = {name: {"size": len(data), "sha256": p.b.digest(data)} for name, data in sorted(self.data.items())}
        self.api = FakeAPI(self.expected)

    def verify(self):
        def attest(directory, pin, verifier):
            self.assertEqual(pin["sourceCommit"], SOURCE)
            self.assertEqual(verifier.name, "inert-gh-verifier")
        return p.verify_candidate(self.artifacts, VERSION, SOURCE, lambda directory, arch: directory / "inert-gh-verifier", attest)

    def publish(self):
        return p.publish(self.api, self.artifacts, VERSION, SOURCE, self.expected)

    def mutations(self):
        return [call for call in self.api.calls if call[0] != "GET"]

    def test_full_private_snapshot_and_exact_provenance_bound_bytes(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir(mode=0o700)
        p.snapshot_candidate(self.artifacts, snapshot, VERSION)
        self.assertEqual({name: path.read_bytes() for path in snapshot.iterdir() for name in [path.name]}, self.data)
        self.assertEqual(self.verify(), self.expected)

    def test_extra_symlink_and_writable_inputs_are_rejected(self):
        snapshot = self.root / "snapshot"
        snapshot.mkdir()
        extra = self.artifacts / "unexpected"
        extra.write_text("extra")
        with self.assertRaises(p.b.Rejected):
            p.snapshot_candidate(self.artifacts, snapshot, VERSION)
        extra.unlink()
        target = self.artifacts / "bootstrap.py"
        target.chmod(0o666)
        with self.assertRaises(p.b.Rejected):
            p.snapshot_candidate(self.artifacts, snapshot, VERSION)
        target.chmod(0o600)
        target.unlink()
        target.symlink_to(self.root / "elsewhere")
        with self.assertRaises(p.b.Rejected):
            p.snapshot_candidate(self.artifacts, snapshot, VERSION)

    def test_changed_asset_bootstrap_or_source_cannot_pass_candidate_verification(self):
        path = self.artifacts / next(iter(p.b.asset_names(VERSION)))
        original = path.read_bytes()
        path.write_bytes(b"changed")
        with self.assertRaises(p.b.Rejected):
            self.verify()
        path.write_bytes(original)
        bootstrap = self.artifacts / "bootstrap.py"
        bootstrap.write_bytes(bootstrap.read_bytes() + b"\n# changed\n")
        with self.assertRaises(p.b.Rejected):
            self.verify()
        with self.assertRaises(p.b.Rejected):
            p.verify_candidate(self.artifacts, VERSION, "b" * 40)

    def test_fresh_version_uploads_exact_assets_and_only_then_publishes(self):
        self.assertEqual(self.publish(), f"https://github.com/{p.b.REPOSITORY}/releases/tag/{VERSION}")
        operations = self.mutations()
        self.assertEqual([item[0] for item in operations], ["POST"] * 12 + ["PATCH"])
        self.assertEqual(operations[0][2], {"ref": "refs/tags/" + VERSION, "sha": SOURCE})
        self.assertTrue(operations[1][2]["draft"])
        self.assertTrue(operations[1][2]["prerelease"])
        self.assertEqual(operations[-1][2], {"draft": False, "make_latest": "false"})
        self.assertEqual({item["name"] for item in self.api.assets}, set(self.expected))
        self.assertFalse(self.api.release["draft"])
        self.assertEqual(self.api.calls[-1][1], p.PREFIX + "/releases/17/assets?per_page=100")

    def test_existing_tag_release_or_hidden_draft_refuses_all_mutation(self):
        for kind in ("tag", "release", "hidden"):
            self.api = FakeAPI(self.expected)
            if kind == "tag": self.api.tag = reference("tags/" + VERSION)
            if kind == "release": self.api.release = {"id": 88, "tag_name": VERSION, "draft": False}
            if kind == "hidden": self.api.hidden_draft = True
            with self.assertRaises(p.b.Rejected):
                self.publish()
            self.assertEqual(self.mutations(), [])

    def test_draft_with_version_urls_also_publishes(self):
        self.api.draft_download_tag = VERSION
        self.assertEqual(self.publish(), f"https://github.com/{p.b.REPOSITORY}/releases/tag/{VERSION}")

    def test_draft_urls_are_bounded_to_the_exact_repository_and_version(self):
        prefix = f"https://github.com/{p.b.REPOSITORY}/releases/tag/"
        for url in (
            prefix + "v0.1.0-other.1", prefix + DRAFT_TAG + "?x=1", prefix + DRAFT_TAG + "#fragment",
            prefix + DRAFT_TAG + "/extra", prefix + "untagged-../bad", prefix + "untagged-" + "a" * 21,
            prefix.replace("https:", "http:") + DRAFT_TAG,
            prefix.replace("github.com", "github.com.evil.example") + DRAFT_TAG,
            prefix.replace("github.com", "user@github.com") + DRAFT_TAG,
            prefix.replace("github.com", "github.com:443") + DRAFT_TAG,
            prefix.replace(p.b.REPOSITORY, "other/repository") + DRAFT_TAG,
            None,
        ):
            with self.subTest(url=url), self.assertRaises(p.b.Rejected):
                p.release_download_tag({"html_url": url}, VERSION, True)
        self.assertEqual(p.release_download_tag({"html_url": prefix + DRAFT_TAG}, VERSION, True), DRAFT_TAG)
        with self.assertRaises(p.b.Rejected):
            p.release_download_tag({"html_url": prefix + DRAFT_TAG}, VERSION, False)

    def test_wrong_draft_asset_url_or_metadata_stops_before_publication(self):
        prefix = f"https://github.com/{p.b.REPOSITORY}/releases/download/"
        first_name = next(iter(self.expected))
        variants = [
            {"browser_download_url": prefix + "untagged-" + "b" * 20 + "/" + first_name},
            {"browser_download_url": prefix + VERSION + "/" + first_name},
            {"browser_download_url": prefix + DRAFT_TAG + "/other.py"},
            {"browser_download_url": prefix.replace(p.b.REPOSITORY, "other/repository") + DRAFT_TAG + "/" + first_name},
            {"browser_download_url": prefix + DRAFT_TAG + "/" + first_name + "?token=x"},
            {"name": "other.py"}, {"size": self.expected[first_name]["size"] + 1},
            {"digest": "sha256:" + "f" * 64}, {"state": "starter"},
        ]
        for override in variants:
            with self.subTest(override=override):
                self.api = FakeAPI(self.expected)
                self.api.upload_override = override
                with self.assertRaises(p.b.Rejected):
                    self.publish()
                self.assertTrue(self.api.release["draft"])
                self.assertFalse(any(item[0] in ("DELETE", "PATCH") for item in self.api.calls))

    def test_changed_draft_url_stops_before_publication(self):
        self.api.change_draft_url_after_upload = True
        with self.assertRaises(p.b.Rejected):
            self.publish()
        self.assertTrue(self.api.release["draft"])
        self.assertFalse(any(item[0] in ("DELETE", "PATCH") for item in self.api.calls))

    def test_published_release_and_assets_must_use_the_exact_version_url(self):
        for field in ("keep_published_draft_url", "keep_published_draft_asset_urls"):
            with self.subTest(field=field):
                self.api = FakeAPI(self.expected)
                setattr(self.api, field, True)
                with self.assertRaises(p.b.Rejected):
                    self.publish()
                self.assertFalse(self.api.release["draft"])
                self.assertEqual(sum(item[0] == "PATCH" for item in self.api.calls), 1)
                self.assertFalse(any(item[0] == "DELETE" for item in self.api.calls))

    def test_wrong_repository_or_moved_main_refuses_all_mutation(self):
        for attribute, value in (("repo_id", 999), ("main", "b" * 40)):
            self.api = FakeAPI(self.expected)
            setattr(self.api, attribute, value)
            with self.assertRaises(p.b.Rejected):
                self.publish()
            self.assertEqual(self.mutations(), [])

    def test_lost_mutation_response_never_retries_or_deletes_and_rerun_refuses(self):
        for field in ("fail_after_tag", "fail_after_draft"):
            self.api = FakeAPI(self.expected)
            setattr(self.api, field, True)
            with self.assertRaises(OSError):
                self.publish()
            before = len(self.mutations())
            self.assertEqual(before, 1 if field == "fail_after_tag" else 2)
            with self.assertRaises(p.b.Rejected):
                self.publish()
            self.assertEqual(len(self.mutations()), before)
            self.assertIsNotNone(self.api.tag)
            self.assertFalse(any(item[0] == "DELETE" for item in self.api.calls))

    def test_bad_upload_or_changed_ref_preserves_draft_without_publication(self):
        for field in ("bad_upload", "change_main_after_upload", "change_tag_after_upload"):
            self.api = FakeAPI(self.expected)
            setattr(self.api, field, True)
            with self.assertRaises(p.b.Rejected):
                self.publish()
            self.assertTrue(self.api.release["draft"])
            self.assertFalse(any(item[0] in ("DELETE", "PATCH") for item in self.api.calls))

    def test_explicit_publish_and_exact_actions_context_are_required(self):
        common = ["publish-linux-release.py", "--version", VERSION, "--source-commit", SOURCE, "--artifacts", str(self.artifacts)]
        with patch.object(p, "GitHubAPI") as api, patch.object(p, "snapshot_candidate") as snapshot:
            with patch.object(p.os, "environ", {}), patch("sys.argv", common), self.assertRaises(p.b.Rejected):
                p.main()
            with patch.object(p.os, "environ", {}), patch("sys.argv", common + ["--publish"]), self.assertRaises(p.b.Rejected):
                p.main()
            api.assert_not_called()
            snapshot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
