#!/usr/bin/env python3
"""Publish one fresh verified version from the same successful Actions run.

The only token consumer. No delete, overwrite, automatic retry, branch update,
repository-setting change, private key, or production bootstrap activation.
"""
import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bootstrap", HERE / "linux-bootstrap.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
REPO_ID = 1403204207
PREFIX = "/repos/" + b.REPOSITORY
MAX_RESPONSE = 2 * 1024 * 1024


class GitHubAPI:
    def __init__(self, token):
        b.require(type(token) is str and 0 < len(token) <= 10000 and not any(c.isspace() for c in token), "A scoped Actions token is required.")
        self._token = token

    def request(self, method, path, payload=None, upload=None, missing=False):
        b.require(method in {"GET", "POST", "PATCH"} and (path == PREFIX or path.startswith(PREFIX + "/")), "Unexpected publication API operation.")
        host = "uploads.github.com" if upload is not None else "api.github.com"
        headers = {"Authorization": "Bearer " + self._token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10",
                   "User-Agent": "Tracebolt-bounded-release-publisher/1", "Accept-Encoding": "identity"}
        body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        stream = None
        if upload is not None:
            stream = upload.open("rb")
            body = stream
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(upload.stat().st_size)})
        elif body is not None:
            headers["Content-Type"] = "application/json"
        conn = http.client.HTTPSConnection(host, 443, timeout=60, context=b.release_context())
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            # No redirects, credential forwarding, retries or raw error output.
            if missing and response.status == 404:
                return None
            expected = 201 if method == "POST" else 200
            b.require(response.status == expected, f"GitHub publication step returned HTTP {response.status}; state may be partial. Inspect it before any new attempt.")
            b.require(response.getheader("Content-Encoding") in (None, "identity"), "Encoded publication response rejected.")
            raw = response.read(MAX_RESPONSE + 1)
            b.require(0 < len(raw) <= MAX_RESPONSE, "Publication response exceeded its bound.")
            return json.loads(raw.decode("utf-8"), object_pairs_hook=b.unique_object)
        finally:
            if stream is not None:
                stream.close()
            conn.close()


def snapshot_candidate(source, destination, version):
    b.require(source.is_absolute() and source == source.resolve() and source.is_dir(), "Use the exact artifact directory.")
    names = b.asset_names(version) | {"manifest.json", "manifest.sigstore.json", "bootstrap.py"}
    b.require({entry.name for entry in source.iterdir()} == names, "Candidate contains missing or unexpected files; publication refused.")
    for name in sorted(names):
        path = source / name
        metadata = path.lstat()
        limit = b.MAX_SOURCE if name.endswith("-source.tar") else b.MAX_BINARY
        if name in {"manifest.json", "manifest.sigstore.json", "bootstrap.py"}:
            limit = b.MAX_MANIFEST if name == "manifest.json" else b.MAX_BUNDLE
        b.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == os.geteuid() and
                  not stat.S_IMODE(metadata.st_mode) & 0o022 and 0 < metadata.st_size <= limit, "Candidate file protection or size is invalid.")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as incoming, b.open_private(destination / name) as outgoing:
            opened = os.fstat(incoming.fileno())
            b.require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                      (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns), "Candidate changed while opening.")
            copied = 0
            while chunk := incoming.read(65536):
                copied += len(chunk)
                b.require(copied <= limit, "Candidate file grew beyond its bound.")
                outgoing.write(chunk)
            b.require(copied == metadata.st_size, "Candidate changed during snapshot.")


def verify_candidate(directory, version, source_commit, verifier_factory=b.prepare_verifier, attest=b.verify_attestation):
    raw = (directory / "manifest.json").read_bytes()
    bundle = (directory / "manifest.sigstore.json").read_bytes()
    pin = {"version": version, "sourceCommit": source_commit, "manifestSHA256": b.digest(raw), "bundleSHA256": b.digest(bundle)}
    b.validate_pin(pin)
    manifest = b.parse_manifest(raw, pin)
    # The verification tool/root are independently pinned in checked-out source;
    # nothing in the downloaded artifact chooses this executable or trust policy.
    with tempfile.TemporaryDirectory(prefix="tracebolt-publication-verifier-") as temp:
        verification = Path(temp)
        (verification / "manifest.json").write_bytes(raw)
        (verification / "manifest.sigstore.json").write_bytes(bundle)
        verifier = verifier_factory(verification, "amd64")
        attest(verification, pin, verifier)
    for name, entry in manifest["assets"].items():
        path = directory / name
        b.require(path.stat().st_size == entry["size"] and b.file_digest(path) == entry["sha256"], "Candidate asset does not match its verified manifest.")
    template = (HERE / "linux-bootstrap.py").read_text()
    b.require(template.count("RELEASE_PIN = None") == 1, "Unexpected bootstrap template.")
    expected = template.replace("RELEASE_PIN = None", "RELEASE_PIN = " + repr(pin)).encode()
    b.require((directory / "bootstrap.py").read_bytes() == expected, "Candidate bootstrap is not the exact verified source and release pin.")
    return {name: {"size": path.stat().st_size, "sha256": b.file_digest(path)} for name in
            sorted(b.asset_names(version) | {"manifest.json", "manifest.sigstore.json", "bootstrap.py"}) for path in [directory / name]}


def validate_ref(value, name, commit):
    b.require(type(value) is dict and value.get("ref") == "refs/" + name and type(value.get("object")) is dict and
              value["object"].get("type") == "commit" and value["object"].get("sha") == commit, "Selected Git ref is missing, changed or ambiguous; publication stopped.")


def release_description(commit):
    return ("Verified Linux download candidate from source " + commit +
            ". Linux amd64: Debian 13 / Ubuntu 24.04 systemd candidate. ARM64 runtime admission remains gated on native acceptance. "
            "Workflow provenance is in manifest.sigstore.json; verify the pinned bootstrap before installation. "
            "Actual host installation/reboot acceptance is separate.")


def release_identity(value, release_id, version, commit, draft):
    b.require(type(value) is dict and type(value.get("id")) is int and value["id"] > 0 and
              (release_id is None or value["id"] == release_id) and value.get("tag_name") == version and
              value.get("target_commitish") == commit and value.get("draft") is draft and value.get("prerelease") is True and
              value.get("name") == "Tracebolt Linux candidate " + version and value.get("body") == release_description(commit),
              "Release identity/state changed or is ambiguous; do not overwrite or delete it.")
    return value["id"]


def release_download_tag(value, version, draft):
    # GitHub gives a fresh draft an opaque URL even when tag_name is already set.
    # Bind every draft asset to this exact release URL; after publication only
    # the chosen version URL is acceptable. Neither URL is followed here.
    url = value.get("html_url")
    prefix = f"https://github.com/{b.REPOSITORY}/releases/tag/"
    b.require(type(url) is str and url.startswith(prefix), "Release URL does not identify the selected repository.")
    tag = url[len(prefix):]
    b.require(tag == version or (draft and re.fullmatch(r"untagged-[0-9a-f]{20}", tag)),
              "Release URL does not match the selected version or its fresh draft.")
    return tag


def check_asset(value, name, entry, download_tag):
    b.require(type(value) is dict and type(value.get("id")) is int and value["id"] > 0 and value.get("name") == name and
              value.get("state") == "uploaded" and type(value.get("size")) is int and value["size"] == entry["size"] and
              value.get("digest") == "sha256:" + entry["sha256"] and
              value.get("browser_download_url") == f"https://github.com/{b.REPOSITORY}/releases/download/{download_tag}/{name}",
              "Release asset readback does not match the verified candidate; inspect the retained release state.")


def check_assets(api, release_id, expected, download_tag):
    assets = api.request("GET", PREFIX + f"/releases/{release_id}/assets?per_page=100")
    b.require(type(assets) is list and len(assets) == len(expected), "Release has missing or unexpected assets; publication stopped.")
    names = [item.get("name") for item in assets if type(item) is dict]
    b.require(len(names) == len(assets) and all(type(name) is str for name in names) and len(set(names)) == len(names) and set(names) == set(expected), "Release asset identity is ambiguous.")
    for item in assets:
        check_asset(item, item["name"], expected[item["name"]], download_tag)


def require_fresh_version(api, version):
    b.require(api.request("GET", PREFIX + "/releases/tags/" + version, missing=True) is None and
              api.request("GET", PREFIX + "/git/ref/tags/" + version, missing=True) is None,
              "That version already has a tag or release. No overwrite, deletion or adoption is allowed.")
    # Also inspect authenticated draft listings: an unpublished draft may not yet
    # have a Git tag. Missing-by-tag alone is not sufficient absence evidence.
    for page in range(1, 11):
        releases = api.request("GET", PREFIX + f"/releases?per_page=100&page={page}")
        b.require(type(releases) is list and len(releases) <= 100 and all(type(item) is dict and type(item.get("tag_name")) is str for item in releases),
                  "Release inventory is ambiguous; publication refused.")
        b.require(all(item["tag_name"] != version for item in releases), "An existing draft or release already uses that version; publication refused.")
        if len(releases) < 100:
            return
    raise b.Rejected("Release inventory exceeds the bounded freshness check; publication refused.")


def publish(api, directory, version, source_commit, expected):
    b.require(b.VERSION.fullmatch(version) and len(version) <= 64 and b.COMMIT.fullmatch(source_commit) and
              set(expected) == b.asset_names(version) | {"manifest.json", "manifest.sigstore.json", "bootstrap.py"}, "Publication target or asset set is not exact.")
    # Read-only provenance verification has completed before entering this method.
    # Every mutation is performed once. A lost/ambiguous response leaves state for
    # deliberate inspection; a rerun refuses it rather than adopting or deleting.
    repo = api.request("GET", PREFIX)
    b.require(type(repo) is dict and repo.get("id") == REPO_ID and repo.get("full_name") == b.REPOSITORY and repo.get("private") is False,
              "Publication repository identity is not the selected public repository.")
    validate_ref(api.request("GET", PREFIX + "/git/ref/heads/main"), "heads/main", source_commit)
    tag_path = PREFIX + "/git/ref/tags/" + version
    require_fresh_version(api, version)
    ref = api.request("POST", PREFIX + "/git/refs", {"ref": "refs/tags/" + version, "sha": source_commit})
    validate_ref(ref, "tags/" + version, source_commit)
    draft = api.request("POST", PREFIX + "/releases", {
        "tag_name": version, "target_commitish": source_commit, "name": "Tracebolt Linux candidate " + version,
        "body": release_description(source_commit),
        "draft": True, "prerelease": True, "generate_release_notes": False, "make_latest": "false"})
    release_id = release_identity(draft, None, version, source_commit, True)
    draft_download_tag = release_download_tag(draft, version, True)
    b.require(draft.get("assets") == [], "New release was not empty; publication stopped.")
    for name, entry in expected.items():
        path = directory / name
        b.require(path.stat().st_size == entry["size"] and b.file_digest(path) == entry["sha256"], "Verified staging changed before upload.")
        asset = api.request("POST", PREFIX + f"/releases/{release_id}/assets?name=" + quote(name, safe=""), upload=path)
        check_asset(asset, name, entry, draft_download_tag)
    check_assets(api, release_id, expected, draft_download_tag)
    validate_ref(api.request("GET", tag_path), "tags/" + version, source_commit)
    draft = api.request("GET", PREFIX + f"/releases/{release_id}")
    release_identity(draft, release_id, version, source_commit, True)
    b.require(release_download_tag(draft, version, True) == draft_download_tag, "Draft release URL changed; publication stopped.")
    validate_ref(api.request("GET", PREFIX + "/git/ref/heads/main"), "heads/main", source_commit)
    published = api.request("PATCH", PREFIX + f"/releases/{release_id}", {"draft": False, "make_latest": "false"})
    release_identity(published, release_id, version, source_commit, False)
    release_download_tag(published, version, False)
    # Read back the final publication and every digest instead of treating a
    # successful PATCH response as enough evidence to activate production pins.
    published = api.request("GET", PREFIX + f"/releases/{release_id}")
    release_identity(published, release_id, version, source_commit, False)
    release_download_tag(published, version, False)
    validate_ref(api.request("GET", tag_path), "tags/" + version, source_commit)
    check_assets(api, release_id, expected, version)
    return f"https://github.com/{b.REPOSITORY}/releases/tag/{version}"


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--publish", action="store_true", help="Explicitly publish this fresh chosen version after local verification")
    args = parser.parse_args()
    b.require(b.VERSION.fullmatch(args.version) and len(args.version) <= 64 and b.COMMIT.fullmatch(args.source_commit), "Exact release version and source commit are required.")
    b.require(args.publish, "Publication requires explicit --publish; no API request was made.")
    b.require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY") == b.REPOSITORY and
              os.environ.get("GITHUB_REF") == "refs/heads/main" and os.environ.get("GITHUB_SHA") == args.source_commit,
              "Publication is restricted to the selected main-branch Actions run.")
    with tempfile.TemporaryDirectory(prefix="tracebolt-verified-publish-") as temp:
        directory = Path(temp)
        snapshot_candidate(args.artifacts, directory, args.version)
        expected = verify_candidate(directory, args.version, args.source_commit)
        api = GitHubAPI(os.environ.get("GH_TOKEN"))
        url = publish(api, directory, args.version, args.source_commit, expected)
    print("Published and read back the chosen candidate release: " + url)
    print("Production bootstrap/UI activation still requires independent published-byte verification.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, b.Rejected) else "Publication failed or is uncertain; inspect the retained tag/draft/assets before another attempt. No automatic retry, overwrite or cleanup was attempted."
        raise SystemExit(message) from None
