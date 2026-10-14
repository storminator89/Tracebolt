#!/usr/bin/env python3
"""Publish only an exact, twice-built, unsigned macOS service-test candidate.

The verification job is read-only. The separate explicit write job rebuilds the
same source and compares a frozen plan before attempting a fresh tag/draft once.
No native code is run; an uncertain write is never adopted, retried, or erased.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "storminator89/Tracebolt"
REPO_ID = 1403204207
OWNER = "storminator89"
OWNER_ID = 30489872
PREFIX = "/repos/" + REPOSITORY
WORKFLOW = ".github/workflows/macos-prerelease.yml"
# The reviewed source pin must be updated with the final package/portability
# review. Dispatch inputs cannot widen it. This initial pin is the current
# package candidate; it is not a claim of native acceptance or release approval.
REVIEWED_SOURCE_SHA = "a7244fb3c573846c179cf4210ea6b2d4d4354c7c"
REVIEWED_SOURCE_TREE = "23977ac051b8dd7f92c3e6e80c17708e782a3436"
# Seven existing source-push workflows only. No full Validate or native
# acceptance workflow is dispatched or required by this publisher.
SOURCE_CI = (
    (377287517, ".github/workflows/windows-service-source.yml", "Windows service source fixtures",
     {"Windows state/SCM/console source fixtures (no host grants or installation)"}),
    (381004687, ".github/workflows/windows-restart-source.yml", "Windows own-restart acceptance source",
     {"Inert contracts and tagged cross-builds"}),
    (383099444, ".github/workflows/macos-source.yml", "macOS source-only checks",
     {"Darwin amd64 compilation only", "Darwin arm64 compilation only",
      "macOS synthetic enrollment and inventory UI"}),
    (382425335, ".github/workflows/pr-checks.yml", "Focused source checks",
     {"Select affected source checks", "Focused Go build and safety checks",
      "Focused UI build and interactions", "Focused browser flows", "PR build and affected-flow checks"}),
    (379322074, ".github/workflows/windows-setup-build.yml", "Build unsigned Windows Setup candidates",
     {"Deterministic x64 and ARM64 Setup artifacts (never executed)"}),
    (377451270, ".github/workflows/windows-prerequisites.yml", "Read-only Windows prerequisite measurement",
     {"Windows static prerequisites (read-only; service access unverified)"}),
    (377189454, ".github/workflows/windows-readonly.yml", "Windows read-only foundation",
     {"Windows amd64 native inventory and event metadata (no service install)"}),
)

PLAN_SCHEMA = "tracebolt.macos-prerelease-plan.v1"
RELEASE_SCHEMA = "tracebolt.macos-prerelease.v1"
RELEASE_MANIFEST = "release-manifest.json"
GUIDE = "macos-prerelease.md"
MAX_JSON = 2 << 20
MAX_PLAN = 16 << 10
MAX_ASSET = 384 << 20
HEX40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z", re.ASCII)
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-macos-preview\.([1-9][0-9]*)\Z", re.ASCII)


class Rejected(Exception):
    pass


def require(ok, message="macOS prerelease verification rejected an input."):
    if not ok:
        raise Rejected(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON fields are not accepted.")
        result[key] = value
    return result


def strict_json(raw, limit=MAX_JSON):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "JSON exceeded its bound.")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("Non-finite JSON rejected.")))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("Invalid JSON response.") from None


def positive_id(value):
    return type(value) is int and 0 < value < 2**63


def parse_source_ci_ids(raw):
    require(type(raw) is str and len(raw) <= 160)
    items = raw.split(",")
    require(len(items) == len(SOURCE_CI) and all(RUN_ID.fullmatch(item) for item in items),
            "Supply exactly seven ordered source-push run IDs without spaces.")
    ids = tuple(int(item) for item in items)
    require(all(item < 2**63 for item in ids) and len(set(ids)) == len(SOURCE_CI))
    return ids


def checked_request(value):
    require(type(value) is dict and set(value) == {"source", "sourceCIRunIDs", "version", "publisherSHA", "publisherRunID"})
    require(all(type(item) is str for item in value.values()))
    require(HEX40.fullmatch(value["source"]) and value["source"] == REVIEWED_SOURCE_SHA
            and HEX40.fullmatch(value["publisherSHA"]) and value["source"] != value["publisherSHA"],
            "Source must equal the independently pinned reviewed package source.")
    require(HEX40.fullmatch(REVIEWED_SOURCE_TREE))
    run_ids = parse_source_ci_ids(value["sourceCIRunIDs"])
    require(RUN_ID.fullmatch(value["publisherRunID"]) and int(value["publisherRunID"]) < 2**63
            and value["publisherRunID"] not in run_ids)
    require(len(value["version"]) <= 64 and VERSION.fullmatch(value["version"]),
            "Use a fresh vMAJOR.MINOR.PATCH-macos-preview.N tag.")
    return value


def authorize(env, publish):
    request = checked_request({"source": env.get("TRACEBOLT_RELEASE_SOURCE", ""),
        "sourceCIRunIDs": env.get("TRACEBOLT_SOURCE_CI_RUN_IDS", ""),
        "version": env.get("TRACEBOLT_RELEASE_VERSION", ""),
        "publisherSHA": env.get("TRACEBOLT_PUBLISHER_SHA", ""),
        "publisherRunID": env.get("GITHUB_RUN_ID", "")})
    fixed = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REPOSITORY_ID": str(REPO_ID),
        "GITHUB_REPOSITORY_OWNER": OWNER, "GITHUB_REPOSITORY_OWNER_ID": str(OWNER_ID),
        "GITHUB_ACTOR": OWNER, "GITHUB_ACTOR_ID": str(OWNER_ID),
        "GITHUB_TRIGGERING_ACTOR": OWNER, "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": request["publisherSHA"],
        "GITHUB_WORKFLOW_SHA": request["publisherSHA"],
        "GITHUB_WORKFLOW_REF": REPOSITORY + "/" + WORKFLOW + "@refs/heads/main",
        "GITHUB_JOB": "publish" if publish else "verify", "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted"}
    require(all(env.get(k) == v for k, v in fixed.items()),
            "Only the first-attempt owner dispatch of the exact main publisher is permitted.")
    require(env.get("TRACEBOLT_RELEASE_PUBLISH") in {"true", "false"})
    require(not publish or env["TRACEBOLT_RELEASE_PUBLISH"] == "true",
            "Publication needs the explicit publish checkbox.")
    return request


def git_raw(root, *args, limit=2 << 20):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= limit,
            "Checkout verification failed.")
    return result.stdout


def git(root, *args):
    return git_raw(root, *args, limit=1 << 20).decode("utf-8", "strict").strip()


def checked_index(root):
    """Refuse hidden tracked edits, links, gitlinks and unmerged index stages."""
    indexed = set()
    for record in git_raw(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        fields = record.split(b"\t", 1)
        require(len(fields) == 2)
        metadata = fields[0].split(b" ")
        require(len(metadata) == 3 and metadata[0] in {b"100644", b"100755"}
                and re.fullmatch(b"[0-9a-f]{40}", metadata[1]) and metadata[2] == b"0"
                and fields[1] and fields[1] not in indexed,
                "Linked, unusual or unmerged tracked source is unsupported.")
        indexed.add(fields[1])
    flags = set()
    for record in git_raw(root, "ls-files", "-v", "-z").split(b"\0"):
        if not record:
            continue
        require(record.startswith(b"H ") and record[2:] in indexed
                and record[2:] not in flags,
                "Assume-unchanged, skip-worktree or unusual index flags are unsupported.")
        flags.add(record[2:])
    require(flags == indexed, "Tracked index listings disagree.")


def checkout_lease(root, commit, tree=None):
    require(root.is_absolute() and root.resolve() == root and root.is_dir())
    require(Path(git(root, "rev-parse", "--show-toplevel")) == root)
    require(git(root, "rev-parse", "HEAD") == commit and
            (tree is None or git(root, "rev-parse", "HEAD^{tree}") == tree),
            "Checked-out source or publisher revision changed.")
    checked_index(root)
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=all"),
            "A dirty source or publisher checkout is not publishable.")


def tracked_blob_lease(root, relative):
    raw = git_raw(root, "show", "HEAD:" + relative, limit=128 << 10)
    require(file_entry(root / relative, 128 << 10) ==
            {"size": len(raw), "sha256": digest(raw)},
            "Publisher or public guide differs from the exact Git blob.")


def publisher_blob_lease():
    # The dispatch revision pins these policy/publication bytes, not merely
    # their names. Never trust a local guide or executable hidden from status.
    for relative in (WORKFLOW, "deploy/macos-release/publish-prerelease.py",
                     "docs/" + GUIDE):
        tracked_blob_lease(ROOT, relative)


def official_host(host):
    return host in {"api.github.com", "uploads.github.com", "github.com",
                    "release-assets.githubusercontent.com"}


class OfficialConnection(http.client.HTTPSConnection):
    def connect(self):
        require(official_host(self.host) and self.port == 443, "Unapproved HTTPS destination.")
        addresses = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        require(0 < len(addresses) <= 16)
        for family, _, _, _, address in addresses:
            ip = ipaddress.ip_address(address[0])
            require(family in (socket.AF_INET, socket.AF_INET6) and ip.is_global and not
                    (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_unspecified),
                    "Non-public HTTPS destination rejected.")
        family, kind, protocol, _, address = addresses[0]
        sock = socket.socket(family, kind, protocol)
        sock.settimeout(self.timeout)
        try:
            sock.connect(address)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    return context


def redirect_target(value):
    require(type(value) is str and 0 < len(value) <= 16384 and "\\" not in value
            and all(32 < ord(c) < 127 for c in value), "Invalid download redirect.")
    target = urlsplit(value)
    require(target.scheme == "https" and target.netloc == "release-assets.githubusercontent.com"
            and target.path.startswith("/github-production-release-asset/") and len(target.path) <= 2048
            and not target.username and not target.password and not target.fragment
            and not any(part in (".", "..") for part in target.path.split("/")),
            "Unapproved public download redirect.")
    return target


def bounded_response(response, bound):
    lengths = [v for k, v in response.getheaders() if k.lower() == "content-length"]
    encodings = [v for k, v in response.getheaders() if k.lower() == "content-encoding"]
    require(len(lengths) <= 1 and all(re.fullmatch(r"[0-9]{1,10}", x) and int(x) <= bound for x in lengths))
    require(not encodings or encodings == ["identity"])
    chunks = []
    total = 0
    while True:
        chunk = response.read(min(1 << 20, bound + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        require(total <= bound, "HTTP response exceeded its bound.")
        chunks.append(chunk)
    require(not lengths or total == int(lengths[0]), "Truncated HTTP response.")
    return b"".join(chunks)


class GitHubAPI:
    def __init__(self, token, *, write=False, connection=OfficialConnection):
        require(type(token) is str and 0 < len(token) <= 10000 and not any(c.isspace() for c in token),
                "The scoped GitHub Actions token is required.")
        self.token, self.write, self.connection = token, write, connection

    def _call(self, host, method, path, *, payload=None, file=None, statuses=(200,), bound=MAX_JSON, auth=True):
        require(official_host(host) and path.startswith("/") and not any(c in path for c in "\r\n"))
        require(not auth or host in {"api.github.com", "uploads.github.com"})
        headers = {"User-Agent": "Tracebolt-macos-prerelease/1", "Accept-Encoding": "identity"}
        if auth:
            headers.update({"Authorization": "Bearer " + self.token,
                            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        body = canonical(payload) if payload is not None else file
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if file is not None:
            require(file.is_file() and 0 < file.stat().st_size <= MAX_ASSET)
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(file.stat().st_size)})
        conn = self.connection(host, 443, timeout=90, context=tls_context())
        try:
            if file is None:
                conn.request(method, path, body=body, headers=headers)
            else:
                with file.open("rb") as stream:
                    conn.request(method, path, body=stream, headers=headers)
            response = conn.getresponse()
            require(response.status in statuses, "GitHub request failed; inspect any partial state before a new attempt.")
            require(not any(k.lower() == "link" for k, _ in response.getheaders()),
                    "Paginated response was not fully verified.")
            if response.status == 302:
                locations = [v for k, v in response.getheaders() if k.lower() == "location"]
                require(len(locations) == 1, "Ambiguous download redirect.")
                return response.status, locations[0]
            if response.status == 404:
                return response.status, None
            return response.status, bounded_response(response, bound)
        finally:
            conn.close()

    def get(self, path, *, missing=False):
        require(path == PREFIX or path.startswith(PREFIX + "/"), "Wrong repository route.")
        status, raw = self._call("api.github.com", "GET", path,
                                 statuses=(200, 404) if missing else (200,))
        return None if status == 404 else strict_json(raw)

    def write_json(self, method, path, payload):
        require(self.write and method in {"POST", "PATCH"})
        require((method == "POST" and path in {PREFIX + "/git/refs", PREFIX + "/releases"})
                or (method == "PATCH" and re.fullmatch(re.escape(PREFIX) + r"/releases/[1-9][0-9]*", path)))
        return strict_json(self._call("api.github.com", method, path, payload=payload,
                        statuses=(201,) if method == "POST" else (200,))[1])

    def upload(self, release_id, name, file):
        require(self.write and positive_id(release_id) and safe_name(name))
        route = PREFIX + f"/releases/{release_id}/assets?name=" + quote(name, safe="")
        return strict_json(self._call("uploads.github.com", "POST", route, file=file,
                                         statuses=(201,))[1])

    def public_digest(self, version, name, bound):
        require(VERSION.fullmatch(version) and safe_name(name) and 0 < bound <= MAX_ASSET)
        path = f"/{REPOSITORY}/releases/download/{version}/{name}"
        status, raw = self._call("github.com", "GET", path, statuses=(200, 302), bound=bound, auth=False)
        if status == 302:
            target = redirect_target(raw)
            raw = self._call(target.netloc, "GET", target.path + ("?" + target.query if target.query else ""),
                             bound=bound, auth=False)[1]
        return len(raw), digest(raw)


def safe_name(name):
    return type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,180}", name) is not None


def check_repository(value):
    require(type(value) is dict and value.get("id") == REPO_ID and value.get("full_name") == REPOSITORY
            and value.get("private") is False and type(value.get("owner")) is dict
            and value["owner"].get("id") == OWNER_ID and value["owner"].get("login") == OWNER,
            "Repository/owner identity changed.")


def check_ref(value, ref, sha):
    require(type(value) is dict and value.get("ref") == ref and type(value.get("object")) is dict
            and value["object"].get("type") == "commit" and value["object"].get("sha") == sha,
            "Branch or tag lease changed.")


def source_branch_lease(api, request):
    check_repository(api.get(PREFIX))
    check_ref(api.get(PREFIX + "/git/ref/heads/main"), "refs/heads/main", request["publisherSHA"])
    commit = api.get(PREFIX + "/git/commits/" + request["source"])
    require(type(commit) is dict and commit.get("sha") == request["source"]
            and type(commit.get("tree")) is dict and commit["tree"].get("sha") == REVIEWED_SOURCE_TREE,
            "Source tree is not the pinned reviewed package tree.")


def verify_source_run(value, request, run_id, contract):
    workflow_id, path, name, _ = contract
    require(type(value) is dict and value.get("id") == run_id
            and value.get("workflow_id") == workflow_id
            and value.get("path") in {path, path + "@main"}
            and value.get("name") == name and value.get("head_sha") == request["source"]
            and value.get("head_branch") == "main" and value.get("event") == "push"
            and value.get("run_attempt") == 1 and value.get("status") == "completed"
            and value.get("conclusion") == "success"
            and value.get("html_url") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "Exact source-push run is missing, rerun, skipped or not successful.")
    check_repository(value.get("repository"))
    check_repository(value.get("head_repository"))


def verify_source_jobs(value, request, run_id, contract):
    _, _, workflow_name, names = contract
    require(type(value) is dict and value.get("total_count") == len(names)
            and type(value.get("jobs")) is list and len(value["jobs"]) == len(names),
            "Exact source-push job inventory is incomplete.")
    seen, ids = set(), set()
    for job in value["jobs"]:
        require(type(job) is dict and job.get("name") in names and job["name"] not in seen
                and positive_id(job.get("id")) and job["id"] not in ids
                and job.get("run_id") == run_id and job.get("run_attempt") == 1
                and job.get("head_sha") == request["source"]
                and job.get("workflow_name") == workflow_name
                and job.get("status") == "completed" and job.get("conclusion") == "success",
                "A required source-push job is missing, skipped or failed.")
        if job["name"] == "PR build and affected-flow checks":
            steps = job.get("steps")
            require(type(steps) is list)
            matches = [step for step in steps if type(step) is dict and
                       step.get("name") == "Require every focused prerequisite, including selection"]
            require(len(matches) == 1 and matches[0].get("status") == "completed"
                    and matches[0].get("conclusion") == "success",
                    "Focused source aggregate did not establish all prerequisites.")
        seen.add(job["name"])
        ids.add(job["id"])
    require(seen == names)


def exact_source_ci(api, request):
    ids = parse_source_ci_ids(request["sourceCIRunIDs"])
    for contract, run_id in zip(SOURCE_CI, ids):
        workflow_id, path, name, _ = contract
        workflow = api.get(PREFIX + f"/actions/workflows/{workflow_id}")
        require(type(workflow) is dict and workflow.get("id") == workflow_id
                and workflow.get("path") == path and workflow.get("name") == name,
                "Source workflow identity changed.")
        route = PREFIX + f"/actions/runs/{run_id}"
        verify_source_run(api.get(route), request, run_id, contract)
        verify_source_run(api.get(route + "/attempts/1"), request, run_id, contract)
        verify_source_jobs(api.get(route + "/attempts/1/jobs?per_page=100"), request,
                           run_id, contract)
        # Catch a rerun during this workflow's job inventory.
        verify_source_run(api.get(route), request, run_id, contract)
    # A later workflow's checks may take long enough for the first workflow to
    # be rerun. Close that window with a compact final current-run sweep.
    for contract, run_id in zip(SOURCE_CI, ids):
        verify_source_run(api.get(PREFIX + f"/actions/runs/{run_id}"),
                          request, run_id, contract)


def file_entry(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
            "Public asset is not a bounded regular file.")
    hash_value = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_size, opened.st_mtime_ns) ==
                (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns),
                "Public asset changed before review.")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while data := stream.read(1 << 20):
                hash_value.update(data)
        after = os.fstat(descriptor)
        require((after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns) ==
                (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns),
                "Public asset changed during review.")
    finally:
        os.close(descriptor)
    return {"size": info.st_size, "sha256": hash_value.hexdigest()}


def expected_assets(version):
    names = {f"tracebolt-{version}-darwin-{arch}-{role}"
             for arch in ("amd64", "arm64")
             for role in ("macos-package-prepare", "service-test-package.tar.gz")}
    return names | {"build-manifest.json", GUIDE, RELEASE_MANIFEST}


def release_body(request):
    macos_run = parse_source_ci_ids(request["sourceCIRunIDs"])[2]
    return ("Unsigned macOS arm64/amd64 service-test prerelease built from exact source "
            + request["source"] + ". Seven exact source-push CI runs, including macOS source: https://github.com/" + REPOSITORY
            + "/actions/runs/" + str(macos_run)
            + ". Read macos-prerelease.md and the package TESTING.md before any separately approved Mac test. "
            "No Developer ID signature, notarization, native install, enrollment, launchd, reboot, "
            "interoperability, or production acceptance is claimed. Direct whole-archive downloads are provided. "
            "No-overwrite is publisher policy, not GitHub platform immutability.")


def prepare_files(request, source_root, output):
    checkout_lease(ROOT, request["publisherSHA"])
    publisher_blob_lease()
    checkout_lease(source_root, request["source"], REVIEWED_SOURCE_TREE)
    require(not output.is_symlink() and output.is_dir() and output.resolve() == output
            and not output.is_relative_to(source_root) and not output.is_relative_to(ROOT))
    spec = importlib.util.spec_from_file_location("_macos_package_builder", source_root / "deploy/macos-release/build-service-test-package.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    raw = (output / "build-manifest.json").read_bytes()
    manifest = strict_json(raw, 16 << 10)
    require(raw == canonical(manifest), "Build manifest is not canonical.")
    builder.validate_output(manifest, output, request["version"], request["source"],
                            REVIEWED_SOURCE_TREE, builder.base.go_version(source_root))
    paths = {name: output / name for name in manifest["assets"]}
    paths["build-manifest.json"] = output / "build-manifest.json"
    guide = ROOT / "docs" / GUIDE
    paths[GUIDE] = guide
    entries = {}
    for name, path in sorted(paths.items()):
        require(safe_name(name))
        entries[name] = file_entry(path, MAX_ASSET if name.endswith(".tar.gz") else 64 << 20)
    release_manifest = {"schema": RELEASE_SCHEMA, "repository": REPOSITORY,
        "repositoryID": REPO_ID, "version": request["version"], "sourceCommit": request["source"],
        "sourceTree": REVIEWED_SOURCE_TREE, "publisherCommit": request["publisherSHA"],
        "publisherRunID": request["publisherRunID"], "publisherRunAttempt": 1,
        "sourceCIWorkflowIDs": [contract[0] for contract in SOURCE_CI],
        "sourceCIRunIDs": list(parse_source_ci_ids(request["sourceCIRunIDs"])),
        "distribution": "unsigned-macos-service-test-prerelease",
        "nativeAccepted": False, "publisherSigned": False, "notarized": False,
        "productionReady": False, "noOverwritePolicy": True,
        "platformImmutabilityClaimed": False, "assets": entries}
    release_raw = canonical(release_manifest)
    require(len(release_raw) <= 64 << 10)
    release_path = output.parent / "release-manifest.json"
    require(not release_path.exists() and not release_path.is_symlink())
    with release_path.open("xb") as stream:
        stream.write(release_raw)
    paths[RELEASE_MANIFEST] = release_path
    entries[RELEASE_MANIFEST] = file_entry(release_path, 64 << 10)
    require(set(paths) == expected_assets(request["version"]))
    checkout_lease(ROOT, request["publisherSHA"])
    publisher_blob_lease()
    checkout_lease(source_root, request["source"], REVIEWED_SOURCE_TREE)
    plan = {"schema": PLAN_SCHEMA, "request": request, "sourceTree": REVIEWED_SOURCE_TREE,
            "buildManifestSHA256": digest(raw), "assets": entries}
    return plan, paths


def validate_plan(plan, request):
    require(type(plan) is dict and set(plan) == {"schema", "request", "sourceTree", "buildManifestSHA256", "assets"}
            and plan["schema"] == PLAN_SCHEMA and plan["request"] == request
            and plan["sourceTree"] == REVIEWED_SOURCE_TREE and HEX64.fullmatch(plan["buildManifestSHA256"]))
    assets = plan["assets"]
    require(type(assets) is dict and set(assets) == expected_assets(request["version"]))
    for name, entry in assets.items():
        require(safe_name(name) and type(entry) is dict and set(entry) == {"size", "sha256"}
                and type(entry["size"]) is int and 0 < entry["size"] <= MAX_ASSET
                and type(entry["sha256"]) is str and HEX64.fullmatch(entry["sha256"]))
    return plan


def frozen_plan(env, request):
    encoded, sha = env.get("TRACEBOLT_VERIFIED_PLAN", ""), env.get("TRACEBOLT_VERIFIED_PLAN_SHA256", "")
    require(type(encoded) is str and 0 < len(encoded) <= (4 * MAX_PLAN // 3 + 4)
            and type(sha) is str and HEX64.fullmatch(sha))
    raw = base64.b64decode(encoded, validate=True)
    require(digest(raw) == sha)
    plan = strict_json(raw, MAX_PLAN)
    require(raw == canonical(plan))
    return validate_plan(plan, request)


def require_fresh(api, request):
    tag = request["version"]
    require(api.get(PREFIX + "/git/ref/tags/" + tag, missing=True) is None
            and api.get(PREFIX + "/releases/tags/" + tag, missing=True) is None,
            "Tag or release already exists; no overwrite or adoption is permitted.")
    for page in range(1, 11):
        releases = api.get(PREFIX + f"/releases?per_page=100&page={page}")
        require(type(releases) is list and len(releases) <= 100 and all(type(x) is dict
                and type(x.get("tag_name")) is str for x in releases))
        require(all(x["tag_name"] != tag for x in releases),
                "A draft already uses the version; leave it intact.")
        if len(releases) < 100:
            return
    raise Rejected("Release inventory exceeds the freshness bound.")


def release_name(request):
    return "Tracebolt macOS service test preview " + request["version"]


def release_identity(value, request, release_id, draft):
    require(type(value) is dict and positive_id(value.get("id"))
            and (release_id is None or value["id"] == release_id)
            and value.get("tag_name") == request["version"]
            and value.get("target_commitish") == request["source"]
            and value.get("draft") is draft and value.get("prerelease") is True
            and value.get("name") == release_name(request) and value.get("body") == release_body(request),
            "Release identity or state changed; leave it intact.")
    url = value.get("html_url")
    prefix = f"https://github.com/{REPOSITORY}/releases/tag/"
    require(type(url) is str and url.startswith(prefix))
    tag = url[len(prefix):]
    require(tag == request["version"] or (draft and re.fullmatch(r"untagged-[0-9a-f]{20}", tag)),
            "Release URL is unexpected.")
    return value["id"], tag


def check_assets(api, release_id, request, entries, ids, download_tags):
    listing = api.get(PREFIX + f"/releases/{release_id}/assets?per_page=100")
    require(type(listing) is list and len(listing) == len(entries))
    seen = set()
    for value in listing:
        name = value.get("name") if type(value) is dict else None
        require(name in entries and name not in seen)
        check_asset(value, name, entries[name], download_tags, ids[name])
        seen.add(name)
    require(seen == set(entries))


def check_asset(value, name, entry, download_tags, asset_id=None):
    if type(download_tags) is str:
        download_tags = {download_tags}
    require(type(download_tags) is set and 0 < len(download_tags) <= 2
            and all(safe_name(tag) for tag in download_tags))
    urls = {f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
            for tag in download_tags}
    require(type(value) is dict and positive_id(value.get("id"))
            and (asset_id is None or value["id"] == asset_id) and value.get("name") == name
            and value.get("state") == "uploaded" and type(value.get("size")) is int
            and value["size"] == entry["size"] and value.get("digest") == "sha256:" + entry["sha256"]
            and value.get("browser_download_url") in urls,
            "Release asset ID, name, size, digest or URL differs.")
    return value["id"]


def publish(api, request, plan, paths, source_root):
    validate_plan(plan, request)
    require({name: file_entry(path, MAX_ASSET) for name, path in paths.items()} == plan["assets"],
            "Rebuilt public asset bytes differ from the frozen plan.")
    source_branch_lease(api, request)
    exact_source_ci(api, request)
    require_fresh(api, request)
    checkout_lease(ROOT, request["publisherSHA"])
    publisher_blob_lease()
    checkout_lease(source_root, request["source"], REVIEWED_SOURCE_TREE)
    # Each write is deliberately one attempt. A partial tag/draft is retained.
    ref = "refs/tags/" + request["version"]
    check_ref(api.write_json("POST", PREFIX + "/git/refs", {"ref": ref, "sha": request["source"]}),
              ref, request["source"])
    draft = api.write_json("POST", PREFIX + "/releases", {
        "tag_name": request["version"], "target_commitish": request["source"],
        "name": release_name(request), "body": release_body(request), "draft": True,
        "prerelease": True, "make_latest": "false", "generate_release_notes": False})
    release_id, draft_download_tag = release_identity(draft, request, None, True)
    draft_download_tags = {request["version"], draft_download_tag}
    require(draft.get("assets") == [], "A new draft unexpectedly contains assets.")
    ids = {}
    for name, path in sorted(paths.items()):
        ids[name] = check_asset(api.upload(release_id, name, path), name,
                                plan["assets"][name], draft_download_tags)
        require(len(set(ids.values())) == len(ids), "An asset ID was reused.")
    check_assets(api, release_id, request, plan["assets"], ids, draft_download_tags)
    check_ref(api.get(PREFIX + "/git/ref/tags/" + request["version"]), ref, request["source"])
    require(release_identity(api.get(PREFIX + f"/releases/{release_id}"), request, release_id, True) ==
            (release_id, draft_download_tag))
    exact_source_ci(api, request)
    require({name: file_entry(path, MAX_ASSET) for name, path in paths.items()} == plan["assets"])
    check_ref(api.get(PREFIX + "/git/ref/tags/" + request["version"]), ref, request["source"])
    require(release_identity(api.get(PREFIX + f"/releases/{release_id}"), request, release_id, True) ==
            (release_id, draft_download_tag))
    check_assets(api, release_id, request, plan["assets"], ids, draft_download_tags)
    source_branch_lease(api, request)
    final = api.write_json("PATCH", PREFIX + f"/releases/{release_id}",
                           {"draft": False, "make_latest": "false"})
    require(release_identity(final, request, release_id, False) == (release_id, request["version"]))
    release_identity(api.get(PREFIX + f"/releases/{release_id}"), request, release_id, False)
    release_identity(api.get(PREFIX + "/releases/tags/" + request["version"]), request, release_id, False)
    check_ref(api.get(PREFIX + "/git/ref/tags/" + request["version"]), ref, request["source"])
    check_assets(api, release_id, request, plan["assets"], ids, request["version"])
    for name, entry in sorted(plan["assets"].items()):
        require(api.public_digest(request["version"], name, entry["size"]) ==
                (entry["size"], entry["sha256"]),
                "Public whole-asset download differs from the verified build.")
    exact_source_ci(api, request)
    source_branch_lease(api, request)
    release_identity(api.get(PREFIX + f"/releases/{release_id}"), request, release_id, False)
    check_ref(api.get(PREFIX + "/git/ref/tags/" + request["version"]), ref, request["source"])
    check_assets(api, release_id, request, plan["assets"], ids, request["version"])
    return f"https://github.com/{REPOSITORY}/releases/tag/{request['version']}"


def main(argv=None, env=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true")
    modes.add_argument("--publish", action="store_true")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    request = authorize(env, args.publish)
    frozen = frozen_plan(env, request) if args.publish else None
    plan, paths = prepare_files(request, args.source_root, args.output)
    validate_plan(plan, request)
    require(frozen is None or plan == frozen, "The independent publish rebuild differs from the read-only verified plan.")
    api = GitHubAPI(env.get("GITHUB_TOKEN", ""), write=False)
    source_branch_lease(api, request)
    exact_source_ci(api, request)
    require_fresh(api, request)
    if not args.publish:
        raw = canonical(plan)
        require(len(raw) <= MAX_PLAN and env.get("GITHUB_OUTPUT"), "Frozen verification output is unavailable.")
        with open(env["GITHUB_OUTPUT"], "a", encoding="ascii", newline="\n") as stream:
            stream.write("plan=" + base64.b64encode(raw).decode("ascii") + "\n")
            stream.write("plan_sha256=" + digest(raw) + "\n")
        print("PASS: exact source, green exact source-push CI and twice-built unsigned package verified; no release mutation.")
        return
    print("Frozen rebuild and fresh-version checks passed; attempting one fresh tag and draft.")
    url = publish(GitHubAPI(env["GITHUB_TOKEN"], write=True), request, plan, paths, args.source_root)
    print("Published unsigned prerelease and re-read every whole public asset: " + url)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("macOS prerelease stopped. Inspect any partial tag/draft/assets; no retry, overwrite or cleanup was attempted.", file=sys.stderr)
        sys.exit(1)
