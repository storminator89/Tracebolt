#!/usr/bin/env python3
"""Promote exact accepted unsigned x64 Setup bytes; never build or run a binary.

Read-only verification is the default workflow job. The separate explicit write
job uses a frozen verification plan and performs each mutation once. An uncertain
write leaves state for human inspection; there is no adoption, overwrite, delete,
force-tag, automatic retry, signing, OIDC, or repository-setting operation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("_windows_setup_gate", ROOT / "tests/windows_native_acceptance/run_setup_gui.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)
REPOSITORY = "storminator89/Tracebolt"
REPO_ID = 1403204207
OWNER = "storminator89"
OWNER_ID = 30489872
PREFIX = "/repos/" + REPOSITORY
# Only this independently reviewed Setup source tree is eligible. A different
# tree needs a new review and explicit publisher change, never an input override.
ACCEPTED_SOURCE_TREE = "93001dc899c69f4590c3477dcd2e8b29899274ce"
NATIVE_WORKFLOW = ".github/workflows/windows-setup-acceptance.yml"
PUBLISH_WORKFLOW = ".github/workflows/windows-prerelease.yml"
AGGREGATE_JOB = "Validate four reports and preserve exact tested public bytes (no rebuild)"
GUIDES = {"windows-prerelease-install.md", "windows-prerelease-changelog.md"}
RELEASE_MANIFEST = "release-manifest.json"
ASSETS = gate.PUBLIC_FILES | {gate.AGGREGATE_REPORT, RELEASE_MANIFEST} | GUIDES
BOUNDS = {gate.SETUP_NAME: 128 << 20, gate.SERVICE_NAME: 128 << 20,
          "source-inputs.json": 4 << 20, "build-manifest.json": 64 << 10,
          "setup-package-amd64.json": 2048, "SHA256SUMS": 4096,
          gate.REPORT_NAME: 16 << 10, gate.AGGREGATE_REPORT: 128 << 10,
          RELEASE_MANIFEST: 64 << 10, **{name: 64 << 10 for name in GUIDES}}
MAX_ARCHIVE = 270 << 20
MAX_JSON = 2 << 20
MAX_PLAN = 64 << 10
HEX40 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z", re.ASCII)
# A Windows-specific prerelease namespace, never a stable/general Linux tag.
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-windows-preview\.([1-9][0-9]*)\Z", re.ASCII)
BRANCH = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z", re.ASCII)


class Rejected(Exception):
    """Only fixed, non-sensitive failure messages leave this publisher."""


def require(ok, message="Windows prerelease verification rejected an input."):
    if not ok:
        raise Rejected(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON fields are not accepted.")
        result[key] = value
    return result


def strict_json(raw, bound=MAX_JSON):
    require(type(raw) is bytes and 0 < len(raw) <= bound, "JSON response exceeds its bound.")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("Non-finite JSON rejected.")))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("Invalid JSON response.") from None


def positive_id(value):
    return type(value) is int and 0 < value < 2**63


def validate_request(value):
    keys = {"source", "acceptanceRunID", "version", "publisherSHA", "publisherRef", "publisherRunID"}
    require(type(value) is dict and set(value) == keys)
    require(all(type(item) is str for item in value.values()))
    require(HEX40.fullmatch(value["source"]) and HEX40.fullmatch(value["publisherSHA"]) and value["source"] != value["publisherSHA"])
    require(RUN_ID.fullmatch(value["acceptanceRunID"]) and RUN_ID.fullmatch(value["publisherRunID"]) and
            int(value["acceptanceRunID"]) < 2**63 and int(value["publisherRunID"]) < 2**63 and
            value["acceptanceRunID"] != value["publisherRunID"])
    require(len(value["version"]) <= 64 and VERSION.fullmatch(value["version"]), "Use a fresh vMAJOR.MINOR.PATCH-windows-preview.N tag.")
    require(BRANCH.fullmatch(value["publisherRef"]) and all(p not in ("", ".", "..") and not p.endswith((".", ".lock")) for p in value["publisherRef"].split("/")) and ".." not in value["publisherRef"])
    return value


def authorize(env, publish):
    request = validate_request({"source": env.get("TRACEBOLT_RELEASE_SOURCE", ""),
        "acceptanceRunID": env.get("TRACEBOLT_ACCEPTANCE_RUN_ID", ""), "version": env.get("TRACEBOLT_RELEASE_VERSION", ""),
        "publisherSHA": env.get("TRACEBOLT_PUBLISHER_SHA", ""), "publisherRef": env.get("GITHUB_REF", ""),
        "publisherRunID": env.get("GITHUB_RUN_ID", "")})
    fixed = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": REPOSITORY,
             "GITHUB_REPOSITORY_ID": str(REPO_ID), "GITHUB_REPOSITORY_OWNER": OWNER,
             "GITHUB_REPOSITORY_OWNER_ID": str(OWNER_ID), "GITHUB_ACTOR": OWNER, "GITHUB_ACTOR_ID": str(OWNER_ID),
             "GITHUB_TRIGGERING_ACTOR": OWNER, "GITHUB_RUN_ATTEMPT": "1", "RUNNER_OS": "Linux",
             "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_SHA": request["publisherSHA"],
             "GITHUB_WORKFLOW_SHA": request["publisherSHA"], "GITHUB_JOB": "publish" if publish else "verify",
             "GITHUB_WORKFLOW_REF": REPOSITORY + "/" + PUBLISH_WORKFLOW + "@" + request["publisherRef"]}
    require(all(env.get(k) == v for k, v in fixed.items()), "Only the exact first-attempt owner-dispatched publisher revision is allowed.")
    require(env.get("TRACEBOLT_RELEASE_PUBLISH") in {"true", "false"})
    require(not publish or env["TRACEBOLT_RELEASE_PUBLISH"] == "true", "The write job requires explicit publish=true.")
    return request


def verify_checkout(request, root=ROOT):
    def git(*args):
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=30, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 1 << 20, "Publisher checkout verification failed.")
        return result.stdout
    require(Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() == root.resolve())
    require(git("rev-parse", "HEAD").decode().strip() == request["publisherSHA"])
    require(not git("status", "--porcelain", "--untracked-files=all"), "Publisher checkout is not clean.")


def official_host(host):
    return host in {"api.github.com", "uploads.github.com", "github.com", "release-assets.githubusercontent.com"} or re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", host) is not None


class OfficialConnection(http.client.HTTPSConnection):
    """No ambient proxy/CA override and no private-address redirect destination."""
    def connect(self):
        require(official_host(self.host) and self.port == 443, "Unapproved HTTPS destination.")
        addresses = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        require(0 < len(addresses) <= 16, "DNS response is empty or exceeds its bound.")
        for family, _, _, _, address in addresses:
            ip = ipaddress.ip_address(address[0])
            require(family in (socket.AF_INET, socket.AF_INET6) and ip.is_global and not
                    (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_unspecified), "Non-public HTTPS destination rejected.")
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


def response_bytes(response, limit):
    headers = response.getheaders()
    lengths = [v for k, v in headers if k.lower() == "content-length"]
    encodings = [v for k, v in headers if k.lower() == "content-encoding"]
    require(len(lengths) <= 1 and all(re.fullmatch(r"[0-9]{1,10}", n) and int(n) <= limit for n in lengths), "HTTP length exceeds its bound.")
    require(not encodings or encodings == ["identity"], "Encoded HTTP response rejected.")
    chunks, total, started = [], 0, time.monotonic()
    while True:
        chunk = response.read(min(65536, limit + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        require(total <= limit and time.monotonic() - started < 600, "Download exceeds its size or time bound.")
        chunks.append(chunk)
    require(not lengths or total == int(lengths[0]), "Truncated HTTP response.")
    return b"".join(chunks)


def redirect_target(value, artifact):
    require(type(value) is str and 0 < len(value) <= 16384 and all(32 < ord(c) < 127 for c in value) and "\\" not in value,
            "Invalid download redirect.")
    target = urlsplit(value)
    host_ok = re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", target.netloc) if artifact else target.netloc == "release-assets.githubusercontent.com"
    require(target.scheme == "https" and host_ok and not target.fragment and not target.username and not target.password and
            target.path.startswith("/") and len(target.path) <= 2048 and not any(p in (".", "..") for p in target.path.split("/")), "Unapproved download redirect.")
    if not artifact:
        require(target.path.startswith("/github-production-release-asset/"), "Unexpected release download route.")
    return target


class GitHubAPI:
    def __init__(self, token, *, write=False, connection=OfficialConnection):
        require(type(token) is str and 0 < len(token) <= 10000 and not any(c.isspace() for c in token), "The existing scoped Actions token is required.")
        self.token, self.write, self.connection = token, write, connection

    def _request(self, host, method, path, *, payload=None, upload=None, token=False, limit=MAX_JSON, statuses=(200,), no_pagination=False):
        require(official_host(host) and path.startswith("/") and not any(c in path for c in "\r\n"))
        require(not token or host in {"api.github.com", "uploads.github.com"}, "Credential forwarding rejected.")
        headers = {"User-Agent": "Tracebolt-windows-prerelease/1", "Accept-Encoding": "identity"}
        if token:
            headers.update(Authorization="Bearer " + self.token, Accept="application/vnd.github+json", **{"X-GitHub-Api-Version": "2026-03-10"})
        body = canonical(payload) if payload is not None else upload
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if upload is not None:
            require(type(upload) is bytes and 0 < len(upload) <= max(BOUNDS.values()))
            headers["Content-Type"] = "application/octet-stream"
        connection = self.connection(host, 443, timeout=60, context=tls_context())
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            require(response.status in statuses, "GitHub request failed. State may be partial; inspect it before any new write attempt.")
            require(not no_pagination or not any(k.lower() == "link" for k, _ in response.getheaders()),
                    "Paginated provenance response rejected.")
            if response.status == 302:
                locations = [v for k, v in response.getheaders() if k.lower() == "location"]
                require(len(locations) == 1, "Ambiguous download redirect.")
                return response.status, locations[0]
            if response.status == 404:
                return response.status, None
            return response.status, response_bytes(response, limit)
        finally:
            connection.close()

    def request(self, method, path, payload=None, *, upload=None, missing=False):
        require(path == PREFIX or path.startswith(PREFIX + "/"), "Wrong repository API route.")
        require(method in {"GET", "POST", "PATCH"})
        if method != "GET":
            require(self.write, "Read-only verification cannot mutate GitHub.")
            suffix = path.removeprefix(PREFIX)
            if method == "POST":
                require(suffix in {"/git/refs", "/releases"} or re.fullmatch(r"/releases/[1-9][0-9]*/assets\?name=[A-Za-z0-9._-]+", suffix), "Unapproved write endpoint.")
            else:
                require(re.fullmatch(r"/releases/[1-9][0-9]*", suffix), "Unapproved write endpoint.")
            require(not missing)
        require(upload is None or (method == "POST" and "/assets?name=" in path and payload is None))
        status, raw = self._request("uploads.github.com" if upload is not None else "api.github.com", method, path,
                                   payload=payload, upload=upload, token=True,
                                   statuses=((200, 404) if missing else (201,) if method == "POST" else (200,)))
        return None if status == 404 else strict_json(raw)

    def artifact(self, artifact_id, limit):
        require(positive_id(artifact_id) and 0 < limit <= MAX_ARCHIVE)
        _, location = self._request("api.github.com", "GET", PREFIX + f"/actions/artifacts/{artifact_id}/zip", token=True, statuses=(302,))
        target = redirect_target(location, True)
        # The signed object URL is trusted only as a one-hop API response. No
        # bearer token, cookie, or signed URL is logged or forwarded elsewhere.
        return self._request(target.netloc, "GET", target.path + ("?" + target.query if target.query else ""), limit=limit)[1]

    def provenance_transport(self, url, headers, limit):
        """Read-only proof transport preserving the publisher HTTPS boundary.

        A blob read needs the exact preceding authenticated artifact redirect.
        Caller-supplied headers are never forwarded to either destination.
        """
        require(type(url) is str and type(headers) is dict and type(limit) is int and
                0 < limit <= gate.provenance.ARCHIVE_LIMIT)
        target = urlsplit(url)
        require(target.scheme == "https" and not target.fragment and not target.username and
                not target.password and "\\" not in url and all(32 < ord(c) < 127 for c in url))
        path = target.path + ("?" + target.query if target.query else "")
        if target.netloc == "api.github.com":
            require(headers.get("Authorization") == "Bearer " + self.token and
                    not any(k.lower() == "cookie" for k in headers))
            require(path in getattr(self, "_provenance_routes", set()), "Unapproved provenance API route.")
            require(getattr(self, "_provenance_redirect", None) is None)
            archive = path.endswith("/zip")
            status, raw = self._request("api.github.com", "GET", path, token=True, limit=limit,
                                       statuses=(302,) if archive else (200,), no_pagination=not archive)
            if archive:
                redirect_target(raw, True)
                self._provenance_redirect = raw
                return status, {"location": raw}, b""
            return status, {}, raw
        require(url == getattr(self, "_provenance_redirect", None), "Unbound provenance download redirect.")
        self._provenance_redirect = None
        require(not any(k.lower() in {"authorization", "cookie", "proxy-authorization"} for k in headers))
        target = redirect_target(url, True)
        status, raw = self._request(target.netloc, "GET", path, limit=limit)
        return status, {}, raw

    def public_asset(self, version, name, size):
        require(VERSION.fullmatch(version) and name in ASSETS and type(size) is int and 0 < size <= BOUNDS[name])
        path = f"/{REPOSITORY}/releases/download/{version}/{name}"
        status, raw = self._request("github.com", "GET", path, limit=size, statuses=(200, 302))
        if status == 200:
            return raw
        target = redirect_target(raw, False)
        return self._request(target.netloc, "GET", target.path + ("?" + target.query if target.query else ""), limit=size)[1]


def check_repository(value):
    require(type(value) is dict and type(value.get("id")) is int and value["id"] == REPO_ID and
            value.get("full_name") == REPOSITORY and value.get("private") is False and type(value.get("owner")) is dict and
            type(value["owner"].get("id")) is int and value["owner"]["id"] == OWNER_ID and value["owner"].get("login") == OWNER,
            "Unexpected repository or owner identity.")


def check_ref(value, ref, sha):
    require(type(value) is dict and value.get("ref") == ref and type(value.get("object")) is dict and
            value["object"].get("type") == "commit" and value["object"].get("sha") == sha, "Source lease or tag changed; stopped without overwrite.")


def publisher_lease(api, request):
    check_repository(api.request("GET", PREFIX))
    check_ref(api.request("GET", PREFIX + "/git/ref/" + request["publisherRef"].removeprefix("refs/")), request["publisherRef"], request["publisherSHA"])
    commit = api.request("GET", PREFIX + "/git/commits/" + request["source"])
    require(type(commit) is dict and commit.get("sha") == request["source"] and type(commit.get("tree")) is dict and
            commit["tree"].get("sha") == ACCEPTED_SOURCE_TREE, "Accepted source is not the exact reviewed Setup tree.")


def check_actor(value):
    require(type(value) is dict and type(value.get("id")) is int and value["id"] == OWNER_ID and value.get("login") == OWNER,
            "Native run was not dispatched by the selected owner.")


def verify_native_run(api, request, *, execution=None):
    run_id, source = int(request["acceptanceRunID"]), request["source"]
    value = api.request("GET", PREFIX + f"/actions/runs/{run_id}")
    require(type(value) is dict and type(value.get("id")) is int and value["id"] == run_id and
            type(value.get("run_attempt")) is int and value["run_attempt"] == 1 and value.get("event") == "workflow_dispatch" and
            value.get("status") == "completed" and value.get("conclusion") == "success" and value.get("head_sha") == source and value.get("head_branch") == "main" and
            value.get("path") == NATIVE_WORKFLOW and value.get("html_url") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "Require the exact successful first-attempt native Setup workflow run.")
    check_repository(value.get("repository"))
    check_repository(value.get("head_repository"))
    check_actor(value.get("actor"))
    check_actor(value.get("triggering_actor"))
    # Repeat the same current/attempt predicates after long proof downloads;
    # an earlier authenticated attempt record is not a perpetual authority.
    attempt = api.request("GET", PREFIX + f"/actions/runs/{run_id}/attempts/1")
    try:
        require(gate.provenance._run(value, source, str(run_id)) == REPO_ID and
                gate.provenance._run(attempt, source, str(run_id)) == REPO_ID)
        require(attempt.get("status") == "completed" and attempt.get("conclusion") == "success" and
                attempt.get("workflow_id") == value.get("workflow_id") and attempt.get("path") == value.get("path"))
    except Exception:
        raise Rejected("Native current or attempt-one metadata rejected.") from None
    workflow_id = value.get("workflow_id")
    require(positive_id(workflow_id))
    workflow = api.request("GET", PREFIX + f"/actions/workflows/{workflow_id}")
    require(type(workflow) is dict and type(workflow.get("id")) is int and workflow["id"] == workflow_id and workflow.get("path") == NATIVE_WORKFLOW and
            workflow.get("name") == gate.provenance.WORKFLOW_NAME)
    jobs = api.request("GET", PREFIX + f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100")
    require(type(jobs) is dict and type(jobs.get("total_count")) is int and jobs["total_count"] == 5 and
            type(jobs.get("jobs")) is list and len(jobs["jobs"]) == 5, "Native jobs are missing, repeated, or ambiguous.")
    expected = {"Actual packaged GUI - " + case: "windows-2025" for case in gate.CHECKS}
    expected[AGGREGATE_JOB] = "ubuntu-24.04"
    selected, runners = {}, {}
    for job in jobs["jobs"]:
        require(type(job) is dict and type(job.get("name")) is str and job["name"] in expected and job["name"] not in selected)
        require(positive_id(job.get("id")) and type(job.get("run_id")) is int and job["run_id"] == run_id and job.get("head_sha") == source and
                job.get("status") == "completed" and job.get("conclusion") == "success" and
                type(job.get("run_attempt")) is int and job["run_attempt"] == 1 and
                job.get("workflow_name") == gate.provenance.WORKFLOW_NAME, "All four native cases and aggregation must succeed.")
        labels = job.get("labels")
        require(labels == [expected[job["name"]]], "Unexpected native runner label.")
        if job["name"] != AGGREGATE_JOB:
            require(positive_id(job.get("runner_id")), "Native runner registration ID must be positive.")
            runners[job["name"].removeprefix("Actual packaged GUI - ")] = job["runner_id"]
        selected[job["name"]] = job["id"]
    require(len(set(selected.values())) == 5 and len(runners) == len(set(runners.values())) == 4)
    # This pinned pure validator repeats every proof-relevant required step,
    # hosted label and registration predicate without another artifact download.
    try:
        cases = gate.provenance._jobs(jobs["jobs"], source, str(run_id), True)
        if execution is not None:
            require(type(execution) is dict and type(execution.get("cases")) is dict and
                    set(execution["cases"]) == set(gate.CHECKS))
            for case, job in cases.items():
                recorded = execution["cases"][case]
                require(str(job["runner_group_id"]) == recorded["runnerGroupID"] and
                        str(job["runner_id"]) == recorded["runnerID"] and str(job["id"]) == recorded["jobID"],
                        "Native registration metadata changed during verification.")
    except Exception:
        raise Rejected("Native execution step or registration metadata rejected.") from None
    return {"workflowID": workflow_id, "jobs": selected, "runners": runners}


def artifact_names(source):
    names = {"windows-setup-gui-" + case + "-" + source: {gate.REPORT_NAME} for case in gate.CHECKS}
    names.update({"windows-setup-public-input-" + source: gate.PUBLIC_FILES,
                  "windows-setup-native-subset-public-" + source: gate.PUBLIC_FILES,
                  "windows-setup-native-subset-evidence-" + source: {gate.AGGREGATE_REPORT}})
    return names


def archive_bound(names):
    require(set(names) and set(names) <= set(BOUNDS))
    return min(MAX_ARCHIVE, sum(BOUNDS[name] for name in names) + (64 << 10))


def artifact_identity(value, name, request):
    require(type(value) is dict and positive_id(value.get("id")) and value.get("name") == name and value.get("expired") is False,
            "Missing, expired, or mismatched immutable artifact ID.")
    require(type(value.get("size_in_bytes")) is int and 0 < value["size_in_bytes"] <= archive_bound(artifact_names(request["source"])[name]) and
            type(value.get("digest")) is str and value["digest"].startswith("sha256:") and HEX64.fullmatch(value["digest"][7:]),
            "Artifact API size or archive digest is missing.")
    run = value.get("workflow_run")
    require(type(run) is dict and type(run.get("id")) is int and run["id"] == int(request["acceptanceRunID"]) and
            type(run.get("repository_id")) is int and run["repository_id"] == REPO_ID and
            type(run.get("head_repository_id")) is int and run["head_repository_id"] == REPO_ID and run.get("head_sha") == request["source"] and run.get("head_branch") == "main",
            "Artifact is not bound to the accepted repository/source/run.")
    return {"id": value["id"], "name": name, "size": value["size_in_bytes"], "sha256": value["digest"][7:]}


def resolve_artifacts(api, request, frozen=None):
    expected = artifact_names(request["source"])
    listing = api.request("GET", PREFIX + "/actions/runs/" + request["acceptanceRunID"] + "/artifacts?per_page=100")
    require(type(listing) is dict and type(listing.get("total_count")) is int and listing["total_count"] == len(expected) and
            type(listing.get("artifacts")) is list and len(listing["artifacts"]) == len(expected), "Native artifact inventory is missing, extra, or ambiguous.")
    selected = {}
    for item in listing["artifacts"]:
        require(type(item) is dict and type(item.get("name")) is str and item["name"] in expected and item["name"] not in selected)
        selected[item["name"]] = artifact_identity(item, item["name"], request)
    require(len({item["id"] for item in selected.values()}) == len(expected))
    require(frozen is None or selected == frozen, "Native artifact IDs or archive digests changed after read-only verification.")
    for name, entry in selected.items():
        readback = api.request("GET", PREFIX + "/actions/artifacts/" + str(entry["id"]))
        require(artifact_identity(readback, name, request) == entry, "Artifact metadata changed during verification.")
    return selected


def unpack_archive(raw, entry, names):
    require(type(raw) is bytes and 0 < len(raw) <= archive_bound(names) and len(raw) == entry["size"] and digest(raw) == entry["sha256"], "Downloaded artifact archive does not match its API digest.")
    # Check the small central-directory count before ZipFile allocates one
    # object per entry. ZIP64/multidisk/comments are unnecessary for this finite
    # package and could turn a bounded compressed archive into a memory bomb.
    require(len(raw) >= 22 and raw.startswith(b"PK\x03\x04") and raw[-22:-18] == b"PK\x05\x06")
    _, disk, directory_disk, disk_count, count, directory_size, directory_offset, comment_size = struct.unpack("<4s4H2LH", raw[-22:])
    require(disk == directory_disk == comment_size == 0 and disk_count == count == len(names) and
            0 < directory_size <= 512 * len(names) and directory_offset + directory_size == len(raw) - 22,
            "Artifact central directory is not the bounded single-disk allowlist.")
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        require(len(infos) == len(names) and not archive.comment, "Artifact archive contains unexpected entries.")
        require(sum(info.file_size for info in infos) <= sum(BOUNDS[name] for name in names))
        for info in infos:
            require(info.filename in names and info.filename not in result and info.orig_filename == info.filename and
                    not info.is_dir() and "/" not in info.filename and "\\" not in info.filename, "Artifact archive path rejected.")
            mode = info.external_attr >> 16
            require(stat.S_IFMT(mode) in {0, stat.S_IFREG} and not (info.external_attr & 0x10), "Artifact archive contains a link or special file.")
            require(not info.flag_bits & (1 | 64 | 8192) and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED} and
                    0 < info.file_size <= BOUNDS[info.filename] and 0 <= info.compress_size <= len(raw), "Artifact member exceeds its contract.")
            with archive.open(info) as stream:
                member = stream.read(BOUNDS[info.filename] + 1)
                require(len(member) == info.file_size and len(member) <= BOUNDS[info.filename])
            result[info.filename] = member
    require(set(result) == set(names))
    return result


def validate_evidence(raw, files, raw_reports, request):
    evidence = strict_json(raw, BOUNDS[gate.AGGREGATE_REPORT])
    require(type(evidence) is dict and "executionProvenance" in evidence)
    execution = evidence["executionProvenance"]
    reports = gate.aggregate_reports(raw_reports, request["source"], request["acceptanceRunID"], execution, files)
    hashes = gate.validate_public_package(files, request["source"], reports["install-uninstall"])
    expected = {"schema": "tracebolt.windows-setup-native-subset.v2", "source": request["source"],
                "runID": request["acceptanceRunID"], "status": "four_case_packaged_gui_subset",
                "distributionStatus": "unsigned-source-candidate-native-subset", "crossOSRebuildEquivalence": False,
                "coverage": dict.fromkeys(sorted(gate.FALSE_COVERAGE), False), "reports": reports, "publicFilesSHA256": hashes, "executionProvenance": execution}
    require(evidence == expected and raw == canonical(expected), "Finite accepted evidence does not match all four immutable reports and package bytes.")
    require(all(raw_reports[case] == canonical(report) for case, report in reports.items()), "Noncanonical native report rejected.")
    return evidence


def verify_execution(api, request, artifacts, native, evidence, files, raw_reports):
    """Authenticate stored v2 evidence afresh; pure JSON checks are insufficient."""
    execution = evidence.get("executionProvenance")
    require(type(execution) is dict)
    gate.aggregate_reports(raw_reports, request["source"], request["acceptanceRunID"], execution, files)
    run = request["acceptanceRunID"]
    routes = {PREFIX + "/actions/runs/" + run + suffix for suffix in
              ("", "/attempts/1", "/attempts/1/jobs?per_page=100", "/artifacts?per_page=100")}
    routes.add(PREFIX + "/actions/workflows/windows-setup-acceptance.yml")
    names = {"windows-setup-gui-" + case + "-" + request["source"] for case in gate.CHECKS}
    names.add("windows-setup-public-input-" + request["source"])
    for name in names:
        path = PREFIX + "/actions/artifacts/" + str(artifacts[name]["id"])
        routes.update({path, path + "/zip"})
    api._provenance_routes, api._provenance_redirect = routes, None
    try:
        verified = gate.provenance.verify_run(request["source"], run, raw_reports, files, api.token,
            expected_provenance=execution, require_aggregate_success=True,
            expected_ref="refs/heads/main", transport=api.provenance_transport)
        require(api._provenance_redirect is None)
    except Exception:
        raise Rejected("Authenticated native execution proof rejected.") from None
    finally:
        api._provenance_routes, api._provenance_redirect = set(), None
    require(verified["repositoryID"] == str(REPO_ID) and verified["workflowID"] == str(native["workflowID"]))
    for case, item in verified["cases"].items():
        require(item["jobID"] == str(native["jobs"]["Actual packaged GUI - " + case]) and
                item["runnerID"] == str(native["runners"][case]))
    for item in [*verified["cases"].values(), verified["publicPackage"]]:
        record = artifacts[item["artifactName"]]
        require(item["artifactID"] == str(record["id"]) and item["artifactZipSHA256"] == record["sha256"],
                "Execution provenance differs from the frozen immutable artifacts.")
    return verified


def verify_public_execution(api, request, plan, files):
    evidence = strict_json(files[gate.AGGREGATE_REPORT], BOUNDS[gate.AGGREGATE_REPORT])
    require(type(evidence) is dict and evidence.get("schema") == "tracebolt.windows-setup-native-subset.v2" and
            type(evidence.get("reports")) is dict and set(evidence["reports"]) == set(gate.CHECKS) and
            files[gate.AGGREGATE_REPORT] == canonical(evidence))
    # Native aggregation enforces this canonical raw-byte form. The proof below
    # must also match each stored report hash and each independently fetched ZIP.
    reports = {case: gate.canonical(report) for case, report in evidence["reports"].items()}
    return verify_execution(api, request, plan["artifacts"], plan["native"], evidence,
                            {name: files[name] for name in gate.PUBLIC_FILES}, reports)


def verify_frozen_metadata(api, request, plan, files):
    """Close the long proof-download window before mutations or final success."""
    evidence = strict_json(files[gate.AGGREGATE_REPORT], BOUNDS[gate.AGGREGATE_REPORT])
    require(type(evidence) is dict and type(evidence.get("executionProvenance")) is dict)
    require(verify_native_run(api, request, execution=evidence["executionProvenance"]) == plan["native"])
    require(resolve_artifacts(api, request, plan["artifacts"]) == plan["artifacts"])
    publisher_lease(api, request)


def file_entries(files):
    return {name: {"size": len(raw), "sha256": digest(raw)} for name, raw in sorted(files.items())}


def read_guides(root=ROOT):
    files = {}
    for name in sorted(GUIDES):
        path = root / "docs" / name
        require(not path.is_symlink())
        meta = path.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and 0 < meta.st_size <= BOUNDS[name])
        raw = path.read_bytes()
        require(len(raw) == meta.st_size and b"\r" not in raw)
        raw.decode("utf-8")
        files[name] = raw
    return files


def validate_plan(value, request):
    require(type(value) is dict and set(value) == {"schema", "request", "sourceTree", "native", "artifacts", "assets"} and
            value["schema"] == "tracebolt.windows-prerelease-plan.v2" and value["request"] == request and value["sourceTree"] == ACCEPTED_SOURCE_TREE)
    require(type(value["native"]) is dict and set(value["native"]) == {"workflowID", "jobs", "runners"} and positive_id(value["native"]["workflowID"]))
    jobs = value["native"]["jobs"]
    require(type(jobs) is dict and set(jobs) == {"Actual packaged GUI - " + case for case in gate.CHECKS} | {AGGREGATE_JOB} and all(positive_id(i) for i in jobs.values()) and len(set(jobs.values())) == 5)
    runners = value["native"]["runners"]
    require(type(runners) is dict and set(runners) == set(gate.CHECKS) and
            all(positive_id(i) for i in runners.values()) and len(set(runners.values())) == 4)
    artifacts = value["artifacts"]
    require(type(artifacts) is dict and set(artifacts) == set(artifact_names(request["source"])))
    for name, entry in artifacts.items():
        require(type(entry) is dict and set(entry) == {"id", "name", "size", "sha256"} and positive_id(entry["id"]) and entry["name"] == name and
                type(entry["size"]) is int and 0 < entry["size"] <= archive_bound(artifact_names(request["source"])[name]) and type(entry["sha256"]) is str and HEX64.fullmatch(entry["sha256"]))
    require(len({entry["id"] for entry in artifacts.values()}) == len(artifacts))
    require(type(value["assets"]) is dict and set(value["assets"]) == ASSETS)
    for name, entry in value["assets"].items():
        require(type(entry) is dict and set(entry) == {"size", "sha256"} and type(entry["size"]) is int and 0 < entry["size"] <= BOUNDS[name] and
                type(entry["sha256"]) is str and HEX64.fullmatch(entry["sha256"]))
    return value


def prepare(api, request, *, frozen=None, root=ROOT):
    validate_request(request)
    if frozen is not None:
        validate_plan(frozen, request)
    publisher_lease(api, request)
    native = verify_native_run(api, request)
    artifacts = resolve_artifacts(api, request, frozen["artifacts"] if frozen else None)
    downloaded = {}
    names = artifact_names(request["source"])
    for name, entry in sorted(artifacts.items()):
        downloaded[name] = unpack_archive(api.artifact(entry["id"], entry["size"]), entry, names[name])
    source = request["source"]
    files = downloaded["windows-setup-native-subset-public-" + source]
    require(files == downloaded["windows-setup-public-input-" + source], "Accepted package is not byte-for-byte identical to the tested TLS package.")
    raw_reports = {case: downloaded["windows-setup-gui-" + case + "-" + source][gate.REPORT_NAME] for case in gate.CHECKS}
    raw_evidence = downloaded["windows-setup-native-subset-evidence-" + source][gate.AGGREGATE_REPORT]
    evidence = validate_evidence(raw_evidence, files, raw_reports, request)
    execution = verify_execution(api, request, artifacts, native, evidence, files, raw_reports)
    public = {**files, gate.AGGREGATE_REPORT: raw_evidence, **read_guides(root)}
    # This is a separate binding document. Original six files, filenames,
    # embedded candidate version and build metadata are never rewritten.
    manifest = {"schema": "tracebolt.windows-prerelease.v2", "repository": REPOSITORY, "repositoryID": REPO_ID,
        "version": request["version"], "sourceCommit": source, "sourceTree": ACCEPTED_SOURCE_TREE,
        "embeddedVersion": gate.VERSION, "architectures": ["amd64"], "authenticode": "unsigned",
        "distributionStatus": "unsigned-windows-prerelease-native-subset", "nativeWorkflow": NATIVE_WORKFLOW,
        "acceptanceRunID": request["acceptanceRunID"], "acceptanceRunAttempt": 1, "acceptanceBranch": "main", "native": native, "artifacts": artifacts, "executionProvenance": execution,
        "publisherWorkflow": PUBLISH_WORKFLOW, "publisherSourceCommit": request["publisherSHA"],
        "publisherRunID": request["publisherRunID"], "publisherRunAttempt": 1, "coverage": dict.fromkeys(sorted(gate.FALSE_COVERAGE), False),
        "noOverwritePolicy": True, "platformImmutabilityClaimed": False, "cryptographicAttestation": False,
        "assets": file_entries(public)}
    public[RELEASE_MANIFEST] = canonical(manifest)
    require(set(public) == ASSETS and all(0 < len(raw) <= BOUNDS[name] for name, raw in public.items()))
    plan = {"schema": "tracebolt.windows-prerelease-plan.v2", "request": request, "sourceTree": ACCEPTED_SOURCE_TREE,
            "native": native, "artifacts": artifacts, "assets": file_entries(public)}
    validate_plan(plan, request)
    require(frozen is None or plan == frozen, "Frozen verification plan no longer matches the exact release bytes.")
    # Close the read/download race before returning any publishable plan.
    require(verify_native_run(api, request, execution=execution) == native)
    require(resolve_artifacts(api, request, artifacts) == artifacts)
    publisher_lease(api, request)
    return plan, public


def require_fresh_version(api, version):
    require(api.request("GET", PREFIX + "/releases/tags/" + version, missing=True) is None and
            api.request("GET", PREFIX + "/git/ref/tags/" + version, missing=True) is None,
            "Tag or release already exists. No overwrite, adoption, deletion, or retry is allowed.")
    # A draft can exist without a tag. Bound the full authenticated inventory.
    for page in range(1, 11):
        releases = api.request("GET", PREFIX + f"/releases?per_page=100&page={page}")
        require(type(releases) is list and len(releases) <= 100 and all(type(item) is dict and type(item.get("tag_name")) is str for item in releases))
        require(all(item["tag_name"] != version for item in releases), "A draft or release already uses the chosen version.")
        if len(releases) < 100:
            return
    raise Rejected("Release inventory exceeds the bounded freshness check.")


def description(request):
    return ("Unsigned Windows x64 preview. Exact unchanged Setup/service bytes from source " + request["source"] +
        ", accepted by four packaged GUI cases in https://github.com/" + REPOSITORY + "/actions/runs/" + request["acceptanceRunID"] +
        ". Download " + gate.SETUP_NAME + "; review windows-prerelease-install.md and windows-prerelease-changelog.md before use. "
        "SHA256SUMS covers the unchanged package; release-manifest.json binds the release tag, evidence, instructions and exact artifact IDs/hashes. "
        "Embedded candidate names/version remain unchanged. No Authenticode signature or trusted Windows publisher is claimed. "
        "Fresh hosted Windows 2025 x64 subset only; human UAC/invitation, real Linux manager/dashboard, reboot, upgrade, ARM64 and VM disposal remain unverified. "
        "No-overwrite is this publisher's policy, not a claim of GitHub platform immutability.")


def release_identity(value, request, release_id, draft):
    require(type(value) is dict and positive_id(value.get("id")) and (release_id is None or value["id"] == release_id) and
            value.get("tag_name") == request["version"] and value.get("target_commitish") == request["source"] and
            value.get("draft") is draft and value.get("prerelease") is True and
            value.get("name") == "Tracebolt Windows preview " + request["version"] and value.get("body") == description(request),
            "Release identity/state changed. Leave it intact for inspection.")
    prefix = f"https://github.com/{REPOSITORY}/releases/tag/"
    url = value.get("html_url")
    require(type(url) is str and url.startswith(prefix))
    tag = url[len(prefix):]
    require(tag == request["version"] or (draft and re.fullmatch(r"untagged-[0-9a-f]{20}", tag)), "Release URL does not identify the expected fresh draft/version.")
    return value["id"], tag


def check_asset(value, name, entry, download_tag, asset_id=None):
    require(type(value) is dict and positive_id(value.get("id")) and (asset_id is None or value["id"] == asset_id) and
            value.get("name") == name and value.get("state") == "uploaded" and type(value.get("size")) is int and
            value["size"] == entry["size"] and value.get("digest") == "sha256:" + entry["sha256"] and
            value.get("browser_download_url") == f"https://github.com/{REPOSITORY}/releases/download/{download_tag}/{name}",
            "Release asset ID, size, hash, or URL does not match the verified upload.")
    return value["id"]


def check_assets(api, release_id, expected, download_tag, asset_ids):
    values = api.request("GET", PREFIX + f"/releases/{release_id}/assets?per_page=100")
    require(type(values) is list and len(values) == len(expected))
    seen = set()
    for value in values:
        require(type(value) is dict and type(value.get("name")) is str and value["name"] in expected and value["name"] not in seen)
        name = value["name"]
        check_asset(value, name, expected[name], download_tag, asset_ids[name])
        seen.add(name)
    require(seen == set(expected))


def publish(api, request, plan, files):
    validate_request(request)
    validate_plan(plan, request)
    require(set(files) == ASSETS and file_entries(files) == plan["assets"], "Verified publication bytes changed.")
    publisher_lease(api, request)
    require(verify_native_run(api, request) == plan["native"])
    require(resolve_artifacts(api, request, plan["artifacts"]) == plan["artifacts"])
    verify_public_execution(api, request, plan, files)
    require_fresh_version(api, request["version"])
    verify_frozen_metadata(api, request, plan, files)
    # From here every write is attempted once. Do not clean up a partial draft,
    # retry an upload, or adopt an existing ref/release on a subsequent run.
    ref = "refs/tags/" + request["version"]
    tag_path = PREFIX + "/git/ref/tags/" + request["version"]
    check_ref(api.request("POST", PREFIX + "/git/refs", {"ref": ref, "sha": request["source"]}), ref, request["source"])
    draft = api.request("POST", PREFIX + "/releases", {"tag_name": request["version"], "target_commitish": request["source"],
        "name": "Tracebolt Windows preview " + request["version"], "body": description(request), "draft": True, "prerelease": True,
        "make_latest": "false", "generate_release_notes": False})
    release_id, download_tag = release_identity(draft, request, None, True)
    require(draft.get("assets") == [], "New draft is not empty; inspect it without modifying existing assets.")
    asset_ids = {}
    for name, raw in sorted(files.items()):
        value = api.request("POST", PREFIX + f"/releases/{release_id}/assets?name=" + quote(name, safe=""), upload=raw)
        asset_ids[name] = check_asset(value, name, plan["assets"][name], download_tag)
        require(len(set(asset_ids.values())) == len(asset_ids), "Upload returned a reused asset ID.")
    check_assets(api, release_id, plan["assets"], download_tag, asset_ids)
    check_ref(api.request("GET", tag_path), ref, request["source"])
    require(release_identity(api.request("GET", PREFIX + f"/releases/{release_id}"), request, release_id, True) == (release_id, download_tag))
    publisher_lease(api, request)
    require(verify_native_run(api, request) == plan["native"])
    require(resolve_artifacts(api, request, plan["artifacts"]) == plan["artifacts"])
    verify_public_execution(api, request, plan, files)
    verify_frozen_metadata(api, request, plan, files)
    check_ref(api.request("GET", tag_path), ref, request["source"])
    require(release_identity(api.request("GET", PREFIX + f"/releases/{release_id}"), request, release_id, True) == (release_id, download_tag))
    check_assets(api, release_id, plan["assets"], download_tag, asset_ids)
    result = api.request("PATCH", PREFIX + f"/releases/{release_id}", {"draft": False, "make_latest": "false"})
    release_identity(result, request, release_id, False)
    release_identity(api.request("GET", PREFIX + f"/releases/{release_id}"), request, release_id, False)
    release_identity(api.request("GET", PREFIX + "/releases/tags/" + request["version"]), request, release_id, False)
    check_ref(api.request("GET", tag_path), ref, request["source"])
    check_assets(api, release_id, plan["assets"], request["version"], asset_ids)
    for name, entry in sorted(plan["assets"].items()):
        raw = api.public_asset(request["version"], name, entry["size"])
        require(len(raw) == entry["size"] and digest(raw) == entry["sha256"], "Published public download bytes differ or are unavailable. Do not republish or overwrite.")
    # A second metadata check detects a replacement or release-state change
    # during the public reads; this is a point-in-time check, not immutability.
    publisher_lease(api, request)
    release_identity(api.request("GET", PREFIX + f"/releases/{release_id}"), request, release_id, False)
    release_identity(api.request("GET", PREFIX + "/releases/tags/" + request["version"]), request, release_id, False)
    check_ref(api.request("GET", tag_path), ref, request["source"])
    check_assets(api, release_id, plan["assets"], request["version"], asset_ids)
    verify_public_execution(api, request, plan, files)
    verify_frozen_metadata(api, request, plan, files)
    release_identity(api.request("GET", PREFIX + f"/releases/{release_id}"), request, release_id, False)
    release_identity(api.request("GET", PREFIX + "/releases/tags/" + request["version"]), request, release_id, False)
    check_ref(api.request("GET", tag_path), ref, request["source"])
    check_assets(api, release_id, plan["assets"], request["version"], asset_ids)
    return f"https://github.com/{REPOSITORY}/releases/tag/{request['version']}"


def decode_plan(env, request):
    encoded, expected = env.get("TRACEBOLT_VERIFIED_PLAN", ""), env.get("TRACEBOLT_VERIFIED_PLAN_SHA256", "")
    require(type(encoded) is str and 0 < len(encoded) <= 4 * MAX_PLAN // 3 + 4 and HEX64.fullmatch(expected), "Missing frozen read-only verification plan.")
    raw = base64.b64decode(encoded, validate=True)
    require(digest(raw) == expected, "Frozen verification plan digest changed.")
    plan = strict_json(raw, MAX_PLAN)
    require(raw == canonical(plan))
    return validate_plan(plan, request)


def main(argv=None, env=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify", action="store_true")
    modes.add_argument("--publish", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    request = authorize(env, args.publish)
    verify_checkout(request)
    frozen = decode_plan(env, request) if args.publish else None
    # Even the write job performs all preparation with a read-only client first.
    api = GitHubAPI(env.get("GITHUB_TOKEN", ""), write=False)
    plan, files = prepare(api, request, frozen=frozen)
    require_fresh_version(api, request["version"])
    if not args.publish:
        raw = canonical(plan)
        require(len(raw) <= MAX_PLAN and env.get("GITHUB_OUTPUT"), "Cannot preserve verified plan output.")
        with open(env["GITHUB_OUTPUT"], "a", encoding="ascii", newline="\n") as stream:
            stream.write("plan=" + base64.b64encode(raw).decode("ascii") + "\nplan_sha256=" + digest(raw) + "\n")
        print("Read-only verification passed: exact accepted x64 bytes and finite evidence; no tag or release was created.")
        return
    url = publish(GitHubAPI(env["GITHUB_TOKEN"], write=True), request, plan, files)
    print("Published and independently re-read every public asset: " + url)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No server body, credential, signed URL, archive path, private source,
        # or arbitrary exception text is emitted, including on uncertain writes.
        print("Windows prerelease stopped. No automatic retry or cleanup was attempted; inspect the run and any partial tag/release before another publication.", file=sys.stderr)
        sys.exit(1)
