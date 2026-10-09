#!/usr/bin/env python3
"""Read-only, finite GitHub execution provenance for packaged Setup acceptance.

Import and pure validation do not perform I/O. Only the aggregate/publisher's
explicit verify functions fetch authenticated GitHub records and public artifacts.
This is job provenance, not VM/hardware attestation: fresh isolation relies on
the exact reviewed workflow, its native github-hosted environment checks, and
GitHub's standard-Windows fresh-VM-per-job contract. Artifacts REST has no
uploader-job field; case-to-job attribution trusts the reviewed one-case-one-upload
wiring. Hostname and runner registration IDs are not VM identifiers.

Official references reviewed 2026-10-09:
https://docs.github.com/en/actions/concepts/runners/github-hosted-runners
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
https://docs.github.com/en/rest/actions/workflow-jobs
https://docs.github.com/en/rest/actions/artifacts
https://github.com/actions/upload-artifact#where-does-the-upload-go
"""
import hashlib
import io
import json
import re
import stat
import struct
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "storminator89/Tracebolt"
REPOSITORY_ID = 1403204207
OWNER = "storminator89"
OWNER_ID = 30489872
WORKFLOW_PATH = ".github/workflows/windows-setup-acceptance.yml"
WORKFLOW_NAME = "Manual disposable packaged Windows Setup GUI acceptance"
SOURCE_REF = "refs/heads/main"
AGGREGATE_NAME = "Validate four reports and preserve exact tested public bytes (no rebuild)"
NATIVE_STEP = "Build exact package and drive actual GUI; fail blocked if no interactive desktop"
REPORT_STEP = "Export finite evidence only; platform disposal remains unverified"
PACKAGE_STEP = "Retain only the exact successful TLS-case public package, pending all-case validation"
CASES = ("install-uninstall", "http-install-uninstall", "cancel-hidden-input", "pending-transport")
REPORT_NAME = "tracebolt-windows-setup-acceptance.json"
SETUP_NAME = "Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe"
SERVICE_NAME = "tracebolt-v0.0.0-setup-candidate-windows-amd64-service.exe"
PUBLIC_BOUNDS = {SETUP_NAME: 128 << 20, SERVICE_NAME: 128 << 20,
                 "setup-package-amd64.json": 2048, "build-manifest.json": 64 << 10,
                 "source-inputs.json": 4 << 20, "SHA256SUMS": 4096}
SCHEMA = "tracebolt.windows-setup-execution-provenance.v1"
PROOF_BASIS = "github-hosted-standard-windows-job-isolation"
ARTIFACT_BINDING = "reviewed-one-case-one-upload-workflow"
FRESH_VM_SOURCE = "https://docs.github.com/en/actions/concepts/runners/github-hosted-runners"
SOURCE_REVIEWED_ON = "2026-10-09"
TOKEN_ENV = "TRACEBOLT_SETUP_API_TOKEN"
API_ROOT = "https://api.github.com/repos/" + REPOSITORY
JSON_LIMIT = 256 << 10
ARCHIVE_LIMIT = 272 << 20
REPORT_LIMIT = 16 << 10


class Rejected(Exception):
    def __init__(self):
        super().__init__("packaged Setup execution provenance rejected")


def require(condition):
    if not condition:
        raise Rejected()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _source(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _id(value, zero=False):
    return type(value) is int and (0 if zero else 1) <= value < 10**24


def _decimal(value):
    return type(value) is str and re.fullmatch(r"[1-9][0-9]{0,23}", value) is not None


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _strict_json(raw):
    require(type(raw) is bytes and 0 < len(raw) <= JSON_LIMIT)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def bad_constant(_value):
        raise Rejected()
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
    except Exception:
        raise Rejected() from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _fp, _code, _message, _headers, _new_url):
        return None


def _request(url, headers, limit):
    """One bounded HTTPS request; no proxies or automatic redirects; no logging."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(limit + 1)
            require(len(body) <= limit)
            return response.code, dict(response.headers.items()), body
    except Exception:
        raise Rejected() from None


def _storage_url(value):
    require(type(value) is str and 0 < len(value) <= 8192 and
            all(32 < ord(char) < 127 for char in value))
    try:
        url = urllib.parse.urlsplit(value)
        # GitHub's artifact endpoint supplies this signed Azure storage URL.
        # No caller-selected host, credentials, HTTP downgrade or second redirect.
        require(url.scheme == "https" and url.username is None and url.password is None
                and url.port in (None, 443) and not url.fragment and url.path.startswith("/")
                and re.fullmatch(r"[a-z0-9]{3,63}\.blob\.core\.windows\.net", url.hostname or "")
                is not None)
    except Exception:
        raise Rejected() from None
    return value


class _API:
    def __init__(self, token, transport=None):
        require(type(token) is str and 1 <= len(token) <= 4096 and
                all(32 < ord(char) < 127 for char in token))
        self.headers = {"Authorization": "Bearer " + token,
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                        "User-Agent": "Tracebolt-Setup-Provenance"}
        self.transport = _request if transport is None else transport

    def request(self, url, headers, limit):
        try:
            status, returned_headers, raw = self.transport(url, headers, limit)
            require(type(status) is int and type(returned_headers) is dict and
                    type(raw) is bytes and len(raw) <= limit)
            normalized = {}
            for key, value in returned_headers.items():
                require(type(key) is str and type(value) is str and key.lower() not in normalized)
                normalized[key.lower()] = value
            return status, normalized, raw
        except Exception:
            raise Rejected() from None

    def json(self, suffix):
        status, headers, raw = self.request(API_ROOT + suffix, self.headers, JSON_LIMIT)
        require(status == 200 and "link" not in headers)
        value = _strict_json(raw)
        require(type(value) is dict)
        return value

    def archive(self, artifact, expected):
        limit = min(ARCHIVE_LIMIT, sum(len(raw) for raw in expected.values()) + (1 << 20))
        status, headers, _raw = self.request(API_ROOT + "/actions/artifacts/" +
                                             str(artifact["id"]) + "/zip", self.headers, JSON_LIMIT)
        require(status == 302 and "location" in headers)
        location = _storage_url(headers["location"])
        status, _headers, raw = self.request(location,
            {"Accept": "application/octet-stream", "User-Agent": "Tracebolt-Setup-Provenance"}, limit)
        # upload-artifact documents the artifact size as its uploaded ZIP size.
        require(status == 200 and len(raw) == artifact["size_in_bytes"] and
                _sha(raw) == artifact["digest"][7:])
        _verify_zip(raw, expected)


def _zip_preflight(raw, expected):
    """Bound central-directory parsing before ZipFile constructs member objects."""
    require(type(raw) is bytes and 22 <= len(raw) <= ARCHIVE_LIMIT and
            type(expected) is dict and 1 <= len(expected) <= 6)
    signature, disk, central_disk, disk_count, count, central_size, central_start, comment = \
        struct.unpack_from("<4s4H2LH", raw, len(raw) - 22)
    require(signature == b"PK\x05\x06" and disk == central_disk == comment == 0 and
            disk_count == count == len(expected) and 46 <= central_size <= 16 << 10 and
            central_start + central_size == len(raw) - 22)
    end, cursor, names = central_start + central_size, central_start, set()
    for _ in range(count):
        require(cursor + 46 <= end)
        fields = struct.unpack_from("<4s6H3L5H2L", raw, cursor)
        (signature, _made_by, needed, flags, method, _mtime, _mdate, _crc,
         compressed, size, name_length, extra_length, comment_length, member_disk,
         _internal_attr, _external_attr, local_start) = fields
        require(signature == b"PK\x01\x02" and needed <= 20 and not (flags & 1) and
                method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and member_disk == 0 and
                comment_length == 0 and compressed != 0xffffffff and size != 0xffffffff and
                local_start < central_start and 0 < name_length <= 256)
        next_cursor = cursor + 46 + name_length + extra_length
        require(next_cursor <= end)
        name = raw[cursor + 46:cursor + 46 + name_length].decode("ascii")
        require(name in expected and name not in names and size == len(expected[name]))
        names.add(name)
        extra_cursor = cursor + 46 + name_length
        while extra_cursor < next_cursor:
            require(extra_cursor + 4 <= next_cursor)
            extra_kind, extra_size = struct.unpack_from("<HH", raw, extra_cursor)
            require(extra_kind != 1)  # No ZIP64 extended-information members.
            extra_cursor += 4 + extra_size
            require(extra_cursor <= next_cursor)
        cursor = next_cursor
    require(cursor == end and names == set(expected))


def _verify_zip(raw, expected):
    try:
        _zip_preflight(raw, expected)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            require(len(members) == len(expected) and
                    {member.filename for member in members} == set(expected))
            for member in members:
                mode = member.external_attr >> 16
                require(not member.is_dir() and not (member.flag_bits & 1) and
                        stat.S_IFMT(mode) in (0, stat.S_IFREG) and
                        member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                        member.file_size == len(expected[member.filename]))
                with archive.open(member) as stream:
                    actual = stream.read(member.file_size + 1)
                require(actual == expected[member.filename])
    except Exception:
        raise Rejected() from None


def _inputs(source, run_id, reports, public_files):
    require(_source(source) and _decimal(run_id) and type(reports) is dict and
            set(reports) == set(CASES) and type(public_files) is dict and
            set(public_files) == set(PUBLIC_BOUNDS))
    require(all(type(raw) is bytes and 0 < len(raw) <= REPORT_LIMIT for raw in reports.values()))
    require(all(type(raw) is bytes and 0 < len(raw) <= PUBLIC_BOUNDS[name]
                for name, raw in public_files.items()))


def _actor(value):
    require(type(value) is dict and value.get("login") == OWNER and
            type(value.get("id")) is int and value["id"] == OWNER_ID)


def _repository(value):
    require(type(value) is dict and value.get("full_name") == REPOSITORY and
            type(value.get("id")) is int and value["id"] == REPOSITORY_ID)
    _actor(value.get("owner"))
    return value["id"]


def _run(value, source, run_id):
    require(type(value) is dict and _id(value.get("id")) and str(value["id"]) == run_id and
            value.get("head_sha") == source and type(value.get("run_attempt")) is int and
            value["run_attempt"] == 1 and value.get("event") == "workflow_dispatch" and
            value.get("name") == WORKFLOW_NAME and _id(value.get("workflow_id")))
    branch = value.get("head_branch")
    require(branch == "main")
    require(value.get("path") in (WORKFLOW_PATH, WORKFLOW_PATH + "@" + branch))
    repository_id = _repository(value.get("repository"))
    require(_repository(value.get("head_repository")) == repository_id)
    _actor(value.get("actor"))
    _actor(value.get("triggering_actor"))
    return repository_id


def _list(value, key, maximum):
    rows = value.get(key)
    require(type(rows) is list and type(value.get("total_count")) is int and
            value["total_count"] == len(rows) and 0 < len(rows) <= maximum and
            all(type(row) is dict for row in rows))
    return rows


def _step(job, name, conclusion="success"):
    steps = job.get("steps")
    require(type(steps) is list and 1 <= len(steps) <= 32 and all(type(row) is dict for row in steps))
    found = [step for step in steps if step.get("name") == name]
    require(len(found) == 1 and found[0].get("status") == "completed" and
            found[0].get("conclusion") == conclusion and _id(found[0].get("number")))
    return found[0]["number"]


def _jobs(rows, source, run_id, require_aggregate_success):
    by_name = {}
    for job in rows:
        name = job.get("name")
        require(type(name) is str and name not in by_name and _id(job.get("id")) and
                _id(job.get("run_id")) and str(job["run_id"]) == run_id and job.get("head_sha") == source and
                type(job.get("run_attempt")) is int and job["run_attempt"] == 1 and
                job.get("workflow_name") == WORKFLOW_NAME)
        by_name[name] = job
    names = {case: "Actual packaged GUI - " + case for case in CASES}
    require(set(by_name) == set(names.values()) | {AGGREGATE_NAME} and
            len({job["id"] for job in by_name.values()}) == len(by_name))
    aggregate = by_name[AGGREGATE_NAME]
    if require_aggregate_success:
        require(aggregate.get("status") == "completed" and aggregate.get("conclusion") == "success")
    else:
        require(aggregate.get("status") == "in_progress" and aggregate.get("conclusion") is None)
    require(aggregate.get("labels") == ["ubuntu-24.04"])
    found = {}
    for case, name in names.items():
        job = by_name[name]
        require(job.get("status") == "completed" and job.get("conclusion") == "success" and
                job.get("labels") == ["windows-2025"] and _id(job.get("runner_id")) and
                _id(job.get("runner_group_id"), zero=True))
        require(_step(job, NATIVE_STEP) < _step(job, REPORT_STEP))
        package_step = _step(job, PACKAGE_STEP, "success" if case == "install-uninstall" else "skipped")
        require(_step(job, REPORT_STEP) < package_step)
        found[case] = job
    # Registration identities corroborate four independent hosted allocations.
    # They are not hardware/VM identifiers or a replacement for platform trust.
    require(len({job["runner_id"] for job in found.values()}) == len(CASES))
    return found


def _artifact(value, name, source, run_id, repository_id, head_branch):
    require(value.get("name") == name and _id(value.get("id")) and value.get("expired") is False and
            type(value.get("size_in_bytes")) is int and 0 < value["size_in_bytes"] <= ARCHIVE_LIMIT and
            type(value.get("digest")) is str and
            re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]) is not None)
    run = value.get("workflow_run")
    require(type(run) is dict and _id(run.get("id")) and str(run["id"]) == run_id and
            run.get("head_sha") == source and run.get("head_branch") == head_branch and
            type(run.get("repository_id")) is int and
            run["repository_id"] == repository_id and type(run.get("head_repository_id")) is int and
            run["head_repository_id"] == repository_id)
    return {"artifactID": str(value["id"]), "artifactName": name,
            "artifactZipSHA256": value["digest"][7:]}


def _verified_artifact(api, listed, name, source, run_id, repository_id, head_branch, expected):
    projection = _artifact(listed, name, source, run_id, repository_id, head_branch)
    actual = api.json("/actions/artifacts/" + str(listed["id"]))
    require(_artifact(actual, name, source, run_id, repository_id, head_branch) == projection and
            actual["size_in_bytes"] == listed["size_in_bytes"])
    api.archive(actual, expected)
    return projection


def verify_run(source, run_id, report_bytes_by_case, public_files, token, *,
               expected_provenance=None, require_aggregate_success=False, transport=None, expected_ref=None):
    """Fetch authoritative records and compare every ZIP member with consumed bytes.

    The publisher must set require_aggregate_success=True and provide the stored
    expected_provenance. No report-provided URL, job ID or artifact ID is fetched.
    transport is injectable solely for inert source fixtures.

    expected_ref is an optional explicit caller policy and must be refs/heads/main.
    REST head_branch corroborates the name "main", not its branch-versus-tag type.
    Exact full-ref authority comes from verify_current_run's reviewed runtime
    GITHUB_REF check and the publisher's exact source/workflow pins, not REST.
    """
    try:
        _inputs(source, run_id, report_bytes_by_case, public_files)
        require(type(require_aggregate_success) is bool)
        api = _API(token, transport)
        prefix = "/actions/runs/" + run_id
        current = api.json(prefix)
        repository_id = _run(current, source, run_id)
        if expected_ref is not None:
            require(expected_ref == SOURCE_REF)
        attempt = api.json(prefix + "/attempts/1")
        require(_run(attempt, source, run_id) == repository_id and
                attempt["workflow_id"] == current["workflow_id"] and
                attempt["head_branch"] == current["head_branch"])
        workflow = api.json("/actions/workflows/windows-setup-acceptance.yml")
        require(_id(workflow.get("id")) and workflow["id"] == current["workflow_id"] and
                workflow.get("path") == WORKFLOW_PATH and workflow.get("name") == WORKFLOW_NAME)
        for record in (current, attempt):
            if require_aggregate_success:
                require(record.get("status") == "completed" and record.get("conclusion") == "success")
            else:
                require(record.get("status") == "in_progress" and record.get("conclusion") is None)
        jobs = _jobs(_list(api.json(prefix + "/attempts/1/jobs?per_page=100"), "jobs", 5),
                     source, run_id, require_aggregate_success)
        records = _list(api.json(prefix + "/artifacts?per_page=100"), "artifacts", 7)
        by_name = {}
        for artifact in records:
            name = artifact.get("name")
            require(type(name) is str and name not in by_name)
            by_name[name] = artifact
        report_names = {case: "windows-setup-gui-" + case + "-" + source for case in CASES}
        package_name = "windows-setup-public-input-" + source
        expected_names = set(report_names.values()) | {package_name}
        output_names = {"windows-setup-native-subset-public-" + source,
                        "windows-setup-native-subset-evidence-" + source}
        require(expected_names <= set(by_name) <= expected_names | output_names)
        selected = {name: by_name[name] for name in expected_names}
        require(all(_id(artifact.get("id")) for artifact in selected.values()) and
                len({artifact["id"] for artifact in selected.values()}) == len(selected))
        cases = {}
        for case in CASES:
            artifact = selected[report_names[case]]
            projection = _verified_artifact(api, artifact, report_names[case], source, run_id,
                                           repository_id, current["head_branch"],
                                           {REPORT_NAME: report_bytes_by_case[case]})
            job = jobs[case]
            projection.update(jobID=str(job["id"]), runnerID=str(job["runner_id"]),
                              runnerGroupID=str(job["runner_group_id"]),
                              reportSHA256=_sha(report_bytes_by_case[case]))
            cases[case] = projection
        artifact = selected[package_name]
        package = _verified_artifact(api, artifact, package_name, source, run_id,
                                     repository_id, current["head_branch"], public_files)
        package.update(jobID=str(jobs["install-uninstall"]["id"]),
                       filesSHA256={name: _sha(raw) for name, raw in sorted(public_files.items())})
        result = {"schema": SCHEMA, "repository": REPOSITORY, "repositoryID": str(repository_id),
                  "source": source, "runID": run_id, "runAttempt": 1,
                  "workflowPath": WORKFLOW_PATH, "workflowID": str(current["workflow_id"]),
                  "proofBasis": PROOF_BASIS, "artifactJobBinding": ARTIFACT_BINDING,
                  "freshVMDocumentation": FRESH_VM_SOURCE, "documentationReviewedOn": SOURCE_REVIEWED_ON,
                  "vmIdentityAttested": False, "cases": cases, "publicPackage": package}
        validate_provenance(result, source, run_id, report_bytes_by_case, public_files)
        if expected_provenance is not None:
            validate_provenance(expected_provenance, source, run_id, report_bytes_by_case, public_files)
            require(result == expected_provenance)
        return result
    except Exception:
        raise Rejected() from None


def validate_provenance(value, source, run_id, report_bytes_by_case, public_files):
    """Pure strict projection validation; this does NOT authenticate its contents."""
    try:
        _inputs(source, run_id, report_bytes_by_case, public_files)
        fixed = {"schema": SCHEMA, "repository": REPOSITORY, "source": source,
                 "runID": run_id, "runAttempt": 1, "workflowPath": WORKFLOW_PATH,
                 "proofBasis": PROOF_BASIS, "artifactJobBinding": ARTIFACT_BINDING,
                 "freshVMDocumentation": FRESH_VM_SOURCE, "documentationReviewedOn": SOURCE_REVIEWED_ON,
                 "vmIdentityAttested": False}
        require(type(value) is dict and set(value) == set(fixed) |
                {"repositoryID", "workflowID", "cases", "publicPackage"})
        require(all(type(value[key]) is type(expected) and value[key] == expected
                    for key, expected in fixed.items()))
        require(value["repositoryID"] == str(REPOSITORY_ID) and _decimal(value["workflowID"]) and
                type(value["cases"]) is dict and set(value["cases"]) == set(CASES))
        artifact_ids, job_ids, runner_ids = set(), set(), set()
        for case, item in value["cases"].items():
            require(type(item) is dict and set(item) == {"artifactID", "artifactName", "artifactZipSHA256",
                    "jobID", "runnerID", "runnerGroupID", "reportSHA256"})
            require(_decimal(item["artifactID"]) and _decimal(item["jobID"]) and
                    item["artifactName"] == "windows-setup-gui-" + case + "-" + source and
                    _digest(item["artifactZipSHA256"]) and item["reportSHA256"] == _sha(report_bytes_by_case[case]))
            require(_decimal(item["runnerID"]) and type(item["runnerGroupID"]) is str and
                    re.fullmatch(r"0|[1-9][0-9]{0,23}", item["runnerGroupID"]) is not None)
            artifact_ids.add(item["artifactID"])
            job_ids.add(item["jobID"])
            runner_ids.add(item["runnerID"])
        require(len(artifact_ids) == len(job_ids) == len(runner_ids) == 4)
        package = value["publicPackage"]
        require(type(package) is dict and set(package) == {"artifactID", "artifactName", "artifactZipSHA256", "jobID", "filesSHA256"})
        require(_decimal(package["artifactID"]) and package["artifactID"] not in artifact_ids and
                package["artifactName"] == "windows-setup-public-input-" + source and
                _digest(package["artifactZipSHA256"]) and
                package["jobID"] == value["cases"]["install-uninstall"]["jobID"] and
                package["filesSHA256"] == {name: _sha(raw) for name, raw in public_files.items()})
        return value
    except Exception:
        raise Rejected() from None


def verify_current_run(env, source, report_bytes_by_case, public_files, *, transport=None):
    """Aggregate-only caller binding; existing full approval checks remain required."""
    try:
        fixed = {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REPOSITORY_OWNER": OWNER,
                 "GITHUB_REPOSITORY_OWNER_ID": str(OWNER_ID), "GITHUB_ACTOR": OWNER,
                 "GITHUB_ACTOR_ID": str(OWNER_ID), "GITHUB_TRIGGERING_ACTOR": OWNER,
                 "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTIONS": "true",
                 "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "accepted-public-package",
                 "GITHUB_SHA": source, "GITHUB_WORKFLOW_SHA": source,
                 "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted"}
        require(all(env.get(key) == expected for key, expected in fixed.items()))
        ref = env.get("GITHUB_REF", "")
        require(ref == SOURCE_REF and
                env.get("GITHUB_WORKFLOW_REF") == REPOSITORY + "/" + WORKFLOW_PATH + "@" + ref)
        return verify_run(source, env.get("GITHUB_RUN_ID", ""), report_bytes_by_case, public_files,
                          env.get(TOKEN_ENV, ""), transport=transport, expected_ref=ref)
    except Exception:
        raise Rejected() from None
