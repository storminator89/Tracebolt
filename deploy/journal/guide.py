#!/usr/bin/env python3
"""Verified local guide for one explicit system-service journal grant.

Inert on import. Source staging is create-only; host policy changes remain in
amend.py. This guide never installs/upgrades software or reads a journal.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import sys
import time
import types
import urllib.request

REPOSITORY = "https://raw.githubusercontent.com/storminator89/Tracebolt/"
CORE_FILES = (
    "deploy/journal/amend.py", "deploy/journal/setup.py",
    "deploy/systemd/tracebolt-agent.service.in",
    "deploy/systemd/tracebolt-journal-reader.service.in",
    "deploy/systemd/tracebolt-journal-reader.socket.in",
)
GUIDE_FILE = "deploy/journal/guide.py"
MANIFEST_FILE = "deploy/journal/source-manifest.json"
MANIFEST_VERSION = "tracebolt.journal-guide-source.v1"
CAPABILITY_PATH = "/v3/journal/capabilities"
MAX_SOURCE_BYTES = 131072
MAX_MANIFEST_BYTES = 8192
AGENT_CAPABILITIES = {
    "schemaVersion": "tracebolt.journal-runtime-capabilities.v1",
    "policyVersions": ["tracebolt.journal-content-policy.v1", "tracebolt.journal-content-policy.v2", "tracebolt.journal-content-policy.v3", "tracebolt.journal-content-policy.v4"],
    "generationReportVersions": ["tracebolt.journal-generation-report.v1", "tracebolt.journal-generation-report.v2", "tracebolt.journal-generation-report.v3"],
    "requestVersions": ["tracebolt.journal-request.v1", "tracebolt.journal-request.v2", "tracebolt.journal-request.v3"],
    "helperProtocols": ["TBJ1", "TBJ2", "TBJ3"],
    "activationVersions": ["tracebolt.journal-activation.v1"],
    "serviceAuthorization": ["exact-units", "all-system-services"],
    "scopes": ["on-demand-allowlisted-system-service-log-content", "on-demand-system-service-log-content", "on-demand-retained-system-service-log-content"],
}


class Rejected(Exception):
    """Only fixed safe failure stages are printed."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def valid_revision(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def canonical(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()


def strict_json(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "bounded-json")
    def pairs(values):
        out = {}
        for key, value in values:
            require(key not in out, "duplicate-json-member")
            out[key] = value
        return out
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("invalid-json-number")))
    except (ValueError, UnicodeError) as exc:
        raise Rejected("invalid-json") from exc


def source_manifest(raw):
    value = strict_json(raw, MAX_MANIFEST_BYTES)
    require(type(value) is dict and set(value) == {"schemaVersion", "files"} and
            value["schemaVersion"] == MANIFEST_VERSION and type(value["files"]) is dict and
            set(value["files"]) == set(CORE_FILES), "source-manifest-members")
    for item in value["files"].values():
        require(type(item) is dict and set(item) == {"sha256", "size"} and valid_hash(item["sha256"]) and
                type(item["size"]) is int and 0 < item["size"] <= MAX_SOURCE_BYTES, "source-manifest-entry")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Rejected("network-redirect-rejected")


def fetch(url, limit, *, ca_pem=None, plaintext=False):
    """Fixed callers supply an immutable source URL or validated public origin."""
    require(type(limit) is int and 0 < limit <= MAX_SOURCE_BYTES, "network-response-limit")
    require(url.startswith("http://") if plaintext else url.startswith("https://"), "network-transport")
    if plaintext:
        require(ca_pem is None, "plaintext-ca-rejected")
        handlers = []
    else:
        context = ssl.create_default_context() if ca_pem is None else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_pem is not None:
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cadata=ca_pem)
        handlers = [urllib.request.HTTPSHandler(context=context)]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), *handlers)
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json, text/plain", "Accept-Encoding": "identity"})
    deadline = time.monotonic() + 20
    with opener.open(request, timeout=10) as response:
        require(response.status == 200 and response.geturl() == url, "network-status-or-origin")
        require(response.headers.get("Content-Encoding", "identity") == "identity", "network-content-encoding")
        length = response.headers.get("Content-Length")
        require(length is None or re.fullmatch(r"[0-9]{1,8}", length) and int(length) <= limit,
                "network-content-length")
        out = bytearray()
        while len(out) <= limit:
            require(time.monotonic() < deadline, "network-deadline")
            chunk = response.read1(min(65536, limit + 1 - len(out)))
            if not chunk:
                break
            out.extend(chunk)
        require(0 < len(out) <= limit and (length is None or len(out) == int(length)), "network-response-size")
        return bytes(out)


def _pin(st):
    return tuple(getattr(st, name) for name in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


@contextlib.contextmanager
def protected_directory(path):
    require(path.startswith("/") and str(Path(path)) == path and ".." not in Path(path).parts, "protected-source-path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = [("/", fd)]
    try:
        for name in ("", *Path(path).parts[1:]):
            if name:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                opened.append((str(Path(opened[-1][0]) / name), fd))
            st = os.fstat(fd)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o6022 == 0,
                    "protected-source-directory")
        yield fd
        for name, handle in opened:
            a, b = os.fstat(handle), os.lstat(name)
            require((a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode) ==
                    (b.st_dev, b.st_ino, b.st_uid, b.st_gid, b.st_mode), "source-parent-changed")
    finally:
        for _, handle in reversed(opened):
            os.close(handle)


class SourceStore:
    def __init__(self, revision):
        require(valid_revision(revision), "immutable-source-revision")
        self.root = "/root/tracebolt-journal-guide-" + revision

    def path(self, relative):
        require(relative in CORE_FILES + (GUIDE_FILE, MANIFEST_FILE, "deploy/systemd"), "fixed-source-path")
        return self.root + "/" + relative

    def read(self, relative, limit):
        path = self.path(relative)
        with protected_directory(str(Path(path).parent)) as parent:
            fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                        stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and 0 < before.st_size <= limit,
                        "protected-source-file")
                raw = bytearray()
                while len(raw) <= limit:
                    chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                require(len(raw) == before.st_size and _pin(before) == _pin(os.fstat(fd)) ==
                        _pin(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)), "source-file-changed")
                return bytes(raw)
            finally:
                os.close(fd)

    def mkdir(self):
        with protected_directory(self.root + "/deploy") as parent:
            os.mkdir("systemd", 0o700, dir_fd=parent)
            with protected_directory(self.root + "/deploy/systemd") as child:
                os.fchmod(child, 0o700)
                os.fchown(child, 0, 0)
                os.fsync(child)
            os.fsync(parent)

    def cache_state(self):
        expected_dirs = {self.root: {"deploy"}, self.root + "/deploy/journal": {"guide.py", "source-manifest.json"}}
        with protected_directory(self.root + "/deploy") as fd:
            children = set(os.listdir(fd))
        require(children in ({"journal"}, {"journal", "systemd"}), "partial-or-foreign-source-cache")
        expected_dirs[self.root + "/deploy"] = children
        complete = "systemd" in children
        if complete:
            expected_dirs[self.root + "/deploy/journal"] |= {"amend.py", "setup.py"}
            expected_dirs[self.root + "/deploy/systemd"] = {Path(path).name for path in CORE_FILES[2:]}
        for path, expected in expected_dirs.items():
            with protected_directory(path) as fd:
                st = os.fstat(fd)
                require(st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700 and set(os.listdir(fd)) == expected,
                        "partial-or-foreign-source-cache")
        return "complete" if complete else "initial"

    def create(self, relative, raw):
        require(relative in CORE_FILES and 0 < len(raw) <= MAX_SOURCE_BYTES, "fixed-source-create")
        path = self.path(relative)
        with protected_directory(str(Path(path).parent)) as parent:
            fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o600)
                remaining = memoryview(raw)
                while remaining:
                    size = os.write(fd, remaining)
                    require(size > 0, "source-short-write")
                    remaining = remaining[size:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        require(self.read(relative, len(raw)) == raw, "source-stage-readback")


def stage_sources(store, revision, manifest_raw, guide_hash, manifest_hash, download=fetch):
    require(valid_revision(revision) and valid_hash(guide_hash) and valid_hash(manifest_hash) and
            sha256(manifest_raw) == manifest_hash and sha256(store.read(GUIDE_FILE, MAX_SOURCE_BYTES)) == guide_hash,
            "reviewed-launcher-hashes")
    manifest = source_manifest(manifest_raw)
    if store.cache_state() == "complete":
        return verify_sources(store, manifest, guide_hash, manifest_hash)
    store.mkdir()  # Create-only. Existing or uncertain staging is retained.
    for relative in CORE_FILES:
        entry = manifest["files"][relative]
        raw = download(REPOSITORY + revision + "/" + relative, entry["size"])
        require(len(raw) == entry["size"] and sha256(raw) == entry["sha256"], "source-download-verification")
        store.create(relative, raw)
    return verify_sources(store, manifest, guide_hash, manifest_hash)


def verify_sources(store, manifest, guide_hash, manifest_hash):
    hashes = {}
    for relative, entry in manifest["files"].items():
        raw = store.read(relative, entry["size"])
        require(len(raw) == entry["size"] and sha256(raw) == entry["sha256"], "source-staging-changed")
        hashes[store.path(relative)] = entry["sha256"]
    for relative, expected, limit in ((GUIDE_FILE, guide_hash, MAX_SOURCE_BYTES), (MANIFEST_FILE, manifest_hash, MAX_MANIFEST_BYTES)):
        require(sha256(store.read(relative, limit)) == expected, "source-staging-changed")
        hashes[store.path(relative)] = expected
    return hashes


def compatibility(s, e, facts, probe, download=fetch):
    require(sha256(e.read(s.BINARY, 256 << 20)) == facts["manifest"]["agentHash"], "installed-agent-changed")
    try:
        raw = probe(facts["uid"], facts["gid"])
    except Exception as exc:
        raise Rejected("agent-upgrade-required") from exc
    require(strict_json(raw, 4096) == AGENT_CAPABILITIES, "agent-upgrade-required")
    bootstrap_raw = e.read(s.BOOTSTRAP, 65536)
    require(sha256(bootstrap_raw) == facts["manifest"]["bootstrapHash"], "public-bootstrap-changed")
    bootstrap = strict_json(bootstrap_raw, 65536)
    profile = facts["profile"]
    require(type(bootstrap) is dict and bootstrap.get("profile") == profile and
            bootstrap.get("collectionProfile") == s.PROFILE and bootstrap.get("agentOrigin") == facts["origin"] and
            s.valid_origin(bootstrap.get("enrollmentOrigin"), profile), "manager-capability-origin")
    plaintext = profile == "http-test"
    ca = bootstrap.get("serverCaPem")
    require(ca == "" if plaintext else type(ca) is str and 0 < len(ca) <= 32768, "manager-public-ca")
    try:
        manager_raw = download(bootstrap["enrollmentOrigin"] + CAPABILITY_PATH, 2048,
                               ca_pem=None if plaintext else ca, plaintext=plaintext)
    except Exception as exc:
        raise Rejected("manager-capability-unavailable-or-upgrade-required") from exc
    expected = dict(schemaVersion="tracebolt.journal-manager-capabilities.v1", agentOrigin=facts["origin"],
                    generationReport="tracebolt.journal-generation-report.v2", request="tracebolt.journal-request.v2",
                    serviceAuthorization=["exact-units", "all-system-services"])
    require(strict_json(manager_raw, 2048) == expected, "manager-upgrade-required")
    return dict(agentCapabilities=AGENT_CAPABILITIES, managerCapabilities=expected,
                managerCapabilityOrigin=bootstrap["enrollmentOrigin"], managerAuthenticity=not plaintext)


def confirmation_text(plan, revision):
    old = ", ".join(plan["oldUnits"])
    preserved = plan["preservedPolicy"]
    lines = ["Grant on-demand journal access to every current and future supported exact system service?",
             "Device: " + plan["deviceId"], "Manager: " + plan["managerOrigin"],
             "Existing exact grant: " + old,
             "Each central request still selects one exact service; no wildcard, kernel, whole-journal, user-journal or file access.",
             "Limits stay: %s seconds per query, %s seconds lookback, priority 0..%s; policy enabled=%s." %
             (preserved["maxWindowSeconds"], preserved["maxLookbackSeconds"], preserved["maxPriority"], str(preserved["enabled"]).lower()),
             "Log messages may contain credentials and personal data despite masking. The manager will also receive the approved service scope and generation metadata.",
             "The owned agent, socket and helper stop briefly; only previously active agent/socket units restart. No binary upgrade or journal read occurs.",
             "Reviewed source revision: " + revision]
    if plan["transportProfile"] == "http-test":
        lines.append("HTTP exposes log content and does not authenticate the manager. Its capability response can be impersonated.")
    return "\n".join(lines)


def run(a, s, e, templates, revision, probe, confirm, emit, download=fetch):
    current = a.inspect(s, e, templates)
    require(current["policy"]["enabled"] is True, "existing-policy-disabled-separate-enable-required")
    if current["policy"].get("serviceAuthorization") == "all-system-services":
        compatibility(s, e, current, probe, download)
        return dict(committed=False, alreadyAuthorized=True, originalActivity=current["activity"],
                    sourceStagingRetained=True, contentRead=False)
    facts, plan = a.preflight(s, e, [], templates, all_system_services=True)
    compatible = compatibility(s, e, facts, probe, download)
    plan_digest = a.digest(a.canonical(plan))
    bound = dict(sourceRevision=revision, planSHA256=plan_digest, compatibility=compatible)
    emit(confirmation_text(plan, revision) + "\nBound plan: " + sha256(canonical(bound)))
    phrase = "GRANT ALL SYSTEM SERVICES" + (" OVER HTTP" if facts["profile"] == "http-test" else "")
    if confirm(phrase) is not True:
        return dict(committed=False, canceled=True, sourceStagingRetained=True, contentRead=False)
    # The amendment owns the transaction and its own final plan-drift check.
    # Recheck compatibility before it acquires any lock or stops a unit.
    require(compatibility(s, e, facts, probe, download) == compatible, "compatibility-changed")
    e.source_hashes()
    return a.apply(s, e, [], templates, plan_digest, True, facts["profile"] == "http-test", all_system_services=True)


@contextlib.contextmanager
def terminal_descriptor():
    # Buffered text update mode ("r+") requires a seekable stream. A terminal
    # is not seekable; keep its checked descriptor unbuffered in both directions.
    fd = None
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        require(os.isatty(fd), "local-terminal-required")
        yield fd
    except OSError as exc:
        raise Rejected("local-terminal-required") from exc
    finally:
        if fd is not None:
            os.close(fd)


def terminal_confirm(phrase):
    with terminal_descriptor() as fd:
        prompt = ("Type " + phrase + " to approve, or press Enter to cancel: ").encode("utf-8")
        while prompt:
            written = os.write(fd, prompt)
            require(written > 0, "terminal-write-failed")
            prompt = prompt[written:]
        answer = bytearray()
        while len(answer) < 128:
            part = os.read(fd, 1)
            if not part:
                break
            answer.extend(part)
            if part == b"\n":
                break
        return bytes(answer) == phrase.encode("utf-8") + b"\n"


def require_terminal():
    with terminal_descriptor():
        pass


def outcome_text(result):
    if result.get("canceled"):
        return "Canceled. The existing grant is unchanged; verified source remains staged for a later retry."
    if result.get("committed"):
        if result.get("restartFailureStage"):
            return "Grant committed, but previous service activity could not be restored. Retain the evidence and inspect the reported restart failure before using Logs."
        if result.get("failureStage"):
            return "Grant committed, but final verification or housekeeping reported a failure. Retain the evidence and review the details below; do not repeat the grant."
        prefix = "Grant committed. "
    elif result.get("alreadyAuthorized"):
        prefix = "All supported current and future system services are already authorized. "
    elif result.get("commitState") == "commit-uncertain":
        return "The grant's commit state is uncertain. Leave services and retained evidence as they are for a separately reviewed recovery."
    else:
        return "The grant was not committed. Retain all source staging and transaction evidence and inspect the failure below."
    if not result.get("originalActivity", {}).get("tracebolt-agent.service", False):
        return prefix + "The previously stopped agent remains stopped. Fresh scope metadata will appear after its normal authorized operation resumes."
    return prefix + "Return to the manager's Logs page after the next agent report to make bounded requests."


def failure_text(stage):
    if stage == "agent-upgrade-required":
        return "The installed agent cannot confirm the required journal support. Use the separately approved normal agent upgrade, then retry."
    if stage == "manager-upgrade-required":
        return "The manager lacks the required journal support. Use the separately approved normal manager upgrade, then retry."
    if stage == "manager-capability-unavailable-or-upgrade-required":
        return "The manager capability check failed. Check the bound manager's availability and compatible version before retrying."
    if stage == "existing-policy-disabled-separate-enable-required":
        return "The existing journal policy is disabled. This grant cannot enable it; use a separately reviewed enablement workflow."
    if stage in ("root-linux-local-administration", "local-terminal-required"):
        return "Run this reviewed command deliberately in a root terminal on the intended Linux endpoint."
    return "Stopped before completion. Inspect the fixed failure stage below and retain all staged evidence."


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--guide-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    def interrupt(_signum, _frame):
        raise Rejected("interrupted")
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    result = None
    try:
        require(sys.platform == "linux" and os.getuid() == os.geteuid() == 0, "root-linux-local-administration")
        require_terminal()
        store = SourceStore(args.revision)
        require(os.path.abspath(__file__) == store.path(GUIDE_FILE), "fixed-launcher-path")
        manifest_raw = store.read(MANIFEST_FILE, MAX_MANIFEST_BYTES)
        sources = stage_sources(store, args.revision, manifest_raw, args.guide_sha256, args.manifest_sha256)
        module = types.ModuleType("tracebolt_reviewed_journal_amend")
        module.__file__ = store.path(CORE_FILES[0])
        exec(compile(store.read(CORE_FILES[0], MAX_SOURCE_BYTES), module.__file__, "exec"), module.__dict__)
        s, _ = module.load_setup()
        e = module.real_effects(s, sources)
        templates = s.read_templates(e)
        def probe(uid, gid):
            # The amendment adapter intentionally admits only preview/accept.
            # This direct base-adapter call is restricted to this exact inert CLI.
            return s.Effects.command(e, [s.BINARY, "--journal-capabilities"], uid=uid, gid=gid,
                                     limit=4096, timeout=5, failure_stage="journal-preview-command-failed")
        result = run(module, s, e, templates, args.revision, probe, terminal_confirm, print)
        print(outcome_text(result))
        print(json.dumps(result, indent=2))
        return 0 if result.get("canceled") or result.get("alreadyAuthorized") or result.get("committed") and "failureStage" not in result and "restartFailureStage" not in result else 1
    except Exception as exc:
        if result is not None:
            # A display/pipe failure after apply is not an uncommitted grant.
            result["reportingFailure"] = "result-output-failed"
            try:
                print(json.dumps(result, indent=2), file=sys.stderr)
            except Exception:
                pass
            return 1
        safe = isinstance(exc, Rejected) or "module" in locals() and isinstance(exc, module.Rejected) or "s" in locals() and isinstance(exc, s.Rejected)
        stage = str(exc) if safe else "guide-preflight-failed"
        print(failure_text(stage), file=sys.stderr)
        print(json.dumps(dict(committed=False, failureStage=stage,
                              warning="Retain staged source and transaction evidence. No automatic cleanup, recovery or upgrade.")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
