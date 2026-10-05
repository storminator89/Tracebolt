#!/usr/bin/env python3
"""One local confirmation for existing Linux inventory consents. Inert on import.

This orchestrates existing identity-bound consent CLIs. It is not an authority,
installer, journal recovery tool, or collector. Run only a reviewed pinned copy.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import time
import types
import urllib.request

REPOSITORY = "https://raw.githubusercontent.com/storminator89/Tracebolt/"
GUIDE_FILE = "deploy/inventory/guide.py"
MANIFEST_FILE = "deploy/inventory/source-manifest.json"
CORE_FILES = ("deploy/journal/setup.py", "deploy/systemd/tracebolt-agent.service.in")
MAX_SOURCE = 131072
TELEMETRY = "/var/lib/tracebolt-agent/enrollment/telemetry"
RESUME = "/usr/bin/systemctl start tracebolt-agent.service"
STATUS = "/usr/bin/systemctl status --no-pager tracebolt-agent.service"
OVERVIEW_DISCLOSURE = "Full visible processes and mounted filesystems in the agent's Linux namespaces, including potentially sensitive process names, mount paths and filesystem labels; fixed 60-second capture cadence. Missing row fields remain explicit. No command lines, environment values, file contents or additional OS privileges. HTTP-test content is unencrypted and the manager is unauthenticated."
APT_DISCLOSURE = "All known newer cached APT candidate rows: package names, architectures, installed and candidate versions, dpkg holds, checked and unknown counts, and original local package-index modification age; fixed six-hour capture cadence. Existing agent permissions only. No repository URLs, refresh, installation, CVE classification or dependency, phasing or installability guarantees. Unknown comparisons remain unknown. Index modification time cannot prove repository freshness. HTTP-test content is unencrypted and the manager is unauthenticated."
SCOPES = {
    "overview": dict(label="Full visible processes and mounts", flag="complete-overview",
        schema="tracebolt.complete-overview-consent-result.v1", extension="tracebolt.linux-complete-overview.v1",
        scope="full-agent-visible-processes-and-mounted-filesystems", cadence=60, disclosure=OVERVIEW_DISCLOSURE,
        sidecar="complete-overview-consent.json", markers=(".complete-overview-initialization", ".complete-overview-consent.tmp"),
        spools=("overview-processes", "overview-volumes")),
    "apt": dict(label="All known cached APT candidates", flag="complete-cached-updates",
        schema="tracebolt.complete-cached-updates-consent-result.v1", extension="tracebolt.complete-cached-apt-updates.v1",
        scope="agent-visible-complete-known-cached-apt-candidate-rows", cadence=21600, disclosure=APT_DISCLOSURE,
        sidecar="complete-cached-updates-consent.json", markers=(".complete-cached-updates-initialization", ".complete-cached-updates-consent.tmp"),
        spools=("cached-updates",)),
    "identity": dict(label="Hostname and interface addresses (separate optional scope)", flag="endpoint-identity",
        schema="tracebolt.endpoint-identity-consent-result.v1", extension="tracebolt.endpoint-identity.v1",
        scope="agent-visible-linux-hostname-and-interface-addresses", sidecar="endpoint-identity-consent.json",
        markers=(".endpoint-identity-consent.tmp",), spools=()),
}


class Rejected(Exception):
    """Fixed safe stages only. Never includes subprocess output or private state."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def valid_revision(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def strict_json(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "bounded-json")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-json-member")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("invalid-json-number")))
    except (ValueError, UnicodeError):
        raise Rejected("invalid-json") from None


def manifest(raw):
    value = strict_json(raw, 8192)
    require(type(value) is dict and set(value) == {"schemaVersion", "files"} and
            value["schemaVersion"] == "tracebolt.inventory-guide-source.v1" and
            type(value["files"]) is dict and set(value["files"]) == set(CORE_FILES), "source-manifest-members")
    for entry in value["files"].values():
        require(type(entry) is dict and set(entry) == {"sha256", "size"} and valid_hash(entry["sha256"]) and
                type(entry["size"]) is int and 0 < entry["size"] <= MAX_SOURCE, "source-manifest-entry")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Rejected("source-redirect-rejected")


def fetch(url, limit):
    require(url.startswith(REPOSITORY) and type(limit) is int and 0 < limit <= MAX_SOURCE, "fixed-public-source")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + 20
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with opener.open(request, timeout=10) as response:
        require(response.status == 200 and response.geturl() == url and
                response.headers.get("Content-Encoding", "identity") == "identity", "source-response")
        raw = bytearray()
        while len(raw) <= limit:
            require(time.monotonic() < deadline, "source-deadline")
            part = response.read1(min(65536, limit + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
    require(0 < len(raw) <= limit, "source-size")
    return bytes(raw)


def load_sources(revision, manifest_hash, download=fetch):
    require(valid_revision(revision) and valid_hash(manifest_hash), "immutable-source-pins")
    prefix = REPOSITORY + revision + "/"
    raw = download(prefix + MANIFEST_FILE, 8192)
    require(digest(raw) == manifest_hash, "source-manifest-hash")
    contents = {}
    for name, entry in manifest(raw)["files"].items():
        data = download(prefix + name, entry["size"])
        require(len(data) == entry["size"] and digest(data) == entry["sha256"], "source-hash")
        contents[name] = data
    # No file is created and no journal entry point is invoked. Only the fixed
    # ownership adapter is compiled after every source hash has been checked.
    s = types.ModuleType("tracebolt_inventory_ownership")
    s.__file__ = "/verified-source/deploy/journal/setup.py"
    exec(compile(contents[CORE_FILES[0]], s.__file__, "exec"), s.__dict__)
    return s, {"tracebolt-agent.service.in": contents[CORE_FILES[1]]}


def selected_scopes(include_identity=False):
    return ("overview", "apt", "identity") if include_identity else ("overview", "apt")


def consent_args(s, facts, key, mode):
    require(key in SCOPES and mode in ("preview", "enable"), "fixed-consent-mode")
    spec = SCOPES[key]
    args = [s.BINARY, "--config", s.CONFIG, "--service-identity", f"{facts['uid']}:{facts['gid']}",
            "--" + spec["flag"] + "-consent", mode]
    if mode == "enable":
        args.append("--ack-" + spec["flag"])
    return args


def consent_result(raw, key, mode):
    spec = SCOPES[key]
    p = strict_json(raw, 8192)
    fields = {"schemaVersion", "mode", "extensionVersion", "scope", "enabled", "existingStatePreserved"}
    if key != "identity":
        fields |= {"disclosure", "captureIntervalSeconds"}
    require(type(p) is dict and set(p) == fields and p["schemaVersion"] == spec["schema"] and
            p["mode"] == mode and p["extensionVersion"] == spec["extension"] and p["scope"] == spec["scope"] and
            type(p["enabled"]) is bool and p["existingStatePreserved"] is True, "consent-result-contract")
    if key != "identity":
        require(p["disclosure"] == spec["disclosure"] and type(p["captureIntervalSeconds"]) is int and
                p["captureIntervalSeconds"] == spec["cadence"], "consent-disclosure-contract")
    require(mode != "enable" or p["enabled"] is True, "enable-not-confirmed")
    return p


def configure(s, e, facts, key, mode):
    return consent_result(e.command(consent_args(s, facts, key, mode), uid=facts["uid"], gid=facts["gid"],
        limit=8192, timeout=45, failure_stage="consent-" + mode + "-failed"), key, mode)


def capability_check(s, e, facts, keys):
    raw = e.command([s.BINARY, "--help"], uid=facts["uid"], gid=facts["gid"],
                    limit=32768, timeout=5, failure_stage="installed-agent-capabilities-unavailable")
    require(type(raw) is bytes and 0 < len(raw) <= 32768, "installed-agent-upgrade-required")
    for name in ("config", "service-identity", "validate-guided", *(
            flag for key in keys for flag in (SCOPES[key]["flag"] + "-consent", "ack-" + SCOPES[key]["flag"]))):
        require(re.search(rb"(?m)^\s+-" + name.encode("ascii") + rb"(?:\s|$)", raw) is not None,
                "installed-agent-upgrade-required")


def config_facts(s, e, facts):
    raw = e.agent_config(facts["uid"], facts["gid"])
    c = strict_json(raw, 16384)
    fields = {"schemaVersion", "profile", "managerOrigin", "agentId", "certificateFile", "privateKeyFile",
              "serverCAFile", "stateDirectory", "insecureHTTPAcknowledged", "collectionProfile"}
    require(type(c) is dict and set(c) == fields and c["schemaVersion"] == "tracebolt.lan-agent.v5" and
            c["collectionProfile"] == s.PROFILE and c["profile"] == facts["profile"] and
            c["managerOrigin"] == facts["origin"] and c["stateDirectory"] == TELEMETRY and
            type(c["agentId"]) is str and re.fullmatch(r"agent_[0-9a-f]{32}", c["agentId"]) is not None and
            c["insecureHTTPAcknowledged"] is (facts["profile"] == "http-test"), "existing-activated-v3-config")
    return dict(configHash=digest(raw), deviceId=c["agentId"])


def inspect(s, e, templates, keys):
    facts = s.inspect_agent(e, templates)
    facts.update(config_facts(s, e, facts))
    capability_check(s, e, facts, keys)
    return facts


def unchanged(s, before, after):
    return s.same_agent(before, after) and all(before[k] == after[k] for k in ("configHash", "deviceId"))


def check_shape(shape, key, enabled):
    spec = SCOPES[key]
    require(set(shape) == {"consentPresent", "markersPresent", "spoolsPresent"} and
            type(shape["consentPresent"]) is bool and type(shape["markersPresent"]) is bool and
            type(shape["spoolsPresent"]) is list and len(shape["spoolsPresent"]) == len(spec["spools"]) and
            all(type(x) is bool for x in shape["spoolsPresent"]), "state-shape-contract")
    require(not shape["markersPresent"], "uncertain-" + key + "-initialization")
    require(shape["consentPresent"] is enabled, "ambiguous-" + key + "-consent")
    spools = shape["spoolsPresent"]
    require(not spools or not any(spools) or all(spools), "partial-" + key + "-spools")
    require(not enabled or all(spools), "missing-" + key + "-spools")


def all_previews(s, e, facts, keys, result):
    previews = {}
    for key in keys:
        p = configure(s, e, facts, key, "preview")
        check_shape(e.scope_shape(facts["uid"], facts["gid"], key), key, p["enabled"])
        previews[key] = p
        result["scopes"][key]["before"] = "enabled" if p["enabled"] else "disabled"
    return previews


def confirmation_text(facts, keys):
    lines = ["Inventory collection setup", "Device: " + facts["deviceId"], "Manager: " + facts["origin"],
        "Current local consent for each selected scope: unknown until stopped-agent validation."]
    for key in keys:
        lines.append("Selected: " + SCOPES[key]["label"])
        if key != "identity":
            lines.append(SCOPES[key]["disclosure"])
        else:
            lines.append("Report the local hostname and all visible interface names, IPv4 and IPv6 addresses under the existing system-inventory cadence. These can identify the host and its networks.")
    if "identity" not in keys:
        lines.append("Hostname and interface addresses: not selected; its existing grant is unchanged.")
    lines += ["After confirmation, briefly pause only the owned agent, validate every selected preview, enable missing selections through its existing local consent commands, then restore previous activity if safe.",
        "Existing device identity, independent sequence counters, pending bytes and original capture ages are preserved. No journal setup or pending-journal recovery is included.",
        "No account, group, service definition, permission, package install, metadata refresh or manager setting changes. Consent commands perform no collection or manager request; the resumed agent uses the approved scopes during normal reporting.",
        "The changes are separate steps: an earlier scope can succeed before a later failure. Uncertain protected state stays untouched and may require a separately reviewed resume.",
        "APT support remains release/configuration dependent; all known candidates does not mean every package is comparable or up to date. Linux namespace and permission limits remain. Socket-to-process ownership is not added."]
    if facts["profile"] == "http-test":
        lines.append("WARNING: HTTP sends the selected metadata in plaintext and does not authenticate this manager.")
    return "\n".join(lines)


def safe_stage(s, exc):
    return str(exc) if isinstance(exc, (Rejected, s.Rejected)) else "inventory-operation-failed"


def run(s, e, templates, include_identity, confirm, emit):
    keys = selected_scopes(include_identity)
    facts = inspect(s, e, templates, keys)  # No sender locks, stop or consent CLI.
    result = dict(schemaVersion="tracebolt.inventory-setup-result.v1", completed=False, canceled=False,
        originalActivity=facts["active"], activity="unchanged", collectionPerformed=False,
        scopes={key: dict(before="unknown", outcome="not_attempted") for key in keys})
    emit(confirmation_text(facts, keys))
    phrase = "ENABLE INVENTORY" + (" OVER HTTP" if facts["profile"] == "http-test" else "")
    if confirm(phrase) is not True:
        result["canceled"] = True
        return result
    stop_attempted = False
    uncertain_write = False
    try:
        with e.lock():
            current = inspect(s, e, templates, keys)
            require(unchanged(s, facts, current) and current["active"] is facts["active"], "reviewed-installation-changed")
            try:
                if facts["active"]:
                    stop_attempted = True  # Also covers a lost stop acknowledgement.
                    e.command(["/usr/bin/systemctl", "stop", s.AGENT_UNIT], timeout=45,
                              failure_stage="agent-stop-failed")
                current = s.inspect_agent(e, templates)
                current.update(config_facts(s, e, current))
                require(unchanged(s, facts, current), "installation-changed-after-stop")
                state = e.status(s.AGENT_UNIT)
                require(s.owned_unit(state, s.AGENT_UNIT, "inactive") and state["MainPID"] == "0",
                        "agent-not-confirmed-stopped")
                previews = all_previews(s, e, facts, keys, result)
                # Preview is read-only; each existing enable still owns deeper
                # spool validation. No atomic cross-scope commit is promised.
                for key in keys:
                    if previews[key]["enabled"]:
                        result["scopes"][key]["outcome"] = "already_enabled"
                        continue
                    uncertain_write = True
                    result["scopes"][key]["outcome"] = "uncertain"
                    configure(s, e, facts, key, "enable")
                    after = configure(s, e, facts, key, "preview")
                    require(after["enabled"], "enable-readback-disabled")
                    check_shape(e.scope_shape(facts["uid"], facts["gid"], key), key, True)
                    result["scopes"][key]["outcome"] = "enabled_confirmed"
                    uncertain_write = False
                result["completed"] = True
            except BaseException as exc:
                result["failureStage"] = safe_stage(s, exc)
            finally:
                if stop_attempted:
                    if uncertain_write:
                        result["activity"] = "left_stopped_uncertain_consent"
                    else:
                        try:
                            current = s.inspect_agent(e, templates)
                            current.update(config_facts(s, e, current))
                            require(unchanged(s, facts, current), "resume-ownership-changed")
                            state = e.status(s.AGENT_UNIT)
                            if s.owned_unit(state, s.AGENT_UNIT, "inactive") and state["MainPID"] == "0":
                                # Existing baseline validator, as the dedicated
                                # service identity, without collection/network.
                                e.command([s.BINARY, "--config", s.CONFIG, "--validate-guided"],
                                    uid=facts["uid"], gid=facts["gid"], failure_stage="resume-protected-state-unverified")
                                e.command(["/usr/bin/systemctl", "start", s.AGENT_UNIT], timeout=45,
                                          failure_stage="agent-resume-failed")
                            state = e.status(s.AGENT_UNIT)
                            require(s.owned_unit(state, s.AGENT_UNIT, "active") and int(state["MainPID"]) > 0,
                                    "agent-resume-not-confirmed")
                            result["activity"] = "restored_active"
                        except BaseException as exc:
                            result["activity"] = "resume_not_confirmed"
                            result["resumeFailureStage"] = safe_stage(s, exc)
    except BaseException as exc:
        result["failureStage"] = safe_stage(s, exc)
    if result["activity"] in ("left_stopped_uncertain_consent", "resume_not_confirmed"):
        result["resumeAfterInspection"] = RESUME
    result["statusCommand"] = STATUS
    if any(v["outcome"] == "uncertain" for v in result["scopes"].values()):
        result["retry"] = "Inspect the reported scope and protected state first. Do not remove sidecars, temporaries or spools, reset identity, or automatically repeat an uncertain enable. After resolving the exact blocker, rerun this same reviewed guide; it re-previews and skips enabled scopes."
    elif not result["completed"] and not result["canceled"]:
        result["retry"] = "Correct the reported preflight/preview blocker, then rerun this same reviewed guide. All existing state is retained and already enabled scopes are skipped."
    return result


@contextlib.contextmanager
def terminal():
    fd = None
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        require(os.isatty(fd), "local-root-terminal-required")
        yield fd
    finally:
        if fd is not None:
            os.close(fd)



def emit_terminal(message):
    # Consent disclosure must remain visible even when JSON stdout is redirected.
    with terminal() as fd:
        raw = (message + "\n").encode("utf-8")
        while raw:
            n = os.write(fd, raw)
            require(n > 0, "terminal-write-failed")
            raw = raw[n:]


def confirm_terminal(phrase):
    with terminal() as fd:
        raw = ("Type " + phrase + " to confirm, or press Enter to cancel: ").encode("ascii")
        while raw:
            n = os.write(fd, raw)
            require(n > 0, "terminal-write-failed")
            raw = raw[n:]
        answer = bytearray()
        while len(answer) < 128:
            part = os.read(fd, 1)
            if not part:
                break
            answer.extend(part)
            if part == b"\n":
                break
        return bytes(answer) == phrase.encode("ascii") + b"\n"


def real_effects(s):
    class Effects(s.Effects):
        @contextlib.contextmanager
        def agent_directory(self, uid, gid, telemetry=False):
            # Descriptor-relative traversal refuses symlinks at every private
            # component. No private key, certificate or ledger bytes are read.
            self.protected_dir("/var/lib")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            opened = []
            try:
                fd = os.open("/var/lib", flags)
                opened.append(("/var/lib", fd))
                for name in ("tracebolt-agent", "enrollment", *(("telemetry",) if telemetry else ())):
                    fd = os.open(name, flags, dir_fd=fd)
                    opened.append((opened[-1][0] + "/" + name, fd))
                    st = os.fstat(fd)
                    require(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700 and
                            st.st_uid == uid and st.st_gid == gid, "protected-agent-directory")
                yield fd
                for name, handle in opened:
                    a, b = os.fstat(handle), os.lstat(name)
                    require((a.st_dev, a.st_ino, a.st_mode, a.st_uid, a.st_gid) ==
                            (b.st_dev, b.st_ino, b.st_mode, b.st_uid, b.st_gid), "agent-directory-changed")
            finally:
                for _, fd in reversed(opened):
                    os.close(fd)

        def agent_config(self, uid, gid):
            with self.agent_directory(uid, gid) as parent:
                fd = os.open("agent.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
                try:
                    before = os.fstat(fd)
                    require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600 and
                            before.st_uid == uid and before.st_gid == gid and before.st_nlink == 1 and
                            0 < before.st_size <= 16384, "protected-agent-config")
                    raw = bytearray()
                    while len(raw) <= 16384:
                        part = os.read(fd, min(4096, 16385 - len(raw)))
                        if not part:
                            break
                        raw.extend(part)
                    require(len(raw) == before.st_size and s.same_file(before, os.fstat(fd)) and
                            s.same_file(before, os.stat("agent.json", dir_fd=parent, follow_symlinks=False)), "agent-config-changed")
                    return bytes(raw)
                finally:
                    os.close(fd)

        def scope_shape(self, uid, gid, key):
            spec = SCOPES[key]
            with self.agent_directory(uid, gid, telemetry=True) as parent:
                def entry(name, directory=False, marker=False):
                    try:
                        st = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        return False
                    if marker:
                        return True  # Any matching entry is unresolved, including symlinks.
                    require((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)) and
                            stat.S_IMODE(st.st_mode) == (0o700 if directory else 0o600) and
                            st.st_uid == uid and st.st_gid == gid and
                            (directory or st.st_nlink == 1 and 0 < st.st_size <= 4096), "protected-" + key + "-state")
                    return True
                return dict(consentPresent=entry(spec["sidecar"]),
                    markersPresent=any(entry(name, marker=True) for name in spec["markers"]),
                    spoolsPresent=[entry(name, directory=True) for name in spec["spools"]])

        def command(self, args, uid=None, gid=None, limit=16384, timeout=45, failure_stage="fixed-command-failed"):
            allowed = [["/usr/bin/systemctl", op, s.AGENT_UNIT] for op in ("stop", "start")]
            allowed.append(["/usr/bin/systemctl", "show", s.AGENT_UNIT,
                            "--property=" + ",".join(s.unit_fields(s.AGENT_UNIT)), "--all", "--no-pager"])
            help_mode = args == [s.BINARY, "--help"]
            if uid is not None:
                require(s.valid_id(uid) and s.valid_id(gid), "nonroot-command-identity")
                facts = dict(uid=uid, gid=gid)
                allowed = [[s.BINARY, "--help"], [s.BINARY, "--config", s.CONFIG, "--validate-guided"]]
                allowed += [consent_args(s, facts, key, mode) for key in SCOPES for mode in ("preview", "enable")]
            require(args in allowed and (uid is None) == (gid is None) and
                    type(limit) is int and 0 < limit <= 32768 and 0 < timeout <= 45, "fixed-inventory-command")
            self.read(args[0], 256 << 20)
            kw = {} if uid is None else dict(user=uid, group=gid, extra_groups=[])
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if help_mode else subprocess.DEVNULL, env=s.ENV, cwd="/",
                close_fds=True, start_new_session=True, **kw)
            raw = bytearray()
            try:
                with selectors.DefaultSelector() as sel:
                    sel.register(child.stdout, selectors.EVENT_READ)
                    until = time.monotonic() + timeout
                    while sel.get_map():
                        require(time.monotonic() < until, "inventory-command-timeout")
                        for key, _ in sel.select(min(0.2, max(0, until - time.monotonic()))):
                            part = os.read(key.fileobj.fileno(), 4096)
                            if not part:
                                sel.unregister(key.fileobj)
                            raw.extend(part)
                            require(len(raw) <= limit, "inventory-command-output-limit")
                require(child.wait(timeout=max(0.01, until - time.monotonic())) == 0, failure_stage)
                return bytes(raw)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                child.stdout.close()
    return Effects()


def outcome_text(result):
    if result["canceled"]:
        return "Canceled before changing consent or stopping the agent."
    if result["completed"]:
        text = "Selected local consents are confirmed."
    else:
        text = "Inventory setup did not complete. Review each scope's outcome below; successful earlier scopes remain enabled."
    if result["activity"] == "restored_active":
        return text + " Previous agent activity was restored. Check newly received inventory and its coverage in the dashboard."
    if not result["originalActivity"]:
        return text + " The previously stopped agent remains stopped."
    if "resumeAfterInspection" in result:
        return text + " Agent resumption is not confirmed. Inspect the exact failure and protected state first; only then resume the same owned service with: " + RESUME
    return text + " No service stop was performed."



def failure_text(stage):
    if stage in ("installed-agent-upgrade-required", "installed-agent-capabilities-unavailable"):
        return "The installed agent cannot confirm the required inventory consent commands. Use the normal separately reviewed compatible-agent upgrade, then rerun this guide. The agent was not paused."
    if stage in ("local-root-linux-required", "local-root-terminal-required"):
        return "Run the reviewed command deliberately in a local root terminal on the intended Linux endpoint."
    return "Inventory preflight did not complete. The guide did not pause the agent or change consent. Inspect the fixed failure stage and keep existing state intact."


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--include-network-identity", action="store_true",
                        help="Separately select hostname and all visible interface IPv4/IPv6 addresses")
    args = parser.parse_args(argv)
    def interrupt(_signum, _frame):
        raise Rejected("interrupted")
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    s = None
    result = None
    try:
        require(sys.platform == "linux" and os.getuid() == os.geteuid() == 0, "local-root-linux-required")
        with terminal():
            pass
        s, templates = load_sources(args.revision, args.manifest_sha256)
        result = run(s, real_effects(s), templates, args.include_network_identity, confirm_terminal, emit_terminal)
        print(outcome_text(result))
        print(json.dumps(result, indent=2))
        return 0 if result["canceled"] or result["completed"] and "resumeFailureStage" not in result else 1
    except Exception as exc:
        stage = str(exc) if isinstance(exc, Rejected) or s is not None and isinstance(exc, s.Rejected) else "inventory-preflight-failed"
        if result is not None:
            # A broken output stream after a grant is not an uncommitted grant.
            result["reportingFailure"] = "result-output-failed"
        else:
            result = dict(completed=False, failureStage=stage, activity="unchanged")
            try:
                print(failure_text(stage), file=sys.stderr)
            except Exception:
                pass
        try:
            print(json.dumps(result), file=sys.stderr)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
