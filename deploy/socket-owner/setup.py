#!/usr/bin/env python3
"""Fixed socket-owner provisioning/revoke adapter. Inert on import.

Only the explicitly approved read-admin socket phase or maintenance dispatcher
calls this module. Tests replace every effect. No helper IPC is performed: local
configuration readback is not native runtime, capture, LSM or reboot acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import time

HELPER = "tracebolt-socket-owner-reader"
AGENT = "tracebolt-agent.service"
SERVICE = HELPER + ".service"
SOCKET = HELPER + ".socket"
UNIT_DIR = "/etc/systemd/system"
CONFIG_DIR = "/etc/tracebolt"
INSTALLER_DIR = "/var/lib/tracebolt-agent-installer"
AGENT_BINARY = "/opt/tracebolt-agent/lan-agent"
BINARY = "/opt/tracebolt-agent/socket-owner-reader"
POLICY = CONFIG_DIR + "/socket-owner-policy.json"
DEPLOYMENT = CONFIG_DIR + "/socket-owner-deployment.json"
RUNTIME = "/run/tracebolt-socket-owner-reader"
SOCKET_PATH = RUNTIME + "/reader.sock"
WANTS = UNIT_DIR + "/sockets.target.wants/" + SOCKET
COMPLETE = INSTALLER_DIR + "/socket-owner-install-complete.json"
REVOKE_STARTED = INSTALLER_DIR + "/socket-owner-revoke-started.json"
REVOKE_COMPLETE = INSTALLER_DIR + "/socket-owner-revoke-complete.json"
DISABLE_STAGE = CONFIG_DIR + "/.socket-owner-policy.disable.tmp"
PARENT_INTENT = INSTALLER_DIR + "/read-admin-intent.json"
SCOPE = "systemd-pid1-local-tcp-udp-socket-owners"
CLIENT_CONTRACT = "tracebolt.socket-owner-activated-identity-client.v1"
POLICY_FIELDS = ("version", "scope", "senderBinding", "managerOrigin", "transportProfile", "collectionProfile", "agentUid", "agentGid", "helperUid", "helperGid", "epoch", "enabled", "metadataAcknowledged", "ptraceRiskAcknowledged", "httpAcknowledged")
IDENTITY_FIELDS = ("schemaVersion", "senderBinding", "managerOrigin", "endpointId", "incarnationDigest", "transportProfile", "agentUid", "agentGid")
CAPABILITIES = dict(schemaVersion="tracebolt.socket-owner-setup-capabilities.v1", identityVersion="tracebolt.socket-owner-setup-identity.v1", resultVersion="tracebolt.socket-owner-setup-result.v1", consentVersion="tracebolt.socket-owner-consent.v1", policyVersion="tracebolt.socket-owner-policy.v1", scope=SCOPE, maxPolicyBytes=4096)
CREATED = frozenset((BINARY, POLICY, DEPLOYMENT, UNIT_DIR + "/" + SERVICE, UNIT_DIR + "/" + SOCKET, COMPLETE, REVOKE_STARTED, REVOKE_COMPLETE, DISABLE_STAGE))
ROOTS = (UNIT_DIR, "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/transient", "/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late")
JOURNAL_FILES = frozenset(CONFIG_DIR + "/" + n for n in ("journal-setup-attempt.json", "journal-content-policy.json", "journal-client-policy.json", "journal-helper.json", "journal-client-helper.json", "journal-activation.json"))
BASIC_FIELDS = ("LoadState", "ActiveState", "FragmentPath", "DropInPaths", "Transient", "Names", "UnitFileState")
NAMESPACE_FIELDS = ("PrivateNetwork", "PrivateUsers", "PrivatePIDs", "NetworkNamespacePath", "JoinsNamespaceOf", "RootDirectory", "RootImage", "ProtectProc", "ProcSubset", "RuntimeDirectory")
SERVICE_FIELDS = ("MainPID", "ControlGroup", "ExecStart", "User", "Group", "SupplementaryGroups", "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges", "KillMode", "Delegate") + NAMESPACE_FIELDS
SOCKET_FIELDS = ("Listen", "SocketUser", "SocketGroup", "SocketMode", "DirectoryMode", "FileDescriptorName", "Accept", "Triggers", "RemoveOnStop")


class Rejected(Exception):
    """Fixed safe stages only; no private state or child diagnostics."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def canonical(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None and value != "0" * 64


def pin(st):
    return tuple(getattr(st, "st_" + k) for k in ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"))


def strict(s, raw, fields=None):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, "bounded-json")
    return s.strict_json(raw, fields)


def fields(name):
    require(name in (AGENT, SERVICE, SOCKET), "fixed-unit")
    return BASIC_FIELDS + (SOCKET_FIELDS if name == SOCKET else SERVICE_FIELDS)


def overrides(e, *, fresh=False):
    for root in ROOTS:
        for name in (AGENT, SERVICE, SOCKET):
            if root != UNIT_DIR:
                require(e.absent(root + "/" + name), "alternate-unit-fragment")
            require(e.absent(root + "/" + name + ".d"), "unit-dropin")
        for name in ("service.d", "socket.d", "tracebolt-.service.d", "tracebolt-.socket.d", "tracebolt-socket-.service.d", "tracebolt-socket-.socket.d", "tracebolt-socket-owner-.service.d", "tracebolt-socket-owner-.socket.d"):
            require(e.absent(root + "/" + name), "unit-dropin")
    if fresh:
        for path in CREATED | {RUNTIME, SOCKET_PATH, WANTS}:
            require(e.absent(path), "existing-socket-owner-state")


def local_accounts(s, e):
    users, groups = s.account_tables(e.read("/etc/passwd", 1 << 20), e.read("/etc/group", 1 << 20))
    nss = e.read("/etc/nsswitch.conf", 65536).decode("ascii")
    for kind in ("passwd", "group"):
        rows = [line.partition(":")[2].split("#", 1)[0].split() for line in nss.splitlines() if line.partition(":")[0].strip() == kind]
        require(len(rows) == 1 and rows[0] and rows[0][0] == "files" and all(x in ("files", "systemd") for x in rows[0]), "local-nss-only")
    return users, groups


def fresh_preflight(s, e):
    """Read-only before the global fresh installer; no current state is adopted."""
    e.platform()
    users, groups = local_accounts(s, e)
    require(HELPER not in users and HELPER not in groups, "existing-socket-owner-account")
    overrides(e, fresh=True)
    for name in (SERVICE, SOCKET):
        state = e.status(name)
        require(state["LoadState"] == "not-found" and state["ActiveState"] == "inactive" and state["FragmentPath"] == state["DropInPaths"] == "" and state["Transient"] == "no" and state["Names"] in ("", name) and state["UnitFileState"] in ("", "not-found") and (name == SOCKET or state["MainPID"] == "0"), "preexisting-loaded-unit")


def parent_proof(s, e, intent_digest, *, complete=False):
    require(valid_hash(intent_digest) and digest(e.read(PARENT_INTENT, 16384, 0o600)) == intent_digest, "parent-intent-changed")
    for phase in ("journal", "socket"):
        states = ("started", "complete") if phase == "journal" or complete else ("started",)
        for state in states:
            raw = e.read(INSTALLER_DIR + "/read-admin-" + phase + "." + state + ".json", 4096, 0o600)
            expected = dict(schemaVersion="tracebolt.read-admin-phase.v2", intentSHA256=intent_digest, phase=phase, state=state)
            require(strict(s, raw) == expected, "parent-phase-evidence")


def exact_file(e, path, mode, gid, *, limit=16384):
    before = e.metadata(path)
    require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == mode and before.st_uid == 0 and before.st_gid == gid and before.st_nlink == 1, "fixed-artifact-metadata")
    raw = e.read(path, limit, mode)
    require(0 < len(raw) <= limit and pin(before) == pin(e.metadata(path)), "fixed-artifact-changed")
    return raw


def exact_dir(e, path):
    e.protected_dir(path)
    for p in (Path(path), *Path(path).parents):
        st = e.metadata(str(p))
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o755, "native-directory-contract")


def journal_snapshot(e):
    exact_dir(e, CONFIG_DIR)
    names = {CONFIG_DIR + "/" + name for name in e.config_names()}
    require(JOURNAL_FILES <= names and names <= JOURNAL_FILES | {POLICY, DEPLOYMENT}, "unowned-configuration-state")
    return {p: (pin(e.metadata(p)), e.read(p, 16384)) for p in sorted(JOURNAL_FILES)}


def journal_unchanged(e, original):
    require(journal_snapshot(e) == original, "journal-state-changed")


def rendered(templates, helper_uid, helper_gid, agent_gid):
    result = {}
    for name in (SERVICE, SOCKET):
        raw = templates[name + ".in"].decode("ascii")
        for key, value in (("HELPER_UID", helper_uid), ("HELPER_GID", helper_gid), ("AGENT_GID", agent_gid)):
            raw = raw.replace("@" + key + "@", str(value))
        require(re.search(r"@[A-Z_]+@", raw) is None, "unresolved-unit-placeholder")
        result[UNIT_DIR + "/" + name] = raw.encode("ascii")
    return result


def policy(identity, hu, hg, epoch):
    require(valid_hash(epoch) and all(type(n) is int and 0 < n < 2**32 - 1 for n in (hu, hg, identity["agentUid"], identity["agentGid"])) and hu != identity["agentUid"] and hg != identity["agentGid"], "fresh-grant-epoch-or-identity")
    return dict(version="tracebolt.socket-owner-policy.v1", scope=SCOPE, senderBinding=identity["senderBinding"], managerOrigin=identity["managerOrigin"], transportProfile=identity["transportProfile"], collectionProfile="managed-operations-v3", agentUid=identity["agentUid"], agentGid=identity["agentGid"], helperUid=hu, helperGid=hg, epoch=epoch, enabled=True, metadataAcknowledged=True, ptraceRiskAcknowledged=True, httpAcknowledged=identity["transportProfile"] == "http-test")


def deployment(p, hashes):
    return dict(version="tracebolt.socket-owner-deployment.v2", profile="systemd-pid1-local-ptrace-activated-client-v2", clientContract=CLIENT_CONTRACT, policyDigest=digest(canonical(p)), helperSha256=hashes[BINARY], agentSha256=hashes[AGENT_BINARY], helperUnitSha256=hashes[UNIT_DIR + "/" + SERVICE], agentUnitSha256=hashes[UNIT_DIR + "/" + AGENT], socketUnitSha256=hashes[UNIT_DIR + "/" + SOCKET])


def cli(s, e, facts, mode, p=None):
    require(mode in ("identity", "preview", "initialize", "disable"), "fixed-consent-mode")
    raw = e.consent(mode, facts, None if p is None else canonical(p))
    result = strict(s, raw, ("schemaVersion", "mode", "identity", "state", "policy", "taggedPendingDiscarded"))
    i = result["identity"]
    require(result["schemaVersion"] == "tracebolt.socket-owner-setup-result.v1" and result["mode"] == mode and type(i) is dict and set(i) == set(IDENTITY_FIELDS) and i["schemaVersion"] == "tracebolt.socket-owner-setup-identity.v1" and valid_hash(i["senderBinding"]) and type(i["incarnationDigest"]) is str and i["incarnationDigest"].startswith("sha256:") and valid_hash(i["incarnationDigest"][7:]) and type(i["endpointId"]) is str and re.fullmatch(r"agent_[0-9a-f]{32}", i["endpointId"]) and i["managerOrigin"] == facts["origin"] and i["transportProfile"] == facts["profile"] and type(i["agentUid"]) is int and type(i["agentGid"]) is int and i["agentUid"] == facts["uid"] and i["agentGid"] == facts["gid"] and type(result["taggedPendingDiscarded"]) is bool, "offline-consent-result")
    require("deviceId" not in facts or i["endpointId"] == facts["deviceId"], "offline-endpoint-identity")
    require(result["state"] in ("absent", "enabled", "disabled") and ((result["policy"] is None) == (result["state"] == "absent")), "offline-consent-state")
    if result["policy"] is not None:
        q = result["policy"]
        require(type(q) is dict and set(q) == set(POLICY_FIELDS) and q == dict(policy(i, q["helperUid"], q["helperGid"], q["epoch"]), enabled=result["state"] == "enabled"), "offline-policy-binding")
    if mode != "disable":
        require(result["taggedPendingDiscarded"] is False, "offline-unexpected-discard")
    if mode in ("initialize", "disable"):
        require(result["policy"] == p and result["state"] == ("enabled" if mode == "initialize" else "disabled"), "offline-mutation-readback")
    else:
        require(result["taggedPendingDiscarded"] is False, "offline-unexpected-mutation")
    return result


def owned(s, name, active=None):
    return (s["LoadState"] == "loaded" and s["FragmentPath"] == UNIT_DIR + "/" + name and s["DropInPaths"] == "" and s["Transient"] == "no" and s["Names"] == name and s["UnitFileState"] in ("enabled", "disabled", "static") and s["ActiveState"] in ((active,) if active else ("active", "inactive")))


def loaded(e, name, uid, gid, argv, *, active=None, allow_failed=False):
    state = e.status(name)
    require(owned(state, name, active) or (allow_failed and active is None and state["ActiveState"] == "failed" and owned(dict(state, ActiveState="inactive"), name)), "loaded-unit-ownership")
    if name == SOCKET:
        expected = dict(Listen=SOCKET_PATH + " (Stream)", SocketUser="0", SocketGroup=str(gid), SocketMode="0660", DirectoryMode="0755", FileDescriptorName="socket-owner-reader", Accept="no", Triggers=SERVICE, RemoveOnStop="yes")
    else:
        cap = "cap_sys_ptrace" if name == SERVICE else ""
        expected = dict(User=str(uid), Group=str(gid), SupplementaryGroups="", CapabilityBoundingSet=cap, AmbientCapabilities=cap, NoNewPrivileges="yes", KillMode="control-group", Delegate="no", PrivateNetwork="no", PrivateUsers="no", NetworkNamespacePath="", JoinsNamespaceOf="", RootDirectory="", RootImage="", ProtectProc="default", ProcSubset="all", RuntimeDirectory="")
        # PrivatePIDs was added after the first supported systemd releases. An
        # absent property means the manager cannot configure that namespace;
        # a supported property must explicitly report disabled.
        require(state.get("PrivatePIDs", "no") == "no", "loaded-pid-namespace")
        require(re.fullmatch(r"[0-9]+", state["MainPID"]) is not None and (state["ActiveState"] != "inactive" or state["MainPID"] == "0"), "loaded-unit-mainpid")
        require(state["ControlGroup"] in ("", "/system.slice/" + name) and (state["ActiveState"] != "active" or state["ControlGroup"] == "/system.slice/" + name), "fixed-control-group")
        expression = (r"\{ path=" + re.escape(argv[0]) + r" ; argv\[\]=" + re.escape(" ".join(argv)) + r" ; ignore_errors=no ; start_time=[^;{}]* ; stop_time=[^;{}]* ; pid=[0-9]+ ; code=[^;{}]* ; status=[^;{}]* \}")
        require(re.fullmatch(expression, state["ExecStart"]) is not None, "loaded-executable-arguments")
    require(all(state.get(k) == v for k, v in expected.items()), "loaded-unit-security-contract")
    return state


def agent_argv(s, templates, facts):
    raw = s.agent_unit(templates[AGENT + ".in"], facts["manifest"]).decode("ascii")
    starts = [line.removeprefix("ExecStart=") for line in raw.splitlines() if line.startswith("ExecStart=")]
    require(len(starts) == 1, "agent-executable-template")
    return starts[0].split(" ")


def inspect(s, e, templates, expected, *, allow_failed_agent=False):
    facts = s.inspect_agent(e, templates)
    require(s.same_agent(facts, expected), "installed-agent-changed")
    loaded(e, AGENT, facts["uid"], facts["gid"], agent_argv(s, templates, facts), allow_failed=allow_failed_agent)
    for path in ("/opt/tracebolt-agent", UNIT_DIR, CONFIG_DIR, "/run"):
        exact_dir(e, path)
    require(digest(exact_file(e, AGENT_BINARY, 0o555, 0, limit=128 << 20)) == facts["manifest"]["agentHash"] and digest(exact_file(e, UNIT_DIR + "/" + AGENT, 0o644, 0)) == facts["manifest"]["unitHash"], "unchanged-main-artifacts")
    return dict(facts, **{k: expected[k] for k in ("deviceId",) if k in expected})


def stop(e, name):
    require(name in (AGENT, SERVICE), "fixed-drain-unit")
    e.command(["/usr/bin/systemctl", "stop", name])
    state = e.status(name)
    require(owned(state, name, "inactive") and state["MainPID"] == "0", "unit-stop-unconfirmed")
    e.drain(name)
    state = e.status(name)
    require(owned(state, name, "inactive") and state["MainPID"] == "0", "unit-drain-unconfirmed")


def restore(s, e, templates, facts, identity, journal, active):
    current = inspect(s, e, templates, facts)
    require(cli(s, e, current, "identity")["identity"] == identity, "resume-identity-changed")
    journal_unchanged(e, journal)
    e.validate(current)
    if active:
        try:
            e.command(["/usr/bin/systemctl", "start", AGENT])
            loaded(e, AGENT, facts["uid"], facts["gid"], agent_argv(s, templates, facts), active="active")
        except Exception:
            stop(e, AGENT)
            raise


def ownership_proof(s, e, templates, facts, intent_digest):
    """Original immutable authority evidence, independent of current declarations."""
    raw = exact_file(e, COMPLETE, 0o600, 0)
    r = strict(s, raw, ("schemaVersion", "parentIntentSHA256", "identity", "ownerHash", "installation", "helperUid", "helperGid", "policy", "deployment", "policySHA256", "deploymentSHA256", "artifactSHA256"))
    require(raw == canonical(r) and r["schemaVersion"] == "tracebolt.socket-owner-install-complete.v1" and r["parentIntentSHA256"] == intent_digest and r["ownerHash"] == facts["ownerHash"] and r["installation"] == facts["manifest"], "original-install-receipt")
    i = r["identity"]
    require(type(i) is dict and set(i) == set(IDENTITY_FIELDS) and i["schemaVersion"] == "tracebolt.socket-owner-setup-identity.v1" and valid_hash(i["senderBinding"]) and type(i["incarnationDigest"]) is str and i["incarnationDigest"].startswith("sha256:") and valid_hash(i["incarnationDigest"][7:]) and i["managerOrigin"] == facts["origin"] and i["transportProfile"] == facts["profile"] and type(i["agentUid"]) is int and type(i["agentGid"]) is int and (i["agentUid"], i["agentGid"]) == (facts["uid"], facts["gid"]) and type(i["endpointId"]) is str and re.fullmatch(r"agent_[0-9a-f]{32}", i["endpointId"]) and ("deviceId" not in facts or i["endpointId"] == facts["deviceId"]), "original-identity-evidence")
    hu, hg = s.account(*local_accounts(s, e), HELPER, "/nonexistent")
    require((hu, hg) == (r["helperUid"], r["helperGid"]) and hu != facts["uid"] and hg != facts["gid"], "helper-account-changed")
    p = r["policy"]
    require(p == policy(r["identity"], hu, hg, p["epoch"]) and digest(canonical(p)) == r["policySHA256"], "original-policy-evidence")
    hashes = r["artifactSHA256"]
    expected_paths = {BINARY, AGENT_BINARY, UNIT_DIR + "/" + AGENT, UNIT_DIR + "/" + SERVICE, UNIT_DIR + "/" + SOCKET}
    require(type(hashes) is dict and set(hashes) == expected_paths and all(valid_hash(h) for h in hashes.values()), "original-artifact-evidence")
    for path, expected_hash in hashes.items():
        require(digest(exact_file(e, path, 0o555 if path == AGENT_BINARY else 0o755 if path == BINARY else 0o644, 0, limit=128 << 20 if path in (BINARY, AGENT_BINARY) else 16384)) == expected_hash, "installed-artifact-changed")
    require(all(exact_file(e, path, 0o644, 0) == body for path, body in rendered(templates, hu, hg, facts["gid"]).items()), "installed-unit-template-changed")
    d = deployment(p, hashes)
    require(r["deployment"] == d and r["deploymentSHA256"] == digest(canonical(d)), "original-deployment-evidence")
    overrides(e)
    return r


def proof(s, e, templates, facts, intent_digest, *, disabled=False):
    r = ownership_proof(s, e, templates, facts, intent_digest)
    expected_policy = dict(r["policy"], enabled=False) if disabled else r["policy"]
    require(exact_file(e, POLICY, 0o640, r["helperGid"]) == canonical(expected_policy), "original-grant-changed-or-disabled")
    require(exact_file(e, DEPLOYMENT, 0o640, r["helperGid"]) == canonical(r["deployment"]), "original-deployment-changed")
    return r


def runtime_configuration(e, facts, receipt, *, enabled=True, allow_failed_helper=False):
    hu, hg = receipt["helperUid"], receipt["helperGid"]
    loaded(e, SERVICE, hu, hg, [BINARY], allow_failed=allow_failed_helper)
    state = loaded(e, SOCKET, 0, facts["gid"], [], active="active" if enabled else "inactive")
    require(state["UnitFileState"] == ("enabled" if enabled else "disabled"), "socket-enablement")
    if enabled:
        require(e.link(WANTS) == UNIT_DIR + "/" + SOCKET, "socket-enablement-link")
        exact_dir(e, RUNTIME)
        st = e.metadata(SOCKET_PATH)
        require(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660 and st.st_uid == 0 and st.st_gid == facts["gid"] and st.st_nlink == 1, "socket-metadata")
    else:
        require(e.absent(WANTS) and e.absent(SOCKET_PATH), "socket-admission-not-disabled")


def configure(s, e, templates, helper_artifact, expected_facts, parent_intent_sha256, *, verify_only=False):
    """Create once, or compare the immutable original evidence. Never regrant."""
    with e.lock():
        parent_proof(s, e, parent_intent_sha256, complete=verify_only)
        facts = inspect(s, e, templates, expected_facts)
        journal = journal_snapshot(e)
        e.platform()
        if not verify_only:
            fresh_preflight(s, e)
        else:
            require(e.absent(REVOKE_STARTED) and e.absent(REVOKE_COMPLETE) and e.absent(DISABLE_STAGE), "revoked-or-uncertain-grant")
        require(strict(s, e.capabilities(facts)) == CAPABILITIES, "installed-socket-cli-incompatible")
        was_active = facts["active"]
        # There is deliberately no finally restart. Every uncertain failure after
        # this point retains state and keeps the sender stopped for inspection.
        stop(e, AGENT)
        facts = inspect(s, e, templates, expected_facts)
        initial = cli(s, e, facts, "identity")
        if verify_only:
            r = proof(s, e, templates, facts, parent_intent_sha256)
            require(initial["identity"] == r["identity"] and initial["state"] == "enabled" and initial["policy"] == r["policy"], "original-private-grant-changed")
        else:
            require(initial["state"] == "absent", "preexisting-private-socket-consent")
            e.command(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--no-log-init", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", HELPER])
            users, groups = local_accounts(s, e)
            hu, hg = s.account(users, groups, HELPER, "/nonexistent")
            require(hu != facts["uid"] and hg != facts["gid"] and {k: v for k, v in users.items() if k != HELPER} == facts["users"] and {k: v for k, v in groups.items() if k != HELPER} == facts["groups"], "unexpected-account-change")
            bodies = rendered(templates, hu, hg, facts["gid"])
            e.install_helper(helper_artifact)
            helper_raw = exact_file(e, BINARY, 0o755, 0, limit=128 << 20)
            require(len(helper_raw) == helper_artifact["size"] and digest(helper_raw) == helper_artifact["sha256"], "installed-helper-artifact")
            for path, body in bodies.items():
                e.create(path, body, 0, 0o644)
            hashes = {path: digest(body) for path, body in bodies.items()}
            hashes.update({BINARY: digest(helper_raw), AGENT_BINARY: facts["manifest"]["agentHash"], UNIT_DIR + "/" + AGENT: facts["manifest"]["unitHash"]})
            p = policy(initial["identity"], hu, hg, e.nonce())
            d = deployment(p, hashes)
            e.create(POLICY, canonical(p), hg, 0o640)
            e.create(DEPLOYMENT, canonical(d), hg, 0o640)
            initialized = cli(s, e, facts, "initialize", p)
            require(initialized["identity"] == initial["identity"], "initialized-identity-changed")
            e.command(["/usr/bin/systemctl", "daemon-reload"])
            loaded(e, SERVICE, hu, hg, [BINARY], active="inactive")
            loaded(e, SOCKET, 0, facts["gid"], [], active="inactive")
            e.command(["/usr/bin/systemctl", "enable", "--now", SOCKET])
            r = dict(schemaVersion="tracebolt.socket-owner-install-complete.v1", parentIntentSHA256=parent_intent_sha256, identity=initial["identity"], ownerHash=facts["ownerHash"], installation=facts["manifest"], helperUid=hu, helperGid=hg, policy=p, deployment=d, policySHA256=digest(canonical(p)), deploymentSHA256=digest(canonical(d)), artifactSHA256=hashes)
        runtime_configuration(e, facts, r)
        checked = cli(s, e, facts, "preview")
        require(checked["identity"] == initial["identity"] and checked["policy"] == r["policy"] and checked["state"] == "enabled", "private-consent-readback")
        journal_unchanged(e, journal)
        inspect(s, e, templates, expected_facts)
        if not verify_only:
            e.create(COMPLETE, canonical(r), 0, 0o600)
        require(proof(s, e, templates, facts, parent_intent_sha256) == r, "completion-readback")
        restore(s, e, templates, facts, initial["identity"], journal, was_active)
        return dict(configured=True, agentRestarted=was_active, configurationOnly=True, nativeAcceptance="not-established")


def revoke(s, e, templates, expected_facts, parent_intent_sha256):
    """Explicit maintenance only. Partial revoke is retained, never replayed."""
    with e.lock():
        parent_proof(s, e, parent_intent_sha256, complete=True)
        require(e.absent(REVOKE_STARTED) and e.absent(REVOKE_COMPLETE) and e.absent(DISABLE_STAGE), "existing-revoke-evidence")
        facts = inspect(s, e, templates, expected_facts, allow_failed_agent=True)
        journal = journal_snapshot(e)
        r = proof(s, e, templates, facts, parent_intent_sha256)
        runtime_configuration(e, facts, r, allow_failed_helper=True)
        was_active = facts["active"]
        evidence = dict(schemaVersion="tracebolt.socket-owner-revoke.v1", parentIntentSHA256=parent_intent_sha256, installReceiptSHA256=digest(canonical(r)), identity=r["identity"], epoch=r["policy"]["epoch"], originalPolicySHA256=r["policySHA256"], disabledPolicySHA256=digest(canonical(dict(r["policy"], enabled=False))))
        try:
            e.create(REVOKE_STARTED, canonical(dict(evidence, state="started")), 0, 0o600)
        except Exception as cause:
            # Even an uncertain receipt write may have left evidence.
            revoke_safety_shutdown(e, cause)
            raise
        try:
            stop(e, AGENT)
            stopped = cli(s, e, facts, "identity")
            require(stopped["identity"] == r["identity"] and stopped["policy"] == r["policy"] and stopped["state"] == "enabled", "revoke-private-identity-changed")
            e.command(["/usr/bin/systemctl", "disable", "--now", SOCKET])
            state = e.status(SOCKET)
            require(owned(state, SOCKET, "inactive") and state["UnitFileState"] == "disabled" and e.absent(WANTS) and e.absent(SOCKET_PATH), "revoke-socket-admission")
            disabled = dict(r["policy"], enabled=False)
            e.disable_policy(canonical(r["policy"]), canonical(disabled), r["helperGid"])
            require(exact_file(e, POLICY, 0o640, r["helperGid"]) == canonical(disabled), "disabled-root-policy-readback")
            stop(e, SERVICE)
            result = cli(s, e, facts, "disable", disabled)
            require(result["identity"] == r["identity"], "disabled-private-identity-changed")
            check = cli(s, e, facts, "preview")
            require(check["identity"] == r["identity"] and check["state"] == "disabled" and check["policy"] == disabled, "disabled-private-readback")
            proof(s, e, templates, facts, parent_intent_sha256, disabled=True)
            runtime_configuration(e, facts, r, enabled=False)
            journal_unchanged(e, journal)
            e.validate(inspect(s, e, templates, expected_facts))
            completed = canonical(dict(evidence, state="complete", taggedPendingDiscarded=result["taggedPendingDiscarded"]))
            e.create(REVOKE_COMPLETE, completed, 0, 0o600)
            require(exact_file(e, REVOKE_COMPLETE, 0o600, 0) == completed, "revoke-completion-readback")
            restore(s, e, templates, facts, r["identity"], journal, was_active)
            return dict(revoked=True, agentRestarted=was_active, taggedPendingDiscarded=result["taggedPendingDiscarded"], configurationOnly=True, nativeAcceptance="not-established")
        except Exception as cause:
            revoke_safety_shutdown(e, cause)
            raise



def revoke_safety_shutdown(e, cause, *, disable_admission=False):
    # These are independent safety attempts, never authority-write retries.
    # Preserve the original error as the cause of an explicit unconfirmed stop.
    uncertain = False
    if disable_admission:
        try:
            e.command(["/usr/bin/systemctl", "disable", "--now", SOCKET])
            require(e.status(SOCKET)["UnitFileState"] == "disabled" and e.absent(WANTS), "safety-socket-disable-unconfirmed")
        except Exception:
            uncertain = True
    try:
        stop(e, AGENT)
    except Exception:
        uncertain = True
    try:
        e.command(["/usr/bin/systemctl", "stop", SOCKET])
        require(owned(e.status(SOCKET), SOCKET, "inactive") and e.absent(SOCKET_PATH), "safety-socket-stop-unconfirmed")
    except Exception:
        uncertain = True
    try:
        stop(e, SERVICE)
    except Exception:
        uncertain = True
    if uncertain:
        raise Rejected("revoke-incomplete-shutdown-unconfirmed") from cause


def fail_closed(s, e, templates, expected_facts, parent_intent_sha256, *, contain_helper=False):
    """Fail-stop sender; explicit maintenance can contain an independently owned helper."""
    with e.lock():
        require(valid_hash(parent_intent_sha256) and digest(e.read(PARENT_INTENT, 16384, 0o600)) == parent_intent_sha256, "fail-stop-parent-intent")
        facts = inspect(s, e, templates, expected_facts, allow_failed_agent=contain_helper)
        if not contain_helper:
            stop(e, AGENT)
            return
        # A failed sender stop must not skip independent helper containment.
        # The shared safety path below separately reconfirms every stop.
        try:
            stop(e, AGENT)
        except Exception:
            pass
        if contain_helper:
            try:
                parent_proof(s, e, parent_intent_sha256, complete=True)
                r = ownership_proof(s, e, templates, facts, parent_intent_sha256)
                loaded(e, SERVICE, r["helperUid"], r["helperGid"], [BINARY], allow_failed=True)
                loaded(e, SOCKET, 0, facts["gid"], [], allow_failed=True)
            except Exception as cause:
                # Never act on a helper whose original receipt, account,
                # artifact or loaded-unit ownership cannot be proved.
                raise Rejected("revoke-helper-shutdown-unconfirmed") from cause
            # Current policy/deployment bytes are deliberately never read,
            # rewritten or adopted by this independently guarded containment.
            revoke_safety_shutdown(e, Rejected("revoke-incomplete"), disable_admission=True)


def real_effects(s):
    """Production-only fixed adapter. Constructing it performs no host access."""
    class Effects(s.Effects):
        def platform(self):
            u = os.uname()
            m = re.match(r"([0-9]+)\.([0-9]+)", u.release)
            require(u.sysname == "Linux" and u.machine == "x86_64" and m and tuple(map(int, m.groups())) >= (6, 5), "supported-linux-amd64-kernel")
            require(self._pseudo("/proc/1/comm", 64) == b"systemd\n", "systemd-pid1-required")
            mounts = self._pseudo("/proc/self/mountinfo", 1 << 20).decode("ascii").splitlines()
            matching = [line.split(" - ", 1) for line in mounts if len(line.split()) >= 7 and line.split()[4] == "/sys/fs/cgroup"]
            require(len(matching) == 1 and len(matching[0]) == 2 and matching[0][1].split()[0] == "cgroup2", "cgroup-v2-required")
            self._pseudo("/sys/fs/cgroup/cgroup.controllers", 4096)

        def _pseudo(self, path, limit):
            allowed = {"/proc/1/comm", "/proc/self/mountinfo", "/sys/fs/cgroup/cgroup.controllers"}
            require(path in allowed, "fixed-platform-path")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                st = os.fstat(fd)
                require(stat.S_ISREG(st.st_mode) and st.st_uid == 0, "platform-file")
                raw = os.read(fd, limit + 1)
                require(len(raw) <= limit, "platform-read-limit")
                return raw
            finally:
                os.close(fd)

        def status(self, name):
            selected = fields(name)
            raw = self.command(["/usr/bin/systemctl", "show", name, "--property=" + ",".join(selected), "--all", "--no-pager"], timeout=5)
            out = {}
            for line in raw.decode("ascii").splitlines():
                key, sep, value = line.partition("=")
                require(sep and key in selected and key not in out, "systemd-status-members")
                out[key] = value
            optional = {"PrivatePIDs"}
            # systemctl's complex-array printers emit no line for an empty
            # ExecStart/Listen, even with --all. Only an absent, inactive helper
            # may omit its array; loaded units still require every proof field.
            if name in (SERVICE, SOCKET) and out.get("LoadState") == "not-found" and out.get("ActiveState") == "inactive":
                optional.add("Listen" if name == SOCKET else "ExecStart")
            require(set(selected) - set(out) <= optional, "systemd-status-members")
            return out

        def command(self, args, uid=None, gid=None, **kw):
            require(uid is None and gid is None, "fixed-root-command")
            allowed = args == ["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--no-log-init", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", HELPER]
            if args and args[0] == "/usr/bin/systemctl":
                allowed = (args == ["/usr/bin/systemctl", "daemon-reload"] or
                    args in (["/usr/bin/systemctl", "enable", "--now", SOCKET], ["/usr/bin/systemctl", "disable", "--now", SOCKET]) or
                    len(args) == 3 and args[1] in ("start", "stop") and args[2] in (AGENT, SERVICE, SOCKET) and (args[1] != "start" or args[2] == AGENT) or
                    len(args) == 6 and args[1] == "show" and args[2] in (AGENT, SERVICE, SOCKET) and args[3:] == ["--property=" + ",".join(fields(args[2])), "--all", "--no-pager"])
            require(allowed, "fixed-socket-command")
            kw.pop("failure_stage", None)
            return super().command(args, failure_stage="fixed-command-failed", **kw)

        def _agent(self, args, facts, body=None, *, limit=16384, timeout=45, failure_stage="offline-cli-failed"):
            require(failure_stage in ("offline-cli-failed", "offline-capabilities-cli-failed", "offline-identity-cli-failed", "offline-preview-cli-failed", "offline-initialize-cli-failed", "offline-disable-cli-failed", "offline-validate-cli-failed"), "fixed-offline-failure-stage")
            require(s.valid_id(facts["uid"]) and s.valid_id(facts["gid"]), "nonroot-offline-identity")
            self.read(AGENT_BINARY, 128 << 20, 0o555)
            child = subprocess.Popen(args, stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=s.ENV, cwd="/", close_fds=True, start_new_session=True, user=facts["uid"], group=facts["gid"], extra_groups=[])
            out = bytearray()
            try:
                deadline = time.monotonic() + timeout
                with selectors.DefaultSelector() as selector:
                    os.set_blocking(child.stdout.fileno(), False)
                    selector.register(child.stdout, selectors.EVENT_READ)
                    remaining = memoryview(body) if body is not None else None
                    if body is not None:
                        os.set_blocking(child.stdin.fileno(), False)
                        selector.register(child.stdin, selectors.EVENT_WRITE)
                    while selector.get_map():
                        require(time.monotonic() < deadline, "offline-cli-timeout")
                        for key, _ in selector.select(min(.2, max(0, deadline - time.monotonic()))):
                            if key.fileobj is child.stdin:
                                n = os.write(child.stdin.fileno(), remaining)
                                require(n > 0, "offline-policy-write")
                                remaining = remaining[n:]
                                if not remaining:
                                    selector.unregister(child.stdin)
                                    child.stdin.close()
                            else:
                                chunk = os.read(child.stdout.fileno(), 4096)
                                if not chunk:
                                    selector.unregister(child.stdout)
                                out.extend(chunk)
                                require(len(out) <= limit, "offline-cli-output-limit")
                require(child.wait(timeout=max(.01, deadline - time.monotonic())) == 0, failure_stage)
                return bytes(out)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                if child.stdin is not None and not child.stdin.closed:
                    child.stdin.close()
                child.stdout.close()

        def capabilities(self, facts):
            return self._agent([AGENT_BINARY, "--socket-owner-setup-capabilities"], facts, timeout=5, failure_stage="offline-capabilities-cli-failed")

        def consent(self, mode, facts, body=None):
            require(mode in ("identity", "preview", "initialize", "disable") and ((body is None) == (mode in ("identity", "preview"))), "fixed-offline-mode")
            if body is not None:
                require(type(body) is bytes and 0 < len(body) <= 4096, "bounded-offline-policy")
            args = [AGENT_BINARY, "--service-identity", f"{facts['uid']}:{facts['gid']}", "--socket-owner-setup-" + mode]
            if mode == "initialize":
                args += ["--ack-socket-owner-metadata", "--ack-socket-owner-ptrace-risk"]
                if facts["profile"] == "http-test":
                    args += ["--ack-socket-owner-http-plaintext"]
            return self._agent(args, facts, body, failure_stage="offline-" + mode + "-cli-failed")

        def validate(self, facts):
            # --service-identity is a foreground-only flag in lan-agent. The
            # existing offline validator runs under _agent's actual UID/GID drop.
            return self._agent([AGENT_BINARY, "--config", s.CONFIG, "--validate-guided"], facts, failure_stage="offline-validate-cli-failed")

        def config_names(self):
            exact_dir(self, CONFIG_DIR)
            return os.listdir(CONFIG_DIR)

        def nonce(self):
            return secrets.token_hex(32)

        def create(self, path, raw, gid, mode):
            require(path in CREATED and type(raw) is bytes and 0 < len(raw) <= (128 << 20 if path == BINARY else 16384), "fixed-create-file")
            expected = 0o755 if path == BINARY else 0o640 if path in (POLICY, DEPLOYMENT, DISABLE_STAGE) else 0o600 if path in (COMPLETE, REVOKE_STARTED, REVOKE_COMPLETE) else 0o644
            require(mode == expected and type(gid) is int and gid >= 0 and (gid > 0 if mode == 0o640 else gid == 0), "fixed-create-metadata")
            parent = str(Path(path).parent)
            self.protected_dir(parent)
            directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                before = os.fstat(directory)
                require(pin(before) == pin(os.lstat(parent)), "create-parent-changed")
                fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                try:
                    os.fchown(fd, 0, gid)
                    os.fchmod(fd, mode)
                    view = memoryview(raw)
                    while view:
                        n = os.write(fd, view)
                        require(n > 0, "fixed-artifact-write")
                        view = view[n:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(directory)
                require(os.fstat(directory).st_ino == os.lstat(parent).st_ino and os.fstat(directory).st_dev == os.lstat(parent).st_dev, "create-parent-replaced")
            finally:
                os.close(directory)
            require(exact_file(self, path, mode, gid, limit=128 << 20 if path == BINARY else 16384) == raw, "created-artifact-readback")

        def install_helper(self, artifact):
            require(type(artifact) is dict and set(artifact) == {"path", "size", "sha256"} and type(artifact["path"]) is str and re.fullmatch(r"/tmp/tracebolt-release-[a-z0-9_]{8}/tracebolt-v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?-linux-amd64-socket-owner-reader", artifact["path"]) and type(artifact["size"]) is int and 0 < artifact["size"] <= 128 << 20 and valid_hash(artifact["sha256"]), "verified-helper-artifact")
            # The bootstrap's one fixed root-private staging directory is the
            # sole sticky-parent exception. Never accept a caller-selected root.
            root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            tmp = stage = fd = -1
            try:
                rst = os.fstat(root)
                require(rst.st_uid == rst.st_gid == 0 and stat.S_IMODE(rst.st_mode) == 0o755, "helper-source-root")
                tmp = os.open("tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                tst = os.fstat(tmp)
                require(tst.st_uid == tst.st_gid == 0 and stat.S_IMODE(tst.st_mode) == 0o1777, "helper-source-temporary-parent")
                parent = Path(artifact["path"]).parent.name
                stage = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=tmp)
                pst = os.fstat(stage)
                require(pst.st_uid == pst.st_gid == 0 and stat.S_IMODE(pst.st_mode) == 0o700, "helper-source-private-parent")
                name = Path(artifact["path"]).name
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=stage)
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o500 and before.st_size == artifact["size"], "helper-source-metadata")
                raw = bytearray()
                while len(raw) <= artifact["size"]:
                    chunk = os.read(fd, min(65536, artifact["size"] + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                def unchanged():
                    return (pin(before) == pin(os.fstat(fd)) == pin(os.stat(name, dir_fd=stage, follow_symlinks=False)) and pin(pst) == pin(os.stat(parent, dir_fd=tmp, follow_symlinks=False)) and tst.st_dev == os.stat("tmp", dir_fd=root, follow_symlinks=False).st_dev and tst.st_ino == os.stat("tmp", dir_fd=root, follow_symlinks=False).st_ino)
                require(len(raw) == artifact["size"] and digest(raw) == artifact["sha256"] and unchanged(), "helper-source-changed")
                self.create(BINARY, bytes(raw), 0, 0o755)
                require(unchanged(), "helper-source-changed-after-copy")
            finally:
                for opened in (fd, stage, tmp, root):
                    if opened >= 0:
                        os.close(opened)

        def link(self, path):
            require(path == WANTS, "fixed-enable-link")
            self.protected_dir(str(Path(path).parent))
            before = os.lstat(path)
            require(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0, "enable-link-metadata")
            target = os.readlink(path)
            require(pin(before) == pin(os.lstat(path)), "enable-link-changed")
            return target

        def drain(self, name):
            require(name in (AGENT, SERVICE), "fixed-drain-unit")
            # cgroup.events populated includes all descendants. Never follow a
            # ControlGroup value returned by systemd or enumerate arbitrary PIDs.
            root = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                system = os.open("system.slice", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                try:
                    try:
                        unit = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=system)
                    except FileNotFoundError:
                        return
                    try:
                        fd = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=unit)
                        try:
                            raw = os.read(fd, 4097)
                            require(len(raw) <= 4096, "cgroup-event-limit")
                            rows = [line.split() for line in raw.decode("ascii").splitlines()]
                            require(all(len(row) == 2 for row in rows) and len({row[0] for row in rows}) == len(rows) and dict(rows).get("populated") == "0", "fixed-cgroup-not-drained")
                            named = os.stat(name, dir_fd=system, follow_symlinks=False)
                            actual = os.fstat(unit)
                            require(stat.S_ISDIR(named.st_mode) and actual.st_dev == named.st_dev and actual.st_ino == named.st_ino, "fixed-cgroup-changed")
                        finally:
                            os.close(fd)
                    finally:
                        os.close(unit)
                finally:
                    os.close(system)
            finally:
                os.close(root)

        def disable_policy(self, old, new, gid):
            a, b = strict(s, old, POLICY_FIELDS), strict(s, new, POLICY_FIELDS)
            require(a["enabled"] is True and b == dict(a, enabled=False), "fixed-policy-disable")
            before = self.metadata(POLICY)
            require(exact_file(self, POLICY, 0o640, gid) == old and pin(before) == pin(self.metadata(POLICY)), "disable-original-policy")
            self.create(DISABLE_STAGE, new, gid, 0o640)
            staged = self.metadata(DISABLE_STAGE)
            directory = os.open(CONFIG_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                require(pin(before) == pin(os.stat(Path(POLICY).name, dir_fd=directory, follow_symlinks=False)) and pin(staged) == pin(os.stat(Path(DISABLE_STAGE).name, dir_fd=directory, follow_symlinks=False)), "disable-policy-changed")
                os.replace(Path(DISABLE_STAGE).name, Path(POLICY).name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
                require(exact_file(self, POLICY, 0o640, gid) == new and self.metadata(POLICY).st_ino == staged.st_ino and self.absent(DISABLE_STAGE), "disabled-policy-unconfirmed")
            finally:
                os.close(directory)

    return Effects()
