#!/usr/bin/env python3
"""Expand an existing local Linux service-journal grant. Default: read-only plan.

Inert on import: setup.py is read, verified and compiled only by main(), after
protected-source checks. Tests inject that module and synthetic Effects.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys
import types

CONFIG_DIR = "/etc/tracebolt"
INSTALLER_DIR = "/var/lib/tracebolt-agent-installer"
ACTIVATION = CONFIG_DIR + "/journal-activation.json"
ACTIVATION_STAGE = CONFIG_DIR + "/.journal-activation.tmp"
POLICY = CONFIG_DIR + "/journal-content-policy.json"
CLIENT_POLICY = CONFIG_DIR + "/journal-client-policy.json"
DEPLOYMENT = CONFIG_DIR + "/journal-helper.json"
CLIENT_DEPLOYMENT = CONFIG_DIR + "/journal-client-helper.json"
REPLACEMENTS = (POLICY, CLIENT_POLICY, DEPLOYMENT, CLIENT_DEPLOYMENT)
STAGES = {p: CONFIG_DIR + "/." + Path(p).name + ".amend.tmp" for p in REPLACEMENTS}
STAGES[ACTIVATION] = ACTIVATION_STAGE
PREFIX = "journal-amendment-"
POLICY_FIELDS = ("scope", "collectionProfile", "senderBinding", "managerOrigin", "transportProfile",
                 "agentUid", "helperUid", "allowedUnits", "maxWindowSeconds", "maxLookbackSeconds",
                 "maxPriority", "enabled", "contentAcknowledged", "plaintextAcknowledged")
DEPLOY_FIELDS = ("helperUid", "helperGid", "journalGid", "agentUid", "agentGid")
MAX_REVISION = 2**64 - 1
V3 = "tracebolt.journal-content-policy.v3"
SCOPE_V3 = "on-demand-system-service-log-content"
ALL_SERVICES = "all-system-services"
EXACT_UNITS = "exact-units"


class Rejected(Exception):
    """Fixed operator-safe failure stage; never includes private command output."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def canonical(v):
    return json.dumps(v, separators=(",", ":"), ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(st):
    return {k: getattr(st, "st_" + k) for k in
            ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")}


def renamed_pin_matches(before, after):
    # Linux rename updates ctime even when the inode and content are unchanged.
    # Permit that one transition only; stable reads still compare complete pins.
    return set(before) == set(after) and all(after[k] == value for k, value in before.items() if k != "ctime_ns")


def revision(value):
    require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None and
            int(value) <= MAX_REVISION, "policy-revision")
    return int(value)


def policy(s, raw):
    require(0 < len(raw) <= 8192, "policy-byte-limit")
    p = s.strict_json(raw)
    v3 = p.get("schemaVersion") == V3
    bound = p.get("schemaVersion") in ("tracebolt.journal-content-policy.v2", V3)
    require(p.get("schemaVersion") in ("tracebolt.journal-content-policy.v1", "tracebolt.journal-content-policy.v2", V3) and
            set(p) == set(("schemaVersion",) + POLICY_FIELDS + (("revision", "generation") if bound else ()) + (("serviceAuthorization",) if v3 else ())), "policy-members")
    out = dict(schemaVersion=p["schemaVersion"])
    if bound:
        revision(p["revision"])
        require(s.valid_digest(p["generation"]), "policy-generation")
        out.update(revision=p["revision"], generation=p["generation"])
    for k in POLICY_FIELDS:
        out[k] = p[k]
        if k == "scope" and v3:
            out["serviceAuthorization"] = p["serviceAuthorization"]
    require(raw in (canonical(out), canonical(out) + b"\n"), "canonical-policy")
    broad = v3 and p["serviceAuthorization"] == ALL_SERVICES
    require((not v3 or p["serviceAuthorization"] in (EXACT_UNITS, ALL_SERVICES)) and
            p["scope"] == (SCOPE_V3 if v3 else s.SCOPE) and p["collectionProfile"] == s.PROFILE and
            s.valid_digest(p["senderBinding"]) and p["transportProfile"] in ("tls", "http-test") and
            s.valid_origin(p["managerOrigin"], p["transportProfile"]) and
            s.valid_id(p["agentUid"]) and s.valid_id(p["helperUid"]) and p["agentUid"] != p["helperUid"] and
            type(p["allowedUnits"]) is list and
            (p["allowedUnits"] == [] if broad else s.selected_units(p["allowedUnits"]) == p["allowedUnits"]) and
            all(type(p[k]) is int for k in ("maxWindowSeconds", "maxLookbackSeconds", "maxPriority")) and
            0 < p["maxWindowSeconds"] <= 3600 and p["maxWindowSeconds"] <= p["maxLookbackSeconds"] <= 86400 and
            0 <= p["maxPriority"] <= 7 and type(p["enabled"]) is bool and
            p["contentAcknowledged"] is True and p["plaintextAcknowledged"] is (p["transportProfile"] == "http-test"), "existing-policy")
    return out


def deployment(s, raw):
    d = s.strict_json(raw)
    v2 = d.get("schemaVersion") == "tracebolt.journal-helper-deployment.v2"
    require(d.get("schemaVersion") in ("tracebolt.journal-helper-deployment.v1", "tracebolt.journal-helper-deployment.v2") and
            set(d) == set(("schemaVersion",) + DEPLOY_FIELDS + (("policyGenerationRequired",) if v2 else ())), "deployment-members")
    out = dict(schemaVersion=d["schemaVersion"], **{k: d[k] for k in DEPLOY_FIELDS})
    if v2:
        require(d["policyGenerationRequired"] is True, "deployment-migration-required")
        out["policyGenerationRequired"] = True
    require(raw == canonical(out) and all(s.valid_id(d[k]) for k in DEPLOY_FIELDS) and
            d["helperUid"] != d["agentUid"] and len({d["helperGid"], d["journalGid"], d["agentGid"]}) == 3,
            "existing-deployment")
    return out


def generation(p):
    if p["schemaVersion"].endswith(".v1"):
        return None
    return dict(revision=p["revision"], generation=p["generation"], policyDigest="sha256:" + digest(canonical(p)))


def snapshot(e, path, gid, mode, limit=16384):
    before = e.metadata(path)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == gid and
            stat.S_IMODE(before.st_mode) == mode and before.st_nlink == 1, "fixed-file-metadata")
    raw = e.read(path, limit, mode)
    require(pin(before) == pin(e.metadata(path)) and before.st_size == len(raw), "fixed-file-changed")
    return dict(raw=raw, pin=pin(before))


def transaction_path(next_revision, committed=False):
    require(type(next_revision) is int and 0 < next_revision <= MAX_REVISION, "transaction-revision")
    return INSTALLER_DIR + "/" + PREFIX + str(next_revision) + (".committed" if committed else ".pending")


def validate_completed_abort(s, e, name, identity, current_policy):
    """Recognize only a fully evidenced abort before the first policy write.

    This is historical proof, never policy authority or permission to recover.
    Partial/foreign archives still block every new amendment.
    """
    match = re.fullmatch(re.escape(PREFIX) + r"1\.aborted-([0-9a-f]{64})", name)
    require(match is not None, "unresolved-amendment-transaction")
    approved = match[1]
    directory = INSTALLER_DIR + "/" + name
    st = e.metadata(directory)
    require(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == st.st_gid == 0,
            "abort-archive-metadata")
    expected_names = {"transaction.json", "activation-absent.json", "nonroot-public-preview.json", "abort-completed.json"} | {
        Path(path).name for path in REPLACEMENTS}
    require(set(e.listdir(directory)) == expected_names, "abort-archive-members")
    receipt_raw = snapshot(e, directory + "/abort-completed.json", 0, 0o600, 8192)["raw"]
    fields = ("schemaVersion", "operation", "planSHA256", "transactionSHA256", "oldPolicySHA256",
              "originalPreviewSHA256", "archivedActivationSHA256", "archivedActivationFile", "senderBinding",
              "deviceId", "certificateHash", "legacyPreviewVerified", "privateGenerationChanged")
    receipt = s.strict_json(receipt_raw, fields)
    gate_path = CONFIG_DIR + "/.journal-activation-1.aborted-" + approved + ".json"
    require(receipt_raw == canonical(receipt) and receipt["schemaVersion"] == "tracebolt.journal-early-abort.v1" and
            receipt["operation"] == "abort-before-policy-write" and receipt["planSHA256"] == approved and
            receipt["archivedActivationFile"] == gate_path and receipt["legacyPreviewVerified"] is True and
            receipt["privateGenerationChanged"] is False and
            all(receipt[k] == identity[k] for k in ("senderBinding", "deviceId", "certificateHash")),
            "abort-receipt-contract")
    transaction_raw = snapshot(e, directory + "/transaction.json", 0, 0o600, 131072)["raw"]
    transaction = s.strict_json(transaction_raw, ("schemaVersion", "planSHA256", "plan", "oldPublicState",
                                                "newPolicyGeneration", "policySHA256", "deploymentSHA256",
                                                "pendingActivationSHA256", "committedActivationSHA256"))
    plan = transaction["plan"]
    require(transaction_raw == canonical(transaction) and digest(transaction_raw) == receipt["transactionSHA256"] and
            transaction["schemaVersion"] == "tracebolt.journal-amendment-evidence.v1" and
            transaction["planSHA256"] == approved and digest(canonical(plan)) == approved and
            plan["nextRevision"] == "1" and plan["activationWasAbsent"] is True and
            plan["oldPolicyGeneration"] is None and plan["pendingDirectory"] == transaction_path(1) and
            plan["archiveDirectory"] == transaction_path(1, True) and
            all(plan[k] == identity[k] for k in ("senderBinding", "deviceId", "certificateHash")),
            "abort-original-transaction")
    require(snapshot(e, directory + "/activation-absent.json", 0, 0o600, 4096)["raw"] == canonical(dict(absent=True)),
            "abort-original-activation")
    backups = {}
    for path in REPLACEMENTS:
        raw = snapshot(e, directory + "/" + Path(path).name, 0, 0o600)["raw"]
        require(digest(raw) == plan["oldFiles"][path]["sha256"], "abort-original-backup")
        backups[path] = raw
    old = policy(s, backups[POLICY])
    old_deployment = deployment(s, backups[DEPLOYMENT])
    require(old["schemaVersion"] == "tracebolt.journal-content-policy.v1" and
            old_deployment["schemaVersion"] == "tracebolt.journal-helper-deployment.v1" and
            backups[POLICY] == backups[CLIENT_POLICY] and backups[DEPLOYMENT] == backups[CLIENT_DEPLOYMENT] and
            digest(canonical(old)) == receipt["oldPolicySHA256"] == plan["oldPolicySHA256"] and
            all(old[k] == current_policy[k] for k in ("senderBinding", "managerOrigin", "transportProfile", "agentUid", "helperUid")),
            "abort-legacy-authority")
    preview_raw = snapshot(e, directory + "/nonroot-public-preview.json", 0, 0o600, 8192)["raw"]
    preview = s.strict_json(preview_raw, ("schemaVersion", "mode", "scope", "senderBinding", "managerOrigin", "transportProfile",
                                         "collectionProfile", "deviceId", "certificateHash", "agentUid", "agentGid",
                                         "policyDigest", "accepted", "existingStatePreserved"))
    require(preview_raw == canonical(transaction["oldPublicState"]) and
            digest(preview_raw) == receipt["originalPreviewSHA256"] and
            preview["schemaVersion"] == "tracebolt.journal-amendment-result.v1" and preview["mode"] == "preview" and
            preview["accepted"] is False and preview["existingStatePreserved"] is True and
            preview["policyDigest"] == "sha256:" + receipt["oldPolicySHA256"] and
            preview["scope"] == old["scope"] and preview["collectionProfile"] == s.PROFILE and
            preview["managerOrigin"] == old["managerOrigin"] and preview["transportProfile"] == old["transportProfile"] and
            preview["agentUid"] == old["agentUid"] and preview["agentGid"] == old_deployment["agentGid"] and
            all(preview[k] == identity[k] for k in ("senderBinding", "deviceId", "certificateHash")),
            "abort-original-preview")
    gate = snapshot(e, gate_path, 0, 0o644, 4096)["raw"]
    g = transaction["newPolicyGeneration"]
    require(type(g) is dict and set(g) == {"revision", "generation", "policyDigest"} and g["revision"] == "1" and
            s.valid_digest(g["generation"]), "abort-abandoned-generation")
    broad = plan["operation"] == "grant-all-system-services"
    require(plan["operation"] in ("add-only", "grant-all-system-services") and
            plan["schemaVersion"] == ("tracebolt.journal-amendment-plan.v2" if broad else "tracebolt.journal-amendment-plan.v1"),
            "abort-original-operation")
    if broad:
        require(plan["addUnits"] == plan["newUnits"] == [] and plan["serviceAuthorization"] == ALL_SERVICES and
                plan["includesFutureServices"] is True, "abort-original-broad-scope")
    else:
        additions = s.selected_units(plan["addUnits"])
        require(not set(additions) & set(old["allowedUnits"]) and
                plan["newUnits"] == s.selected_units(old["allowedUnits"] + additions), "abort-original-exact-scope")
    proposed = amended_policy(old, plan["newUnits"], "1", g["generation"], broad)
    proposed_raw = canonical(proposed)
    policy(s, proposed_raw)
    proposed_deployment = canonical(dict(schemaVersion="tracebolt.journal-helper-deployment.v2",
                                        **{k: old_deployment[k] for k in DEPLOY_FIELDS}, policyGenerationRequired=True))
    require(g == generation(proposed) and transaction["policySHA256"] == digest(proposed_raw) and
            transaction["deploymentSHA256"] == digest(proposed_deployment) and
            transaction["committedActivationSHA256"] == digest(canonical(activation_record(identity, g, "committed"))) and
            gate == canonical(activation_record(identity, g, "pending")) and
            digest(gate) == receipt["archivedActivationSHA256"] == transaction["pendingActivationSHA256"],
            "abort-archived-activation")


def inspect(s, e, templates, *, check_transactions=True, activation_phase="committed"):
    facts = s.inspect_agent(e, templates)
    e.protected_dir(CONFIG_DIR)
    cfg = e.metadata(CONFIG_DIR)
    require(stat.S_IMODE(cfg.st_mode) == 0o755 and cfg.st_gid == 0, "configuration-directory")
    hu, hg = s.account(facts["users"], facts["groups"], s.HELPER, "/nonexistent")
    groups = facts["groups"]
    require("systemd-journal" in groups, "existing-journal-group")
    jg = int(groups["systemd-journal"][2])
    require(s.valid_id(jg) and hu != facts["uid"] and len({hg, facts["gid"], jg}) == 3 and
            sum(int(g[2]) == jg for g in groups.values()) == 1, "helper-identity")
    files = {}
    for path, gid in ((POLICY, hg), (CLIENT_POLICY, facts["gid"]), (DEPLOYMENT, hg), (CLIENT_DEPLOYMENT, facts["gid"])):
        files[path] = snapshot(e, path, gid, 0o640, 8192)
    require(files[POLICY]["raw"] == files[CLIENT_POLICY]["raw"] and
            files[DEPLOYMENT]["raw"] == files[CLIENT_DEPLOYMENT]["raw"], "asymmetric-declaration-copies")
    p, d = policy(s, files[POLICY]["raw"]), deployment(s, files[DEPLOYMENT]["raw"])
    require([d[k] for k in DEPLOY_FIELDS] == [hu, hg, jg, facts["uid"], facts["gid"]] and
            p["agentUid"] == facts["uid"] and p["helperUid"] == hu and
            p["managerOrigin"] == facts["origin"] and p["transportProfile"] == facts["profile"] and
            (p["schemaVersion"] != "tracebolt.journal-content-policy.v1") == d["schemaVersion"].endswith(".v2"), "bound-declarations")
    attempt = snapshot(e, s.ATTEMPT, 0, 0o600)
    a = s.strict_json(attempt["raw"], ("schemaVersion", "planSHA256", "senderBinding", "deviceId", "certificateHash"))
    require(a["schemaVersion"] == "tracebolt.journal-setup-attempt.v1" and s.valid_digest(a["planSHA256"]) and
            a["senderBinding"] == p["senderBinding"] and s.valid_digest(a["certificateHash"]) and
            type(a["deviceId"]) is str and re.fullmatch(r"agent_[0-9a-f]{32}", a["deviceId"]), "setup-provenance")
    files[s.ATTEMPT] = attempt
    activity, enablement = {}, {}
    for name in (s.AGENT_UNIT, s.SOCKET, s.SERVICE):
        state = e.status(name)
        require(s.owned_unit(state, name) and state["ActiveState"] in ("active", "inactive") and
                (name == s.SOCKET or (state["MainPID"] == "0") == (state["ActiveState"] == "inactive")) and
                e.absent(s.UNIT_DIR + "/" + name + ".d"), "owned-fixed-unit")
        activity[name] = state["ActiveState"] == "active"
        enablement[name] = state["UnitFileState"]
    service = templates[s.SERVICE + ".in"].replace(b"@HELPER_UID@", str(hu).encode()).replace(
        b"@HELPER_GID@", str(hg).encode()).replace(b"@JOURNAL_GID@", str(jg).encode())
    sock = templates[s.SOCKET + ".in"].replace(b"@AGENT_GID@", str(facts["gid"]).encode())
    for name, expected in ((s.SERVICE, service), (s.SOCKET, sock)):
        path = s.UNIT_DIR + "/" + name
        files[path] = snapshot(e, path, 0, 0o644)
        require(files[path]["raw"] == expected, "fixed-helper-template")
    require(enablement[s.SERVICE] == "static" and enablement[s.SOCKET] in ("enabled", "disabled"), "helper-enablement")
    link = s.UNIT_DIR + "/sockets.target.wants/" + s.SOCKET
    if enablement[s.SOCKET] == "enabled":
        require(e.link(link) == s.UNIT_DIR + "/" + s.SOCKET, "owned-socket-enablement-link")
    else:
        require(e.absent(link), "unexpected-socket-enablement-link")
    if not e.absent(s.RUNTIME_DIR):
        e.protected_dir(s.RUNTIME_DIR)
        st = e.metadata(s.RUNTIME_DIR)
        require(stat.S_IMODE(st.st_mode) == 0o755 and st.st_gid == 0, "runtime-directory")
    if not e.absent(s.SOCKET_PATH):
        st = e.metadata(s.SOCKET_PATH)
        require(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660 and
                st.st_uid == 0 and st.st_gid == facts["gid"] and st.st_nlink == 1, "socket-metadata")
    require(not activity[s.SOCKET] or not e.absent(s.SOCKET_PATH), "active-socket-missing")
    require(e.absent(ACTIVATION_STAGE), "activation-stage-present")
    activation = None
    if not e.absent(ACTIVATION):
        files[ACTIVATION] = snapshot(e, ACTIVATION, 0, 0o644, 4096)
        activation = s.strict_json(files[ACTIVATION]["raw"], ("schemaVersion", "phase", "senderBinding", "deviceId", "certificateHash", "policyGeneration"))
        expected = activation_record(a, generation(p), activation_phase)
        require(activation == expected and files[ACTIVATION]["raw"] == canonical(expected), "committed-activation-mismatch")
    require((activation is not None) == (generation(p) is not None), "activation-migration-mismatch")
    if check_transactions:
        require(all(e.absent(v) for v in STAGES.values()), "unresolved-amendment-stage")
        for name in e.listdir(INSTALLER_DIR):
            if name.startswith(PREFIX):
                if ".aborted-" in name:
                    validate_completed_abort(s, e, name, a, p)
                    continue
                match = re.fullmatch(re.escape(PREFIX) + r"([1-9][0-9]{0,19})\.committed", name)
                require(match is not None and int(match[1]) <= int(p.get("revision", "0")), "unresolved-amendment-transaction")
                archive = e.metadata(INSTALLER_DIR + "/" + name)
                require(stat.S_ISDIR(archive.st_mode) and stat.S_IMODE(archive.st_mode) == 0o700 and
                        archive.st_uid == archive.st_gid == 0, "archive-metadata")
    facts.update(policy=p, deployment=d, files=files, activity=activity, enablement=enablement,
                 helperUid=hu, helperGid=hg, journalGid=jg, activation=activation, identity=a)
    return facts


def amended_policy(p, units, next_revision, nonce, all_system_services=False):
    # A broader grant is a distinct, explicit v3 profile. Never infer it from a
    # wildcard, missing list, inventory result, or older policy's empty array.
    v3 = all_system_services or p["schemaVersion"] == V3
    out = dict(schemaVersion=V3 if v3 else "tracebolt.journal-content-policy.v2",
               revision=str(next_revision), generation=nonce)
    for key in POLICY_FIELDS:
        out[key] = p[key]
        if key == "scope" and v3:
            out[key] = SCOPE_V3
            out["serviceAuthorization"] = ALL_SERVICES if all_system_services else p["serviceAuthorization"]
    out["allowedUnits"] = units
    return out


def preflight(s, e, additions, templates, *, all_system_services=False):
    require(type(all_system_services) is bool, "explicit-service-profile")
    facts = inspect(s, e, templates)
    p = facts["policy"]
    require(p.get("serviceAuthorization") != ALL_SERVICES, "all-system-services-already-authorized")
    if all_system_services:
        require(additions == [], "profile-and-units-are-exclusive")
        units = []
    else:
        additions = s.selected_units(additions)
        require(not set(additions) & set(p["allowedUnits"]), "addition-already-authorized")
        units = s.selected_units(p["allowedUnits"] + additions)
    old_revision = int(p.get("revision", "0"))
    require(old_revision < MAX_REVISION, "policy-revision-overflow")
    next_revision = old_revision + 1
    prospective = amended_policy(p, units, next_revision, "f" * 64, all_system_services)
    policy(s, canonical(prospective))
    pending, archive = transaction_path(next_revision), transaction_path(next_revision, True)
    require(e.absent(pending) and e.absent(archive), "existing-transaction-target")
    plan = dict(schemaVersion="tracebolt.journal-amendment-plan.v1", operation="add-only", managerOrigin=facts["origin"],
                transportProfile=facts["profile"], senderBinding=p["senderBinding"], deviceId=facts["identity"]["deviceId"],
                certificateHash=facts["identity"]["certificateHash"], agentUid=facts["uid"], agentGid=facts["gid"],
                helperUid=facts["helperUid"], helperGid=facts["helperGid"], journalGid=facts["journalGid"],
                oldUnits=p["allowedUnits"], addUnits=additions, newUnits=units, oldPolicySHA256=digest(canonical(p)),
                oldPolicyGeneration=generation(p), nextRevision=str(next_revision), freshGeneration="32-random-bytes-during-apply",
                preservedPolicy={k: p[k] for k in POLICY_FIELDS if k != "allowedUnits"},
                agentManifest=facts["manifest"], ownerHash=facts["ownerHash"],
                sourceHashes=e.source_hashes(), templateHashes={k: digest(v) for k, v in templates.items()},
                oldFiles={path: dict(sha256=digest(v["raw"]), metadata=v["pin"]) for path, v in sorted(facts["files"].items())},
                activationWasAbsent=facts["activation"] is None, originalActivity=facts["activity"], preservedEnablement=facts["enablement"],
                replaceFiles=list(REPLACEMENTS), activationFile=ACTIVATION, stages=STAGES,
                pendingDirectory=pending, archiveDirectory=archive, evidenceMode="0700 directory; 0600 independent copies",
                backupFiles=[Path(x).name for x in REPLACEMENTS] + ["journal-activation.json-or-absence", "nonroot-public-preview.json"],
                replacementMode="root:original-group 0640", activationMode="root:root 0644",
                stopUnits=[s.AGENT_UNIT, s.SOCKET, s.SERVICE],
                restartUnits=[x for x in (s.SOCKET, s.AGENT_UNIT) if facts["activity"][x]],
                privateStateEffect="nonroot CLI advances separate journal-policy-generation tuple; existing consumed floors preserved",
                generationReport="normal agent cycle sends public identity, revision, generation and policy digest to bound manager after commit",
                warning="Additional service log messages may contain credentials and personal data; masking is best effort, never secret-free.",
                plaintextWarning="HTTP content is observable and the manager can be impersonated." if facts["profile"] == "http-test" else "",
                sourceVerified=False, contentRead=False)
    if all_system_services:
        plan.update(schemaVersion="tracebolt.journal-amendment-plan.v2", operation="grant-all-system-services",
                    serviceAuthorization=ALL_SERVICES, includesFutureServices=True,
                    preservedPolicy={k: p[k] for k in POLICY_FIELDS if k not in ("allowedUnits", "scope")},
                    generationReport="normal agent cycle sends public identity, revision, generation, policy digest, enabled state and authorized service scope to the bound manager after commit")
    return facts, plan


def activation_record(identity, g, phase):
    return dict(schemaVersion="tracebolt.journal-activation.v1", phase=phase,
                senderBinding=identity["senderBinding"], deviceId=identity["deviceId"],
                certificateHash=identity["certificateHash"], policyGeneration=g)


def command(s, e, facts, mode, expected_policy):
    args = [s.BINARY, "--config", s.CONFIG, "--service-identity", f"{facts['uid']}:{facts['gid']}", "--journal-policy-amendment", mode]
    if mode == "accept":
        args.append("--ack-journal-content")
        if facts["profile"] == "http-test":
            args.append("--ack-journal-http-plaintext")
    raw = e.command(args, uid=facts["uid"], gid=facts["gid"], limit=8192, failure_stage="journal-preview-command-failed")
    fields = ("schemaVersion", "mode", "scope", "senderBinding", "managerOrigin", "transportProfile", "collectionProfile",
              "deviceId", "certificateHash", "agentUid", "agentGid", "policyDigest", "accepted", "existingStatePreserved")
    g = generation(expected_policy)
    p = s.strict_json(raw, fields + (("policyGeneration",) if g else ()))
    require(p["schemaVersion"] == "tracebolt.journal-amendment-result.v1" and p["mode"] == mode and
            p["scope"] == expected_policy["scope"] and p["collectionProfile"] == s.PROFILE and p["managerOrigin"] == facts["origin"] and
            p["transportProfile"] == facts["profile"] and type(p["agentUid"]) is int and type(p["agentGid"]) is int and
            p["agentUid"] == facts["uid"] and p["agentGid"] == facts["gid"] and
            all(p[k] == facts["identity"][k] for k in ("senderBinding", "deviceId", "certificateHash")) and
            p["policyDigest"] == "sha256:" + digest(canonical(expected_policy)) and p.get("policyGeneration") == g and
            p["accepted"] is (mode == "accept") and p["existingStatePreserved"] is True, "nonroot-amendment-result")
    return p


def inactive(s, e):
    for name in (s.AGENT_UNIT, s.SOCKET, s.SERVICE):
        state = e.status(name)
        require(s.owned_unit(state, name, "inactive") and (name == s.SOCKET or state["MainPID"] == "0"), "units-not-stopped")


def unchanged(s, e, facts, templates):
    require(s.same_agent(facts, s.inspect_agent(e, templates)), "installed-agent-changed")
    for path, expected in facts["files"].items():
        require(snapshot(e, path, expected["pin"]["gid"], stat.S_IMODE(expected["pin"]["mode"])) == expected, "original-files-changed")
    if facts["activation"] is None:
        require(e.absent(ACTIVATION), "activation-appeared")
    require(all(e.absent(x) for x in STAGES.values()), "stage-appeared")


def apply(s, e, additions, templates, expected_plan, content_ack, plaintext_ack, *, all_system_services=False):
    require(content_ack is True, "content-acknowledgement-required")
    result = None
    try:
        with e.lock():
            result = _apply_locked(s, e, additions, templates, expected_plan, plaintext_ack, all_system_services=all_system_services)
    except Exception:
        if result is None:
            raise
        # Closing/rechecking the lock may fail after the activation already
        # committed. Preserve its established result rather than report false.
        result.setdefault("failureStage", "installer-lock-release")
        result["lockReleaseState"] = "uncertain-retain-evidence"
        return result
    result["lockReleaseState"] = "released"
    return result


def _apply_locked(s, e, additions, templates, expected_plan, plaintext_ack, *, all_system_services=False):
    facts, plan = preflight(s, e, additions, templates, all_system_services=all_system_services)
    require(s.valid_digest(expected_plan) and digest(canonical(plan)) == expected_plan, "reviewed-plan-changed")
    require(plaintext_ack is (facts["profile"] == "http-test"), "transport-specific-acknowledgement")
    result = dict(committed=False, commitState="not-started", retainedEvidence=False, sourceVerified=False,
                  contentRead=False, agentRestarted=False, socketRestarted=False, helperForceStarted=False,
                  originalActivity=facts["activity"], restartState="not-attempted")
    stage, stopped, writing, archive_ok = "stop-agent", False, False, False
    try:
        stopped = True
        for name, label in ((s.AGENT_UNIT, "agent"), (s.SOCKET, "socket"), (s.SERVICE, "helper")):
            stage = "stop-" + label
            e.command(["/usr/bin/systemctl", "stop", name])
        stage = "verify-stopped-units"
        inactive(s, e)
        unchanged(s, e, facts, templates)
        stopped_facts = inspect(s, e, templates)
        require(stopped_facts["enablement"] == facts["enablement"] and stopped_facts["deployment"] == facts["deployment"], "stopped-installation-changed")
        stage = "nonroot-amendment-preview"
        preview = command(s, e, facts, "preview", facts["policy"])
        # The exited preview is not a lease. accept reacquires and rechecks.
        stage = "prepare-new-generation"
        nonce = e.nonce()
        require(s.valid_digest(nonce) and nonce != facts["policy"].get("generation"), "fresh-generation")
        new_policy = amended_policy(facts["policy"], plan["newUnits"], plan["nextRevision"], nonce, all_system_services)
        policy_raw = canonical(new_policy)
        policy(s, policy_raw)
        new_deployment = dict(schemaVersion="tracebolt.journal-helper-deployment.v2", **{k: facts["deployment"][k] for k in DEPLOY_FIELDS}, policyGenerationRequired=True)
        deploy_raw = canonical(new_deployment)
        g = generation(new_policy)
        pending_raw = canonical(activation_record(preview, g, "pending"))
        committed_raw = canonical(activation_record(preview, g, "committed"))
        pending = plan["pendingDirectory"]
        stage = "create-transaction-evidence"
        result["retainedEvidence"] = True
        e.begin(pending)
        evidence = dict(schemaVersion="tracebolt.journal-amendment-evidence.v1", planSHA256=expected_plan, plan=plan,
                        oldPublicState=preview, newPolicyGeneration=g, policySHA256=digest(policy_raw),
                        deploymentSHA256=digest(deploy_raw), pendingActivationSHA256=digest(pending_raw),
                        committedActivationSHA256=digest(committed_raw))
        e.backup(pending, "transaction.json", canonical(evidence))
        for path in REPLACEMENTS:
            stage = "backup-" + Path(path).name
            e.backup(pending, Path(path).name, facts["files"][path]["raw"])
        stage = "backup-activation"
        e.backup(pending, "journal-activation.json" if facts["activation"] else "activation-absent.json",
                 facts["files"][ACTIVATION]["raw"] if facts["activation"] else canonical(dict(absent=True)))
        e.backup(pending, "nonroot-public-preview.json", canonical(preview))
        unchanged(s, e, facts, templates)
        inactive(s, e)
        stage = "publish-pending-activation"
        writing = True
        result["commitState"] = "pending-write-attempted"
        e.replace(ACTIVATION, pending_raw, 0, 0o644, facts["files"].get(ACTIVATION), "pending-activation")
        result["commitState"] = "pending"
        pending_snapshot = snapshot(e, ACTIVATION, 0, 0o644, 4096)
        for path in REPLACEMENTS:
            stage = "replace-" + Path(path).name
            prior = facts["files"][path]
            e.replace(path, policy_raw if path in (POLICY, CLIENT_POLICY) else deploy_raw,
                      prior["pin"]["gid"], 0o640, prior, Path(path).name)
        stage = "nonroot-amendment-accept"
        accepted = command(s, e, facts, "accept", new_policy)
        e.backup(pending, "nonroot-public-accept.json", canonical(accepted))
        stage = "verify-staged-declarations"
        # Verify all public ownership, old identity, unit/account/template metadata,
        # both final pairs and the nonroot accepted DTO before the sole commit.
        staged_facts = inspect(s, e, templates, check_transactions=False, activation_phase="pending")
        require(s.same_agent(facts, staged_facts) and staged_facts["enablement"] == facts["enablement"] and
                staged_facts["policy"] == new_policy and staged_facts["deployment"] == new_deployment, "staged-installation-changed")
        require(e.source_hashes() == plan["sourceHashes"] and s.read_templates(e) == templates, "reviewed-source-changed")
        for path in REPLACEMENTS:
            actual = snapshot(e, path, facts["files"][path]["pin"]["gid"], 0o640)
            require(actual["raw"] == (policy_raw if path in (POLICY, CLIENT_POLICY) else deploy_raw), "staged-declarations-changed")
        for path in facts["files"]:
            if path not in REPLACEMENTS and path != ACTIVATION:
                prior = facts["files"][path]
                require(snapshot(e, path, prior["pin"]["gid"], stat.S_IMODE(prior["pin"]["mode"])) == prior, "fixed-artifact-changed")
        require(snapshot(e, ACTIVATION, 0, 0o644, 4096) == pending_snapshot, "pending-activation-changed")
        require(all(e.absent(x) for x in STAGES.values()), "staging-remnant")
        inactive(s, e)
        stage = "commit-activation"
        result["commitState"] = "pending"
        e.replace(ACTIVATION, committed_raw, 0, 0o644, pending_snapshot, "commit-activation")
        require(snapshot(e, ACTIVATION, 0, 0o644, 4096)["raw"] == committed_raw, "committed-activation-changed")
        result.update(committed=True, commitState="committed", policySHA256=digest(policy_raw), policyGeneration=g)
        stage = "archive-committed-evidence"
        e.archive(pending, plan["archiveDirectory"])
        archive_ok = True
        result["retainedEvidence"] = False
    except Exception as exc:
        if stage == "commit-activation" and getattr(e, "commit_uncertain", True):
            result["commitState"] = "commit-uncertain"
        result["failureStage"] = stage
        result["detailStage"] = str(exc) if isinstance(exc, (Rejected, s.Rejected)) else "local-operation-failed"
    # Archive failure cannot uncommit the public activation. It is separate
    # housekeeping evidence; normal activity may resume after exact recheck.
    if result["committed"] or stopped and not writing:
        try:
            result["restartState"] = "checking-ownership"
            if result["committed"]:
                now = inspect(s, e, templates, check_transactions=archive_ok)
                require(s.same_agent(facts, now) and now["policy"] == new_policy and now["deployment"] == new_deployment and
                        now["enablement"] == facts["enablement"], "restart-ownership-changed")
            else:
                unchanged(s, e, facts, templates)
                now = inspect(s, e, templates, check_transactions=False)
                require(now["enablement"] == facts["enablement"], "restart-enablement-changed")
            for name, flag in ((s.SOCKET, "socketRestarted"), (s.AGENT_UNIT, "agentRestarted")):
                if facts["activity"][name]:
                    result["restartState"] = "start-" + name
                    e.command(["/usr/bin/systemctl", "start", name])
                    require(s.owned_unit(e.status(name), name, "active"), "restart-unit-status")
                    result[flag] = True
            result["restartState"] = "original-agent-socket-activity-restored"
        except Exception:
            result["restartState"] = "restart-blocked-or-failed"
            result["restartFailureStage"] = "owned-activity-restore-failed"
    elif stopped:
        result["restartState"] = "left-stopped-retain-evidence"
    return result


# Root bootstrap and real adapter. No sibling code executes until verified bytes
# have been read through protected, non-symlink ancestors and pinned descriptors.
def _directory_ok(st):
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o6022 == 0, "protected-directory")


@contextlib.contextmanager
def _directory(path):
    require(path.startswith("/") and str(Path(path)) == path and ".." not in Path(path).parts, "absolute-protected-path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = [("/", fd)]
    try:
        _directory_ok(os.fstat(fd))
        prefix = ""
        for name in Path(path).parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            prefix += "/" + name
            opened.append((prefix, child))
            fd = child
            _directory_ok(os.fstat(fd))
        yield fd
        for name, handle in opened:
            a, b = os.fstat(handle), os.lstat(name)
            require((a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode) ==
                    (b.st_dev, b.st_ino, b.st_uid, b.st_gid, b.st_mode), "protected-parent-changed")
    finally:
        for _, handle in reversed(opened):
            os.close(handle)


def _read(path, limit=65536, mode=None):
    with _directory(str(Path(path).parent)) as parent:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and st.st_mode & 0o6022 == 0 and
                    0 <= st.st_size <= limit and (mode is None or stat.S_IMODE(st.st_mode) == mode), "protected-file")
            chunks, count = [], 0
            while count <= limit:
                part = os.read(fd, min(65536, limit + 1 - count))
                if not part:
                    break
                chunks.append(part)
                count += len(part)
            require(count == st.st_size and pin(st) == pin(os.fstat(fd)) ==
                    pin(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)), "protected-file-changed")
            return b"".join(chunks)
        finally:
            os.close(fd)


def load_setup():
    source = os.path.abspath(__file__)
    setup_path = str(Path(source).with_name("setup.py"))
    own, raw = _read(source, 131072), _read(setup_path, 131072)
    module = types.ModuleType("tracebolt_reviewed_journal_setup")
    module.__file__ = setup_path
    exec(compile(raw, setup_path, "exec"), module.__dict__)
    return module, {source: digest(own), setup_path: digest(raw)}


def real_effects(s, sources):
    class Effects(s.Effects):
        def read(self, path, limit=65536, mode=None):
            return _read(path, limit, mode)

        def source_hashes(self):
            require(all(digest(_read(path, 131072)) == h for path, h in sources.items()), "reviewed-source-changed")
            return sources.copy()

        def protected_dir(self, path):
            with _directory(path):
                pass

        def metadata(self, path):
            with _directory(str(Path(path).parent)) as parent:
                return os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)

        def absent(self, path):
            # ENOTDIR, EACCES and all other failures are not absence. Missing
            # nested runtime paths may be absent only if their parent is absent.
            if str(Path(path).parent) == s.RUNTIME_DIR:
                if self.absent(s.RUNTIME_DIR):
                    return True
            if str(Path(path).parent) == s.UNIT_DIR + "/sockets.target.wants":
                if self.absent(str(Path(path).parent)):
                    return True
            try:
                self.metadata(path)
                return False
            except FileNotFoundError:
                return True

        def listdir(self, path):
            require(path == INSTALLER_DIR or re.fullmatch(re.escape(INSTALLER_DIR + "/" + PREFIX) +
                                                         r"1\.aborted-[0-9a-f]{64}", path), "fixed-directory-list")
            with _directory(path) as fd:
                return sorted(os.listdir(fd))

        def link(self, path):
            require(path == s.UNIT_DIR + "/sockets.target.wants/" + s.SOCKET, "fixed-enablement-link")
            with _directory(str(Path(path).parent)) as fd:
                before = os.stat(Path(path).name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1, "enablement-link-metadata")
                target = os.readlink(Path(path).name, dir_fd=fd)
                require(pin(before) == pin(os.stat(Path(path).name, dir_fd=fd, follow_symlinks=False)), "enablement-link-changed")
                return target

        def nonce(self):
            return secrets.token_hex(32)

        def command(self, args, uid=None, gid=None, **kw):
            allowed = False
            if args[0] == "/usr/bin/systemctl" and uid is None and gid is None:
                allowed = (len(args) == 3 and args[1] in ("stop", "start") and args[2] in (s.AGENT_UNIT, s.SOCKET, s.SERVICE) and
                           not (args[1] == "start" and args[2] == s.SERVICE)) or (
                    len(args) == 6 and args[1] == "show" and args[2] in (s.AGENT_UNIT, s.SOCKET, s.SERVICE) and
                    args[3] == "--property=" + ",".join(s.unit_fields(args[2])) and args[4:] == ["--all", "--no-pager"])
            elif args[0] == s.BINARY and s.valid_id(uid) and s.valid_id(gid):
                prefix = [s.BINARY, "--config", s.CONFIG, "--service-identity", f"{uid}:{gid}", "--journal-policy-amendment"]
                allowed = args == prefix + ["preview"] or args == prefix + ["accept", "--ack-journal-content"] or args == prefix + ["accept", "--ack-journal-content", "--ack-journal-http-plaintext"]
            require(allowed, "fixed-amendment-command")
            return super().command(args, uid=uid, gid=gid, **kw)

        @contextlib.contextmanager
        def lock(self):
            import fcntl
            path = INSTALLER_DIR + "/install.lock"
            old = snapshot(self, path, 0, 0o600, 4096)
            with _directory(INSTALLER_DIR) as parent:
                fd = os.open("install.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    require(pin(os.fstat(fd)) == old["pin"], "installer-lock-changed")
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    require(pin(os.stat("install.lock", dir_fd=parent, follow_symlinks=False)) == old["pin"], "installer-lock-changed")
                    yield
                finally:
                    os.close(fd)

        def _transaction(self, path, committed=False):
            m = re.fullmatch(re.escape(INSTALLER_DIR + "/" + PREFIX) + r"([1-9][0-9]{0,19})" + (r"\.committed" if committed else r"\.pending"), path)
            require(m is not None and int(m[1]) <= MAX_REVISION, "fixed-transaction-directory")
            return int(m[1])

        def begin(self, path):
            self._transaction(path)
            with _directory(INSTALLER_DIR) as parent:
                os.mkdir(Path(path).name, 0o700, dir_fd=parent)
                with _directory(path) as fd:
                    os.fchown(fd, 0, 0)
                    os.fchmod(fd, 0o700)
                    os.fsync(fd)
                os.fsync(parent)

        def _step(self, label, fn):
            try:
                return fn()
            except Exception as exc:
                raise Rejected(label) from exc

        def _write_new(self, parent, name, raw, gid, mode, label):
            fd = self._step(label + ".create", lambda: os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent))
            try:
                self._step(label + ".chown", lambda: os.fchown(fd, 0, gid))
                self._step(label + ".chmod", lambda: os.fchmod(fd, mode))
                view = memoryview(raw)
                while view:
                    n = self._step(label + ".write", lambda: os.write(fd, view))
                    require(n > 0, "stage-write")
                    view = view[n:]
                self._step(label + ".file-fsync", lambda: os.fsync(fd))
                st = os.fstat(fd)
                require(st.st_uid == 0 and st.st_gid == gid and stat.S_IMODE(st.st_mode) == mode and st.st_nlink == 1 and
                        st.st_size == len(raw) and pin(st) == pin(os.stat(name, dir_fd=parent, follow_symlinks=False)), "stage-metadata")
                return pin(st)
            finally:
                os.close(fd)

        def backup(self, directory, name, raw):
            self._transaction(directory)
            allowed = {Path(x).name for x in REPLACEMENTS} | {"transaction.json", "journal-activation.json", "activation-absent.json", "nonroot-public-preview.json", "nonroot-public-accept.json"}
            require(name in allowed and len(raw) <= 131072, "fixed-backup-file")
            with _directory(directory) as fd:
                st = os.fstat(fd)
                require(stat.S_IMODE(st.st_mode) == 0o700 and st.st_gid == 0, "transaction-metadata")
                self._write_new(fd, name, raw, 0, 0o600, "backup-" + name)
                self._step("backup-" + name + ".directory-fsync", lambda: os.fsync(fd))
            require(snapshot(self, directory + "/" + name, 0, 0o600, 131072)["raw"] == raw, "backup-verification")

        def replace(self, path, raw, gid, mode, expected, label):
            self.commit_uncertain = False
            require(path in STAGES and len(raw) <= 8192 and (mode, gid == 0) == ((0o644, True) if path == ACTIVATION else (0o640, False)), "fixed-replacement")
            if expected is None:
                require(path == ACTIVATION and self.absent(path), "replacement-expected-absence")
            else:
                require(snapshot(self, path, gid, mode) == expected, "replacement-old-file-changed")
            stage = STAGES[path]
            with _directory(CONFIG_DIR) as fd:
                staged = self._write_new(fd, Path(stage).name, raw, gid, mode, label)
                self._step(label + ".stage-directory-fsync", lambda: os.fsync(fd))
                require(snapshot(self, stage, gid, mode)["raw"] == raw and pin(os.stat(Path(stage).name, dir_fd=fd, follow_symlinks=False)) == staged, "replacement-stage-changed")
                if expected is None:
                    require(self.absent(path), "replacement-target-appeared")
                else:
                    require(snapshot(self, path, gid, mode) == expected, "replacement-old-file-changed")
                self.commit_uncertain = label == "commit-activation"
                self._step(label + ".rename", lambda: os.replace(Path(stage).name, Path(path).name, src_dir_fd=fd, dst_dir_fd=fd))
                # Failure here is commit-uncertain for the final activation.
                self._step(label + ".directory-fsync", lambda: os.fsync(fd))
                published = snapshot(self, path, gid, mode)
                require(published["raw"] == raw and renamed_pin_matches(staged, published["pin"]) and
                        pin(os.stat(Path(path).name, dir_fd=fd, follow_symlinks=False)) == published["pin"], "replacement-readback")

        def archive(self, pending, archived):
            require(self._transaction(pending) == self._transaction(archived, True), "archive-revision")
            with _directory(INSTALLER_DIR) as fd:
                require(self.absent(archived), "archive-already-exists")
                before = self.metadata(pending)
                require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700 and before.st_uid == before.st_gid == 0, "archive-source-metadata")
                os.rename(Path(pending).name, Path(archived).name, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
                require((before.st_dev, before.st_ino) == (self.metadata(archived).st_dev, self.metadata(archived).st_ino), "archive-readback")
    return Effects()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--add-unit", action="append")
    selection.add_argument("--all-system-services", action="store_true",
                           help="Explicitly grant on-demand logs for all supported current and future system services")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--ack-journal-content", action="store_true")
    parser.add_argument("--ack-journal-http-plaintext", action="store_true")
    args = parser.parse_args(argv)
    def interrupt(_signum, _frame):
        raise Rejected("interrupted")
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        require(sys.platform == "linux" and os.geteuid() == 0, "root-linux-local-administration")
        s, sources = load_setup()
        e = real_effects(s, sources)
        templates = s.read_templates(e)
        if args.apply:
            result = apply(s, e, args.add_unit or [], templates, args.expected_plan_sha256,
                           args.ack_journal_content, args.ack_journal_http_plaintext,
                           all_system_services=args.all_system_services)
            print(json.dumps(result, indent=2))
            return 0 if result["committed"] and "failureStage" not in result and "restartFailureStage" not in result else 1
        require(not args.expected_plan_sha256 and not args.ack_journal_content and not args.ack_journal_http_plaintext,
                "plan-does-not-accept-apply-flags")
        _, plan = preflight(s, e, args.add_unit or [], templates, all_system_services=args.all_system_services)
        print(json.dumps(dict(plan=plan, planSHA256=digest(canonical(plan))), indent=2))
        return 0
    except Exception as exc:
        safe = isinstance(exc, Rejected) or "s" in locals() and isinstance(exc, s.Rejected)
        print(json.dumps(dict(committed=False, failureStage=str(exc) if safe else "local-preflight-failed",
                             warning="Retain all evidence. No automatic rollback, adoption, cleanup or identity reset.")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
