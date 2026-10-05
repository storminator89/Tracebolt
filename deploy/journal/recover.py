#!/usr/bin/env python3
"""Inspect one first-migration failure. Default: no service changes or agent CLI.

Explicit apply only archives the verified early pending gate, checks the original
legacy grant as the existing nonroot agent, and restores prior socket/agent
activity. It never retries a migration, copies policy, or changes private state.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import types

SOURCE_REVISION = "18819d936fc1d6e8f213aa45edbdafa7e7cf10a4"
SOURCE_ROOT = "/root/tracebolt-journal-guide-" + SOURCE_REVISION
SOURCE_FILES = {
    "deploy/journal/guide.py": "3a0e4081589b6630e3df95795ab8faf44163819084d7c8c2ad549dd4a9bfe5d5",
    "deploy/journal/amend.py": "458ed9694a850638b967c67b5faeb6715359fb2e20a55fdf752ffd115853eb7a",
    "deploy/journal/setup.py": "abdea35026d4ff56b88bbbdd413f70a4a9f52d01089a05e7ba86336e7ed12b5a",
    "deploy/journal/source-manifest.json": "f46a5a2d34f81b65d373681ff6c86030fac5dbbd1f9408981e241dd23ad12c47",
    "deploy/systemd/tracebolt-agent.service.in": "0bc6374c36f6252e42751f4692464429165b512bcb196486b81ff4785671ea0c",
    "deploy/systemd/tracebolt-journal-reader.service.in": "13859165f9316faf0993db666feb1ef24348e04fb40dbefaa3c36ceabbc11e86",
    "deploy/systemd/tracebolt-journal-reader.socket.in": "d38c782fe7b2e6a0f058b97fe870c9fee8035cc022ca22a7ffa1ce102758867c",
}
PENDING = "/var/lib/tracebolt-agent-installer/journal-amendment-1.pending"
RECEIPT_NAME = "abort-completed.json"


def activation_archive(plan_digest):
    require(type(plan_digest) is str and len(plan_digest) == 64 and
            all(char in "0123456789abcdef" for char in plan_digest), "abort-plan-digest")
    return "/etc/tracebolt/.journal-activation-1.aborted-" + plan_digest + ".json"


def evidence_archive(plan_digest):
    activation_archive(plan_digest)
    return "/var/lib/tracebolt-agent-installer/journal-amendment-1.aborted-" + plan_digest


class Rejected(Exception):
    """Only fixed operator-safe stages escape."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def _pin(st):
    return tuple(getattr(st, "st_" + name) for name in
                 ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"))


@contextlib.contextmanager
def _directory(path):
    require(path.startswith("/") and str(Path(path)) == path and ".." not in Path(path).parts,
            "protected-source-path")
    opened = []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened.append(("/", fd))
        prefix = ""
        for component in ("",) + Path(path).parts[1:]:
            if component:
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                prefix += "/" + component
                opened.append((prefix, fd))
            st = os.fstat(fd)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o6022 == 0,
                    "protected-source-directory")
        yield fd
        for name, handle in opened:
            before, after = os.fstat(handle), os.lstat(name)
            require((before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode) ==
                    (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode),
                    "source-parent-changed")
    finally:
        for _, fd in reversed(opened):
            os.close(fd)


def _read(path):
    with _directory(str(Path(path).parent)) as parent:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                    before.st_mode & 0o6022 == 0 and 0 < before.st_size <= 131072, "protected-source-file")
            raw = bytearray()
            while len(raw) <= 131072:
                part = os.read(fd, min(65536, 131073 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            require(len(raw) == before.st_size and _pin(before) == _pin(os.fstat(fd)) ==
                    _pin(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)), "source-file-changed")
            return bytes(raw)
        finally:
            os.close(fd)


def load_sources():
    # No sibling executes before every fixed original source is hash verified.
    own_path = os.path.abspath(__file__)
    own = _read(own_path)
    sources, contents = {}, {}
    for relative, expected in SOURCE_FILES.items():
        path = SOURCE_ROOT + "/" + relative
        raw = _read(path)
        require(hashlib.sha256(raw).hexdigest() == expected, "original-reviewed-source-changed")
        sources[path], contents[relative] = expected, raw
    a = types.ModuleType("tracebolt_original_journal_amend")
    a.__file__ = SOURCE_ROOT + "/deploy/journal/amend.py"
    exec(compile(contents["deploy/journal/amend.py"], a.__file__, "exec"), a.__dict__)
    s = types.ModuleType("tracebolt_original_journal_setup")
    s.__file__ = SOURCE_ROOT + "/deploy/journal/setup.py"
    exec(compile(contents["deploy/journal/setup.py"], s.__file__, "exec"), s.__dict__)
    original_sources = sources.copy()
    sources[own_path] = hashlib.sha256(own).hexdigest()
    return a, s, real_effects(a, s, sources), original_sources


class OriginalView:
    """Only hide the independently checked pending gate and its exact evidence."""
    def __init__(self, a, e, original_sources):
        self.a, self.e, self.original_sources = a, e, original_sources

    def __getattr__(self, name):
        return getattr(self.e, name)

    def absent(self, path):
        return True if path in (self.a.ACTIVATION, PENDING) else self.e.absent(path)

    def listdir(self, path):
        return [name for name in self.e.listdir(path)
                if path != self.a.INSTALLER_DIR or name != Path(PENDING).name]

    def source_hashes(self):
        self.e.source_hashes()
        return self.original_sources.copy()


def preview_record(a, s, facts):
    return dict(schemaVersion="tracebolt.journal-amendment-result.v1", mode="preview", scope=facts["policy"]["scope"],
                senderBinding=facts["identity"]["senderBinding"], managerOrigin=facts["origin"],
                transportProfile=facts["profile"], collectionProfile=s.PROFILE,
                deviceId=facts["identity"]["deviceId"], certificateHash=facts["identity"]["certificateHash"],
                agentUid=facts["uid"], agentGid=facts["gid"], policyDigest="sha256:" + a.digest(a.canonical(facts["policy"])),
                accepted=False, existingStatePreserved=True)


def verify(a, s, e, templates, expected_plan, original_sources):
    require(s.valid_digest(expected_plan), "approved-plan-digest-required")
    e.protected_dir(PENDING)
    directory = e.metadata(PENDING)
    require(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700 and
            directory.st_uid == directory.st_gid == 0, "pending-evidence-metadata")
    names = {"transaction.json", "activation-absent.json", "nonroot-public-preview.json"} | {
        Path(path).name for path in a.REPLACEMENTS}
    require(set(e.listdir(PENDING)) == names, "unexpected-or-incomplete-pending-evidence")
    evidence_files = {name: a.snapshot(e, PENDING + "/" + name, 0, 0o600, 131072) for name in sorted(names)}
    raw = evidence_files["transaction.json"]["raw"]
    evidence = s.strict_json(raw, ("schemaVersion", "planSHA256", "plan", "oldPublicState", "newPolicyGeneration",
                                   "policySHA256", "deploymentSHA256", "pendingActivationSHA256", "committedActivationSHA256"))
    require(raw == a.canonical(evidence) and evidence["schemaVersion"] == "tracebolt.journal-amendment-evidence.v1" and
            evidence["planSHA256"] == expected_plan and a.digest(a.canonical(evidence["plan"])) == expected_plan,
            "approved-evidence-plan-mismatch")
    plan = evidence["plan"]
    require(plan.get("activationWasAbsent") is True and plan.get("nextRevision") == "1" and
            plan.get("oldPolicyGeneration") is None and plan.get("pendingDirectory") == PENDING and
            plan.get("sourceHashes") == original_sources, "not-first-pending-activation")
    require(evidence_files["activation-absent.json"]["raw"] == a.canonical(dict(absent=True)), "original-activation-was-not-absent")
    require(all(e.absent(path) for path in a.STAGES.values()) and e.absent(activation_archive(expected_plan)) and
            e.absent(evidence_archive(expected_plan)),
            "authority-stage-or-archive-present")
    gate = a.snapshot(e, a.ACTIVATION, 0, 0o644, 4096)
    g = evidence["newPolicyGeneration"]
    require(type(g) is dict and set(g) == {"revision", "generation", "policyDigest"} and
            g["revision"] == "1" and s.valid_digest(g["generation"]), "pending-generation")
    original_activity = plan.get("originalActivity")
    require(type(original_activity) is dict and set(original_activity) == {s.AGENT_UNIT, s.SOCKET, s.SERVICE} and
            all(type(value) is bool for value in original_activity.values()), "original-activity")
    operation = plan.get("operation")
    require(operation in ("add-only", "grant-all-system-services"), "unsupported-original-operation")
    # Preserve the approved mapping's JSON order as part of its exact digest.
    view = OriginalView(a, e, plan["sourceHashes"])
    facts, reconstructed = a.preflight(s, view, plan.get("addUnits"), templates,
                                       all_system_services=operation == "grant-all-system-services")
    require(facts["policy"]["schemaVersion"] == "tracebolt.journal-content-policy.v1" and
            facts["deployment"]["schemaVersion"] == "tracebolt.journal-helper-deployment.v1", "legacy-authority-required")
    reconstructed["originalActivity"] = original_activity
    reconstructed["restartUnits"] = [unit for unit in (s.SOCKET, s.AGENT_UNIT) if original_activity[unit]]
    require(a.digest(a.canonical(reconstructed)) == expected_plan, "original-installation-or-authority-changed")
    require(not facts["activity"][s.SOCKET] and not facts["activity"][s.SERVICE], "journal-units-must-remain-stopped")
    for path in a.REPLACEMENTS:
        require(evidence_files[Path(path).name]["raw"] == facts["files"][path]["raw"], "original-backup-mismatch")
    preview = preview_record(a, s, facts)
    require(evidence["oldPublicState"] == preview and
            evidence_files["nonroot-public-preview.json"]["raw"] == a.canonical(preview), "original-public-preview-mismatch")
    new_policy = a.amended_policy(facts["policy"], plan["newUnits"], "1", g["generation"], operation == "grant-all-system-services")
    a.policy(s, a.canonical(new_policy))
    new_deployment = dict(schemaVersion="tracebolt.journal-helper-deployment.v2",
                          **{key: facts["deployment"][key] for key in a.DEPLOY_FIELDS}, policyGenerationRequired=True)
    expected_gate = a.canonical(a.activation_record(preview, a.generation(new_policy), "pending"))
    require(g == a.generation(new_policy) and evidence["policySHA256"] == a.digest(a.canonical(new_policy)) and
            evidence["deploymentSHA256"] == a.digest(a.canonical(new_deployment)) and gate["raw"] == expected_gate and
            evidence["pendingActivationSHA256"] == a.digest(expected_gate) and
            evidence["committedActivationSHA256"] == a.digest(a.canonical(a.activation_record(preview, g, "committed"))),
            "pending-activation-evidence-mismatch")
    verification = dict(schemaVersion="tracebolt.journal-early-abort-verification.v1", operation="abort-before-policy-write",
                        approvedPlanSHA256=expected_plan, transactionSHA256=a.digest(raw),
                        evidenceFiles={name: dict(sha256=a.digest(value["raw"]), metadata=value["pin"]) for name, value in evidence_files.items()},
                        pendingDirectory=PENDING, activationFile=a.ACTIVATION, archivedActivation=activation_archive(expected_plan),
                        archivedEvidence=evidence_archive(expected_plan), completedReceipt=RECEIPT_NAME,
                        pendingActivationSHA256=a.digest(gate["raw"]), activationMetadata=gate["pin"],
                        managerOrigin=facts["origin"], deviceId=facts["identity"]["deviceId"], oldUnits=facts["policy"]["allowedUnits"],
                        originalActivity=original_activity, currentActivity=facts["activity"],
                        allUnitsStopped=not any(facts["activity"].values()), restartUnits=reconstructed["restartUnits"],
                        stopUnits=[s.AGENT_UNIT] if facts["activity"][s.AGENT_UNIT] else [],
                        sourceHashes=e.source_hashes(), retainedEvidence=True,
                        amendmentRetryRequires="verified completed abort archive and separately approved fresh corrected grant",
                        privateStateEffect="existing nonroot preview only; no accept, reset or floor modification")
    return facts, preview, gate, verification


def real_effects(a, s, sources):
    base = type(a.real_effects(s, sources))

    class Effects(base):
        def listdir(self, path):
            require(path in (a.INSTALLER_DIR, PENDING), "fixed-recovery-directory-list")
            with a._directory(path) as fd:
                return sorted(os.listdir(fd))

        def archive_activation(self, expected, plan_digest):
            self.abort_uncertain = False
            archived = activation_archive(plan_digest)
            require(a.snapshot(self, a.ACTIVATION, 0, 0o644, 4096) == expected and
                    self.absent(archived), "abort-activation-changed")
            with a._directory(a.CONFIG_DIR) as fd:
                require(a.snapshot(self, a.ACTIVATION, 0, 0o644, 4096) == expected and
                        self.absent(archived), "abort-activation-changed")
                self.abort_uncertain = True
                self._step("abort-activation.rename", lambda: os.rename(Path(a.ACTIVATION).name, Path(archived).name,
                                                                        src_dir_fd=fd, dst_dir_fd=fd))
                self._step("abort-activation.directory-fsync", lambda: os.fsync(fd))
                after = a.snapshot(self, archived, 0, 0o644, 4096)
                require(after["raw"] == expected["raw"] and all(after["pin"][key] == value for key, value in expected["pin"].items()
                                                                if key != "ctime_ns") and self.absent(a.ACTIVATION),
                        "abort-activation-readback")
            self.abort_uncertain = False

        def write_abort_receipt(self, raw):
            require(type(raw) is bytes and 0 < len(raw) <= 8192, "fixed-abort-receipt")
            with a._directory(PENDING) as fd:
                st = os.fstat(fd)
                require(stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == st.st_gid == 0, "abort-evidence-metadata")
                self._write_new(fd, RECEIPT_NAME, raw, 0, 0o600, "abort-receipt")
                self._step("abort-receipt.directory-fsync", lambda: os.fsync(fd))
            require(a.snapshot(self, PENDING + "/" + RECEIPT_NAME, 0, 0o600, 8192)["raw"] == raw, "abort-receipt-readback")

        def archive_aborted_evidence(self, plan_digest, receipt, evidence_files):
            archived = evidence_archive(plan_digest)
            self.evidence_archive_uncertain = False
            with a._directory(a.INSTALLER_DIR) as fd:
                require(self.absent(archived), "abort-evidence-archive-exists")
                before = self.metadata(PENDING)
                require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700 and
                        before.st_uid == before.st_gid == 0, "abort-evidence-metadata")
                require(a.snapshot(self, PENDING + "/" + RECEIPT_NAME, 0, 0o600, 8192)["raw"] == receipt,
                        "abort-receipt-changed")
                for name, expected in evidence_files.items():
                    actual = a.snapshot(self, PENDING + "/" + name, 0, 0o600, 131072)
                    require(actual["pin"] == expected["metadata"] and a.digest(actual["raw"]) == expected["sha256"],
                            "abort-evidence-changed")
                self.evidence_archive_uncertain = True
                self._step("abort-evidence.rename", lambda: os.rename(Path(PENDING).name, Path(archived).name,
                                                                      src_dir_fd=fd, dst_dir_fd=fd))
                self._step("abort-evidence.directory-fsync", lambda: os.fsync(fd))
                after = self.metadata(archived)
                require((before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode) ==
                        (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode) and self.absent(PENDING),
                        "abort-evidence-archive-readback")
                require(a.snapshot(self, archived + "/" + RECEIPT_NAME, 0, 0o600, 8192)["raw"] == receipt,
                        "abort-archived-receipt-changed")
                for name, expected in evidence_files.items():
                    actual = a.snapshot(self, archived + "/" + name, 0, 0o600, 131072)
                    require(actual["pin"] == expected["metadata"] and a.digest(actual["raw"]) == expected["sha256"],
                            "abort-archived-evidence-changed")
            self.evidence_archive_uncertain = False

    return Effects()


def apply_abort(a, s, e, templates, expected_plan, expected_verification, original_sources):
    require(s.valid_digest(expected_verification), "reviewed-verification-digest-required")
    result = None
    try:
        with e.lock():
            facts, preview, gate, verification = verify(a, s, e, templates, expected_plan, original_sources)
            require(a.digest(a.canonical(verification)) == expected_verification, "reviewed-verification-changed")
            result = dict(aborted=False, grantCommitted=False, activationState="pending", retainedEvidence=True,
                          amendmentRetryBlocked=True, agentRestarted=False, socketRestarted=False, helperForceStarted=False,
                          contentRead=False, restartState="not-attempted")
            stage = "stop-owned-agent"
            try:
                if verification["stopUnits"]:
                    e.command(["/usr/bin/systemctl", "stop", s.AGENT_UNIT])
                a.inactive(s, e)
                stage = "recheck-stopped-evidence"
                stopped_facts, stopped_preview, stopped_gate, stopped_verification = verify(a, s, e, templates, expected_plan, original_sources)
                stopped_verification["currentActivity"] = verification["currentActivity"]
                stopped_verification["allUnitsStopped"] = verification["allUnitsStopped"]
                stopped_verification["stopUnits"] = verification["stopUnits"]
                require(stopped_verification == verification and stopped_preview == preview and stopped_gate == gate,
                        "recovery-evidence-changed-after-stop")
                require(s.same_agent(facts, stopped_facts), "recovery-agent-changed-after-stop")
                stage = "archive-early-pending-activation"
                e.archive_activation(gate, expected_plan)
                archived_gate = a.snapshot(e, activation_archive(expected_plan), 0, 0o644, 4096)
                result["activationState"] = "archived-original-absence-restored"
                stage = "verify-legacy-authority"
                now = a.inspect(s, e, templates, check_transactions=False)
                require(s.same_agent(facts, now), "recovery-agent-changed")
                require(now["files"] == facts["files"] and now["enablement"] == facts["enablement"], "recovery-authority-changed")
                a.inactive(s, e)
                stage = "nonroot-original-preview"
                require(a.command(s, e, now, "preview", now["policy"]) == preview, "recovery-private-preview-mismatch")
                stage = "verify-before-restore"
                a.unchanged(s, e, facts, templates)
                fresh = a.inspect(s, e, templates, check_transactions=False)
                require(fresh["enablement"] == facts["enablement"] and e.source_hashes() == verification["sourceHashes"],
                        "recovery-installation-changed")
                require(a.snapshot(e, activation_archive(expected_plan), 0, 0o644, 4096) == archived_gate,
                        "archived-gate-changed")
                a.inactive(s, e)
                result["aborted"] = True
                receipt = a.canonical(dict(schemaVersion="tracebolt.journal-early-abort.v1", operation="abort-before-policy-write",
                                           planSHA256=expected_plan, transactionSHA256=verification["transactionSHA256"],
                                           oldPolicySHA256=a.digest(a.canonical(facts["policy"])),
                                           originalPreviewSHA256=a.digest(a.canonical(preview)),
                                           archivedActivationSHA256=a.digest(gate["raw"]), archivedActivationFile=activation_archive(expected_plan),
                                           senderBinding=preview["senderBinding"], deviceId=preview["deviceId"], certificateHash=preview["certificateHash"],
                                           legacyPreviewVerified=True, privateGenerationChanged=False))
                stage = "write-completed-abort-receipt"
                e.write_abort_receipt(receipt)
                stage = "archive-completed-abort-evidence"
                e.archive_aborted_evidence(expected_plan, receipt, verification["evidenceFiles"])
                result.update(amendmentRetryBlocked=False, evidenceArchive=evidence_archive(expected_plan),
                              activationArchive=activation_archive(expected_plan))
                stage = "verify-before-restore"
                a.unchanged(s, e, facts, templates)
                final = a.inspect(s, e, templates, check_transactions=False)
                require(final["enablement"] == facts["enablement"], "recovery-final-enablement-changed")
                require(a.snapshot(e, activation_archive(expected_plan), 0, 0o644, 4096) == archived_gate and
                        e.source_hashes() == verification["sourceHashes"], "recovery-final-evidence-changed")
                a.inactive(s, e)
                stage = "restore-original-activity"
                for unit, flag in ((s.SOCKET, "socketRestarted"), (s.AGENT_UNIT, "agentRestarted")):
                    if verification["originalActivity"][unit]:
                        result["restartState"] = "start-" + unit
                        e.command(["/usr/bin/systemctl", "start", unit])
                        require(s.owned_unit(e.status(unit), unit, "active"), "recovery-restart-status")
                        result[flag] = True
                result["restartState"] = "original-agent-socket-activity-restored"
            except Exception as exc:
                if stage == "archive-early-pending-activation" and getattr(e, "abort_uncertain", True):
                    result["activationState"] = "archive-uncertain-retain-evidence"
                if stage == "archive-completed-abort-evidence" and getattr(e, "evidence_archive_uncertain", True):
                    result["evidenceArchiveState"] = "uncertain-retain-evidence"
                result["failureStage"] = stage
                result["detailStage"] = str(exc) if isinstance(exc, (Rejected, a.Rejected, s.Rejected)) else "local-operation-failed"
                result["restartState"] = ("stop-state-unverified-retain-evidence" if stage == "stop-owned-agent" else
                                          "restore-failed-or-not-attempted" if result["aborted"] else "left-stopped-retain-evidence")
    except Exception:
        if result is None:
            raise
        result.setdefault("failureStage", "installer-lock-release")
        result["lockReleaseState"] = "uncertain-retain-evidence"
        return result
    result["lockReleaseState"] = "released"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-verification-sha256")
    args = parser.parse_args(argv)
    def interrupted(_signum, _frame):
        raise Rejected("interrupted")
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    result = None
    try:
        require(sys.platform == "linux" and os.getuid() == os.geteuid() == 0, "root-linux-local-administration")
        require(args.apply == bool(args.expected_verification_sha256), "apply-requires-reviewed-verification")
        a, s, e, sources = load_sources()
        templates = s.read_templates(e)
        if args.apply:
            result = apply_abort(a, s, e, templates, args.expected_plan_sha256, args.expected_verification_sha256, sources)
        else:
            _, _, _, verification = verify(a, s, e, templates, args.expected_plan_sha256, sources)
            result = dict(verified=True, readOnly=True, verification=verification,
                          verificationSHA256=a.digest(a.canonical(verification)))
        print(json.dumps(result, indent=2))
        return 0 if result.get("verified") or result.get("aborted") and "failureStage" not in result else 1
    except Exception as exc:
        safe = isinstance(exc, Rejected) or "a" in locals() and isinstance(exc, a.Rejected) or "s" in locals() and isinstance(exc, s.Rejected)
        if result is None:
            result = dict(verified=False, failureStage=str(exc) if safe else "recovery-inspection-failed", retainedEvidence=True,
                          warning="Retain all evidence. No automatic retry, cleanup, policy replacement or identity reset.")
        else:
            result["reportingFailure"] = "result-output-failed"
        print(json.dumps(result), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
