"""Inert recovery evidence and syscall tests. No actual systemd/private reads."""
import copy
import contextlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

import test_amend as amendment

a, s = amendment.a, amendment.s
SPEC = importlib.util.spec_from_file_location("journal_recover", Path(__file__).with_name("recover.py"))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


class Fixture(amendment.Fixture):
    def fail_early(self, broad=True):
        additions = [] if broad else ["cron.service"]
        plan = a.preflight(s, self, additions, self.templates, all_system_services=broad)[1]
        self.approved = a.digest(a.canonical(plan))
        self.failpoint = "pending-activation.readback"
        out = a.apply(s, self, additions, self.templates, self.approved, True,
                      self.manifest["profile"] == "http-test", all_system_services=broad)
        assert out["failureStage"] == "publish-pending-activation", out
        self.failpoint = None
        self.actions.clear()
        return self

    def archive_activation(self, expected, plan_digest):
        archived = r.activation_archive(plan_digest)
        r.require(a.snapshot(self, a.ACTIVATION, 0, 0o644) == expected and self.absent(archived), "archive-changed")
        self.abort_uncertain = True
        self.point("abort-activation.rename")
        self.files[archived] = self.files.pop(a.ACTIVATION)
        self.meta[archived] = self.meta.pop(a.ACTIVATION)
        self.meta[archived].st_ctime_ns += 1
        self.point("abort-activation.directory-fsync")
        self.abort_uncertain = False

    def write_abort_receipt(self, raw):
        self.point("abort-receipt.create")
        path = r.PENDING + "/" + r.RECEIPT_NAME
        r.require(self.absent(path), "receipt-already-exists")
        self.files[path] = raw
        self.setmeta(path, stat.S_IFREG | 0o600, size=len(raw))
        self.point("abort-receipt.directory-fsync")

    def archive_aborted_evidence(self, plan_digest, receipt, evidence_files):
        archived = r.evidence_archive(plan_digest)
        self.evidence_archive_uncertain = True
        self.point("abort-evidence.rename")
        r.require(self.absent(archived), "archive-already-exists")
        for path in list(self.meta):
            if path == r.PENDING or path.startswith(r.PENDING + "/"):
                target = archived + path[len(r.PENDING):]
                self.meta[target] = self.meta.pop(path)
                if path in self.files:
                    self.files[target] = self.files.pop(path)
        self.point("abort-evidence.directory-fsync")
        self.evidence_archive_uncertain = False

    def command(self, args, uid=None, gid=None, **kw):
        if args[0] == s.BINARY and args[6] == "preview":
            r.require(self.absent(a.ACTIVATION) and self.private_generation is None, "legacy-private-floor-present")
        return super().command(args, uid=uid, gid=gid, **kw)

    def verification(self):
        return r.verify(a, s, self, self.templates, self.approved, self.source_hashes())[3]

    def abort(self, expected=None):
        expected = expected or a.digest(a.canonical(self.verification()))
        return r.apply_abort(a, s, self, self.templates, self.approved, expected, self.source_hashes())


class RecoveryTests(unittest.TestCase):
    def test_default_verification_is_read_only_and_keeps_gate_and_evidence(self):
        f = Fixture().fail_early()
        before = copy.deepcopy((f.files, f.meta, f.units, f.floors, f.other_private))
        result = f.verification()
        self.assertTrue(result["allUnitsStopped"])
        self.assertEqual(result["oldUnits"], ["docker.service", "ssh.service"])
        self.assertEqual(before, (f.files, f.meta, f.units, f.floors, f.other_private))
        self.assertEqual(f.actions, [])
        self.assertFalse(any(path.startswith(s.STATE_DIR + "/") for path in f.reads))

    def test_verifier_describes_restarted_agent_and_approved_apply_stops_it_first(self):
        f = Fixture().fail_early()
        f.units[s.AGENT_UNIT]["ActiveState"], f.units[s.AGENT_UNIT]["MainPID"] = "active", "345"
        self.assertFalse(f.verification()["allUnitsStopped"])
        self.assertEqual(f.verification()["stopUnits"], [s.AGENT_UNIT])
        result = f.abort()
        self.assertTrue(result["aborted"], result)
        actions = [item[0] for item in f.actions]
        self.assertLess(actions.index("command.stop." + s.AGENT_UNIT), actions.index("abort-activation.rename"))

    def test_running_journal_units_reject_even_readonly_verification(self):
        for unit in (s.SOCKET, s.SERVICE):
            f = Fixture().fail_early()
            f.units[unit]["ActiveState"] = "active"
            f.units[unit]["MainPID"] = "678" if unit == s.SERVICE else "0"
            if unit == s.SOCKET:
                f.setmeta(s.SOCKET_PATH, stat.S_IFSOCK | 0o660, gid=201)
            with self.assertRaisesRegex(r.Rejected, "journal-units-must-remain-stopped"):
                f.verification()
            self.assertEqual(f.actions, [])

    def test_failed_stop_never_archives_or_claims_agent_stopped(self):
        f = Fixture().fail_early()
        f.units[s.AGENT_UNIT]["ActiveState"], f.units[s.AGENT_UNIT]["MainPID"] = "active", "345"
        f.failpoint = "command.stop." + s.AGENT_UNIT
        result = f.abort()
        self.assertFalse(result["aborted"])
        self.assertEqual(result["restartState"], "stop-state-unverified-retain-evidence")
        self.assertFalse(f.absent(a.ACTIVATION))
        self.assertEqual(f.units[s.AGENT_UNIT]["ActiveState"], "active")

    def test_apply_preserves_original_grant_all_evidence_and_floors(self):
        for broad, profile in ((True, "tls"), (True, "http-test"), (False, "tls")):
            with self.subTest(broad=broad, profile=profile):
                f = Fixture(profile).fail_early(broad)
                old = {path: a.snapshot(f, path, f.meta[path].st_gid, 0o640) for path in a.REPLACEMENTS}
                gate, evidence = f.files[a.ACTIVATION], {path: raw for path, raw in f.files.items() if path.startswith(r.PENDING + "/")}
                floors = f.floors, f.other_private
                result = f.abort()
                self.assertTrue(result["aborted"], result)
                self.assertTrue(result["agentRestarted"] and result["socketRestarted"])
                self.assertFalse(result["grantCommitted"] or result["helperForceStarted"])
                self.assertEqual(f.files[r.activation_archive(f.approved)], gate)
                self.assertTrue(f.absent(a.ACTIVATION))
                archived_evidence = r.evidence_archive(f.approved)
                self.assertEqual(evidence, {r.PENDING + path[len(archived_evidence):]: raw for path, raw in f.files.items()
                                           if path.startswith(archived_evidence + "/") and Path(path).name != r.RECEIPT_NAME})
                self.assertTrue(f.absent(r.PENDING))
                self.assertIn(archived_evidence + "/" + r.RECEIPT_NAME, f.files)
                self.assertFalse(result["amendmentRetryBlocked"])
                self.assertEqual(old, {path: a.snapshot(f, path, f.meta[path].st_gid, 0o640) for path in a.REPLACEMENTS})
                self.assertEqual((f.floors, f.other_private), floors)
                self.assertIsNone(f.private_generation)

    def test_prior_inactive_and_disabled_policy_are_preserved(self):
        f = Fixture(active=False, socket=False, enabled=False, policy_enabled=False).fail_early()
        result = f.abort()
        self.assertTrue(result["aborted"], result)
        self.assertFalse(result["agentRestarted"] or result["socketRestarted"])
        self.assertFalse(a.policy(s, f.files[a.POLICY])["enabled"])

    def test_rejects_new_or_restored_policy_metadata_even_with_same_bytes(self):
        for path in a.REPLACEMENTS:
            f = Fixture().fail_early()
            f.meta[path].st_ctime_ns += 1
            with self.assertRaisesRegex(r.Rejected, "original-installation-or-authority-changed"):
                f.verification()
            self.assertEqual(f.actions, [])

    def test_rejects_pending_evidence_mutation_stage_accept_and_other_transaction(self):
        for alteration in ("accept", "stage", "other-transaction", "backup", "gate", "archive", "owner", "plan", "committed"):
            with self.subTest(alteration=alteration):
                f = Fixture().fail_early()
                if alteration in ("accept", "stage", "other-transaction", "archive"):
                    path = {"accept": r.PENDING + "/nonroot-public-accept.json", "stage": a.ACTIVATION_STAGE,
                            "other-transaction": a.transaction_path(2), "archive": r.activation_archive(f.approved)}[alteration]
                    f.files[path] = b"unexpected"
                    f.setmeta(path, stat.S_IFREG | 0o600, size=len(f.files[path]))
                elif alteration == "backup":
                    path = r.PENDING + "/" + Path(a.POLICY).name
                    f.files[path] += b" "
                    f.meta[path].st_size += 1
                elif alteration in ("gate", "committed"):
                    raw = f.files[a.ACTIVATION].replace(b'"pending"', b'"committed"') if alteration == "committed" else f.files[a.ACTIVATION] + b" "
                    f.files[a.ACTIVATION] = raw
                    f.meta[a.ACTIVATION].st_size = len(raw)
                elif alteration == "owner":
                    f.meta[r.PENDING].st_uid = 200
                else:
                    f.approved = "f" * 64
                with self.assertRaises((r.Rejected, a.Rejected, s.Rejected)):
                    f.verification()
                self.assertEqual(f.actions, [])

    def test_apply_digest_drift_prevents_archive(self):
        f = Fixture().fail_early()
        with self.assertRaisesRegex(r.Rejected, "reviewed-verification-changed"):
            f.abort("f" * 64)
        self.assertFalse(f.absent(a.ACTIVATION))

    def test_private_floor_blocks_restart_after_archive_without_reset(self):
        f = Fixture().fail_early()
        f.private_generation = {"revision": "1"}
        result = f.abort()
        self.assertFalse(result["aborted"])
        self.assertEqual(result["failureStage"], "nonroot-original-preview")
        self.assertEqual(f.private_generation, {"revision": "1"})
        self.assertTrue(f.absent(a.ACTIVATION))
        self.assertFalse(f.absent(r.activation_archive(f.approved)))
        self.assertTrue(all(state["ActiveState"] == "inactive" for state in f.units.values()))

    def test_archive_failure_is_uncertain_stopped_and_never_retried(self):
        for point in ("abort-activation.rename", "abort-activation.directory-fsync"):
            with self.subTest(point=point):
                f = Fixture().fail_early()
                f.failpoint = point
                result = f.abort()
                self.assertFalse(result["aborted"])
                self.assertEqual(result["activationState"], "archive-uncertain-retain-evidence")
                self.assertTrue(all(state["ActiveState"] == "inactive" for state in f.units.values()))
                self.assertEqual(sum(action[0] == "abort-activation.rename" for action in f.actions), 1)

    def test_receipt_or_evidence_archive_failure_never_restarts(self):
        for point in ("abort-receipt.create", "abort-receipt.directory-fsync", "abort-evidence.rename", "abort-evidence.directory-fsync"):
            with self.subTest(point=point):
                f = Fixture().fail_early()
                f.failpoint = point
                result = f.abort()
                self.assertTrue(result["aborted"])
                self.assertTrue(result["amendmentRetryBlocked"])
                self.assertIn("failureStage", result)
                self.assertFalse(result["agentRestarted"] or result["socketRestarted"])
                self.assertTrue(all(state["ActiveState"] == "inactive" for state in f.units.values()))

    def test_restart_failure_keeps_completed_abort_and_reports_partial_activity(self):
        f = Fixture().fail_early()
        f.failpoint = "command.start." + s.AGENT_UNIT
        result = f.abort()
        self.assertTrue(result["aborted"])
        self.assertFalse(result["amendmentRetryBlocked"])
        self.assertTrue(result["socketRestarted"])
        self.assertFalse(result["agentRestarted"])
        self.assertEqual(result["failureStage"], "restore-original-activity")

    def test_completed_abort_allows_separately_approved_fresh_corrected_grant(self):
        f = Fixture().fail_early()
        self.assertTrue(f.abort()["aborted"])
        archived = r.evidence_archive(f.approved)
        preserved = {path: a.snapshot(f, path, 0, 0o600) for path in f.files if path.startswith(archived + "/")}
        gate = a.snapshot(f, r.activation_archive(f.approved), 0, 0o644)
        f.source_hashes = lambda: {"reviewed-corrected-amend.py": "3" * 64, "reviewed-setup.py": "e" * 64}
        f.nonce = lambda: "2" * 64
        plan = a.preflight(s, f, [], f.templates, all_system_services=True)[1]
        next_approval = a.digest(a.canonical(plan))
        self.assertNotEqual(next_approval, f.approved)
        result = a.apply(s, f, [], f.templates, next_approval, True, False, all_system_services=True)
        self.assertTrue(result["committed"], result)
        self.assertEqual(result["policyGeneration"]["generation"], "2" * 64)
        self.assertEqual(result["policyGeneration"]["revision"], "1")
        self.assertEqual(preserved, {path: a.snapshot(f, path, 0, 0o600) for path in preserved})
        self.assertEqual(gate, a.snapshot(f, r.activation_archive(f.approved), 0, 0o644))
        self.assertFalse(f.absent(a.transaction_path(1, True)))

    def test_incomplete_or_corrupt_completed_archive_still_blocks_new_grant(self):
        for change in ("missing-gate", "bad-receipt", "extra-accept", "missing-receipt", "backup-mode", "pending-remnant"):
            with self.subTest(change=change):
                f = Fixture().fail_early()
                self.assertTrue(f.abort()["aborted"])
                archive = r.evidence_archive(f.approved)
                receipt = archive + "/" + r.RECEIPT_NAME
                if change in ("missing-gate", "missing-receipt"):
                    path = r.activation_archive(f.approved) if change == "missing-gate" else receipt
                    f.files.pop(path)
                    f.meta.pop(path)
                elif change == "bad-receipt":
                    f.files[receipt] += b" "
                    f.meta[receipt].st_size += 1
                elif change == "backup-mode":
                    f.meta[archive + "/transaction.json"].st_mode = stat.S_IFREG | 0o644
                else:
                    path = archive + "/nonroot-public-accept.json" if change == "extra-accept" else r.PENDING
                    f.files[path] = b"retained uncertain evidence"
                    f.setmeta(path, stat.S_IFREG | 0o600, size=len(f.files[path]))
                f.actions.clear()
                with self.assertRaises((r.Rejected, a.Rejected, s.Rejected, FileNotFoundError, KeyError)):
                    a.preflight(s, f, [], f.templates, all_system_services=True)
                self.assertEqual(f.actions, [])

    def test_source_loader_hashes_all_original_bytes_before_compile(self):
        with mock.patch.object(r, "_read", return_value=b"changed"), mock.patch("builtins.compile", side_effect=AssertionError("unverified compile")):
            with self.assertRaisesRegex(r.Rejected, "original-reviewed-source-changed"):
                r.load_sources()


class RealArchiveTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture_owner(self):
        # These temporary files belong to the test user. Normalize only UID/GID
        # to the production root identity; retain real device/inode, contents,
        # modes, link counts, timestamps, file descriptors and rename/fsync.
        real_stat, real_fstat, real_chown = os.stat, os.fstat, os.fchown
        uid, gid = os.geteuid(), os.getegid()
        def identity(st):
            values = {name: getattr(st, name) for name in dir(st) if name.startswith("st_")}
            self.assertEqual(values["st_uid"], uid)
            self.assertEqual(values["st_gid"], gid)
            values.update(st_uid=0, st_gid=0)
            return types.SimpleNamespace(**values)
        def chown(fd, owner, group):
            self.assertEqual((owner, group), (0, 0))
            real_chown(fd, uid, gid)
        with mock.patch.object(os, "stat", side_effect=lambda *args, **kw: identity(real_stat(*args, **kw))), \
             mock.patch.object(os, "fstat", side_effect=lambda fd: identity(real_fstat(fd))), \
             mock.patch.object(os, "fchown", side_effect=chown):
            yield

    def test_real_filesystem_preserves_gate_inode_and_archives_all_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            config = Path(root, "config")
            installer = Path(root, "installer")
            config.mkdir(mode=0o700)
            installer.mkdir(mode=0o700)
            pending = installer / Path(r.PENDING).name
            pending.mkdir(mode=0o700)
            roots = {a.CONFIG_DIR: config, a.INSTALLER_DIR: installer, r.PENDING: pending}
            digest = "a" * 64
            archived = installer / Path(r.evidence_archive(digest)).name
            roots[r.evidence_archive(digest)] = archived

            @contextlib.contextmanager
            def directory(path):
                # Only the filesystem root is redirected. All real open/stat,
                # write/fsync and rename operations run inside this temp tree.
                fd = os.open(roots[path], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    yield fd
                finally:
                    os.close(fd)

            gate = config / Path(a.ACTIVATION).name
            gate.write_bytes(b"synthetic pending gate")
            gate.chmod(0o644)
            old = pending / "transaction.json"
            old.write_bytes(b"synthetic transaction evidence")
            old.chmod(0o600)
            with mock.patch.object(a, "_directory", directory), self.fixture_owner():
                e = r.real_effects(a, s, {})
                expected = a.snapshot(e, a.ACTIVATION, 0, 0o644)
                before_evidence = a.snapshot(e, r.PENDING + "/transaction.json", 0, 0o600)
                e.archive_activation(expected, digest)
                self.assertTrue(e.absent(a.ACTIVATION))
                after = a.snapshot(e, r.activation_archive(digest), 0, 0o644)
                self.assertEqual(expected["raw"], after["raw"])
                self.assertEqual(expected["pin"]["ino"], after["pin"]["ino"])
                receipt = b"synthetic completed abort receipt"
                e.write_abort_receipt(receipt)
                e.archive_aborted_evidence(digest, receipt, {"transaction.json": dict(
                    sha256=a.digest(before_evidence["raw"]), metadata=before_evidence["pin"])})
                self.assertTrue(e.absent(r.PENDING))
                self.assertEqual(before_evidence, a.snapshot(e, r.evidence_archive(digest) + "/transaction.json", 0, 0o600))
                self.assertEqual(receipt, a.snapshot(e, r.evidence_archive(digest) + "/" + r.RECEIPT_NAME, 0, 0o600)["raw"])

    def test_real_archive_never_overwrites_existing_destination(self):
        with tempfile.TemporaryDirectory() as root:
            config = Path(root)
            digest = "a" * 64
            source = config / Path(a.ACTIVATION).name
            dest = config / Path(r.activation_archive(digest)).name
            source.write_bytes(b"pending")
            source.chmod(0o644)
            dest.write_bytes(b"retained earlier evidence")
            dest.chmod(0o644)

            @contextlib.contextmanager
            def directory(path):
                self.assertEqual(path, a.CONFIG_DIR)
                fd = os.open(config, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    yield fd
                finally:
                    os.close(fd)

            with mock.patch.object(a, "_directory", directory), self.fixture_owner():
                e = r.real_effects(a, s, {})
                expected = a.snapshot(e, a.ACTIVATION, 0, 0o644)
                with self.assertRaisesRegex(r.Rejected, "abort-activation-changed"):
                    e.archive_activation(expected, digest)
            self.assertEqual(source.read_bytes(), b"pending")
            self.assertEqual(dest.read_bytes(), b"retained earlier evidence")


if __name__ == "__main__":
    unittest.main()
