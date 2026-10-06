"""Inert onboarding fixtures: no real installation, grants, sources or credentials."""
import contextlib
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

w = load("onboarding", Path(__file__).with_name("read_admin.py"))
VERSION = "v0.1.0-inert.1"

def plan(http=False):
    args = SimpleNamespace(action="install", resume=False, bootstrap_sha256="d" * 64,
        manager_origin="http://192.168.1.2:8787" if http else "https://manager.example:8443",
        invitation_id="invite_" + "e" * 32, insecure_http_test=http,
        read_admin_agent_origin="http://192.168.1.2:8788" if http else "https://manager.example:8444")
    assets = {f"tracebolt-{VERSION}-linux-amd64-{role}": {"sha256": (str(i) * 64)}
              for i, role in enumerate(("agent-service", "enroll-agent", "lan-agent", "socket-owner-reader"), 1)}
    assets[f"tracebolt-{VERSION}-source.tar"] = {"sha256": "c" * 64}
    return w.make_plan(args, dict(version=VERSION, sourceCommit="a" * 40, assets=assets), "amd64")

class Fixture:
    def __init__(self, http=False):
        self.plan = plan(http)
        self.files, self.events = {}, []
        self.locked = False
        self.confirmed = False
        self.confirm_result = True
        self.prompts = []
        self.failed = None
        self.installed = False
        self.native_result = 0
        self.facts = dict(manifest=dict(sourceHash="c" * 64, agentHash="3" * 64,
            enrollHash="2" * 64, bootstrapHash="d" * 64), ownerHash="5" * 64,
            configHash="6" * 64, deviceId="agent_" + "7" * 32, origin=self.plan["agentOrigin"],
            uid=200, gid=201, profile="http-test" if http else "tls")
        self.selected = set()
        self.output = []
        self.stopped = False

    def preflight(self, p, resume):
        self.events.append("preflight")
        if resume:
            w.require(w.RECEIPT in self.files, "owned-read-admin-receipt-required")
            w.require(self.files[w.RECEIPT] == w.canonical(w.identity(p, self.facts)), "read-admin-receipt-mismatch")
        else:
            w.require(not self.installed, "existing-installation-use-upgrade-or-recovery")
        if self.failed == "platform":
            raise w.Rejected("socket-owner-linux-amd64-kernel-6.5-required")
        if self.failed == "preflight":
            raise w.Rejected("existing-journal-state-retained")

    def confirm(self, phrase):
        self.prompts.append(phrase)
        self.confirmed = self.confirm_result
        return self.confirm_result

    def install(self):
        assert self.confirmed
        self.events.append("install")
        self.installed = self.native_result == 0
        return self.native_result

    def inspect(self):
        assert self.installed
        return copy.deepcopy(self.facts)

    def ready(self, bound, resume):
        self.events.append("ready")
        if self.failed == "ready":
            raise w.Rejected("manager-upgrade-required")

    @contextlib.contextmanager
    def lock(self):
        assert self.confirmed and not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def read(self, path):
        return self.files.get(path)

    def create(self, path, raw):
        assert self.confirmed and self.locked and path not in self.files
        self.events.append("create:" + path)
        self.files[path] = raw
        if self.failed == path:
            raise w.Rejected("injected-after-write")

    def configure(self, phase, bound, *, verify_only):
        assert not self.locked and self.confirmed
        assert self.files[w.phase_path(phase, "started")] == w.phase_record(bound, phase, "started")
        self.events.append((phase, verify_only))
        if verify_only:
            w.require(phase in self.selected, "previously-completed-scope-changed")
        else:
            self.selected.add(phase)
        if self.failed == phase:
            raise w.Rejected("injected-" + phase + "-uncertainty")

    def fail_socket(self, bound):
        self.stopped = True
        self.events.append("stop-socket-failure")

    def run(self, resume=False):
        return w.run(self.plan, self, self.install, self.confirm, self.output.append, resume=resume)

class Tests(unittest.TestCase):
    def test_one_combined_approval_precedes_install_and_all_scopes(self):
        f = Fixture()
        result = f.run()
        self.assertTrue(result["configurationComplete"])
        self.assertEqual(len(f.prompts), 1)
        self.assertEqual(f.prompts[0], "INSTALL READ ADMIN")
        self.assertIn(f.plan["agentOrigin"], f.output[0])
        self.assertIn(f.plan["bootstrapSHA256"], f.output[0])
        self.assertEqual(f.events[:2], ["preflight", "install"])
        self.assertLess(f.events.index("ready"), f.events.index(("inventory", False)))
        self.assertEqual(f.selected, {"inventory", "journal", "socket"})
        self.assertEqual(result["phases"], dict(inventory="configured_confirmed", journal="configured_confirmed", socket="configured_confirmed"))
        self.assertEqual(len(f.files), 7)
        self.assertFalse(result["collectionPerformed"])
        self.assertEqual(result["nativeAcceptance"], "not-established")
        self.assertIn("socketProcessAttribution", result["limitations"])
        self.assertIn("controlledActions", result["limitations"])

    def test_cancel_has_no_install_or_write(self):
        for answer in (False, None, "yes", 1):
            f = Fixture(); f.confirm_result = answer
            result = f.run()
            self.assertTrue(result["canceled"])
            self.assertEqual(f.events, ["preflight"])
            self.assertEqual(f.files, {})

    def test_http_consent_is_explicit_and_tls_default(self):
        for http in (False, True):
            f = Fixture(http)
            result = f.run()
            self.assertTrue(result["configurationComplete"])
            self.assertEqual(f.prompts[0].endswith(" OVER HTTP"), http)
            self.assertEqual("WARNING:" in f.output[0], http)
            for text in ("credentials", "future system services", "nonroot", "No kernel/whole-system", "six hours"):
                self.assertIn(text, f.output[0])

    def test_incomplete_install_does_not_create_profile_or_grants(self):
        f = Fixture(); f.native_result = 1
        result = f.run()
        self.assertFalse(result["configurationComplete"])
        self.assertEqual(result["failureStage"], "install-or-device-approval-incomplete")
        self.assertEqual(f.files, {})
        self.assertEqual(f.selected, set())

    def test_existing_install_and_pending_journal_never_adopted(self):
        for existing in (True, False):
            f = Fixture(); f.installed = existing
            if not existing: f.failed = "preflight"
            sentinel = b"retain pending journal and original consumed floor"
            f.files["/etc/tracebolt/journal-activation.json"] = sentinel
            result = f.run()
            self.assertFalse(result["configurationComplete"])
            self.assertEqual(f.prompts, [])
            self.assertEqual(f.files, {"/etc/tracebolt/journal-activation.json": sentinel})

    def test_changed_release_or_bootstrap_stops_before_any_profile_write(self):
        for field in ("sourceHash", "agentHash", "enrollHash", "bootstrapHash"):
            f = Fixture(); f.facts["manifest"][field] = "f" * 64
            result = f.run()
            self.assertEqual(result["failureStage"], "installed-release-or-bootstrap-changed")
            self.assertEqual(f.files, {})

    def test_approved_ingress_mismatch_stops_before_scope_grants(self):
        f = Fixture(); f.facts["origin"] = "https://different.example:8444"
        result = f.run()
        self.assertEqual(result["failureStage"], "installed-release-or-bootstrap-changed")
        self.assertEqual(f.files, {})
        self.assertEqual(f.selected, set())

    def test_all_preflight_checks_precede_optional_grants(self):
        f = Fixture(); f.failed = "ready"
        result = f.run()
        self.assertEqual(result["failureStage"], "manager-upgrade-required")
        self.assertEqual(f.selected, set())
        self.assertEqual(set(f.files), {w.RECEIPT})
        f.failed = None
        self.assertTrue(f.run(resume=True)["configurationComplete"])

    def test_each_uncertain_phase_retains_evidence_and_cannot_replay(self):
        for phase in w.PHASES:
            f = Fixture(); f.failed = phase
            result = f.run()
            self.assertFalse(result["configurationComplete"])
            self.assertEqual(result["phases"][phase], "uncertain")
            self.assertIn(w.phase_path(phase, "started"), f.files)
            self.assertNotIn(w.phase_path(phase, "complete"), f.files)
            before = copy.deepcopy(f.files)
            f.failed = None
            result = f.run(resume=True)
            self.assertFalse(result["configurationComplete"])
            self.assertEqual(result["failureStage"], "uncertain-" + phase + "-phase-retained")
            self.assertEqual(f.files, before)
            self.assertEqual(f.events.count((phase, False)), 1)
            self.assertEqual(f.events.count("install"), 1)

    def test_completed_rerun_revalidates_without_regrant_or_reinstall(self):
        f = Fixture(); self.assertTrue(f.run()["configurationComplete"])
        before = copy.deepcopy(f.files)
        result = f.run(resume=True)
        self.assertTrue(result["configurationComplete"])
        self.assertEqual(result["phases"], dict(inventory="verified_existing", journal="verified_existing", socket="verified_existing"))
        self.assertEqual(f.files, before)
        self.assertEqual(f.events.count("install"), 1)
        self.assertEqual(f.events.count(("journal", False)), 1)
        self.assertIn(("journal", True), f.events)

    def test_completed_scope_revocation_is_not_silently_reenabled(self):
        f = Fixture(); f.run(); f.selected.remove("inventory")
        result = f.run(resume=True)
        self.assertFalse(result["configurationComplete"])
        self.assertEqual(result["failureStage"], "previously-completed-scope-changed")
        self.assertNotIn("inventory", f.selected)

    def test_changed_scope_destination_receipt_or_identity_blocks_resume(self):
        for change in ("plan", "identity", "receipt", "start"):
            f = Fixture(); f.run()
            if change == "plan": f.plan["enrollmentOrigin"] = "https://other.example"
            if change == "identity": f.facts["deviceId"] = "agent_" + "8" * 32
            if change == "receipt": f.files[w.RECEIPT] = b"foreign receipt"
            if change == "start": del f.files[w.phase_path("inventory", "started")]
            before = copy.deepcopy(f.files)
            result = f.run(resume=True)
            self.assertFalse(result["configurationComplete"])
            self.assertEqual(f.files, before)

    def test_after_effect_receipt_failure_never_invokes_automatic_retry(self):
        for path in (w.RECEIPT, w.phase_path("inventory", "started"), w.phase_path("inventory", "complete"),
                     w.phase_path("journal", "started"), w.phase_path("journal", "complete"),
                     w.phase_path("socket", "started"), w.phase_path("socket", "complete")):
            f = Fixture(); f.failed = path
            result = f.run()
            self.assertFalse(result["configurationComplete"])
            self.assertIn(path, f.files)
            self.assertEqual(f.events.count("install"), 1)

    def test_resume_requires_owned_receipt(self):
        f = Fixture(); f.installed = True
        self.assertEqual(f.run(resume=True)["failureStage"], "owned-read-admin-receipt-required")
        self.assertEqual(f.prompts, [])

    def test_old_v1_intent_never_authorizes_new_scope(self):
        f = Fixture(); f.run()
        f.files[w.RECEIPT] = f.files[w.RECEIPT].replace(b"read-admin-intent.v2", b"read-admin-intent.v1").replace(b"linux-read-admin.v2", b"linux-read-admin.v1")
        f.prompts.clear(); f.events.clear()
        before = dict(f.files)
        result = f.run(resume=True)
        self.assertEqual(result["failureStage"], "read-admin-receipt-mismatch")
        self.assertEqual(f.events, ["preflight"])
        self.assertEqual(f.prompts, [])
        self.assertEqual(f.files, before)

    def test_platform_rejected_before_install_or_approval(self):
        f = Fixture(); f.failed = "platform"
        self.assertIn("6.5", f.run()["failureStage"])
        self.assertEqual(f.events, ["preflight"])
        self.assertEqual(f.prompts, [])
        self.assertEqual(f.files, {})

    def test_socket_disclosure_is_one_explicit_combined_approval(self):
        f = Fixture(); self.assertTrue(f.run()["configurationComplete"])
        text = f.output[0]
        self.assertEqual(text.count("CAP_SYS_PTRACE"), 1)
        for wording in ("broad process-memory authority", "code policy", "not an OS read-only confidentiality boundary", "no weaker fallback"):
            self.assertIn(wording, text)
        self.assertEqual(len(f.prompts), 1)
        self.assertEqual(f.plan["readProfile"], "tracebolt.linux-read-admin.v2")
        self.assertEqual(f.plan["artifacts"]["socket-owner-reader"], "4" * 64)

    def test_socket_partial_receipt_gap_and_revoked_scope_are_fail_stopped(self):
        for failed in ("socket", w.phase_path("socket", "started"), w.phase_path("socket", "complete")):
            f = Fixture(); f.failed = failed
            self.assertFalse(f.run()["configurationComplete"])
            self.assertTrue(f.stopped)
            self.assertIn(w.phase_path("socket", "started"), f.files)
        f = Fixture(); f.run(); f.selected.remove("socket")
        self.assertFalse(f.run(resume=True)["configurationComplete"])
        self.assertNotIn("socket", f.selected)
        self.assertTrue(f.stopped)
        self.assertEqual(f.events.count(("socket", False)), 1)

    def test_uncertain_socket_evidence_is_stopped_before_network_compatibility(self):
        f = Fixture(); f.failed = "socket"; f.run()
        f.failed = "ready"; f.events.clear(); f.stopped = False
        result = f.run(resume=True)
        self.assertEqual(result["failureStage"], "uncertain-socket-phase-retained")
        self.assertTrue(f.stopped)
        self.assertNotIn("ready", f.events)
        self.assertNotIn(("socket", False), f.events)

    def test_completed_socket_resume_later_failure_is_fail_stopped(self):
        f = Fixture(); f.run(); f.failed = "ready"
        result = f.run(resume=True)
        self.assertEqual(result["failureStage"], "manager-upgrade-required")
        self.assertTrue(f.stopped)
        self.assertEqual(f.events.count(("socket", False)), 1)

    def test_cancel_resume_with_socket_evidence_never_stops_or_replays(self):
        f = Fixture(); f.run(); f.confirm_result = False; f.events.clear()
        self.assertTrue(f.run(resume=True)["canceled"])
        self.assertFalse(f.stopped)
        self.assertEqual(f.events, ["preflight"])

    def test_failed_approved_revoke_stops_and_keeps_evidence(self):
        class Maintenance:
            def __init__(self): self.stopped = False
            def inspect(self): return dict(deviceId="agent_fixture", managerOrigin="https://manager.example")
            def revoke(self, bound): raise w.Rejected("root-policy-corrupt")
            def fail_socket(self, bound): self.stopped = True
        m = Maintenance()
        result = w.run_revoke(m, lambda _: True, lambda _: None)
        self.assertEqual(result["failureStage"], "root-policy-corrupt")
        self.assertFalse(result["revoked"])
        self.assertTrue(m.stopped)
        self.assertNotIn("stopUnconfirmed", result)

    def test_revoke_cannot_claim_helper_shutdown_when_containment_proof_fails(self):
        class Maintenance:
            def inspect(self): return dict(deviceId="agent_fixture", managerOrigin="https://manager.example")
            def revoke(self, bound): raise w.Rejected("root-policy-corrupt")
            def fail_socket(self, bound): raise w.Rejected("helper-shutdown-unconfirmed")
        result = w.run_revoke(Maintenance(), lambda _: True, lambda _: None)
        self.assertEqual(result["failureStage"], "root-policy-corrupt")
        self.assertTrue(result["helperShutdownUnconfirmed"])
        self.assertEqual(result["containmentFailureStage"], "helper-shutdown-unconfirmed")
        self.assertFalse(result["revoked"])

    def test_revoke_is_separate_deliberate_maintenance_approval(self):
        class Maintenance:
            def __init__(self): self.calls = []
            def inspect(self): return dict(deviceId="agent_fixture", managerOrigin="https://manager.example")
            def revoke(self, bound): self.calls.append(bound)
        m = Maintenance(); prompts = []; output = []
        result = w.run_revoke(m, lambda phrase: prompts.append(phrase) or True, output.append)
        self.assertTrue(result["revoked"])
        self.assertEqual(prompts, ["REVOKE SOCKET OWNERS"])
        self.assertEqual(len(m.calls), 1)
        m = Maintenance()
        result = w.run_revoke(m, lambda _: False, output.append)
        self.assertTrue(result["canceled"])
        self.assertEqual(m.calls, [])

if __name__ == "__main__":
    unittest.main()
