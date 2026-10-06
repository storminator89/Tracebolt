"""Compose the real read-admin adapter with inert existing scope/setup fixtures."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

w = load("read_admin_existing_adapters", Path(__file__).with_name("read_admin.py"))
f = load("existing_inventory_fixtures", ROOT / "deploy/inventory/test_guide.py")
a = load("existing_amendment", ROOT / "deploy/journal/amend.py")
j = load("existing_journal_guide", ROOT / "deploy/journal/guide.py")
s, i = f.s, f.g

class Combined(f.Fixture):
    def __init__(self, transport="tls"):
        super().__init__(transport)
        for key in tuple(self.files):
            if key.startswith("/etc/tracebolt/"):
                del self.files[key]
        self.confirmed = True

    def command(self, args, uid=None, gid=None, **kw):
        if "--journal-content-consent" in args or args[0] == "/usr/sbin/useradd" or \
                args[:2] in (["/usr/bin/systemctl", "daemon-reload"], ["/usr/bin/systemctl", "enable"]):
            return f.f.Fixture.command(self, args, uid=uid, gid=gid, **kw)
        return super().command(args, uid=uid, gid=gid, **kw)

class Tests(unittest.TestCase):
    def build(self, transport="tls"):
        x = Combined(transport)
        p = dict(artifacts={"source": x.manifest["sourceHash"], "lan-agent": x.manifest["agentHash"],
                           "enroll-agent": x.manifest["enrollHash"]}, bootstrapSHA256=x.manifest["bootstrapHash"],
                 transportProfile=transport, agentOrigin=x.config["managerOrigin"])
        with mock.patch.object(i, "real_effects", return_value=x), \
             mock.patch.object(a, "real_effects", return_value=x), mock.patch.object(s, "Effects", return_value=x):
            socket_setup = SimpleNamespace(real_effects=lambda _: x, Rejected=w.Rejected)
            adapter = w.real_adapter(s, i, a, j, socket_setup, x.templates, p, dict(path="/inert/helper", size=1, sha256="f" * 64))
        bound = w.identity(p, adapter.inspect())
        return x, adapter, bound

    def test_real_inventory_composition_enables_all_three_scopes_under_prior_approval(self):
        x, adapter, bound = self.build()
        adapter.configure("inventory", bound, verify_only=False)
        self.assertTrue(all(x.enabled.values()))
        self.assertEqual(x.prompts, [])
        self.assertLess(x.events.index("identity:preview"), x.events.index("overview:enable"))
        self.assertEqual(x.units[s.AGENT_UNIT]["ActiveState"], "active")
        before = x.enabled.copy()
        adapter.configure("inventory", bound, verify_only=True)
        self.assertEqual(before, x.enabled)
        self.assertEqual(sum(event.endswith(":enable") for event in x.events), 3)

    def test_real_inventory_composition_refuses_changed_identity_and_regrant(self):
        x, adapter, bound = self.build()
        bad = dict(bound, deviceId="agent_" + "f" * 32)
        with self.assertRaisesRegex(w.Rejected, "approved-installation-changed"):
            adapter.configure("inventory", bad, verify_only=False)
        self.assertNotIn("stop", x.events)
        adapter.configure("inventory", bound, verify_only=False)
        x.enabled["apt"] = False
        x.shapes["apt"]["consentPresent"] = False
        with self.assertRaisesRegex(w.Rejected, "previously-completed-scope-changed"):
            adapter.configure("inventory", bound, verify_only=True)
        self.assertFalse(x.enabled["apt"])

    def test_real_fresh_journal_setup_is_called_with_explicit_broad_grant(self):
        for transport in ("tls", "http-test"):
            x, adapter, bound = self.build(transport)
            readback = []
            # Existing strict amendment/private-floor readback has its own
            # cross-component test in deploy/journal/test_setup.py. This fixture
            # isolates composition, to avoid a second emulation of that ledger.
            adapter.verify_journal = readback.append
            adapter.configure("journal", bound, verify_only=False)
            policy = json.loads(x.files[s.POLICY])
            self.assertEqual(policy["serviceAuthorization"], "all-system-services")
            self.assertEqual(policy["schemaVersion"], "tracebolt.journal-content-policy.v3")
            self.assertEqual(policy["plaintextAcknowledged"], transport == "http-test")
            self.assertEqual(readback, [bound])
            self.assertEqual(x.files[s.POLICY], x.files[s.CLIENT_POLICY])
            self.assertEqual(x.units[s.AGENT_UNIT]["ActiveState"], "active")
            self.assertEqual(x.prompts, [])

    def test_exact_socket_manager_capability_uses_bound_bootstrap_origin_and_ca(self):
        for transport in ("tls", "http-test"):
            x, adapter, bound = self.build(transport)
            facts = adapter.inspect()
            bootstrap = json.loads(x.files[s.BOOTSTRAP])
            bootstrap.update(enrollmentOrigin="https://manager.example:8443" if transport == "tls" else "http://192.168.10.2:8787",
                             serverCaPem="PUBLIC TEST CA" if transport == "tls" else "")
            x.files[s.BOOTSTRAP] = w.canonical(bootstrap)
            facts["manifest"]["bootstrapHash"] = w.digest(x.files[s.BOOTSTRAP])
            expected = dict(schemaVersion="tracebolt.system-manager-capabilities.v1", agentOrigin=facts["origin"],
                systemFrame="tracebolt.agent-system-inventory.v4", socketOwnerSource="tracebolt.socket-owner-source.v1",
                socketOwnerScope="systemd-pid1-local-tcp-udp-socket-owners")
            fetch = mock.Mock(return_value=w.canonical(expected))
            result = w.socket_manager_compatibility(s, x, j, facts, fetch)
            fetch.assert_called_once_with(bootstrap["enrollmentOrigin"] + "/v4/system/capabilities", 2048,
                ca_pem=None if transport == "http-test" else bootstrap["serverCaPem"], plaintext=transport == "http-test")
            self.assertEqual(result["managerAuthenticity"], transport == "tls")
            for change in ({}, dict(expected, systemFrame="tracebolt.agent-system-inventory.v3"),
                           dict(expected, agentOrigin="https://other.example"), dict(expected, extra=True)):
                with self.assertRaisesRegex(w.Rejected, "socket-manager-upgrade-required"):
                    w.socket_manager_compatibility(s, x, j, facts, lambda *a, **k: w.canonical(change))
            with self.assertRaisesRegex(w.Rejected, "socket-manager-capability-unavailable"):
                w.socket_manager_compatibility(s, x, j, facts, mock.Mock(side_effect=OSError("inert unavailable")))

    def test_real_socket_composition_passes_exact_intent_and_verified_asset(self):
        x, _, _ = self.build()
        p = dict(artifacts={"source": x.manifest["sourceHash"], "lan-agent": x.manifest["agentHash"],
                           "enroll-agent": x.manifest["enrollHash"]}, bootstrapSHA256=x.manifest["bootstrapHash"],
                 transportProfile="tls", agentOrigin=x.config["managerOrigin"])
        helper = dict(path="/inert/staged-helper", size=7, sha256="f" * 64)
        socket_setup = SimpleNamespace(real_effects=lambda _: x, Rejected=w.Rejected,
            configure=mock.Mock(return_value=dict(configured=True, configurationOnly=True)), fail_closed=mock.Mock())
        with mock.patch.object(i, "real_effects", return_value=x), mock.patch.object(a, "real_effects", return_value=x), mock.patch.object(s, "Effects", return_value=x):
            adapter = w.real_adapter(s, i, a, j, socket_setup, x.templates, p, helper)
        facts = adapter.inspect(); bound = w.identity(p, facts)
        for verify_only in (False, True):
            adapter.configure("socket", bound, verify_only=verify_only)
            socket_setup.configure.assert_called_with(s, x, x.templates, helper, facts, w.digest(w.canonical(bound)), verify_only=verify_only)
        adapter.fail_socket(bound)
        socket_setup.fail_closed.assert_called_once_with(s, x, x.templates, facts, w.digest(w.canonical(bound)))
        self.assertEqual(x.prompts, [])

    def test_real_preflight_rejects_retained_installer_and_journal_before_socket_effects(self):
        x, _, _ = self.build()
        p = dict(artifacts={"source": x.manifest["sourceHash"], "lan-agent": x.manifest["agentHash"],
                           "enroll-agent": x.manifest["enrollHash"]}, bootstrapSHA256=x.manifest["bootstrapHash"],
                 transportProfile="tls", agentOrigin=x.config["managerOrigin"])
        socket_setup = SimpleNamespace(real_effects=lambda _: x, Rejected=w.Rejected, fresh_preflight=mock.Mock())
        with mock.patch.object(i, "real_effects", return_value=x), mock.patch.object(a, "real_effects", return_value=x), mock.patch.object(s, "Effects", return_value=x):
            adapter = w.real_adapter(s, i, a, j, socket_setup, x.templates, p, {})
        with self.assertRaisesRegex(w.Rejected, "existing-installation-use-upgrade"):
            adapter.preflight(p, False)
        socket_setup.fresh_preflight.assert_not_called()
        with mock.patch.object(x, "absent", side_effect=lambda path: path != s.CONFIG_DIR):
            with self.assertRaisesRegex(w.Rejected, "existing-journal-state-retained"):
                adapter.preflight(p, False)
        socket_setup.fresh_preflight.assert_not_called()
        with mock.patch.object(x, "absent", return_value=True):
            adapter.preflight(p, False)
        socket_setup.fresh_preflight.assert_called_once_with(s, x)

    def test_ready_requires_socket_capability_before_journal_or_scope_grants(self):
        x, adapter, bound = self.build()
        with mock.patch.object(w, "socket_manager_compatibility", side_effect=w.Rejected("socket-manager-upgrade-required")) as capability, \
             mock.patch.object(j, "compatibility") as journal, mock.patch.object(s, "apply") as grant, mock.patch.object(i, "run") as inventory:
            with self.assertRaisesRegex(w.Rejected, "socket-manager-upgrade-required"):
                adapter.ready(bound, False)
        capability.assert_called_once()
        journal.assert_not_called(); grant.assert_not_called(); inventory.assert_not_called()

    def test_maintenance_requires_exact_current_v2_identity_source_and_phase(self):
        x, adapter, bound = self.build()
        release = dict(version="v0.1.0-inert.1", assets={"tracebolt-v0.1.0-inert.1-source.tar": dict(sha256=x.manifest["sourceHash"])})
        socket_setup = SimpleNamespace(real_effects=lambda _: x, Rejected=w.Rejected, revoke=mock.Mock(return_value=dict(revoked=True)), fail_closed=mock.Mock())
        files = {w.RECEIPT: w.canonical(bound)}
        files.update({w.phase_path("socket", state): w.phase_record(bound, "socket", state) for state in ("started", "complete")})
        original_read = x.read
        def read(path, *args):
            if path in files: return files[path]
            return original_read(path, *args)
        with mock.patch.object(i, "real_effects", return_value=x), mock.patch.object(x, "read", side_effect=read):
            maintenance = w.real_maintenance(s, i, socket_setup, x.templates, release)
            self.assertEqual(maintenance.inspect(), bound)
            maintenance.revoke(bound)
            socket_setup.revoke.assert_called_once_with(s, x, x.templates, adapter.inspect(), w.digest(w.canonical(bound)))
            maintenance.fail_socket(bound)
            socket_setup.fail_closed.assert_called_once_with(s, x, x.templates, adapter.inspect(), w.digest(w.canonical(bound)), contain_helper=True)
            before = socket_setup.revoke.call_count
            for mutation in (dict(bound, schemaVersion="tracebolt.read-admin-intent.v1"),
                             dict(bound, readProfile="tracebolt.linux-read-admin.v1"),
                             dict(bound, deviceId="agent_" + "e" * 32), dict(bound, other="unexpected")):
                files[w.RECEIPT] = w.canonical(mutation)
                with self.assertRaises(w.Rejected): maintenance.inspect()
            files[w.RECEIPT] = w.canonical(bound)
            release["assets"]["tracebolt-v0.1.0-inert.1-source.tar"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(w.Rejected, "socket-maintenance-source-changed"): maintenance.inspect()
            release["assets"]["tracebolt-v0.1.0-inert.1-source.tar"]["sha256"] = x.manifest["sourceHash"]
            files[w.phase_path("socket", "complete")] = b"changed completion"
            with self.assertRaisesRegex(w.Rejected, "socket-parent-phase-required"): maintenance.inspect()
            self.assertEqual(socket_setup.revoke.call_count, before)

    def test_actual_socket_adapter_accepts_v2_parent_receipts_and_never_regrants(self):
        # Compose both production state machines over the sibling's inert
        # systemd/filesystem/private-consent adapter. No native program runs.
        fixtures = load("socket_onboarding_composition_fixture", ROOT / "deploy/socket-owner/test_setup.py")
        socket_setup, setup = fixtures.x, fixtures.s
        host = fixtures.Fixture()
        facts = dict(host.expected, configHash="f" * 64)
        args = SimpleNamespace(action="install", resume=False, bootstrap_sha256=facts["manifest"]["bootstrapHash"],
            manager_origin="https://manager.example:8443", invitation_id="invite_" + "e" * 32,
            insecure_http_test=False, read_admin_agent_origin=facts["origin"])
        version = "v1.2.3"
        hashes = {"agent-service": "b" * 64, "enroll-agent": facts["manifest"]["enrollHash"],
                  "lan-agent": facts["manifest"]["agentHash"], "socket-owner-reader": host.artifact["sha256"]}
        assets = {f"tracebolt-{version}-linux-amd64-{role}": dict(sha256=value) for role, value in hashes.items()}
        assets[f"tracebolt-{version}-source.tar"] = dict(sha256=facts["manifest"]["sourceHash"])
        plan = w.make_plan(args, dict(version=version, sourceCommit="a" * 40, assets=assets), "amd64")
        bound = w.identity(plan, facts)
        host.intent = w.digest(w.canonical(bound))
        host.files[w.RECEIPT] = w.canonical(bound)
        for phase in w.PHASES:
            for state in ("started", "complete"):
                path = w.phase_path(phase, state)
                if phase == "socket": host.files.pop(path, None)
                else: host.files[path] = w.phase_record(bound, phase, state)
        prompts, phases = [], []
        class Adapter:
            rejection_types = (socket_setup.Rejected, setup.Rejected)
            def preflight(self, plan, resume):
                w.require(resume and self.read(w.RECEIPT) == w.canonical(bound), "fixture-exact-resume")
            def inspect(self): return dict(setup.inspect_agent(host, host.templates), deviceId=facts["deviceId"], configHash=facts["configHash"])
            def lock(self): return host.lock()
            def read(self, path): return host.files.get(path)
            def create(self, path, raw):
                w.require(host.locked and path in w.FILES and path not in host.files, "fixture-exclusive-parent-receipt")
                host.files[path] = raw
            def ready(self, bound, resume): pass  # Network contract is independently tested above.
            def configure(self, phase, bound, *, verify_only):
                phases.append((phase, verify_only))
                if phase == "socket":
                    result = socket_setup.configure(setup, host, host.templates, host.artifact, self.inspect(),
                                                    w.digest(w.canonical(bound)), verify_only=verify_only)
                    w.require(result["configured"] and result["configurationOnly"], "fixture-socket-result")
                else: w.require(verify_only, "fixture-existing-earlier-phase")
            def fail_socket(self, bound):
                socket_setup.fail_closed(setup, host, host.templates, self.inspect(), w.digest(w.canonical(bound)))
        adapter = Adapter()
        def forbidden_install(): raise AssertionError("resume must never install")
        def confirm(phrase): prompts.append(phrase); return True
        first = w.run(plan, adapter, forbidden_install, confirm, lambda _: None, resume=True)
        self.assertTrue(first["configurationComplete"], first)
        receipt = host.files[socket_setup.COMPLETE]
        self.assertEqual(json.loads(receipt)["parentIntentSHA256"], w.digest(w.canonical(bound)))
        self.assertEqual(host.files[w.phase_path("socket", "complete")], w.phase_record(bound, "socket", "complete"))
        second = w.run(plan, adapter, forbidden_install, confirm, lambda _: None, resume=True)
        self.assertTrue(second["configurationComplete"], second)
        self.assertEqual(host.files[socket_setup.COMPLETE], receipt)
        self.assertEqual(phases.count(("socket", False)), 1)
        self.assertEqual(host.events.count("consent:initialize"), 1)
        self.assertTrue(socket_setup.revoke(setup, host, host.templates, adapter.inspect(), w.digest(w.canonical(bound)))["revoked"])
        third = w.run(plan, adapter, forbidden_install, confirm, lambda _: None, resume=True)
        self.assertFalse(third["configurationComplete"])
        self.assertEqual(third["failureStage"], "revoked-or-uncertain-grant")
        self.assertEqual(host.units[socket_setup.AGENT]["ActiveState"], "inactive")
        self.assertFalse(host.policy["enabled"])
        self.assertEqual(host.events.count("consent:initialize"), 1)
        self.assertEqual(prompts, ["INSTALL READ ADMIN"] * 3)

if __name__ == "__main__":
    unittest.main()
