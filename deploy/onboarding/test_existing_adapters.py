"""Compose the real read-admin adapter with inert existing scope/setup fixtures."""
import importlib.util
import json
from pathlib import Path
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
            adapter = w.real_adapter(s, i, a, j, x.templates, p)
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

if __name__ == "__main__":
    unittest.main()
