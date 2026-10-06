"""Compose real onboarding restore paths with inert adapters and a bounded clock."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Tests(unittest.TestCase):
    def test_composed_onboarding_exhausts_unchanged_start_budget(self):
        unit = (ROOT / "internal/agentinstall/unit.go").read_text()
        self.assertIn("StartLimitIntervalSec=300s\nStartLimitBurst=5\n", unit)
        composition = load("restart_budget_composition", ROOT / "deploy/onboarding/test_existing_adapters.py")
        sockets = load("restart_budget_socket", ROOT / "deploy/socket-owner/test_setup.py")
        starts = ["installer OpStart"]
        phase = ""

        def observe(host):
            original = host.command

            def command(args, **kwargs):
                if list(args) == ["/usr/bin/systemctl", "start", "tracebolt-agent.service"]:
                    starts.append(phase)
                return original(args, **kwargs)

            host.command = command

        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("native execution forbidden")):
            host, adapter, bound = composition.Tests().build()
            observe(host)
            phase = "inventory restore"
            adapter.configure("inventory", bound, verify_only=False)
            original_verify = adapter.verify_journal
            adapter.verify_journal = lambda _: None
            phase = "journal setup restore"
            adapter.configure("journal", bound, verify_only=False)
            adapter.verify_journal = original_verify
            phase = "journal readback restore"
            # Keep the real stop/validate/start flow. The private journal preview
            # is an inert DTO; no runtime command, account or network is used.
            inspected = dict(policy=json.loads(host.files[composition.s.POLICY]),
                             activity={composition.s.SOCKET: True},
                             enablement={composition.s.SOCKET: "enabled"})
            with mock.patch.object(composition.a, "inspect", return_value=inspected), \
                 mock.patch.object(composition.a, "command", return_value={}), \
                 mock.patch.object(composition.s.Effects, "command",
                                   lambda self, args, **kw: host.command(args, **kw)):
                adapter.verify_journal(bound)
            socket_host = sockets.Fixture()
            observe(socket_host)
            phase = "socket configure restore"
            self.assertTrue(socket_host.configure()["configured"])
            self.assertEqual(starts, ["installer OpStart", "inventory restore", "journal setup restore",
                                      "journal readback restore", "socket configure restore"])
            # v255 ratelimit_below increments each manual/automatic start in a
            # single <300-second window. Native restart is sixth; revoke seventh.
            accepted = [number <= 5 for number in range(1, len(starts) + 3)]
            self.assertEqual(accepted, [True] * 5 + [False, False])
            socket_host.parent_complete()
            phase = "socket revoke restore"
            self.assertTrue(socket_host.revoke()["revoked"])
            self.assertEqual(starts[-1], phase)
        # The Go inert-adapter test executes this exact transaction sequence,
        # verifies the reset occurs after validation, and admits restart/revoke.
        self.assertIn("operations = []Operation{OpStop, OpValidate, OpResetRestartState, OpStart}",
                      (ROOT / "internal/agentinstall/transaction.go").read_text())


if __name__ == "__main__":
    unittest.main()
