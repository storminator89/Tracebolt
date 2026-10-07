"""Real restore/command/proof composition over inert process and filesystem effects.

Never executes a host command, reads private state, or changes systemd/account data.
"""
import copy
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import test_upgrade as f

u, s, x, w = f.u, f.s, f.x, f.w
a = f.load("restore_journal_amendment", f.ROOT / "deploy/journal/amend.py")
i = f.load("restore_inventory", f.ROOT / "deploy/inventory/guide.py")


class Composition:
    def __init__(self, directory, *, agent_active=True, helpers_active=False):
        self.host = h = f.installed()
        self.calls, self.drains = [], []
        self.unloaded = set()
        self.reset_failure = set()
        self.reset_error = None
        self.enumeration_failure = False
        self.enumeration_output = None
        self.after_enumeration = lambda unit: None
        # Both helper identities are distinct and the real journal inspector
        # consumes the same protected declarations/templates as production.
        h.files["/etc/passwd"] += b"tracebolt-journal-reader:x:400:401::/nonexistent:/usr/sbin/nologin\n"
        h.files["/etc/group"] += b"tracebolt-journal-reader:x:401:\n"
        h.meta[s.RUNTIME_DIR] = f.f.f.meta(stat.S_IFDIR | 0o755)
        _, raw = s.declarations(h.preview, 400, 401, 190, ["ssh.service"])
        policy = a.amended_policy(s.strict_json(raw), [], "1", "f" * 64, True)
        deployment = dict(schemaVersion="tracebolt.journal-helper-deployment.v2", helperUid=400, helperGid=401,
                          journalGid=190, agentUid=200, agentGid=201, policyGenerationRequired=True)
        identity = dict(schemaVersion="tracebolt.journal-setup-attempt.v1", planSHA256="a" * 64,
                        **{key: h.preview[key] for key in ("senderBinding", "deviceId", "certificateHash")})
        for path, gid, value, mode in (
                (a.POLICY, 401, policy, 0o640), (a.CLIENT_POLICY, 201, policy, 0o640),
                (a.DEPLOYMENT, 401, deployment, 0o640), (a.CLIENT_DEPLOYMENT, 201, deployment, 0o640),
                (s.ATTEMPT, 0, identity, 0o600),
                (a.ACTIVATION, 0, a.activation_record(identity, a.generation(policy), "committed"), 0o644)):
            f.put(h, path, a.canonical(value), mode, gid)
        for name in (s.SOCKET, s.SERVICE):
            raw = h.templates[name + ".in"].replace(b"@HELPER_UID@", b"400").replace(
                b"@HELPER_GID@", b"401").replace(b"@JOURNAL_GID@", b"190").replace(b"@AGENT_GID@", b"201")
            f.put(h, s.UNIT_DIR + "/" + name, raw, 0o644)
            state = h.make_state(x.SOCKET if name == s.SOCKET else x.SERVICE)
            state.update(Names=name, FragmentPath=s.UNIT_DIR + "/" + name, UnitFileState="disabled")
            if name == s.SOCKET:
                state.update(Listen=s.SOCKET_PATH + " (Stream)", SocketUser="root", Triggers=s.SERVICE,
                             FileDescriptorName="journal-reader")
            else:
                state.update(UnitFileState="static", User="400", Group="401", SupplementaryGroups="190",
                             CapabilityBoundingSet="", AmbientCapabilities="", PrivateNetwork="yes",
                             ProtectProc="invisible", ProcSubset="pid", ExecStart=f.f.exec_state([u.AGENT, "--journal-reader"]))
            h.units[name] = state
        h.units[x.SERVICE]["UnitFileState"] = "static"
        self.services = (s.AGENT_UNIT, s.SERVICE, x.SERVICE)
        for name, state in h.units.items():
            state["ActiveState"] = "inactive"
            if name in self.services:
                state.update(MainPID="0", ControlGroup="", Result="success", NRestarts="0")
            else:
                h.files.pop(s.UNIT_DIR + "/sockets.target.wants/" + name, None)
            if name == s.AGENT_UNIT:
                state["UnitFileState"] = "disabled"
        h.meta.pop(x.SOCKET_PATH, None)
        h.units[x.SOCKET]["UnitFileState"] = "disabled"
        self.original = dict(active=agent_active, journalPolicy=policy, journalIdentity=identity,
            enablement={name: "static" if name in self.services[1:] else "enabled" for name in h.units},
            activity={name: helpers_active if name in self.services[1:] else agent_active if name == s.AGENT_UNIT else True for name in h.units})
        self.current = dict(h.expected, receipt=s.strict_json(h.files[x.COMPLETE]),
                           journalHelperUid=400, journalHelperGid=401, journalGid=190,
                           unitHashes={name: u.digest(h.files[s.UNIT_DIR + "/" + name]) for name in h.units})
        # A stopped loaded service can retain an exhausted manual-start budget
        # despite Result=success and NRestarts=0. Only reset or unloading clears it.
        self.budgets = {name: 5 for name in self.services}
        je, se = a.real_effects(s, {}), x.real_effects(s)
        h.listdir = lambda path: sorted(Path(q).name for q in h.meta if str(Path(q).parent) == path)
        for effects in (je, se):
            for method in ("read", "metadata", "absent", "protected_dir", "link", "listdir"):
                setattr(effects, method, getattr(h, method))
        directory.joinpath("manifest.json").write_bytes(b'{"inert":true}')
        release = dict(version="v2.0.0", assets={f"tracebolt-v2.0.0-linux-amd64-{role}": dict(size=1, sha256="a" * 64)
            for role in ("agent-service", "lan-agent", "enroll-agent", "socket-owner-reader")})
        release["assets"]["tracebolt-v2.0.0-source.tar"] = dict(sha256="b" * 64)
        with mock.patch.object(i, "real_effects", return_value=h), mock.patch.object(a, "real_effects", return_value=je), \
             mock.patch.object(x, "real_effects", return_value=se):
            self.adapter = u.real_adapter(w, s, i, a, x, h.templates, release, directory, [])
        # The sole cgroup effect stays inert; ownership, restore ordering, real
        # status parsers, command guards and downstream inspectors are unmodified.
        self.adapter.drain = lambda unit: self.drains.append(unit)

    def process(self, args, **kwargs):
        self.calls.append(args)
        raw, code = b"", 0
        h = self.host
        if args[0] == "/usr/bin/systemctl":
            verb = args[1]
            name = args[-1] if verb == "list-units" else args[2]
            state = h.units[name]
            if verb == "show":
                fields = args[3].removeprefix("--property=").split(",")
                raw = "".join(key + "=" + state[key] + "\n" for key in fields).encode()
            elif verb == "reset-failed":
                if self.reset_error is not None:
                    raise self.reset_error
                if name in self.unloaded:
                    self.budgets[name] = 0
                    code = 1  # ResetFailedUnit does not reload a collected unit.
                elif name in self.reset_failure:
                    code = 1
                else:
                    self.budgets[name] = 0
            elif verb == "list-units":
                assert args == ["/usr/bin/systemctl", "list-units", "--all", "--full", "--plain", "--no-legend", name]
                raw = b"" if name in self.unloaded else (name + " loaded inactive dead inert\n").encode()
                if self.enumeration_output is not None:
                    raw = self.enumeration_output
                code = int(self.enumeration_failure)
                self.after_enumeration(name)
            elif verb == "enable":
                state["UnitFileState"] = "enabled"
                if name != s.AGENT_UNIT:
                    h.files[s.UNIT_DIR + "/sockets.target.wants/" + name] = (s.UNIT_DIR + "/" + name).encode()
            elif verb == "start":
                if name in self.budgets:
                    assert self.budgets[name] < 5, "retained start budget exhausted"
                    self.budgets[name] += 1
                    state.update(MainPID="123", ControlGroup="/system.slice/" + name)
                else:
                    path = s.SOCKET_PATH if name == s.SOCKET else x.SOCKET_PATH
                    h.meta[path] = f.f.f.meta(stat.S_IFSOCK | 0o660, gid=201)
                state["ActiveState"] = "active"
            else:
                raise AssertionError("unexpected inert command")
        else:
            assert args == [u.AGENT, "--config", s.CONFIG, "--validate-guided"]
            assert kwargs["user"] == 200 and kwargs["group"] == 201 and kwargs["extra_groups"] == []
            assert h.units[s.AGENT_UNIT]["ActiveState"] == "inactive"
        # Real pipe/selector consumption, but no subprocess is created.
        reader, writer = os.pipe()
        os.write(writer, raw)
        os.close(writer)
        child = mock.Mock(stdin=None, stdout=os.fdopen(reader, "rb"), returncode=code)
        child.wait.return_value = code
        child.poll.return_value = code
        return child

    def restore(self):
        with mock.patch.object(s.subprocess, "Popen", side_effect=self.process):
            self.adapter.restore(self.original, self.current)


class RestoreTests(unittest.TestCase):
    def build(self, **kwargs):
        temporary = tempfile.TemporaryDirectory(prefix="inert-upgrade-restore-")
        self.addCleanup(temporary.cleanup)
        return Composition(Path(temporary.name), **kwargs)

    def test_real_restore_resets_loaded_inactive_manual_start_budget(self):
        for active in (False, True):
            with self.subTest(agent_active=active):
                c = self.build(agent_active=active, helpers_active=True)
                c.restore()
                self.assertFalse(any(args[1] == "list-units" for args in c.calls))
                self.assertEqual([args[2] for args in c.calls if args[1] == "reset-failed"], list(c.services))
                self.assertEqual(c.host.units[s.AGENT_UNIT]["ActiveState"], "active" if active else "inactive")
                self.assertEqual(c.budgets, {s.AGENT_UNIT: int(active), s.SERVICE: 1, x.SERVICE: 1})

    def test_real_restore_accepts_only_proven_unloaded_reset_targets(self):
        c = self.build(helpers_active=True)
        c.unloaded.update(c.services)
        before = copy.deepcopy(c.host.files)
        c.restore()
        self.assertEqual(c.drains, list(c.services))
        self.assertEqual([args[-1] for args in c.calls if args[1] == "list-units"], list(c.services))
        for path, raw in before.items():
            self.assertEqual(c.host.files[path], raw)
        self.assertEqual(c.budgets, {name: 1 for name in c.services})

    def test_reset_failure_for_loaded_successful_unit_remains_fatal(self):
        c = self.build()
        c.reset_failure.add(s.AGENT_UNIT)
        with self.assertRaisesRegex(u.Rejected, "upgrade-reset-loaded-unit-unconfirmed"):
            c.restore()
        self.assertEqual(c.budgets[s.AGENT_UNIT], 5)
        self.assertFalse(any(args[1] in ("enable", "start") for args in c.calls))

    def test_absence_probe_must_succeed_and_be_exactly_empty(self):
        for output, fail in ((b"", True), (b"\n", False), (b"unexpected", False)):
            with self.subTest(output=output, fail=fail):
                c = self.build()
                c.unloaded.add(s.AGENT_UNIT)
                c.enumeration_output, c.enumeration_failure = output, fail
                with self.assertRaises((s.Rejected, u.Rejected)):
                    c.restore()
                self.assertFalse(any(args[1] in ("enable", "start") for args in c.calls))

    def test_changed_ownership_or_activity_after_absence_is_rejected(self):
        for field, value in (("DropInPaths", "/foreign.conf"), ("User", "0"), ("ActiveState", "active")):
            with self.subTest(field=field):
                c = self.build()
                c.unloaded.add(s.AGENT_UNIT)
                c.after_enumeration = lambda unit: c.host.units[unit].update({field: value})
                with self.assertRaises((s.Rejected, x.Rejected, u.Rejected)):
                    c.restore()
                self.assertFalse(any(args[1] in ("enable", "start") for args in c.calls))

    def test_failed_drain_after_absence_cannot_start_participants(self):
        c = self.build()
        c.unloaded.add(s.AGENT_UNIT)
        c.adapter.drain = mock.Mock(side_effect=u.Rejected("inert-undrained"))
        with self.assertRaisesRegex(u.Rejected, "inert-undrained"):
            c.restore()
        self.assertFalse(any(args[1] in ("enable", "start") for args in c.calls))

    def test_timeout_and_other_reset_errors_never_use_absence_fallback(self):
        for reason in ("command-timeout", "command-output-limit", "protected-file"):
            with self.subTest(reason=reason):
                c = self.build()
                c.reset_error = s.Rejected(reason)
                with self.assertRaisesRegex(s.Rejected, reason):
                    c.restore()
                self.assertFalse(any(args[1] in ("list-units", "enable", "start") for args in c.calls))

    def test_coordinator_projects_only_closed_restore_step_on_failure(self):
        for step in (*u.RESTORE_STEPS, "untrusted-private-value", None, []):
            with self.subTest(step=step):
                lifecycle = f.Lifecycle("restore")
                lifecycle.restore_step = step
                result = u.run(lifecycle, lambda _: True, lambda _: None)
                self.assertEqual(result["failureStage"], "restore-runtime")
                self.assertEqual(result["failureReason"], "injected-restore")
                self.assertEqual(result.get("restoreStep"), step if type(step) is str and step in u.RESTORE_STEPS else None)
                self.assertNotIn("untrusted-private-value", str(result))


if __name__ == "__main__":
    unittest.main()
