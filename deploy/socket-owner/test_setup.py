"""Generated inert effects only. Never executes provisioning or reads host state."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import stat
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

x = load("socket_setup", Path(__file__).with_name("setup.py"))
f = load("socket_journal_fixture", ROOT / "deploy/journal/test_setup.py")
s = f.s


def exec_state(argv):
    return "{ path=" + argv[0] + " ; argv[]=" + " ".join(argv) + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"


class Fixture(f.Fixture):
    # Inherits an inert fixture, never the production adapter.
    def __init__(self, profile="tls", active=True):
        super().__init__(profile, active)
        self.templates.update({name + ".in": (ROOT / "deploy/systemd" / (name + ".in")).read_bytes() for name in (x.SERVICE, x.SOCKET)})
        self.policy = None
        self.journal = {}
        self.fail = None
        self.events = []
        self.platform_ok = True
        self.drain_ok = True
        self.identity_changed = False
        self.bad_capabilities = False
        self.pending_tagged = False
        self.helper_raw = b"inert helper executable fixture, never run"
        self.artifact = dict(path="/tmp/tracebolt-release-abcd1234/tracebolt-v1.2.3-linux-amd64-socket-owner-reader", size=len(self.helper_raw), sha256=x.digest(self.helper_raw))
        self.files[x.PARENT_INTENT] = b'{"parent":"generated-fixture"}'
        self.intent = x.digest(self.files[x.PARENT_INTENT])
        for phase in ("journal", "socket"):
            for state in ("started", "complete") if phase == "journal" else ("started",):
                self.files[x.INSTALLER_DIR + "/read-admin-" + phase + "." + state + ".json"] = x.canonical(dict(schemaVersion="tracebolt.read-admin-phase.v2", intentSHA256=self.intent, phase=phase, state=state))
        for path in x.JOURNAL_FILES:
            self.files[path] = x.canonical(dict(inertJournalFixture=Path(path).name))
        for path in list(self.files):
            mode = 0o600 if path.startswith(x.INSTALLER_DIR + "/") else 0o555 if path in (x.AGENT_BINARY, "/opt/tracebolt-agent/enroll-agent") else 0o644
            self.meta[path] = f.meta(stat.S_IFREG | mode)
            self.meta[path].st_size = len(self.files[path])
        for path in (x.UNIT_DIR, x.CONFIG_DIR, "/opt/tracebolt-agent", "/run"):
            for directory in (Path(path), *Path(path).parents):
                self.meta[str(directory)] = f.meta(stat.S_IFDIR | 0o755)
        self.meta[x.INSTALLER_DIR] = f.meta(stat.S_IFDIR | 0o700)
        self.units[x.AGENT] = self.make_state(x.AGENT, active="active" if active else "inactive")
        self.units[x.SERVICE] = self.make_state(x.SERVICE, loaded=False)
        self.units[x.SOCKET] = self.make_state(x.SOCKET, loaded=False)
        self.expected = s.inspect_agent(self, self.templates)
        self.expected["deviceId"] = "agent_" + "d" * 32
        self.public_identity = dict(schemaVersion="tracebolt.socket-owner-setup-identity.v1", senderBinding="c" * 64, managerOrigin=self.expected["origin"], endpointId=self.expected["deviceId"], incarnationDigest="sha256:" + "e" * 64, transportProfile=profile, agentUid=200, agentGid=201)

    def make_state(self, name, loaded=True, active="inactive", enabled=False):
        state = {k: "" for k in x.fields(name)}
        state.update(LoadState="loaded" if loaded else "not-found", ActiveState=active, FragmentPath=x.UNIT_DIR + "/" + name if loaded else "", DropInPaths="", Transient="no", Names=name, UnitFileState=("enabled" if enabled or name == x.AGENT else "disabled") if loaded else "not-found")
        if name == x.SOCKET:
            state.update(Listen=x.SOCKET_PATH + " (Stream)", SocketUser="0", SocketGroup="201", SocketMode="0660", DirectoryMode="0755", FileDescriptorName="socket-owner-reader", Accept="no", Triggers=x.SERVICE, RemoveOnStop="yes")
        else:
            helper = name == x.SERVICE
            argv = [x.BINARY] if helper else x.agent_argv(s, self.templates, {"manifest": self.manifest})
            state.update(MainPID="123" if active == "active" else "0", ControlGroup="/system.slice/" + name if active == "active" else "", ExecStart=exec_state(argv), User="300" if helper else "200", Group="301" if helper else "201", SupplementaryGroups="", CapabilityBoundingSet="cap_sys_ptrace" if helper else "", AmbientCapabilities="cap_sys_ptrace" if helper else "", NoNewPrivileges="yes", KillMode="control-group", Delegate="no", PrivateNetwork="no", PrivateUsers="no", PrivatePIDs="no", NetworkNamespacePath="", JoinsNamespaceOf="", RootDirectory="", RootImage="", ProtectProc="default", ProcSubset="all", RuntimeDirectory="")
        return state

    @contextlib.contextmanager
    def lock(self):
        x.require(not self.locked, "nested-fixture-lock")
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise x.Rejected("injected-" + name)

    def platform(self):
        x.require(self.platform_ok, "unsupported-fixture-platform")

    def config_names(self):
        return [Path(p).name for p in self.files if str(Path(p).parent) == x.CONFIG_DIR]

    def capabilities(self, facts):
        return x.canonical({} if self.bad_capabilities else x.CAPABILITIES)

    def create(self, path, raw, gid, mode):
        x.require(self.locked and path in x.CREATED and self.absent(path), "fixture-exclusive-create")
        self.event("create:" + path)
        self.files[path] = raw
        self.meta[path] = f.meta(stat.S_IFREG | mode, gid=gid, ino=len(self.meta) + 10)
        self.meta[path].st_size = len(raw)

    def install_helper(self, artifact):
        self.event("copy-helper")
        x.require(artifact == self.artifact, "fixture-verified-artifact")
        self.create(x.BINARY, self.helper_raw, 0, 0o755)

    def command(self, args, **kwargs):
        x.require(self.locked, "fixture-command-lock")
        name = " ".join(args[1:])
        self.event(name)
        if args[0] == "/usr/sbin/useradd":
            self.files["/etc/passwd"] += b"tracebolt-socket-owner-reader:x:300:301::/nonexistent:/usr/sbin/nologin\n"
            self.files["/etc/group"] += b"tracebolt-socket-owner-reader:x:301:\n"
            return b""
        if args[1] == "daemon-reload":
            self.units[x.SERVICE] = self.make_state(x.SERVICE)
            self.units[x.SOCKET] = self.make_state(x.SOCKET)
        elif args[1] == "enable":
            self.units[x.SOCKET] = self.make_state(x.SOCKET, active="active", enabled=True)
            self.files[x.WANTS] = (x.UNIT_DIR + "/" + x.SOCKET).encode()
            self.meta[x.RUNTIME] = f.meta(stat.S_IFDIR | 0o755)
            self.meta[x.SOCKET_PATH] = f.meta(stat.S_IFSOCK | 0o660, gid=201)
        elif args[1] == "disable":
            self.units[x.SOCKET] = self.make_state(x.SOCKET)
            self.files.pop(x.WANTS, None)
            self.meta.pop(x.SOCKET_PATH, None)
        elif args[1] == "stop" and args[2] == x.SOCKET:
            self.units[x.SOCKET]["ActiveState"] = "inactive"
            self.meta.pop(x.SOCKET_PATH, None)
        elif args[1] in ("stop", "start"):
            self.units[args[2]]["ActiveState"] = "inactive" if args[1] == "stop" else "active"
            self.units[args[2]]["MainPID"] = "0" if args[1] == "stop" else "123"
            self.units[args[2]]["ControlGroup"] = "" if args[1] == "stop" else "/system.slice/" + args[2]
        return b""

    def drain(self, name):
        self.event("drain:" + name)
        x.require(self.drain_ok, "fixed-cgroup-not-drained")

    def consent(self, mode, facts, body=None):
        x.require(self.locked and self.units[x.AGENT]["ActiveState"] == "inactive" and facts["uid"] == 200 and facts["gid"] == 201, "fixture-stopped-nonroot-consent")
        self.event("consent:" + mode)
        discarded = False
        if mode == "initialize":
            x.require(self.policy is None and not self.pending_tagged, "fixture-create-only-private-consent")
            self.policy = json.loads(body)
        if mode == "disable":
            disabled = json.loads(body)
            x.require(self.policy is not None and disabled == dict(self.policy, enabled=False), "fixture-exact-private-disable")
            self.policy = disabled
            discarded = self.pending_tagged
            self.pending_tagged = False
        identity = copy.deepcopy(self.public_identity)
        if self.identity_changed:
            identity["incarnationDigest"] = "sha256:" + "f" * 64
        return x.canonical(dict(schemaVersion="tracebolt.socket-owner-setup-result.v1", mode=mode, identity=identity, state="absent" if self.policy is None else "enabled" if self.policy["enabled"] else "disabled", policy=self.policy, taggedPendingDiscarded=discarded))

    def validate(self, facts):
        self.event("validate-baseline")

    def link(self, path):
        return self.files[path].decode()

    def disable_policy(self, old, new, gid):
        x.require(self.files[x.POLICY] == old, "fixture-original-policy")
        self.create(x.DISABLE_STAGE, new, gid, 0o640)
        self.event("disable-policy-rename")
        self.files[x.POLICY] = self.files.pop(x.DISABLE_STAGE)
        self.meta[x.POLICY] = self.meta.pop(x.DISABLE_STAGE)
        self.event("disable-policy-fsync")

    def parent_complete(self):
        self.files[x.INSTALLER_DIR + "/read-admin-socket.complete.json"] = x.canonical(dict(schemaVersion="tracebolt.read-admin-phase.v2", intentSHA256=self.intent, phase="socket", state="complete"))

    def configure(self, verify_only=False):
        return x.configure(s, self, self.templates, self.artifact, self.expected, self.intent, verify_only=verify_only)

    def revoke(self):
        return x.revoke(s, self, self.templates, self.expected, self.intent)


class SetupTests(unittest.TestCase):
    def test_import_and_effect_construction_inert(self):
        with mock.patch.object(x.os, "open", side_effect=AssertionError("host access")), mock.patch.object(x.os, "lstat", side_effect=AssertionError("host access")), mock.patch.object(x.subprocess, "Popen", side_effect=AssertionError("command")):
            load("inert_socket_setup", Path(__file__).with_name("setup.py"))
            x.real_effects(s)

    def test_configure_tls_and_http_without_journal_changes(self):
        for profile in ("tls", "http-test"):
            with self.subTest(profile=profile):
                e = Fixture(profile)
                journal = x.journal_snapshot(e)
                agent = e.files[x.UNIT_DIR + "/" + x.AGENT]
                result = e.configure()
                self.assertTrue(result["configured"])
                self.assertTrue(result["configurationOnly"])
                self.assertEqual(result["nativeAcceptance"], "not-established")
                self.assertEqual(x.journal_snapshot(e), journal)
                self.assertEqual(e.files[x.UNIT_DIR + "/" + x.AGENT], agent)
                receipt = json.loads(e.files[x.COMPLETE])
                self.assertEqual(receipt["policy"]["httpAcknowledged"], profile == "http-test")
                self.assertEqual(receipt["deployment"]["clientContract"], x.CLIENT_CONTRACT)
                self.assertEqual(receipt["identity"]["incarnationDigest"], "sha256:" + "e" * 64)
                self.assertEqual(e.units[x.AGENT]["ActiveState"], "active")

    def test_verify_original_receipt_is_non_granting(self):
        e = Fixture()
        e.configure()
        e.parent_complete()
        before = copy.deepcopy(e.files)
        e.events.clear()
        self.assertTrue(e.configure(True)["configured"])
        self.assertEqual(e.files, before)
        self.assertNotIn("consent:initialize", e.events)
        self.assertNotIn("copy-helper", e.events)

    def test_inactive_agent_stays_inactive(self):
        e = Fixture(active=False)
        e.configure()
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
        self.assertNotIn("start " + x.AGENT, e.events)

    def test_parent_evidence_required(self):
        for path in (x.PARENT_INTENT, x.INSTALLER_DIR + "/read-admin-socket.started.json", x.INSTALLER_DIR + "/read-admin-journal.complete.json"):
            with self.subTest(path=path):
                e = Fixture()
                e.files.pop(path)
                with self.assertRaises(Exception):
                    e.configure()
                self.assertFalse(e.events)

    def test_fresh_rejects_every_existing_fixed_state(self):
        for path in x.CREATED | {x.RUNTIME, x.SOCKET_PATH, x.WANTS, x.UNIT_DIR + "/" + x.SERVICE + ".d"}:
            with self.subTest(path=path):
                e = Fixture()
                e.files[path] = b"foreign"
                with self.assertRaises(x.Rejected):
                    x.fresh_preflight(s, e)
                self.assertFalse(e.events)

    def test_loaded_security_properties_reject_mismatch(self):
        cases = [(x.AGENT, k, "bad") for k in ("ExecStart", "User", "Group", "SupplementaryGroups", "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges", "KillMode", "Delegate", *x.NAMESPACE_FIELDS)]
        for name, key, value in cases:
            with self.subTest(key=key):
                e = Fixture()
                e.units[name][key] = value
                with self.assertRaises(x.Rejected):
                    e.configure()

    def test_stopping_and_descendant_drain_gate(self):
        e = Fixture()
        e.drain_ok = False
        with self.assertRaisesRegex(x.Rejected, "drained"):
            e.configure()
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
        self.assertNotIn("copy-helper", e.events)

    def test_mutation_failures_keep_agent_stopped(self):
        failures = ["copy-helper", "create:" + x.POLICY, "create:" + x.DEPLOYMENT, "consent:initialize", "daemon-reload", "enable --now " + x.SOCKET, "consent:preview", "create:" + x.COMPLETE, "validate-baseline"]
        for failure in failures:
            with self.subTest(failure=failure):
                e = Fixture()
                e.fail = failure
                with self.assertRaises(x.Rejected):
                    e.configure()
                self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
                self.assertNotIn("start " + x.AGENT, e.events)

    def test_private_disabled_and_existing_states_not_adopted(self):
        for enabled in (True, False):
            e = Fixture()
            e.policy = dict(x.policy(e.public_identity, 300, 301, "f" * 64), enabled=enabled)
            with self.assertRaisesRegex(x.Rejected, "preexisting"):
                e.configure()
            self.assertNotIn("copy-helper", e.events)

    def test_verify_does_not_adopt_new_epoch(self):
        e = Fixture()
        e.configure()
        e.parent_complete()
        e.policy["epoch"] = "a" * 64
        e.files[x.POLICY] = x.canonical(e.policy)
        with self.assertRaisesRegex(x.Rejected, "original-grant"):
            e.configure(True)
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")

    def test_verify_detects_identity_changed(self):
        e = Fixture()
        e.configure()
        e.parent_complete()
        e.identity_changed = True
        with self.assertRaisesRegex(x.Rejected, "original-private-grant"):
            e.configure(True)
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")

    def test_inner_receipt_does_not_override_parent_uncertainty(self):
        e = Fixture()
        e.configure()
        with self.assertRaises(Exception):
            e.configure(True)
        x.fail_closed(s, e, e.templates, e.expected, e.intent)
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")

    def test_revoke_order_and_original_receipt_retained(self):
        e = Fixture()
        e.configure()
        e.parent_complete()
        original = e.files[x.COMPLETE]
        e.pending_tagged = True
        e.events.clear()
        result = e.revoke()
        self.assertTrue(result["revoked"])
        self.assertTrue(result["taggedPendingDiscarded"])
        self.assertEqual(e.files[x.COMPLETE], original)
        self.assertFalse(e.policy["enabled"])
        order = ["stop " + x.AGENT, "disable --now " + x.SOCKET, "disable-policy-fsync", "stop " + x.SERVICE, "drain:" + x.SERVICE, "consent:disable", "validate-baseline", "start " + x.AGENT]
        self.assertEqual([e.events.index(v) for v in order], sorted(e.events.index(v) for v in order))
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "active")
        with self.assertRaises(x.Rejected):
            e.revoke()
        with self.assertRaises(x.Rejected):
            e.configure(True)

    def test_partial_revoke_failures_never_resume(self):
        for failure in ("create:" + x.REVOKE_STARTED, "disable --now " + x.SOCKET, "disable-policy-rename", "disable-policy-fsync", "stop " + x.SERVICE, "consent:disable", "consent:preview", "create:" + x.REVOKE_COMPLETE, "validate-baseline"):
            with self.subTest(failure=failure):
                e = Fixture()
                e.configure()
                e.parent_complete()
                e.events.clear()
                e.fail = failure
                with self.assertRaises(x.Rejected):
                    e.revoke()
                self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
                self.assertNotIn("start " + x.AGENT, e.events)

    def test_upstream_systemd_show_shapes_without_host_access(self):
        # Derived from upstream v255 systemctl-show.c and v255/v257 D-Bus
        # property declarations, not from inspecting this execution host.
        fixture = Fixture()
        real = x.real_effects(s)
        for version in (255, 257):
            for name in (x.AGENT, x.SERVICE, x.SOCKET):
                state = fixture.make_state(name)
                if version == 255 and name != x.SOCKET:
                    state.pop("PrivatePIDs")
                raw = "".join(k + "=" + v + "\n" for k, v in state.items()).encode()
                with mock.patch.object(real, "command", return_value=raw):
                    self.assertEqual(real.status(name), state)
                    x.loaded(real, name, 300 if name == x.SERVICE else 200, 301 if name == x.SERVICE else 201, [x.BINARY] if name == x.SERVICE else x.agent_argv(s, fixture.templates, fixture.expected) if name == x.AGENT else [])
        self.assertNotIn("Service", x.fields(x.SOCKET))
        self.assertIn("Triggers", x.fields(x.SOCKET))

    def test_socket_and_helper_security_fields_are_enforced(self):
        for name, keys in ((x.SOCKET, x.SOCKET_FIELDS), (x.SERVICE, ("User", "Group", "ExecStart", "Delegate", "CapabilityBoundingSet", "AmbientCapabilities", *x.NAMESPACE_FIELDS))):
            for key in keys:
                with self.subTest(name=name, key=key):
                    e = Fixture()
                    e.configure()
                    e.parent_complete()
                    e.units[name][key] = "foreign"
                    with self.assertRaises(x.Rejected):
                        e.configure(True)
                    self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")

    def test_effect_boundaries_reject_before_host_access(self):
        real = x.real_effects(s)
        e = Fixture()
        with mock.patch.object(x.os, "open", side_effect=AssertionError("host access")), mock.patch.object(x.subprocess, "Popen", side_effect=AssertionError("command")):
            for args in (["/bin/sh", "-c", "true"], ["/usr/bin/systemctl", "start", x.SERVICE], ["/usr/bin/systemctl", "stop", "other.service"], ["/usr/sbin/useradd", "other"]):
                with self.assertRaises(x.Rejected):
                    real.command(args)
            with self.assertRaises(x.Rejected):
                real.create("/tmp/unapproved", b"x", 0, 0o644)
            with self.assertRaises(x.Rejected):
                real.install_helper(dict(e.artifact, path="/arbitrary/helper"))
            with self.assertRaises(x.Rejected):
                real.consent("initialize", e.expected, b"x" * 4097)
            with self.assertRaises(x.Rejected):
                real.drain("foreign.service")

    def test_revoke_policy_failure_safety_stops_running_helper(self):
        e = Fixture()
        e.configure()
        e.parent_complete()
        e.units[x.SERVICE] = e.make_state(x.SERVICE, active="active")
        e.fail = "disable-policy-fsync"
        with self.assertRaises(x.Rejected):
            e.revoke()
        self.assertEqual(e.units[x.SERVICE]["ActiveState"], "inactive")
        self.assertEqual(e.units[x.SOCKET]["ActiveState"], "inactive")
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
        self.assertIn(x.REVOKE_STARTED, e.files)
        self.assertNotIn(x.REVOKE_COMPLETE, e.files)


    def test_go_marshaled_public_identity_and_policy_contract(self):
        # Generated and separately round-tripped by the actual Go public types.
        fixtures = json.loads((Path(__file__).parent / "testdata/go-public-results.json").read_bytes())
        identity = fixtures["Identity"]["identity"]
        facts = dict(uid=identity["agentUid"], gid=identity["agentGid"], origin=identity["managerOrigin"], profile=identity["transportProfile"], deviceId=identity["endpointId"])
        e = mock.Mock()
        for name, result in fixtures.items():
            mode = name.lower()
            raw = x.canonical(result)
            e.consent.return_value = raw
            p = result["policy"] if mode in ("initialize", "disable") else None
            self.assertEqual(x.cli(s, e, facts, mode, p), result)
            if result["policy"] is not None:
                original = result["policy"]
                expected = dict(x.policy(identity, original["helperUid"], original["helperGid"], original["epoch"]), enabled=original["enabled"])
                self.assertEqual(x.canonical(expected), x.canonical(original))

    def test_revoke_failed_owned_helper_and_started_write_failure(self):
        for failed in (True, False):
            e = Fixture()
            e.configure()
            e.parent_complete()
            e.units[x.SERVICE] = e.make_state(x.SERVICE, active="failed" if failed else "active")
            if not failed:
                e.fail = "create:" + x.REVOKE_STARTED
                with self.assertRaises(x.Rejected):
                    e.revoke()
                self.assertEqual(e.units[x.SERVICE]["ActiveState"], "inactive")
                self.assertEqual(e.units[x.SOCKET]["ActiveState"], "inactive")
            else:
                self.assertTrue(e.revoke()["revoked"])
            self.assertEqual(e.units[x.SERVICE]["ActiveState"], "inactive")

    def test_revoke_helper_stop_failure_is_explicitly_unconfirmed(self):
        e = Fixture()
        e.configure()
        e.parent_complete()
        e.units[x.SERVICE] = e.make_state(x.SERVICE, active="active")
        e.fail = "stop " + x.SERVICE
        with self.assertRaisesRegex(x.Rejected, "shutdown-unconfirmed"):
            e.revoke()
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
        self.assertEqual(e.units[x.SOCKET]["ActiveState"], "inactive")
        self.assertEqual(e.units[x.SERVICE]["ActiveState"], "active")


    def test_explicit_revoke_containment_ignores_corrupt_current_declarations(self):
        for path in (x.POLICY, x.DEPLOYMENT):
            with self.subTest(path=path):
                e = Fixture()
                e.configure()
                e.parent_complete()
                original_receipt = e.files[x.COMPLETE]
                e.units[x.SERVICE] = e.make_state(x.SERVICE, active="active")
                corrupt = b"corrupt current declaration retained"
                e.files[path] = corrupt
                e.events.clear()
                x.fail_closed(s, e, e.templates, e.expected, e.intent, contain_helper=True)
                self.assertEqual(e.files[path], corrupt)
                self.assertEqual(e.files[x.COMPLETE], original_receipt)
                self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
                self.assertEqual(e.units[x.SERVICE]["ActiveState"], "inactive")
                self.assertEqual(e.units[x.SOCKET]["ActiveState"], "inactive")
                self.assertEqual(e.units[x.SOCKET]["UnitFileState"], "disabled")
                self.assertNotIn("consent:disable", e.events)
                self.assertNotIn("disable-policy-rename", e.events)
                self.assertNotIn(x.REVOKE_COMPLETE, e.files)

    def test_revoke_containment_refuses_unproven_helper_ownership(self):
        for corrupted in ("receipt", "binary", "account", "loaded"):
            with self.subTest(corrupted=corrupted):
                e = Fixture()
                e.configure()
                e.parent_complete()
                e.units[x.SERVICE] = e.make_state(x.SERVICE, active="active")
                if corrupted == "receipt":
                    e.files[x.COMPLETE] = b"corrupt original receipt"
                elif corrupted == "binary":
                    e.files[x.BINARY] = b"foreign binary"
                elif corrupted == "account":
                    e.files["/etc/group"] += b"foreign:x:900:tracebolt-socket-owner-reader\n"
                else:
                    e.units[x.SERVICE]["ExecStart"] = exec_state(["/foreign/helper"])
                e.events.clear()
                with self.assertRaisesRegex(x.Rejected, "helper-shutdown-unconfirmed"):
                    x.fail_closed(s, e, e.templates, e.expected, e.intent, contain_helper=True)
                self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
                self.assertEqual(e.units[x.SERVICE]["ActiveState"], "active")
                self.assertEqual(e.units[x.SOCKET]["ActiveState"], "active")
                self.assertNotIn("stop " + x.SERVICE, e.events)
                self.assertNotIn("stop " + x.SOCKET, e.events)
                self.assertNotIn("disable --now " + x.SOCKET, e.events)


    def test_revoke_containment_attempts_helper_stop_when_sender_stop_fails(self):
        e = Fixture()
        e.configure()
        e.parent_complete()
        e.units[x.SERVICE] = e.make_state(x.SERVICE, active="active")
        e.fail = "stop " + x.AGENT
        e.events.clear()
        with self.assertRaisesRegex(x.Rejected, "shutdown-unconfirmed"):
            x.fail_closed(s, e, e.templates, e.expected, e.intent, contain_helper=True)
        self.assertEqual(e.units[x.AGENT]["ActiveState"], "active")
        self.assertEqual(e.units[x.SERVICE]["ActiveState"], "inactive")
        self.assertEqual(e.units[x.SOCKET]["ActiveState"], "inactive")
        self.assertEqual(e.units[x.SOCKET]["UnitFileState"], "disabled")


    def test_failed_owned_agent_is_contained_only_by_explicit_maintenance(self):
        for containment in (True, False):
            e = Fixture()
            e.configure()
            e.parent_complete()
            e.units[x.AGENT] = e.make_state(x.AGENT, active="failed")
            e.units[x.SERVICE] = e.make_state(x.SERVICE, active="active")
            e.events.clear()
            if containment:
                e.files[x.POLICY] = b"corrupt retained policy"
                x.fail_closed(s, e, e.templates, e.expected, e.intent, contain_helper=True)
            else:
                self.assertTrue(e.revoke()["revoked"])
            self.assertEqual(e.units[x.AGENT]["ActiveState"], "inactive")
            self.assertEqual(e.units[x.SERVICE]["ActiveState"], "inactive")
            self.assertEqual(e.units[x.SOCKET]["ActiveState"], "inactive")
            self.assertNotIn("start " + x.AGENT, e.events)
        e = Fixture()
        e.units[x.AGENT] = e.make_state(x.AGENT, active="failed")
        with self.assertRaises(x.Rejected):
            e.configure()
        self.assertFalse(e.events)


    def test_native_installer_read_only_agent_mode_is_exact(self):
        # Source-bound check of the existing publisher, not a chmod workaround.
        source = (ROOT / "internal/agentinstall/host_transaction_linux.go").read_text()
        self.assertIn("os.Chmod(dest, 0555)", source)
        self.assertIn('t.changeBytes(InstallDirectory+"/"+string(a.Role()), raw, 0555)', source)
        e = Fixture()
        self.assertEqual(stat.S_IMODE(e.meta[x.AGENT_BINARY].st_mode), 0o555)
        self.assertTrue(e.configure()["configured"])
        self.assertEqual(stat.S_IMODE(e.meta[x.AGENT_BINARY].st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(e.meta[x.BINARY].st_mode), 0o755)
        e = Fixture()
        e.meta[x.AGENT_BINARY].st_mode = stat.S_IFREG | 0o755
        with self.assertRaisesRegex(x.Rejected, "fixed-artifact-metadata"):
            e.configure()
        self.assertEqual(e.events, [])

    def test_template_does_not_modify_native_namespaces_or_parent(self):
        raw = (ROOT / "deploy/systemd" / (x.SERVICE + ".in")).read_text()
        for forbidden in ("PrivateNetwork=yes", "PrivateUsers=yes", "PrivatePIDs=yes", "RuntimeDirectory=", "ProtectProc=invisible", "ProcSubset=pid", "PassPIDFD="):
            self.assertNotIn(forbidden, raw)
        self.assertIn("AmbientCapabilities=CAP_SYS_PTRACE", raw)
        self.assertIn("CapabilityBoundingSet=CAP_SYS_PTRACE", raw)
        socket = (ROOT / "deploy/systemd" / (x.SOCKET + ".in")).read_text()
        self.assertIn("FileDescriptorName=socket-owner-reader", socket)
        self.assertIn("DirectoryMode=0755", socket)


if __name__ == "__main__":
    unittest.main()
