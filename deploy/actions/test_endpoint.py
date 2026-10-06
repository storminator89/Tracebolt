"""In-memory endpoint setup fixtures. No host commands, sockets or writes."""
import base64
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

x = module("action_endpoint_fixture_module", Path(__file__).with_name("endpoint.py"))
s = module("action_installation_fixture_module", ROOT / "deploy/journal/setup.py")


def metadata(mode, uid=0, gid=0, ino=1, size=0):
    return types.SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_dev=1,
        st_ino=ino, st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)


def status(name, active="inactive", enabled="not-found"):
    loaded = enabled != "not-found"
    result = dict(LoadState="loaded" if loaded else "not-found", ActiveState=active,
        FragmentPath=x.UNIT_DIR + "/" + name if loaded else "", DropInPaths="", Transient="no",
        Names=name, UnitFileState=enabled)
    if name != x.SOCKET:
        result["MainPID"] = "100" if active == "active" else "0"
    return result


class Fixture:
    """No relationship to Effects: all files/units and commands are invented."""
    def __init__(self, profile="tls", active=True, shared_config=False):
        self.files, self.meta, self.links = {}, {}, {}
        self.commands, self.effects = [], []
        self.fail_at, self.fail_after, self.effect_count = None, False, 0
        self.locked = False
        self.on_stop = None
        self.bad_ready = False
        self.templates = {n + ".in": (ROOT / "deploy/systemd" / (n + ".in")).read_bytes()
                          for n in (x.AGENT, x.SERVICE, x.SOCKET)}
        self.meta[x.INSTALLER_DIR] = metadata(stat.S_IFDIR | 0o700)
        self.meta[s.STATE_DIR] = metadata(stat.S_IFDIR | 0o700, 200, 201, 44)
        if shared_config:
            self.meta[x.CONFIG_DIR] = metadata(stat.S_IFDIR | 0o755, ino=50)
            self.put(x.CONFIG_DIR + "/journal-helper.json", b"untouched existing journal grant", 0o640, 301)
        self.units = {x.AGENT: status(x.AGENT, "active" if active else "inactive", "enabled"),
                      x.SERVICE: status(x.SERVICE), x.SOCKET: status(x.SOCKET)}
        self.put("/etc/passwd", b"root:x:0:0:root:/root:/bin/bash\ntracebolt-agent:x:200:201::/var/lib/tracebolt-agent:/usr/sbin/nologin\n")
        self.put("/etc/group", b"root:x:0:\ntracebolt-agent:x:201:\n")
        self.put("/etc/nsswitch.conf", b"passwd: files systemd\ngroup: files systemd\n")
        self.put(s.BINARY, b"inert fixture lan agent", 0o755)
        self.put("/opt/tracebolt-agent/enroll-agent", b"inert fixture enroll agent", 0o755)
        self.put("/usr/bin/systemctl", b"inert fixture systemctl", 0o755)
        origin = "https://manager.example:8444" if profile == "tls" else "http://192.0.2.2:8788"
        self.put(s.BOOTSTRAP, s.canonical(dict(profile=profile, collectionProfile=s.PROFILE, agentOrigin=origin)))
        m = dict(version="tracebolt.agent-installation.v2", profile=profile, uid=200, gid=201,
            agentHash=s.digest(self.files[s.BINARY]), enrollHash=s.digest(self.files["/opt/tracebolt-agent/enroll-agent"]),
            sourceHash="a" * 64, bootstrapHash=s.digest(self.files[s.BOOTSTRAP]), unitHash="b" * 64)
        self.put(s.UNIT_DIR + "/" + x.AGENT, s.agent_unit(self.templates[x.AGENT + ".in"], m))
        m["unitHash"] = s.digest(self.files[s.UNIT_DIR + "/" + x.AGENT])
        self.put(s.MANIFEST, s.canonical(m))
        self.put(x.INSTALLER_DIR + "/installation-owner.json", s.canonical(dict(
            version="tracebolt.agent-install-owner.v2", status="installed", installation=m,
            stateDevice=1, stateInode=44)), 0o600)
        self.put(x.INSTALLER_DIR + "/ownership", b"tracebolt.agent-installer-owned.v1\n", 0o600)
        self.put(x.INSTALLER_DIR + "/install.lock", b"", 0o600)
        self.identity = dict(schemaVersion="tracebolt.action-setup-identity.v1", senderBinding="c" * 64,
            managerOrigin=origin, endpointId="agent_" + "d" * 32, incarnationDigest="sha256:" + "e" * 64,
            transportProfile="production-tls" if profile == "tls" else "disposable-http-test", agentUid=200, agentGid=201)
        self.target = dict(unit="demo.service", reviewDigest="sha256:" + "f" * 64,
            units=[dict(unit="demo.service", configurationDigest="sha256:" + "a" * 64)],
            inputs=[dict(path="/usr/bin/systemctl", digest="sha256:" + "b" * 64)])
        self.public = dict(schemaVersion="tracebolt.action-setup-bundle.v1", managerId="manager_" + "1" * 32,
            managerOrigin=origin, endpointId=self.identity["endpointId"], incarnationDigest=self.identity["incarnationDigest"],
            transportProfile=self.identity["transportProfile"], httpTestAcknowledged=profile == "http-test",
            commandPublicKey=base64.b64encode(b"p" * 32).decode(), keyId=x.digest(b"p" * 32))
        self.public["bundleDigest"] = x.digest(json.dumps(self.public, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        self.put("/root/public-bundle.json", x.canonical(self.public), 0o600)
        self.put("/root/review.json", x.canonical(self.target), 0o600)
        self.request = dict(bundlePath="/root/public-bundle.json", bundleFingerprint=self.public["bundleDigest"],
                            reviewPath="/root/review.json", allowUnit="demo.service", httpAcknowledged=profile == "http-test")

    def put(self, path, raw, mode=0o644, gid=0):
        self.files[path] = raw
        self.meta[path] = metadata(stat.S_IFREG | mode, gid=gid, ino=len(self.meta) + 100, size=len(raw))

    def metadata(self, path):
        if path not in self.meta:
            raise FileNotFoundError(path)
        return copy.copy(self.meta[path])

    def absent(self, path):
        return path not in self.meta and path not in self.links

    def protected_dir(self, path):
        if path in self.meta:
            st = self.meta[path]
            x.require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o6022 == 0, "fixture-directory")

    def read(self, path, limit=65536, mode=None):
        if path not in self.files:
            raise FileNotFoundError(path)
        st, raw = self.meta[path], self.files[path]
        x.require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
            st.st_mode & 0o6022 == 0 and (mode is None or stat.S_IMODE(st.st_mode) == mode) and len(raw) <= limit,
            "fixture-file-protection")
        return raw

    def status(self, name):
        return copy.deepcopy(self.units[name])

    def link(self, path):
        return self.links[path]

    def names(self, path):
        return sorted(Path(p).name for p in self.meta if str(Path(p).parent) == path)

    @contextlib.contextmanager
    def lock(self):
        x.require(not self.locked, "fixture-lock")
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def effect(self, name, operation):
        x.require(self.locked, "fixture-effect-without-lock")
        self.effect_count += 1
        self.effects.append(name)
        if self.effect_count == self.fail_at and not self.fail_after:
            raise x.Rejected("injected-before-effect")
        operation()
        if self.effect_count == self.fail_at and self.fail_after:
            raise x.Rejected("injected-after-effect")

    def mkdir(self, path):
        def work():
            x.require(path == x.CONFIG_DIR and self.absent(path), "fixture-exclusive-dir")
            self.meta[path] = metadata(stat.S_IFDIR | 0o755, ino=60)
        self.effect(("mkdir", path), work)

    def create(self, path, raw, gid, mode):
        def work():
            x.require(path in x.CREATED_FILES and self.absent(path), "fixture-exclusive-file")
            self.put(path, raw, mode, gid)
        self.effect(("create", path), work)

    def command(self, args, uid=None, gid=None, **_):
        args = tuple(args)
        self.commands.append((args, uid, gid))
        if args == (x.BINARY, "--action-setup-capabilities"):
            return x.canonical(x.CAPABILITIES)
        if args == (x.BINARY, "--validate-guided", "--config", x.CONFIG):
            x.require(uid == 200 and gid == 201 and self.units[x.AGENT]["ActiveState"] == "inactive", "fixture-stopped-sender-validation")
            return b"Tracebolt guided handoff validated locally; no collection or network request performed.\n"
        if args[0] == x.BINARY and args[1] in ("--action-setup-identity", "--action-setup-readiness"):
            x.require(uid == 200 and gid == 201 and args[2:] == ("--config", x.CONFIG, "--service-identity", "200:201"), "fixture-nonroot-probe")
            if args[1] == "--action-setup-identity":
                return x.canonical(self.identity)
            def ready():
                x.require(self.units[x.AGENT]["ActiveState"] == "inactive", "fixture-readiness-before-restore")
                self.units[x.SERVICE] = status(x.SERVICE, "active", "static")
            self.effect(("readiness",), ready)
            p = x.strict_json(self.files[x.POLICY])
            c = dict(version="tracebolt.action-capabilities.v1", enabled=True,
                **{k: p[k] for k in ("managerId", "keyId", "endpointId", "incarnationDigest", "transportProfile", "httpTestAcknowledged", "maxLifetimeSeconds")},
                rootPolicyDigest=x.digest(self.files[x.POLICY]), capturedAt=1790000000,
                services=[dict(unit="demo.service", unitPolicyDigest=x.digest(x.canonical(self.target)))])
            if self.bad_ready:
                c["keyId"] = "sha256:" + "0" * 64
            return x.canonical(dict(schemaVersion="tracebolt.action-setup-readiness.v1", identity=self.identity, capabilities=c))
        if args[:2] == (x.BINARY, "--action-setup-check-target"):
            x.require(args[2:] == ("--review", "/root/review.json"), "fixture-review-path")
            return x.canonical(dict(schemaVersion="tracebolt.action-setup-target.v1", target=self.target,
                unitPolicyDigest=x.digest(x.canonical(self.target)), observedState="active"))
        if args == (x.BINARY, "--action-setup-initialize"):
            def initialize():
                x.require(self.units[x.AGENT]["ActiveState"] == "inactive" and self.absent(x.STARTED) and self.absent(x.LEDGER), "fixture-fresh-initialize")
                intent = x.strict_json(self.files[x.INTENT])
                intent["version"] = "tracebolt.action-ledger-started.v1"
                self.put(x.STARTED, x.canonical(intent), 0o600)
                self.meta[x.LEDGER] = metadata(stat.S_IFDIR | 0o700, ino=70)
                self.put(x.LEDGER + "/action-consumption.json", b"inert fixture ledger", 0o600)
                self.put(x.LEDGER + "/action-consumption.lock", b"", 0o600)
            self.effect(("initialize",), initialize)
            return x.canonical(dict(schemaVersion="tracebolt.action-setup-initialized.v1", initialized=True))
        x.require(args[0] == "/usr/bin/systemctl", "fixture-fixed-command")
        def systemctl():
            if args[1] == "stop":
                n = args[2]
                self.units[n]["ActiveState"], self.units[n]["MainPID"] = "inactive", "0"
                if n == x.AGENT and self.on_stop:
                    hook, self.on_stop = self.on_stop, None
                    hook()
            elif args == ("/usr/bin/systemctl", "start", x.AGENT):
                x.require(self.units[x.SERVICE]["ActiveState"] == "active", "fixture-restore-before-readiness")
                self.units[x.AGENT] = status(x.AGENT, "active", self.units[x.AGENT]["UnitFileState"])
            elif args[1:] == ("daemon-reload",):
                self.units[x.SERVICE] = status(x.SERVICE, enabled="static")
                self.units[x.SOCKET] = status(x.SOCKET, enabled="disabled")
            elif args[1:] == ("enable", "--now", x.SOCKET):
                self.units[x.SOCKET] = status(x.SOCKET, "active", "enabled")
                self.links[x.WANTS] = x.UNIT_DIR + "/" + x.SOCKET
                self.meta[x.RUNTIME] = metadata(stat.S_IFDIR | 0o755, ino=80)
                self.meta[x.SOCKET_PATH] = metadata(stat.S_IFSOCK | 0o660, gid=201, ino=81)
            elif args[1:] == ("disable", "--now", x.SOCKET):
                self.units[x.SOCKET] = status(x.SOCKET, enabled="disabled")
                self.links.pop(x.WANTS, None)
                self.meta.pop(x.SOCKET_PATH, None)
            else:
                raise AssertionError("unexpected fixture command: " + str(args))
        self.effect(("systemctl", *args[1:]), systemctl)
        return b""

    def adapter(self):
        return x.EndpointAdapter(self, s, self.templates)


def prepare(fixture):
    a = fixture.adapter()
    facts = a.inspect(fixture.request)
    return a, dict(schemaVersion="tracebolt.action-setup-plan.v1", endpoint=facts, planDigest="sha256:" + "9" * 64)


class EndpointTests(unittest.TestCase):
    def test_inspect_is_read_only_and_socket_free(self):
        f = Fixture()
        _, plan = prepare(f)
        self.assertEqual(f.effects, [])
        self.assertEqual(plan["endpoint"]["state"], "fresh")
        self.assertTrue(all(c[0][1] in ("--action-setup-capabilities", "--action-setup-identity", "--action-setup-check-target") for c in f.commands))
        self.assertTrue(all(c[1:] == (200, 201) for c in f.commands if c[0][1] == "--action-setup-identity"))

    def test_both_profiles_shared_directory_and_stopped_agent(self):
        for profile in ("tls", "http-test"):
            for active in (False, True):
                for shared in (False, True):
                    with self.subTest(profile=profile, active=active, shared=shared):
                        f = Fixture(profile, active, shared)
                        if not active:
                            f.units[x.AGENT]["UnitFileState"] = "disabled"
                        shared_before = copy.deepcopy((f.files.get(x.CONFIG_DIR + "/journal-helper.json"), f.meta.get(x.CONFIG_DIR)))
                        a, plan = prepare(f)
                        result = a.apply(plan, f.public)
                        self.assertTrue(result["configured"], result)
                        self.assertEqual(result["agentRestarted"], active)
                        self.assertEqual(result["agentStopped"], not active)
                        self.assertEqual(f.effects[0], ("create", x.INTENT))
                        self.assertEqual(f.units[x.AGENT]["UnitFileState"], "enabled" if active else "disabled")
                        self.assertEqual(stat.S_IMODE(f.meta[x.POLICY].st_mode), 0o600)
                        self.assertEqual(stat.S_IMODE(f.meta[x.PUBLIC_KEY].st_mode), 0o600)
                        self.assertEqual((stat.S_IMODE(f.meta[x.CLIENT].st_mode), f.meta[x.CLIENT].st_gid), (0o640, 201))
                        self.assertFalse(result["targetActionExecuted"])
                        if shared:
                            self.assertEqual(shared_before, (f.files[x.CONFIG_DIR + "/journal-helper.json"], f.meta[x.CONFIG_DIR]))
                        self.assertNotIn("try-restart", str(f.commands))
                        self.assertNotIn("useradd", str(f.commands))

    def test_identical_complete_rerun_is_read_only(self):
        f = Fixture()
        a, plan = prepare(f)
        self.assertTrue(a.apply(plan, f.public)["configured"])
        f.effects.clear()
        f.commands.clear()
        a, complete = prepare(f)
        self.assertEqual(complete["endpoint"]["state"], "complete")
        result = a.apply(complete, f.public)
        self.assertTrue(result["alreadyConfigured"])
        self.assertEqual(f.effects, [])
        self.assertNotIn("--action-setup-readiness", str(f.commands))
        self.assertNotIn("--action-setup-initialize", str(f.commands))

    def test_changed_complete_artifact_rejected_without_adoption(self):
        for what in ("policy", "fence", "receipt", "ledger", "socket", "enablement", "dropin", "unknown-ledger-file"):
            with self.subTest(what=what):
                f = Fixture()
                a, plan = prepare(f)
                self.assertTrue(a.apply(plan, f.public)["configured"])
                if what == "policy":
                    f.put(x.POLICY, f.files[x.POLICY], 0o600)  # Identical bytes, changed object identity.
                    f.meta[x.POLICY].st_ino += 1
                elif what == "fence":
                    f.files.pop(x.STARTED); f.meta.pop(x.STARTED)
                elif what == "receipt":
                    f.put(x.COMPLETE, b"{}", 0o600)
                elif what == "ledger":
                    f.meta[x.LEDGER].st_ino += 1
                elif what == "socket":
                    f.meta[x.SOCKET_PATH].st_gid = 999
                elif what == "unknown-ledger-file":
                    f.put(x.LEDGER + "/unknown", b"foreign", 0o600)
                elif what == "enablement":
                    f.units[x.AGENT]["UnitFileState"] = "disabled"
                else:
                    f.meta[x.UNIT_DIR + "/" + x.SERVICE + ".d"] = metadata(stat.S_IFDIR | 0o755)
                f.effects.clear()
                with self.assertRaises((x.Rejected, FileNotFoundError)):
                    a.inspect(f.request)
                self.assertEqual(f.effects, [])

    def test_every_effect_fault_retains_fence_and_never_resumes(self):
        baseline = Fixture()
        a, p = prepare(baseline)
        self.assertTrue(a.apply(p, baseline.public)["configured"])
        count = baseline.effect_count
        for after in (False, True):
            for index in range(1, count + 1):
                with self.subTest(after=after, index=index):
                    f = Fixture()
                    a, plan = prepare(f)
                    f.fail_at, f.fail_after = index, after
                    result = a.apply(plan, f.public)
                    self.assertFalse(result["configured"], result)
                    self.assertTrue(result["retainedPartialState"])
                    self.assertEqual(f.effects[0], ("create", x.INTENT))
                    if index == 1:
                        self.assertEqual(len(f.effects), 1)
                        self.assertEqual(f.units[x.AGENT]["ActiveState"], "active")
                    else:
                        self.assertIn(x.INTENT, f.files)
                        self.assertEqual(f.units[x.AGENT]["ActiveState"], "inactive")
                    self.assertNotIn("try-restart", str(f.commands))
                    if not f.absent(x.COMPLETE):
                        # An uncertain completion marker never authorizes resume.
                        self.assertFalse(result["agentRestarted"])
                    if not f.absent(x.INTENT) and f.absent(x.COMPLETE):
                        with self.assertRaises((x.Rejected, FileNotFoundError)):
                            a.inspect(f.request)

    def test_input_or_identity_drift_before_apply_has_no_effects(self):
        for which in ("bundle", "review", "identity", "account", "binary", "activity"):
            with self.subTest(which=which):
                f = Fixture()
                a, plan = prepare(f)
                if which == "bundle":
                    f.put(f.request["bundlePath"], f.files[f.request["bundlePath"]], 0o600)
                    f.meta[f.request["bundlePath"]].st_ino += 1
                elif which == "review":
                    f.meta[f.request["reviewPath"]].st_mtime_ns += 1
                elif which == "identity":
                    f.identity["senderBinding"] = "8" * 64
                elif which == "account":
                    f.put("/etc/group", f.files["/etc/group"] + b"adm:x:4:tracebolt-agent\n")
                elif which == "binary":
                    f.put(x.BINARY, b"incompatible fixture binary", 0o755)
                else:
                    f.units[x.AGENT] = status(x.AGENT, enabled="enabled")
                with self.assertRaises(x.Rejected):
                    a.apply(plan, f.public)
                self.assertEqual(f.effects, [])

    def test_after_stop_drift_retains_intent_without_grant(self):
        f = Fixture()
        a, plan = prepare(f)
        f.on_stop = lambda: f.identity.update(senderBinding="8" * 64)
        result = a.apply(plan, f.public)
        self.assertFalse(result["configured"])
        self.assertIn(x.INTENT, f.files)
        self.assertNotIn(x.POLICY, f.files)
        self.assertEqual(f.units[x.AGENT]["ActiveState"], "inactive")
        self.assertNotIn(("systemctl", "start", x.AGENT), f.effects)

    def test_bad_readiness_never_restores_agent(self):
        f = Fixture()
        a, plan = prepare(f)
        f.bad_ready = True
        result = a.apply(plan, f.public)
        self.assertFalse(result["configured"])
        self.assertEqual(result["failureStage"], "helper-readiness-bindings")
        self.assertTrue(result["agentStopped"])
        self.assertNotIn(("systemctl", "start", x.AGENT), f.effects)
        self.assertEqual(f.units[x.SOCKET]["UnitFileState"], "disabled")
        self.assertEqual(f.units[x.SERVICE]["ActiveState"], "inactive")
        self.assertIn(x.STARTED, f.files)
        self.assertIn(x.LEDGER + "/action-consumption.json", f.files)

    def test_foreign_partial_and_unsafe_inputs_rejected_read_only(self):
        for path in x.ACTION_PATHS:
            with self.subTest(path=path):
                f = Fixture()
                f.put(path, b"unknown", 0o600)
                with self.assertRaises((x.Rejected, FileNotFoundError)):
                    f.adapter().inspect(f.request)
                self.assertEqual(f.effects, [])
        for mutate in (
            lambda f: f.request.update(bundleFingerprint="sha256:" + "0" * 64),
            lambda f: f.request.update(allowUnit="other.service"),
            lambda f: f.request.update(reviewPath="/root/../root/review.json"),
            lambda f: setattr(f.meta[f.request["reviewPath"]], "st_mode", stat.S_IFLNK | 0o777),
            lambda f: setattr(f.meta[f.request["bundlePath"]], "st_nlink", 2),
        ):
            f = Fixture()
            mutate(f)
            with self.assertRaises(x.Rejected):
                f.adapter().inspect(f.request)
            self.assertEqual(f.effects, [])

    def test_separate_local_http_risk_acknowledgement(self):
        for profile, ack in (("tls", True), ("http-test", False), ("http-test", None)):
            f = Fixture(profile)
            f.request["httpAcknowledged"] = ack
            with self.assertRaisesRegex(x.Rejected, "local-http-action-risk-acknowledgement"):
                f.adapter().inspect(f.request)
            self.assertEqual(f.effects, [])

    def test_unconfirmed_unit_status_is_explicitly_unknown(self):
        f = Fixture()
        a, _ = prepare(f)
        with mock.patch.object(f, "status", side_effect=OSError("unavailable fixture status")):
            result = a._status_result({})
        self.assertIsNone(result["agentStopped"])
        self.assertTrue(all(v == dict(activeState="unknown", enablement="unknown") for v in result["unitStates"].values()))

    def test_templates_root_socket_and_drain_contract(self):
        f = Fixture()
        service = f.templates[x.SERVICE + ".in"].decode()
        socket = f.templates[x.SOCKET + ".in"].decode()
        for line in ("User=0", "Group=0", "SupplementaryGroups=", "Restart=no", "KillMode=mixed", "TimeoutStopSec=60s",
                     "ExecStart=/opt/tracebolt-agent/lan-agent --action-helper"):
            self.assertIn(line + "\n", service)
        for prohibited in ("StateDirectory=", "ConfigurationDirectory=", "ExecStartPre=", "[Install]"):
            self.assertNotIn(prohibited, service)
        self.assertIn("FileDescriptorName=action-helper\n", socket)
        self.assertIn("SocketGroup=@AGENT_GID@\n", socket)
        self.assertIn("SocketMode=0660\n", socket)

    def test_real_nonroot_subprocess_clears_supplementary_groups(self):
        e = x.Effects()
        with mock.patch.object(e, "read", return_value=b"inert"), mock.patch.object(x.subprocess, "Popen", side_effect=OSError("fixture stop")) as popen:
            with self.assertRaises(OSError):
                e.command([x.BINARY, "--action-setup-identity"], uid=200, gid=201)
        kwargs = popen.call_args.kwargs
        self.assertEqual((kwargs["user"], kwargs["group"], kwargs["extra_groups"]), (200, 201, []))
        self.assertTrue(kwargs["close_fds"])
        self.assertEqual(kwargs["cwd"], "/")
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["env"], x.ENV)


if __name__ == "__main__":
    unittest.main()
