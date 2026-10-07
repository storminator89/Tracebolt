"""Inert upgrade lifecycle and real immutable socket-binding/revoke proofs.

No host account, service, private path, installer executable or network is used.
"""
import contextlib
import ast
import types
import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

u = load("read_admin_upgrade_fixture", Path(__file__).with_name("upgrade.py"))
f = load("upgrade_socket_fixtures", ROOT / "deploy/socket-owner/test_setup.py")
x, s = f.x, f.s
w = load("upgrade_original_workflow", Path(__file__).with_name("read_admin.py"))


def put(host, path, raw, mode=0o600, gid=0):
    host.files[path] = raw
    host.meta[path] = f.f.meta(stat.S_IFREG | mode, gid=gid, ino=len(host.meta) + 50)
    host.meta[path].st_size = len(raw)


def installed(profile="tls"):
    host = f.Fixture(profile)
    facts = dict(host.expected, configHash="f" * 64)
    plan = dict(artifacts={"source": facts["manifest"]["sourceHash"], "lan-agent": facts["manifest"]["agentHash"], "enroll-agent": facts["manifest"]["enrollHash"]},
                bootstrapSHA256=facts["manifest"]["bootstrapHash"], transportProfile=profile, agentOrigin=facts["origin"])
    bound = w.identity(plan, facts)
    put(host, w.RECEIPT, w.canonical(bound))
    host.intent = w.digest(w.canonical(bound))
    for phase in w.PHASES:
        for state in ("started", "complete"):
            if phase == "socket" and state == "complete": continue
            put(host, w.phase_path(phase, state), w.phase_record(bound, phase, state))
    host.configure(); host.parent_complete()
    put(host, w.phase_path("socket", "complete"), w.phase_record(bound, "socket", "complete"))
    host.expected = dict(s.inspect_agent(host, host.templates), deviceId=host.expected["deviceId"])
    # The helper fixture already supplies a complete old-profile grant, private
    # consent and exact owned installed agent. Keep these original bytes forever.
    return host


def upgrade_binding(host, revision="new", prior=""):
    old = json.loads(host.files[x.COMPLETE])
    new_agent = ("verified replacement agent " + revision).encode()
    new_helper = ("verified replacement helper " + revision).encode()
    put(host, x.AGENT_BINARY, new_agent, 0o555)
    put(host, x.BINARY, new_helper, 0o755)
    host.manifest["agentHash"] = x.digest(new_agent)
    host.manifest["sourceHash"] = x.digest(("new-source-" + revision).encode())
    host.manifest["enrollHash"] = x.digest(host.files["/opt/tracebolt-agent/enroll-agent"])
    put(host, s.MANIFEST, s.canonical(host.manifest), 0o644)
    owner = json.loads(host.files[s.INSTALLER_DIR + "/installation-owner.json"])
    owner["installation"] = host.manifest
    put(host, s.INSTALLER_DIR + "/installation-owner.json", s.canonical(owner))
    facts = s.inspect_agent(host, host.templates)
    facts["deviceId"] = host.expected["deviceId"]
    hashes = dict(old["artifactSHA256"], **{x.AGENT_BINARY: x.digest(new_agent), x.BINARY: x.digest(new_helper)})
    deployment = x.deployment(old["policy"], hashes)
    put(host, x.DEPLOYMENT, x.canonical(deployment), 0o640, old["helperGid"])
    record = dict(schemaVersion="tracebolt.read-admin-upgrade-binding.v1", originalParentSHA256=host.intent,
                  originalSocketSHA256=x.digest(host.files[x.COMPLETE]), previousBindingSHA256=prior,
                  installation=copy.deepcopy(facts["manifest"]), ownerHash=facts["ownerHash"], deployment=deployment,
                  artifactSHA256=hashes, releaseManifestSHA256=x.digest(("signed-release-" + revision).encode()))
    raw = x.canonical(record)
    put(host, x.CURRENT_BINDING, raw)
    put(host, x.INSTALLER_DIR + "/read-admin-upgrade-" + x.digest(raw) + ".complete.json", raw)
    host.expected = facts
    return record


class BindingTests(unittest.TestCase):
    def test_real_upgrade_adapter_selects_matching_arm64_assets_and_rejects_cross_architecture(self):
        inventory, amendment = mock.Mock(), mock.Mock()
        inventory.Rejected = amendment.Rejected = x.Rejected
        effects = mock.Mock()
        roles = ("agent-service", "lan-agent", "enroll-agent", "socket-owner-reader")
        with tempfile.TemporaryDirectory(prefix="inert-arm64-upgrade-") as tmp:
            directory = Path(tmp)
            (directory / "manifest.json").write_bytes(b'{"inert":true}')
            # Only ARM64 entries are present: selecting amd64 must fail.
            release = dict(version="v2.0.0", assets={f"tracebolt-v2.0.0-linux-arm64-{role}": dict(size=1, sha256="a"*64) for role in roles})
            release["assets"]["tracebolt-v2.0.0-source.tar"] = dict(sha256="b"*64)
            with mock.patch.object(x, "real_effects", return_value=effects):
                adapter = u.real_adapter(w, s, inventory, amendment, x, {}, release, directory, [], arch="arm64")
            with mock.patch.object(x, "native_architecture", return_value="amd64"):
                with self.assertRaisesRegex(u.Rejected, "upgrade-architecture-mismatch"):
                    adapter.inspect()
            inventory.inspect.assert_not_called()
            # Recreate at the exact public staging shape with manifest reads inert.
            with mock.patch.object(x, "real_effects", return_value=effects), mock.patch.object(Path, "read_bytes", return_value=b'{"inert":true}'):
                adapter = u.real_adapter(w, s, inventory, amendment, x, {}, release, Path("/tmp/tracebolt-release-abcd1234"), [], arch="arm64")
            for role in roles:
                with self.subTest(role=role), mock.patch.object(u.os, "lstat", side_effect=AssertionError("verified native artifact path accepted")):
                    with self.assertRaisesRegex(AssertionError, "verified native artifact path accepted"):
                        adapter.artifact(role)
            for bad in ("arm", "armhf", "aarch64", "i386"):
                with self.subTest(arch=bad), self.assertRaisesRegex(u.Rejected, "supported-upgrade-architecture"):
                    u.real_adapter(w, s, inventory, amendment, x, {}, release, directory, [], arch=bad)

    def test_new_artifacts_retain_original_grant_and_allow_supported_revoke(self):
        for profile in ("tls", "http-test"):
            with self.subTest(profile=profile):
                host = installed(profile)
                immutable = {p: raw for p, raw in host.files.items() if p == x.COMPLETE or "read-admin-" in p}
                consent = copy.deepcopy(host.policy)
                journal = x.journal_snapshot(host)
                record = upgrade_binding(host)
                actual = x.proof(s, host, host.templates, host.expected, host.intent)
                self.assertEqual(actual["deployment"], record["deployment"])
                self.assertEqual(actual["policy"], consent)
                self.assertEqual(host.policy, consent)
                self.assertEqual(x.journal_snapshot(host), journal)
                for p, raw in immutable.items(): self.assertEqual(host.files[p], raw)
                # Maintenance consumes the new explicit binding, retaining both
                # the original receipt and epoch through a real revoke state machine.
                result = host.revoke()
                self.assertTrue(result["revoked"], result)
                self.assertEqual(host.policy["epoch"], consent["epoch"])
                self.assertFalse(host.policy["enabled"])
                self.assertEqual(host.files[x.COMPLETE], immutable[x.COMPLETE])

    def test_history_chain_is_required_and_same_scope_only(self):
        host = installed()
        first = upgrade_binding(host, "one")
        prior = x.digest(x.canonical(first))
        second = upgrade_binding(host, "two", prior)
        x.proof(s, host, host.templates, host.expected, host.intent)
        original = host.files[x.CURRENT_BINDING]
        changes = [dict(second, originalSocketSHA256="a"*64),
                   dict(second, originalParentSHA256="b"*64),
                   dict(second, previousBindingSHA256="c"*64),
                   dict(second, installation=dict(second["installation"], uid=900)),
                   dict(second, artifactSHA256=dict(second["artifactSHA256"], **{x.UNIT_DIR+"/"+x.AGENT:"d"*64})),
                   dict(second, deployment=dict(second["deployment"], policyDigest="e"*64))]
        for changed in changes:
            with self.subTest(changed=changed):
                raw = x.canonical(changed)
                put(host, x.CURRENT_BINDING, raw)
                put(host, x.INSTALLER_DIR + "/read-admin-upgrade-" + x.digest(raw) + ".complete.json", raw)
                with self.assertRaises((x.Rejected, s.Rejected, KeyError)):
                    x.proof(s, host, host.templates, host.expected, host.intent)
        put(host, x.CURRENT_BINDING, original)
        host.files.pop(x.INSTALLER_DIR + "/read-admin-upgrade-" + prior + ".complete.json")
        with self.assertRaises((x.Rejected, s.Rejected, KeyError)):
            x.proof(s, host, host.templates, host.expected, host.intent)

    def test_maintenance_uses_new_source_with_immutable_original_parent(self):
        host = installed()
        original = host.files[w.RECEIPT]
        upgrade_binding(host)
        facts = dict(host.expected, configHash="f" * 64)
        release = dict(version="v2.0.0", assets={"tracebolt-v2.0.0-source.tar":dict(sha256=facts["manifest"]["sourceHash"])})
        inventory = mock.Mock()
        inventory.real_effects.return_value = host
        inventory.inspect.return_value = facts
        inventory.strict_json.side_effect = lambda raw, limit: s.strict_json(raw)
        inventory.valid_hash.side_effect = x.valid_hash
        inventory.Rejected = x.Rejected
        with mock.patch.object(x,"real_effects",return_value=host):
            maintenance = w.real_maintenance(s,inventory,x,host.templates,release)
            self.assertEqual(maintenance.inspect(),json.loads(original))
            maintenance.revoke(json.loads(original))
        self.assertEqual(host.files[w.RECEIPT],original)
        self.assertFalse(host.policy["enabled"])

    def test_ordinary_binary_swap_and_incomplete_upgrade_cannot_be_adopted(self):
        host = installed()
        old = host.files[x.AGENT_BINARY]
        put(host, x.AGENT_BINARY, b"unbound replacement", 0o555)
        with self.assertRaises(x.Rejected): x.proof(s, host, host.templates, host.expected, host.intent)
        put(host, x.AGENT_BINARY, old, 0o555)
        put(host, x.UPGRADE_TRANSACTION, b'{"uncertain":"retained"}')
        with self.assertRaisesRegex(x.Rejected, "unresolved-read-admin-upgrade"):
            host.revoke()


class Lifecycle:
    rejection_types = (u.Rejected, x.Rejected, s.Rejected)
    def __init__(self, fail=None, inactive=False):
        self.host = installed()
        self.fail = fail; self.failed = False; self.events=[]; self.locked=False; self.updated=False
        self.state = {"identity":b"original-key-and-ready", "metrics":b"floor=41", "inventory":b"floor=73", "journal":b"floor=19", "renewal":b"future-state-untouched"}
        self.oldstate = copy.deepcopy(self.state)
        self.facts = dict(self.host.expected, configHash="f"*64, active=not inactive)
        self.before = copy.deepcopy((self.host.files,self.host.meta,self.host.manifest,self.host.expected,self.host.policy))
        self.original_receipt=self.host.files[x.COMPLETE]
    def event(self, name):
        self.events.append(name)
        if name==self.fail and not self.failed:
            self.failed=True; raise u.Rejected("injected-"+name)
    def inspect(self, updating=False):
        self.event("inspect-updated" if updating else "inspect")
        facts = dict(self.host.expected, configHash="f"*64, active=self.facts["active"])
        if updating: x.proof(s,self.host,self.host.templates,self.host.expected,self.host.intent)
        return copy.deepcopy(facts)
    def disclosure(self, facts): return "inert concrete release and same-scope plan"
    @contextlib.contextmanager
    def lock(self):
        assert not self.locked
        self.locked=True; self.event("lock")
        try: yield
        finally:
            self.locked=False
            if self.fail == "lock-exit": raise u.Rejected("injected-lock-exit")
    def prepare(self, original):
        assert self.locked
        self.event("prepare")
    def quiesce(self, original):
        assert self.locked
        self.event("drain")
        self.host.units[x.AGENT]["ActiveState"]="inactive"
        self.host.units[x.AGENT]["MainPID"]="0"
    def contain(self, facts):
        self.quiesce(facts)
        return True
    def retained(self, facts):
        assert self.locked and self.host.units[x.AGENT]["ActiveState"]=="inactive"
        self.event("validate")
        return copy.deepcopy(self.state)
    def native_upgrade(self, original):
        assert self.locked and self.host.units[x.AGENT]["ActiveState"]=="inactive"
        self.event("native")
    def rebind(self, original):
        assert self.locked and self.host.units[x.AGENT]["ActiveState"]=="inactive"
        upgrade_binding(self.host)
        self.updated=True; self.event("rebind")
        if self.fail=="counter-change": self.state["inventory"]=b"floor=0"
    def restore(self, original, current):
        self.event("restore")
        assert self.state==self.oldstate
        x.proof(s,self.host,self.host.templates,self.host.expected,self.host.intent)
        self.host.units[x.AGENT]["ActiveState"]="active" if original["active"] else "inactive"
    def commit(self): self.event("commit")
    def rollback(self, original):
        self.event("rollback")
        self.host.files,self.host.meta,self.host.manifest,self.host.expected,self.host.policy=copy.deepcopy(self.before)
        return True


class LifecycleTests(unittest.TestCase):
    def test_original_full_profile_to_new_artifacts_and_revoke(self):
        a=Lifecycle()
        out=u.run(a,lambda phrase: phrase=="UPGRADE READ ADMIN",lambda _:None)
        self.assertTrue(out["completed"],out)
        self.assertEqual(a.state,a.oldstate)
        self.assertEqual(a.host.files[x.COMPLETE],a.original_receipt)
        self.assertLess(a.events.index("native"),a.events.index("rebind"))
        self.assertLess(a.events.index("inspect-updated"),a.events.index("restore"))
        self.assertTrue(out["restartBookkeepingReset"])
        self.assertTrue(a.host.revoke()["revoked"])
    def test_cancel_and_inactive_agent(self):
        a=Lifecycle();out=u.run(a,lambda _:False,lambda _:None)
        self.assertTrue(out["canceled"]);self.assertNotIn("lock",a.events)
        a=Lifecycle(inactive=True);out=u.run(a,lambda _:True,lambda _:None)
        self.assertTrue(out["completed"],out);self.assertEqual(a.host.units[x.AGENT]["ActiveState"],"inactive")
    def test_each_interruption_contains_then_rolls_back_without_starting(self):
        for phase in ("prepare","drain","validate","native","rebind","inspect-updated","restore","commit"):
            with self.subTest(phase=phase):
                a=Lifecycle(phase);out=u.run(a,lambda _:True,lambda _:None)
                self.assertFalse(out["completed"],out)
                self.assertTrue(out["participantsStopped"],out)
                self.assertTrue(out["rollbackConfirmed"],out)
                self.assertEqual(a.host.units[x.AGENT]["ActiveState"],"inactive")
                self.assertEqual(a.state,a.oldstate)
                self.assertEqual(a.host.files[x.COMPLETE],a.original_receipt)
                self.assertEqual(a.events[-2:],["drain","rollback"])
    def test_lock_exit_failure_never_reports_completed(self):
        a=Lifecycle("lock-exit");out=u.run(a,lambda _:True,lambda _:None)
        self.assertFalse(out["completed"],out)
        self.assertEqual(out["failureStage"],"lock-release")
        self.assertFalse(out["participantsStopped"])
        self.assertFalse(out["rollbackConfirmed"])

    def test_private_digest_rejects_directory_growth_before_unbounded_allocation(self):
        # Execute only the fixed bounded enumeration function over an invented
        # streaming iterator. No private directory or native child is opened.
        tree=ast.parse(u.STATE_DIGEST)
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="bounded_names")
        consumed=[]
        class Entries:
            def __enter__(self): return self
            def __exit__(self,*_): pass
            def __iter__(self):
                for i in range(1000000):
                    consumed.append(i)
                    yield types.SimpleNamespace(name=str(i))
        fake_os=types.SimpleNamespace(scandir=lambda _:Entries())
        scope={"os":fake_os}
        exec(compile(ast.Module(body=[function],type_ignores=[]),"<inert-bounded-enumerator>","exec"),scope)
        with self.assertRaisesRegex(ValueError,"state-entry-limit"):
            scope["bounded_names"](7,3)
        self.assertEqual(consumed,[0,1,2,3])
        self.assertNotIn("os.listdir",u.STATE_DIGEST)
        self.assertIn("count+=len(names)",u.STATE_DIGEST)
        self.assertIn("bounded_names(fd,len(names))",u.STATE_DIGEST)

    def test_real_adapter_containment_continues_past_foreign_or_failed_unit(self):
        inventory=mock.Mock();inventory.Rejected=x.Rejected
        amendment=mock.Mock();amendment.Rejected=x.Rejected
        ie,je,se=mock.Mock(),mock.Mock(),mock.Mock()
        inventory.real_effects.return_value=ie;amendment.real_effects.return_value=je
        def status(name):
            return dict(LoadState="loaded",ActiveState="inactive",FragmentPath=s.UNIT_DIR+"/"+name,DropInPaths="",Transient="no",Names=name,
                        UnitFileState="disabled" if name in (s.AGENT_UNIT,s.SOCKET,x.SOCKET) else "static",MainPID="0")
        je.status.side_effect=status;se.status.side_effect=status
        je.absent.return_value=True;se.absent.return_value=True
        with tempfile.TemporaryDirectory(prefix="inert-upgrade-adapter-") as tmp:
            directory=Path(tmp);(directory/"manifest.json").write_bytes(b'{"inert":true}')
            release=dict(version="v2.0.0",assets={f"tracebolt-v2.0.0-linux-amd64-{role}":dict(size=1,sha256="a"*64) for role in ("agent-service","lan-agent","enroll-agent","socket-owner-reader")})
            release["assets"]["tracebolt-v2.0.0-source.tar"]=dict(sha256="b"*64)
            with mock.patch.object(x,"real_effects",return_value=se):
                adapter=u.real_adapter(w,s,inventory,amendment,x,{},release,directory,[], arch="amd64")
            effects=[]
            def proof(facts,unit):
                if unit==x.SERVICE:raise u.Rejected("foreign-unit")
            adapter.prove_unit_ownership=proof
            adapter.systemctl=lambda verb,unit:effects.append((verb,unit))
            adapter.drain=mock.Mock()
            self.assertFalse(adapter.contain({}))
            self.assertNotIn(("stop",x.SERVICE),effects)
            for unit in (s.AGENT_UNIT,s.SOCKET,x.SOCKET,s.SERVICE):self.assertIn(("stop",unit),effects)
            adapter.prove_unit_ownership=lambda *_:None
            def failed_stop(verb,unit):
                effects.append((verb,unit))
                if verb=="stop" and unit==s.AGENT_UNIT:raise u.Rejected("stop-failed")
            adapter.systemctl=failed_stop
            def partial_status(name):
                current=status(name)
                if name==s.AGENT_UNIT:current.update(ActiveState="active",MainPID="123")
                return current
            je.status.side_effect=partial_status
            effects.clear()
            self.assertFalse(adapter.contain({}))
            self.assertIn(("stop",s.SERVICE),effects)
            self.assertIn(("stop",x.SERVICE),effects)

    def test_primary_failure_survives_incomplete_containment(self):
        a=Lifecycle("native")
        a.contain=lambda _:False
        out=u.run(a,lambda _:True,lambda _:None)
        self.assertEqual(out["failureReason"],"injected-native")
        self.assertFalse(out["participantsStopped"])
        self.assertFalse(out["rollbackConfirmed"])
        self.assertNotIn("rollback",a.events)

    def test_counter_or_floor_mutation_never_reaches_restart(self):
        a=Lifecycle("counter-change");out=u.run(a,lambda _:True,lambda _:None)
        self.assertFalse(out["completed"]);self.assertEqual(out["failureReason"],"retained-state-changed")
        self.assertNotIn("restore",a.events)
        # Rollback touches public artifacts only; it never 'repairs' private counters.
        self.assertEqual(a.state["inventory"],b"floor=0")
