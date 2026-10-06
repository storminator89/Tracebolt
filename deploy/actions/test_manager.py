import copy
import json
import unittest
from unittest import mock
import manager
from common import Rejected, canonical, digest
from manager import ManagerAdapter, runtime_digest
from guide import make_plan
from pathlib import Path

class FakeDocker:
    def __init__(self, fail=0):
        self.id = "a" * 64
        self.image = "sha256:" + "b" * 64
        self.hash = "c" * 64
        self.request = dict(composeFile="/etc/tracebolt/compose.yaml", project="manager", service="manager", endpoint="agent_" + "d" * 32, httpAcknowledged=False, lanIP=None)
        self.plan = dict(schemaVersion="tracebolt.action-manager-setup.v1", uid=65532, gid=65532,
                        endpointId=self.request["endpoint"], transportProfile="production-tls", stateDirectory="/data/state",
                        lanConfig="/run/tracebolt/lan.json", enrollmentConfig="/run/tracebolt/enrollment.json", digest="sha256:" + "e" * 64)
        self.command = ["--lan-config", self.plan["lanConfig"], "--enrollment-config", self.plan["enrollmentConfig"]]
        self.container = dict(State=dict(Running=True, Restarting=False), Path="/tracebolt/manager", Image=self.image,
            Config=dict(Entrypoint=["/tracebolt/manager"], Cmd=self.command[:], User="65532:65532", Labels={
                "com.docker.compose.project":"manager", "com.docker.compose.service":"manager",
                "com.docker.compose.project.config_files":self.request["composeFile"], "com.docker.compose.config-hash":self.hash}),
            HostConfig=dict(ReadonlyRootfs=True, Privileged=False), Mounts=[dict(RW=True, Destination="/data")],
            NetworkSettings=dict(Networks={"manager_default": {}}))
        self.config = dict(services=dict(manager=dict(command=self.command[:])), networks={}, volumes={})
        self.files = {self.request["composeFile"]: b"compose"}
        self.public = dict(bundleDigest="sha256:"+"f"*64)
        self.effects = []
        self.calls = []
        self.fail = fail
    def effect(self, value):
        self.effects.append(value)
        if len(self.effects) == self.fail:
            raise Rejected("injected-failure")
    def read(self, p): return self.files[p]
    def absent(self, p): return p not in self.files
    def create(self, p, b):
        if p in self.files: raise Rejected("exists")
        self.effect("create:"+p)
        self.files[p] = b
    def run(self, args, data=None, timeout=30, lan_ip=None):
        self.calls.append(args)
        if args[:2] == ["context","inspect"]:
            return canonical([dict(Endpoints=dict(docker=dict(Host="unix:///var/run/docker.sock")))])
        if args[0] == "inspect": return canonical([self.container])
        if args[0] == "exec": return canonical(self.public if "status" in args else self.plan)
        if args[0] == "stop":
            self.effect("stop"); self.container["State"]["Running"] = False; return b""
        if args[0] == "run": self.effect("provision"); return canonical(self.public)
        if args[0] == "compose":
            if "config" in args:
                return ("manager " + (self.hash if not hasattr(self,"expected_ip") or lan_ip==self.expected_ip else "changed")).encode() if "--hash" in args else canonical(self.config)
            if "ps" in args: return self.id.encode()
            if "up" in args:
                self.effect("activate"); self.container["State"]["Running"] = True
                self.container["Config"]["Cmd"] = ["--lan-config", "/data/state/service-action-setup/lan.json", "--enrollment-config", self.plan["enrollmentConfig"]]
                return b""
        raise AssertionError(args)

class ManagerTests(unittest.TestCase):
    def test_production_argv_pins_local_daemon_for_every_operation(self):
        effects = manager.DockerEffects()
        with mock.patch.object(manager, "run", return_value=b"inert") as runner:
            for args in (["inspect", "id"], ["exec", "id", "probe"], ["stop", "id"], ["run", "image"],
                         ["compose", "up"], ["context", "inspect", "default"]):
                effects.run(args)
                self.assertEqual(runner.call_args.args[0], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args])

    def test_recreation_bookkeeping_only_is_normalized(self):
        fx=FakeDocker();old=copy.deepcopy(fx.container);old["Id"]="a"*64;old["Config"]["Hostname"]="a"*12
        new=copy.deepcopy(old);new["Id"]="b"*64;new["Config"]["Hostname"]="b"*12
        new["Config"]["Labels"]["com.docker.compose.replace"]=old["Id"]
        new["Config"]["Labels"]["com.docker.compose.project.config_files"]="/frozen/resolved.json"
        self.assertEqual(runtime_digest(old),runtime_digest(new))
        new["Config"]["Labels"]["user-label"]="changed"
        self.assertNotEqual(runtime_digest(old),runtime_digest(new))

    def test_shipped_http_interpolation_only_uses_bound_private_ip(self):
        fx=FakeDocker();fx.plan["transportProfile"]="disposable-http-test";fx.request["httpAcknowledged"]=True
        fx.request["lanIP"]="192.168.1.50";fx.expected_ip=fx.request["lanIP"]
        fx.files[fx.request["composeFile"]]=(Path(__file__).resolve().parents[1]/"compose.http-complete-test.yaml").read_bytes()
        self.assertEqual(ManagerAdapter(fx).inspect(fx.request)["request"]["lanIP"],fx.expected_ip)
        fx.request["lanIP"]="192.168.1.51"
        with self.assertRaises(Rejected):ManagerAdapter(fx).inspect(fx.request)
        self.assertEqual(fx.effects,[])
        for invalid in ("127.0.0.1","0.0.0.0","169.254.1.1","8.8.8.8","192.168.001.2","::1"):
            fx.request["lanIP"]=invalid
            with self.assertRaises(Rejected):ManagerAdapter(fx).inspect(fx.request)
        fx=FakeDocker();fx.request["lanIP"]="10.1.1.1"
        with self.assertRaises(Rejected):ManagerAdapter(fx).inspect(fx.request)

    def test_default_inspection_does_not_mutate(self):
        fx = FakeDocker(); a = ManagerAdapter(fx)
        facts = a.inspect(fx.request)
        self.assertEqual(facts["state"], "fresh")
        self.assertEqual(fx.effects, [])
    def test_happy_path_and_exact_completed_repeat(self):
        fx = FakeDocker(); a = ManagerAdapter(fx)
        facts = a.inspect(fx.request)
        result = a.apply(make_plan("manager", facts))
        self.assertTrue(result["configured"])
        self.assertEqual(fx.effects.count("provision"), 1)
        self.assertEqual(a.inspect(fx.request)["state"], "complete")
        self.assertEqual(fx.effects.count("provision"), 1)
        command = next(c for c in fx.calls if c[0] == "run")
        self.assertIn("--pull", command); self.assertIn("never", command)
        self.assertIn("--network", command); self.assertIn("none", command)
        self.assertIn(fx.image, command)
    def test_fault_every_mutation_no_reset_or_regeneration(self):
        for failure in range(1, 9):
            with self.subTest(failure=failure):
                fx=FakeDocker(failure); a=ManagerAdapter(fx); p=make_plan("manager",a.inspect(fx.request))
                if failure == 1:
                    with self.assertRaises(Rejected): a.apply(p)
                else:
                    result = a.apply(p)
                    self.assertFalse(result["configured"])
                    self.assertTrue(result["retainedPartialState"])
                if failure>1:
                    self.assertIn(fx.request["composeFile"]+".actions.intent.json",fx.files)
                    count=fx.effects.count("provision")
                    with self.assertRaises(Rejected): a.inspect(fx.request)
                    self.assertEqual(fx.effects.count("provision"),count)
                self.assertFalse(any("start" in c or "rm" in c or "down" in c for c in fx.calls))
    def test_changes_and_unrecognized_launcher_fail_readonly(self):
        for mutate in (lambda fx: fx.container["Config"].update(User="root"),
                       lambda fx: fx.config["services"]["manager"].update(post_start=[dict(command="unsafe")]),
                       lambda fx: fx.container["Config"]["Labels"].update({"com.docker.compose.config-hash":"changed"}),
                       lambda fx: fx.plan.update(transportProfile="disposable-http-test"),
                       lambda fx: fx.container.update(Path="unknown")):
            fx=FakeDocker(); mutate(fx)
            with self.assertRaises(Rejected): ManagerAdapter(fx).inspect(fx.request)
            self.assertEqual(fx.effects,[])
    def test_compose_changes_during_provision_never_start(self):
        fx=FakeDocker();a=ManagerAdapter(fx);p=make_plan("manager",a.inspect(fx.request))
        original=fx.run
        def changed(args, data=None, timeout=30, lan_ip=None):
            result=original(args,data,timeout,lan_ip=lan_ip)
            if args[0]=="run":
                fx.config["services"]["manager"]["post_start"]=[{"command":"must never run"}]
            return result
        fx.run=changed
        result=a.apply(p)
        self.assertFalse(result["configured"])
        self.assertFalse(any("up" in c for c in fx.calls))

    def test_source_import_indirection_rejected_before_docker(self):
        for source in (b"include: other.yaml", b"? include # explicit key\n: other.yaml\nservices: {}", b"env_file: secret.env", b"x: !tag value", b"%TAG !x! tag:example,2000:\nservices: {}", b'"include": []', b'x: &alias []', b'"\\u0069nclude": []'):
            fx=FakeDocker();fx.files[fx.request["composeFile"]]=source
            with self.assertRaises(Rejected):ManagerAdapter(fx).inspect(fx.request)
            self.assertEqual(fx.calls,[])

    def test_changed_plan_no_stop(self):
        fx=FakeDocker();a=ManagerAdapter(fx);p=make_plan("manager",a.inspect(fx.request));fx.container["Config"]["Env"]=["CHANGED=1"]
        with self.assertRaises(Rejected):a.apply(p)
        self.assertEqual(fx.effects,[])

if __name__ == "__main__": unittest.main()
