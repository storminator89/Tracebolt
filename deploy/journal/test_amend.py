"""Inert amendment fixtures: no host configuration, systemd or journal reads."""
import copy
import contextlib
import os
import importlib.util
import json
from pathlib import Path
import stat
import unittest
from unittest import mock

import test_setup as base
s = base.s
SPEC = importlib.util.spec_from_file_location("journal_amend", Path(__file__).with_name("amend.py"))
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)


class Fixture(base.Fixture):
    def __init__(self, profile="tls", active=True, socket=True, helper=False, enabled=True, policy_enabled=True):
        super().__init__(profile, active)
        self.tick = 100
        self.failpoint = None
        self.hook = None
        self.commit_uncertain = False
        self.reads = []
        self.floors = b"synthetic existing consumed floor; must never change"
        self.other_private = b"synthetic old sender/key/counter bytes; never read by root"
        self.private_generation = None
        self.files["/etc/passwd"] += b"tracebolt-journal-reader:x:300:301::/nonexistent:/usr/sbin/nologin\n"
        self.files["/etc/group"] += b"tracebolt-journal-reader:x:301:\n"
        dep, pol = s.declarations(self.preview, 300, 301, 190, ["docker.service", "ssh.service"])
        p = json.loads(pol)
        p.update(maxWindowSeconds=900, maxLookbackSeconds=3600, maxPriority=4, enabled=policy_enabled)
        pol = a.canonical(p)
        self.files.update({a.POLICY: pol, a.CLIENT_POLICY: pol, a.DEPLOYMENT: dep, a.CLIENT_DEPLOYMENT: dep})
        self.files[s.ATTEMPT] = a.canonical(dict(schemaVersion="tracebolt.journal-setup-attempt.v1", planSHA256="a" * 64,
            senderBinding=self.preview["senderBinding"], deviceId=self.preview["deviceId"], certificateHash=self.preview["certificateHash"]))
        self.files[s.UNIT_DIR + "/" + s.SERVICE] = self.templates[s.SERVICE + ".in"].replace(b"@HELPER_UID@", b"300").replace(b"@HELPER_GID@", b"301").replace(b"@JOURNAL_GID@", b"190")
        self.files[s.UNIT_DIR + "/" + s.SOCKET] = self.templates[s.SOCKET + ".in"].replace(b"@AGENT_GID@", b"201")
        for key, raw in self.templates.items():
            self.files[str(s.TEMPLATES / key)] = raw
        self.meta[s.CONFIG_DIR] = base.meta(stat.S_IFDIR | 0o755)
        self.meta[s.RUNTIME_DIR] = base.meta(stat.S_IFDIR | 0o755)
        for path in self.files:
            mode = 0o640 if path in a.REPLACEMENTS else 0o600 if path in (s.ATTEMPT, s.INSTALLER_DIR + "/install.lock", s.INSTALLER_DIR + "/ownership", s.INSTALLER_DIR + "/installation-owner.json") else 0o644
            gid = 301 if path in (a.POLICY, a.DEPLOYMENT) else 201 if path in (a.CLIENT_POLICY, a.CLIENT_DEPLOYMENT) else 0
            self.setmeta(path, stat.S_IFREG | mode, gid=gid, size=len(self.files[path]))
        for path, meta in list(self.meta.items()):
            if not hasattr(meta, "st_size"):
                self.setmeta(path, meta.st_mode, uid=meta.st_uid, gid=meta.st_gid, ino=meta.st_ino)
        self.units[s.SOCKET] = base.status(s.SOCKET, True, "active" if socket else "inactive", enabled)
        self.units[s.SERVICE] = base.status(s.SERVICE, True, "active" if helper else "inactive")
        self.units[s.SERVICE]["UnitFileState"] = "static"
        self.units[s.SERVICE]["MainPID"] = "333" if helper else "0"
        self.links = {}
        if enabled:
            link = s.UNIT_DIR + "/sockets.target.wants/" + s.SOCKET
            self.links[link] = s.UNIT_DIR + "/" + s.SOCKET
            self.setmeta(link, stat.S_IFLNK | 0o777)
        if socket:
            self.setmeta(s.SOCKET_PATH, stat.S_IFSOCK | 0o660, gid=201)

    def setmeta(self, path, mode, uid=0, gid=0, size=0, ino=None):
        self.tick += 1
        st = base.meta(mode, uid, gid, self.tick if ino is None else ino)
        st.st_size, st.st_mtime_ns, st.st_ctime_ns = size, self.tick, self.tick
        self.meta[path] = st

    def source_hashes(self):
        return {"reviewed-amend.py": "f" * 64, "reviewed-setup.py": "e" * 64}

    def read(self, path, limit=65536, mode=None):
        self.reads.append(path)
        if path.startswith(s.STATE_DIR + "/"):
            raise AssertionError("Root read of private state: " + path)
        raw = super().read(path, limit, mode)
        st = self.meta[path]
        a.require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                  st.st_mode & 0o6022 == 0 and (mode is None or stat.S_IMODE(st.st_mode) == mode), "fixture-protected-file")
        return raw

    def listdir(self, path):
        return sorted(Path(x).name for x in self.meta if str(Path(x).parent) == path)

    def link(self, path):
        st = self.meta[path]
        a.require(stat.S_ISLNK(st.st_mode) and st.st_uid == st.st_gid == 0 and st.st_nlink == 1, "fixture-link")
        return self.links[path]

    def nonce(self):
        return "1" * 64 if self.private_generation is None else "2" * 64

    def point(self, stage):
        a.require(self.locked, "fixture-unlocked-effect")
        self.actions.append((stage,))
        if self.hook:
            self.hook(self, stage)
        if self.failpoint == stage:
            raise a.Rejected(stage)

    def begin(self, path):
        self.point("evidence.mkdir")
        a.require(self.absent(path), "fixture-evidence-exists")
        self.setmeta(path, stat.S_IFDIR | 0o700)
        self.point("evidence.directory-fsync")
        self.point("evidence.parent-fsync")

    def backup(self, directory, name, raw):
        path = directory + "/" + name
        for step in ("create", "chown", "chmod", "write", "file-fsync", "directory-fsync"):
            self.point("backup-" + name + "." + step)
            if step == "create":
                a.require(self.absent(path), "fixture-backup-exists")
                self.files[path] = b""
                self.setmeta(path, stat.S_IFREG | 0o600)
            elif step == "write":
                self.files[path] = raw
                self.meta[path].st_size = len(raw)

    def replace(self, path, raw, gid, mode, expected, label):
        self.commit_uncertain = False
        a.require(path in a.STAGES, "fixture-fixed-replacement")
        if expected is None:
            a.require(path == a.ACTIVATION and self.absent(path), "fixture-target-absent")
        else:
            a.require(a.snapshot(self, path, gid, mode) == expected, "fixture-old-changed")
        temp = a.STAGES[path]
        for step in ("create", "chown", "chmod", "write", "file-fsync", "stage-directory-fsync", "stage-verify", "rename", "directory-fsync", "readback"):
            if step == "rename":
                self.commit_uncertain = label == "commit-activation"
            self.point(label + "." + step)
            if step == "create":
                a.require(self.absent(temp), "fixture-stage-exists")
                self.files[temp] = b""
                self.setmeta(temp, stat.S_IFREG | mode, gid=gid)
            elif step == "write":
                self.files[temp] = raw
                self.meta[temp].st_size = len(raw)
            elif step == "rename":
                self.files[path] = self.files.pop(temp)
                self.meta[path] = self.meta.pop(temp)

    def archive(self, pending, archived):
        self.point("archive.rename")
        a.require(self.absent(archived), "fixture-archive-exists")
        for path in list(self.meta):
            if path == pending or path.startswith(pending + "/"):
                dest = archived + path[len(pending):]
                self.meta[dest] = self.meta.pop(path)
                if path in self.files:
                    self.files[dest] = self.files.pop(path)
        self.point("archive.directory-fsync")

    def command(self, args, uid=None, gid=None, limit=16384, timeout=45, failure_stage="fixed-command-failed"):
        self.point("command." + (args[1] + "." + args[2] if args[0] == "/usr/bin/systemctl" else args[6]))
        self.actions.append(("command", tuple(args), uid, gid))
        if args[0] == s.BINARY:
            a.require(uid == 200 and gid == 201 and all(x["ActiveState"] == "inactive" for x in self.units.values()), "fixture-stopped-cli")
            a.require(args[:6] == [s.BINARY, "--config", s.CONFIG, "--service-identity", "200:201", "--journal-policy-amendment"], "fixture-cli")
            mode = args[6]
            p = a.policy(s, self.files[a.CLIENT_POLICY])
            g = a.generation(p)
            if mode == "accept":
                a.require(args[7:] == ["--ack-journal-content"] + (["--ack-journal-http-plaintext"] if p["transportProfile"] == "http-test" else []), "fixture-cli-acks")
                gate = json.loads(self.files[a.ACTIVATION])
                a.require(gate["phase"] == "pending" and gate["policyGeneration"] == g and self.absent(a.ACTIVATION_STAGE), "fixture-accept-gate")
                self.private_generation = g
            else:
                a.require(args[7:] == [] and (g is None or json.loads(self.files[a.ACTIVATION])["phase"] == "committed" and self.private_generation == g), "fixture-preview-gate")
            out = dict(schemaVersion="tracebolt.journal-amendment-result.v1", mode=mode, scope=p["scope"],
                senderBinding=self.preview["senderBinding"], managerOrigin=self.preview["managerOrigin"],
                transportProfile=self.preview["transportProfile"], collectionProfile=s.PROFILE,
                deviceId=self.preview["deviceId"], certificateHash=self.preview["certificateHash"], agentUid=200, agentGid=201,
                policyDigest="sha256:" + a.digest(a.canonical(p)))
            if g:
                out["policyGeneration"] = g
            out.update(accepted=mode == "accept", existingStatePreserved=True)
            if getattr(self, "bad_dto", None):
                self.bad_dto(out, mode)
            return a.canonical(out)
        a.require(args[0] == "/usr/bin/systemctl" and len(args) == 3 and args[1] in ("stop", "start"), "fixture-fixed-command")
        verb, name = args[1:]
        a.require(name in self.units and not (verb == "start" and name == s.SERVICE), "fixture-no-helper-force-start")
        self.units[name]["ActiveState"] = "inactive" if verb == "stop" else "active"
        if name != s.SOCKET:
            self.units[name]["MainPID"] = "0" if verb == "stop" else "234"
        elif verb == "stop":
            self.meta.pop(s.SOCKET_PATH, None)
        else:
            self.setmeta(s.SOCKET_PATH, stat.S_IFSOCK | 0o660, gid=201)
        return b""

    def plan(self, additions=("cron.service",)):
        return a.preflight(s, self, list(additions), self.templates)[1]

    def apply(self, additions=("cron.service",), content=True, plaintext=None, expected=None):
        if plaintext is None:
            plaintext = self.manifest["profile"] == "http-test"
        expected = expected or a.digest(a.canonical(self.plan(additions)))
        return a.apply(s, self, list(additions), self.templates, expected, content, plaintext)


class AllServiceProfileTests(unittest.TestCase):
    def plan(self, f):
        return a.preflight(s, f, [], f.templates, all_system_services=True)[1]

    def apply(self, f, expected=None, content=True, plaintext=None):
        expected = expected or a.digest(a.canonical(self.plan(f)))
        plain = f.manifest["profile"] == "http-test" if plaintext is None else plaintext
        return a.apply(s, f, [], f.templates, expected, content, plain, all_system_services=True)

    def test_one_time_profile_plan_does_not_change_or_read_private_state(self):
        f = Fixture()
        before = copy.deepcopy((f.files, f.meta, f.units))
        plan = self.plan(f)
        self.assertEqual(f.actions, [])
        self.assertEqual(before, (f.files, f.meta, f.units))
        self.assertEqual(plan["operation"], "grant-all-system-services")
        self.assertEqual(plan["schemaVersion"], "tracebolt.journal-amendment-plan.v2")
        self.assertEqual(plan["serviceAuthorization"], a.ALL_SERVICES)
        self.assertTrue(plan["includesFutureServices"])
        self.assertEqual(plan["oldUnits"], ["docker.service", "ssh.service"])
        self.assertEqual(plan["newUnits"], [])
        self.assertNotIn("scope", plan["preservedPolicy"])
        self.assertIn("authorized service scope", plan["generationReport"])
        self.assertFalse(any(x.startswith(s.STATE_DIR + "/") for x in f.reads))

    def test_v1_migration_preserves_identity_limits_floors_and_backup(self):
        for profile in ("tls", "http-test"):
            with self.subTest(profile=profile):
                f = Fixture(profile, helper=True)
                before = f.files[a.POLICY]
                old = a.policy(s, before)
                floors = f.floors, f.other_private
                result = self.apply(f)
                self.assertTrue(result["committed"], result)
                p = a.policy(s, f.files[a.POLICY])
                self.assertEqual(p["schemaVersion"], a.V3)
                self.assertEqual(p["scope"], a.SCOPE_V3)
                self.assertEqual(p["serviceAuthorization"], a.ALL_SERVICES)
                self.assertEqual(p["allowedUnits"], [])
                self.assertEqual(p["revision"], "1")
                for k in a.POLICY_FIELDS:
                    if k not in ("scope", "allowedUnits"):
                        self.assertEqual(p[k], old[k])
                self.assertEqual(f.files[a.CLIENT_POLICY], f.files[a.POLICY])
                self.assertEqual(f.files[a.transaction_path(1, True) + "/" + Path(a.POLICY).name], before)
                self.assertEqual((f.floors, f.other_private), floors)
                self.assertEqual(f.private_generation, a.generation(p))
                self.assertFalse(result["contentRead"] or result["sourceVerified"])

    def test_v2_migration_uses_new_generation_and_existing_replay_floor(self):
        f = Fixture()
        self.assertTrue(f.apply()["committed"])
        old_generation = f.private_generation
        self.assertTrue(self.apply(f)["committed"])
        p = a.policy(s, f.files[a.POLICY])
        self.assertEqual(p["revision"], "2")
        self.assertNotEqual(f.private_generation, old_generation)
        self.assertEqual(f.private_generation, a.generation(p))
        self.assertFalse(f.absent(a.transaction_path(1, True)))

    def test_broad_profile_is_not_an_enablement_or_restart_permission(self):
        f = Fixture(active=False, socket=False, enabled=False, policy_enabled=False)
        r = self.apply(f)
        self.assertTrue(r["committed"], r)
        self.assertFalse(r["agentRestarted"] or r["socketRestarted"])
        self.assertFalse(a.policy(s, f.files[a.POLICY])["enabled"])

    def test_no_implicit_broadness_and_conflicting_or_repeat_requests_rejected(self):
        for additions, broad in (([], False), (["*.service"], False), (["cron.service"], True), ([], "true")):
            f = Fixture()
            with self.assertRaises((a.Rejected, s.Rejected)):
                a.preflight(s, f, additions, f.templates, all_system_services=broad)
            self.assertEqual(f.actions, [])
        f = Fixture()
        self.assertTrue(self.apply(f)["committed"])
        f.actions.clear()
        for additions, broad in (([], True), (["new.service"], False)):
            with self.assertRaisesRegex(a.Rejected, "already-authorized"):
                a.preflight(s, f, additions, f.templates, all_system_services=broad)
            self.assertEqual(f.actions, [])

    def test_profile_confirmation_binds_mode_and_full_plan(self):
        f = Fixture()
        exact_hash = a.digest(a.canonical(f.plan()))
        with self.assertRaisesRegex(a.Rejected, "reviewed-plan-changed"):
            self.apply(f, expected=exact_hash)
        self.assertFalse(any(x[0].startswith("command.") for x in f.actions))
        for profile, content, plain in (("tls", False, False), ("tls", True, True), ("http-test", True, False)):
            f = Fixture(profile)
            with self.assertRaisesRegex(a.Rejected, "acknowledgement"):
                self.apply(f, content=content, plaintext=plain)
            self.assertFalse(any(x[0].startswith("command.") for x in f.actions))

    def test_v3_requires_explicit_canonical_mode_and_list(self):
        old = a.policy(s, Fixture().files[a.POLICY])
        valid = a.amended_policy(old, [], 1, "a" * 64, True)
        self.assertEqual(a.policy(s, a.canonical(valid)), valid)
        for update in ({"serviceAuthorization": "*"}, {"serviceAuthorization": None}, {"allowedUnits": None},
                       {"allowedUnits": ["cron.service"]}, {"scope": s.SCOPE}, {"schemaVersion": "tracebolt.journal-content-policy.v2"}):
            with self.subTest(update=update), self.assertRaises((a.Rejected, s.Rejected)):
                a.policy(s, a.canonical(dict(valid, **update)))
        del valid["serviceAuthorization"]
        with self.assertRaises(a.Rejected):
            a.policy(s, a.canonical(valid))

    def test_broad_write_failure_retains_evidence_and_never_activates(self):
        # Exercise every real authority replacement stage for the broad mode.
        success = Fixture()
        self.assertTrue(self.apply(success)["committed"])
        labels = ["pending-activation"] + [Path(p).name for p in a.REPLACEMENTS] + ["commit-activation"]
        stages = [x[0] for x in success.actions if any(x[0].startswith(label + ".") for label in labels)]
        self.assertTrue(stages)
        for stage in stages:
            f = Fixture()
            f.failpoint = stage
            r = self.apply(f)
            self.assertIn("failureStage", r, stage)
            self.assertTrue(r["retainedEvidence"], stage)
            self.assertFalse(r["agentRestarted"] or r["socketRestarted"], stage)



class AmendmentTests(unittest.TestCase):
    def test_import_is_inert_and_never_loads_sibling(self):
        spec = importlib.util.spec_from_file_location("inert_amend", Path(__file__).with_name("amend.py"))
        module = importlib.util.module_from_spec(spec)
        code = Path(__file__).with_name("amend.py").read_bytes()
        with mock.patch("os.open", side_effect=AssertionError("host access")), mock.patch("builtins.open", side_effect=AssertionError("file access")):
            exec(compile(code, str(Path(__file__).with_name("amend.py")), "exec"), module.__dict__)

    def test_plan_is_read_only_and_bound_to_old_bytes_metadata_and_effects(self):
        f = Fixture()
        original = copy.deepcopy((f.files, f.meta, f.units))
        plan = f.plan()
        self.assertEqual(f.actions, [])
        self.assertEqual(original, (f.files, f.meta, f.units))
        self.assertEqual(plan["oldUnits"], ["docker.service", "ssh.service"])
        self.assertEqual(plan["newUnits"], ["cron.service", "docker.service", "ssh.service"])
        self.assertEqual(plan["nextRevision"], "1")
        self.assertEqual(set(plan["replaceFiles"]), set(a.REPLACEMENTS))
        self.assertEqual(plan["activationFile"], a.ACTIVATION)
        self.assertIn("normal agent cycle", plan["generationReport"])
        self.assertFalse(any(x.startswith(s.STATE_DIR + "/") for x in f.reads))

    def test_complete_flow_preserves_existing_grant_and_floors(self):
        f = Fixture(helper=True)
        old = a.policy(s, f.files[a.POLICY])
        oldraw = {p: f.files[p] for p in a.REPLACEMENTS}
        floors = f.floors
        result = f.apply()
        self.assertTrue(result["committed"], result)
        self.assertEqual(result["commitState"], "committed")
        self.assertTrue(result["agentRestarted"] and result["socketRestarted"])
        self.assertFalse(result["helperForceStarted"] or result["sourceVerified"] or result["contentRead"])
        self.assertEqual(f.units[s.SERVICE]["ActiveState"], "inactive")
        p = a.policy(s, f.files[a.POLICY])
        for key in a.POLICY_FIELDS:
            if key != "allowedUnits":
                self.assertEqual(p[key], old[key])
        self.assertEqual(f.files[a.POLICY], f.files[a.CLIENT_POLICY])
        self.assertEqual(f.files[a.DEPLOYMENT], f.files[a.CLIENT_DEPLOYMENT])
        self.assertEqual(p["revision"], "1")
        self.assertEqual(p["generation"], "1" * 64)
        self.assertEqual(f.floors, floors)
        self.assertEqual(f.private_generation, a.generation(p))
        self.assertEqual(json.loads(f.files[a.ACTIVATION])["phase"], "committed")
        archive = a.transaction_path(1, True)
        for path, raw in oldraw.items():
            dest = archive + "/" + Path(path).name
            self.assertEqual(f.files[dest], raw)
            self.assertNotEqual(f.meta[dest].st_ino, f.meta[path].st_ino)
            self.assertEqual(stat.S_IMODE(f.meta[dest].st_mode), 0o600)
        commands = [x[1] for x in f.actions if x[0] == "command"]
        self.assertEqual([c[6] for c in commands if c[0] == s.BINARY], ["preview", "accept"])
        self.assertFalse(any("enable" in c or "journalctl" in c or "useradd" in c for c in commands))

    def test_second_amendment_increments_generation_and_preserves_old_grants(self):
        f = Fixture()
        self.assertTrue(f.apply()["committed"])
        self.assertTrue(f.apply(["db.service"])["committed"])
        p = a.policy(s, f.files[a.POLICY])
        self.assertEqual(p["revision"], "2")
        self.assertEqual(p["generation"], "2" * 64)
        self.assertEqual(p["allowedUnits"], ["cron.service", "db.service", "docker.service", "ssh.service"])
        self.assertFalse(f.absent(a.transaction_path(1, True)))
        self.assertFalse(f.absent(a.transaction_path(2, True)))

    def test_disabled_policy_and_unit_enablement_remain_unchanged(self):
        f = Fixture(active=False, socket=False, enabled=False, policy_enabled=False)
        original = {k: v["UnitFileState"] for k, v in f.units.items()}
        r = f.apply()
        self.assertTrue(r["committed"], r)
        self.assertFalse(r["agentRestarted"] or r["socketRestarted"])
        self.assertFalse(json.loads(f.files[a.POLICY])["enabled"])
        self.assertEqual(original, {k: v["UnitFileState"] for k, v in f.units.items()})

    def test_addition_bounds_and_exact_grammar(self):
        for units in ([], ["cron.service", "cron.service"], ["ssh.service"], ["kernel"], ["*.service"], ["x@.service"], ["../a.service"], [f"x{i}.service" for i in range(31)]):
            with self.subTest(units=units):
                f = Fixture()
                with self.assertRaises((a.Rejected, s.Rejected)):
                    f.plan(units)
                self.assertEqual(f.actions, [])
        self.assertEqual(len(Fixture().plan([f"x{i}.service" for i in range(30)])["newUnits"]), 32)

    def test_expanded_policy_size_rejected_in_read_only_plan(self):
        f = Fixture()
        p = json.loads(f.files[a.POLICY])
        p["allowedUnits"] = ["x" + str(i).zfill(2) + "z" * 244 + ".service" for i in range(29)]
        raw = a.canonical(p)
        self.assertLessEqual(len(raw), 8192)
        for path in (a.POLICY, a.CLIENT_POLICY):
            f.files[path] = raw
            f.meta[path].st_size = len(raw)
        with self.assertRaisesRegex(a.Rejected, "policy-byte-limit"):
            f.plan(["x29" + "z" * 244 + ".service"])
        self.assertEqual(f.actions, [])

    def test_exact_acknowledgements_before_stop(self):
        for profile, content, plain in (("tls", False, False), ("tls", True, True), ("http-test", True, False)):
            with self.subTest(profile=profile):
                f = Fixture(profile)
                with self.assertRaisesRegex(a.Rejected, "acknowledgement"):
                    f.apply(content=content, plaintext=plain)
                self.assertFalse(any(x[0].startswith("command.") for x in f.actions))
        self.assertTrue(Fixture("http-test").apply()["committed"])

    def test_plan_drift_rejects_before_stop(self):
        for change in (lambda f: setattr(f.meta[a.POLICY], "st_ino", 99999),
                       lambda f: f.units[s.AGENT_UNIT].update(ActiveState="inactive", MainPID="0"),
                       lambda f: setattr(f, "source_hashes", lambda: {"reviewed-amend.py": "a" * 64})):

            f = Fixture()
            plan = a.digest(a.canonical(f.plan()))
            change(f)
            with self.assertRaisesRegex(a.Rejected, "reviewed-plan-changed"):
                f.apply(expected=plan)
            self.assertFalse(any(x[0].startswith("command.") for x in f.actions))

    def test_foreign_metadata_units_and_transactions_fail_closed(self):
        mutations = [lambda f: setattr(f.meta[a.POLICY], "st_nlink", 2),
                     lambda f: setattr(f.meta[a.DEPLOYMENT], "st_gid", 201),
                     lambda f: setattr(f.meta[a.CLIENT_POLICY], "st_mode", stat.S_IFLNK | 0o640),
                     lambda f: f.units[s.SERVICE].update(Names=s.SERVICE + " alias.service"),
                     lambda f: f.units[s.SOCKET].update(DropInPaths="/foreign"),
                     lambda f: f.units[s.SERVICE].update(ActiveState="activating"),
                     lambda f: f.setmeta(a.ACTIVATION_STAGE, stat.S_IFREG | 0o644),
                     lambda f: f.setmeta(a.transaction_path(1), stat.S_IFDIR | 0o700),
                     lambda f: f.files.__setitem__(a.CLIENT_POLICY, f.files[a.CLIENT_POLICY] + b"\n"),
                     lambda f: f.links.update({s.UNIT_DIR + "/sockets.target.wants/" + s.SOCKET: "/foreign/socket"})]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                f = Fixture()
                mutate(f)
                with self.assertRaises((a.Rejected, s.Rejected)):
                    f.plan()
                self.assertEqual(f.actions, [])

    def test_rejects_bad_nonroot_preview_before_authority_writes_and_restores(self):
        for key, value in (("schemaVersion", "old"), ("deviceId", "agent_" + "a" * 32), ("policyDigest", "sha256:" + "f" * 64), ("agentUid", True), ("existingStatePreserved", False)):
            f = Fixture()
            f.bad_dto = lambda dto, mode, k=key, v=value: dto.update({k: v})
            r = f.apply()
            self.assertFalse(r["committed"])
            self.assertEqual(r["failureStage"], "nonroot-amendment-preview")
            self.assertTrue(r["agentRestarted"] and r["socketRestarted"])
            self.assertTrue(f.absent(a.ACTIVATION))

    def test_each_stage_failure_retains_evidence_and_keeps_units_stopped(self):
        labels = ["pending-activation"] + [Path(p).name for p in a.REPLACEMENTS] + ["commit-activation"]
        for label in labels:
            for point in ("create", "chown", "chmod", "write", "file-fsync", "stage-directory-fsync", "stage-verify", "rename", "directory-fsync", "readback"):
                with self.subTest(label=label, point=point):
                    f = Fixture()
                    old_floors = f.floors
                    f.failpoint = label + "." + point
                    r = f.apply()
                    self.assertFalse(r["committed"], r)
                    self.assertTrue(r["retainedEvidence"])
                    self.assertEqual(r["restartState"], "left-stopped-retain-evidence")
                    self.assertTrue(all(v["ActiveState"] == "inactive" for v in f.units.values()))
                    self.assertFalse(f.absent(a.transaction_path(1)))
                    self.assertEqual(f.floors, old_floors)
                    if label == "commit-activation" and point in ("rename", "directory-fsync", "readback"):
                        self.assertEqual(r["commitState"], "commit-uncertain")
                    if label == "commit-activation" and point in ("directory-fsync", "readback"):
                        self.assertEqual(json.loads(f.files[a.ACTIVATION])["phase"], "committed")
                    with self.assertRaises((a.Rejected, s.Rejected)):
                        f.plan()

    def test_backup_and_evidence_failures_restore_only_unchanged_old_activity(self):
        for point in ("evidence.mkdir", "evidence.directory-fsync", "evidence.parent-fsync", "backup-transaction.json.write", "backup-journal-content-policy.json.file-fsync", "backup-activation-absent.json.directory-fsync"):
            f = Fixture()
            original = {p: f.files[p] for p in a.REPLACEMENTS}
            f.failpoint = point
            r = f.apply()
            self.assertFalse(r["committed"])
            self.assertTrue(r["agentRestarted"] and r["socketRestarted"], r)
            self.assertEqual(original, {p: f.files[p] for p in a.REPLACEMENTS})
            self.assertTrue(f.absent(a.ACTIVATION))

    def test_accept_failure_does_not_commit_or_restart(self):
        f = Fixture()
        f.failpoint = "command.accept"
        r = f.apply()
        self.assertEqual(r["failureStage"], "nonroot-amendment-accept")
        self.assertEqual(json.loads(f.files[a.ACTIVATION])["phase"], "pending")
        self.assertEqual(r["restartState"], "left-stopped-retain-evidence")

    def test_archive_failure_is_separate_from_successful_commit(self):
        for point in ("archive.rename", "archive.directory-fsync"):
            f = Fixture()
            f.failpoint = point
            r = f.apply()
            self.assertTrue(r["committed"], r)
            self.assertEqual(r["failureStage"], "archive-committed-evidence")
            self.assertTrue(r["agentRestarted"] and r["socketRestarted"])
            self.assertTrue(r["retainedEvidence"])
            self.assertEqual(json.loads(f.files[a.ACTIVATION])["phase"], "committed")

    def test_restart_failure_keeps_commit_success_separate(self):
        f = Fixture()
        f.failpoint = "command.start." + s.AGENT_UNIT
        r = f.apply()
        self.assertTrue(r["committed"])
        self.assertTrue(r["socketRestarted"])
        self.assertFalse(r["agentRestarted"])
        self.assertEqual(r["restartState"], "restart-blocked-or-failed")

    def test_lock_release_failure_preserves_already_established_commit_result(self):
        for committed in (True, False):
            f = Fixture()
            if not committed:
                f.failpoint = "command.accept"
            original_lock = f.lock
            @contextlib.contextmanager
            def fail_release():
                with original_lock():
                    yield
                raise a.Rejected("synthetic-lock-release-error")
            f.lock = fail_release
            result = f.apply()
            self.assertEqual(result["committed"], committed)
            self.assertEqual(result["lockReleaseState"], "uncertain-retain-evidence")
            self.assertEqual(result["commitState"], "committed" if committed else "pending")
            self.assertEqual(result["failureStage"], "installer-lock-release" if committed else "nonroot-amendment-accept")

    def test_identity_changes_during_transaction_block_commit(self):
        f = Fixture()
        def change(f, stage):
            if stage == "command.accept":
                f.files["/etc/group"] += b"foreign:x:999:tracebolt-journal-reader\n"
                f.meta["/etc/group"].st_size = len(f.files["/etc/group"])
        f.hook = change
        r = f.apply()
        self.assertFalse(r["committed"])
        self.assertEqual(r["failureStage"], "verify-staged-declarations")
        self.assertEqual(r["restartState"], "left-stopped-retain-evidence")


class AdapterTests(unittest.TestCase):
    """Run the actual adapter methods with a synthetic syscall boundary only."""
    def boundary(self, fail_fsync=None, fail_rename=False, corrupt=False):
        e = a.real_effects(s, {})
        original = b"old"
        files = {a.ACTIVATION: original}
        metas = {}
        handles, calls = {}, []
        tick = [100]
        def metadata(path, gid=0, mode=0o644):
            tick[0] += 1
            st = base.meta(stat.S_IFREG | mode, gid=gid, ino=tick[0])
            st.st_size, st.st_mtime_ns, st.st_ctime_ns = len(files[path]), tick[0], tick[0]
            metas[path] = st
        metadata(a.ACTIVATION)
        expected = dict(raw=original, pin=a.pin(metas[a.ACTIVATION]))
        @contextlib.contextmanager
        def directory(path):
            self.assertEqual(path, a.CONFIG_DIR)
            calls.append(("directory", path))
            yield 10
        def open_(name, flags, mode, dir_fd):
            self.assertEqual(dir_fd, 10)
            self.assertEqual(name, Path(a.ACTIVATION_STAGE).name)
            self.assertTrue(flags & os.O_CREAT and flags & os.O_EXCL and flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC)
            self.assertEqual(mode, 0o600)
            path = a.CONFIG_DIR + "/" + name
            self.assertNotIn(path, files)
            files[path] = b""
            metadata(path, mode=mode)
            handles[20] = path
            calls.append(("open", name))
            return 20
        def chown(fd, uid, gid):
            self.assertEqual(uid, 0)
            metas[handles[fd]].st_uid, metas[handles[fd]].st_gid = uid, gid
            calls.append(("chown",))
        def chmod(fd, mode):
            metas[handles[fd]].st_mode = stat.S_IFREG | mode
            calls.append(("chmod",))
        def write(fd, raw):
            # Exercise a bounded short write loop in the actual adapter.
            n = min(2, len(raw))
            path = handles[fd]
            files[path] += bytes(raw[:n])
            metas[path].st_size = len(files[path])
            calls.append(("write", n))
            return n
        synced = [0]
        def fsync(fd):
            synced[0] += 1
            calls.append(("fsync", fd))
            if synced[0] == fail_fsync:
                raise OSError("synthetic fsync failure")
            if corrupt and synced[0] == 2:
                metas[a.ACTIVATION_STAGE].st_gid = 999
        def stat_(name, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            self.assertEqual(dir_fd, 10)
            return copy.deepcopy(metas[a.CONFIG_DIR + "/" + name])
        def replace(src, dst, src_dir_fd, dst_dir_fd):
            self.assertEqual((src_dir_fd, dst_dir_fd), (10, 10))
            calls.append(("rename", src, dst))
            if fail_rename:
                raise OSError("synthetic rename uncertainty")
            source, target = a.CONFIG_DIR + "/" + src, a.CONFIG_DIR + "/" + dst
            files[target], metas[target] = files.pop(source), metas.pop(source)
        def read(path, limit=65536, mode=None):
            st = metas[path]
            a.require(stat.S_IMODE(st.st_mode) == mode and st.st_uid == 0, "synthetic-file-metadata")
            return files[path]
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(a, "_directory", directory))
        stack.enter_context(mock.patch.object(e, "metadata", lambda path: copy.deepcopy(metas[path])))
        stack.enter_context(mock.patch.object(e, "read", read))
        stack.enter_context(mock.patch.object(e, "absent", lambda path: path not in files))
        patches = dict(open=open_, fchown=chown, fchmod=chmod, write=write, fsync=fsync,
                       fstat=lambda fd: copy.deepcopy(metas[handles[fd]]), stat=stat_, replace=replace,
                       close=lambda fd: calls.append(("close", fd)))
        for name, value in patches.items():
            stack.enter_context(mock.patch.object(a.os, name, value))
        return stack, e, files, metas, calls, expected

    def test_real_replace_uses_exclusive_stage_short_writes_and_fsync_before_after_rename(self):
        stack, e, files, metas, calls, expected = self.boundary()
        with stack:
            e.replace(a.ACTIVATION, b"committed", 0, 0o644, expected, "commit-activation")
        self.assertEqual(files[a.ACTIVATION], b"committed")
        self.assertNotIn(a.ACTIVATION_STAGE, files)
        self.assertNotEqual(metas[a.ACTIVATION].st_ino, expected["pin"]["ino"])
        ordering = [x for x in calls if x[0] in ("fsync", "rename")]
        self.assertEqual([x[0] for x in ordering], ["fsync", "fsync", "rename", "fsync"])
        self.assertEqual([x[1] for x in ordering if x[0] == "fsync"], [20, 10, 10])
        self.assertEqual([x[1] for x in calls if x[0] == "write"], [2, 2, 2, 2, 1])

    def test_real_replace_fsync_failure_distinguishes_precommit_from_uncertain_commit(self):
        for point in (1, 2, 3):
            with self.subTest(point=point):
                stack, e, files, _, calls, expected = self.boundary(fail_fsync=point)
                with stack, self.assertRaisesRegex(a.Rejected, "commit-activation\\."):
                    e.replace(a.ACTIVATION, b"committed", 0, 0o644, expected, "commit-activation")
                self.assertEqual(e.commit_uncertain, point == 3)
                self.assertEqual(files[a.ACTIVATION], b"committed" if point == 3 else b"old")
                self.assertEqual(a.ACTIVATION_STAGE in files, point < 3)
                self.assertEqual(any(x[0] == "rename" for x in calls), point == 3)

    def test_real_replace_rename_failure_is_uncertain_and_never_retried(self):
        stack, e, files, _, calls, expected = self.boundary(fail_rename=True)
        with stack, self.assertRaisesRegex(a.Rejected, "commit-activation\\.rename"):
            e.replace(a.ACTIVATION, b"committed", 0, 0o644, expected, "commit-activation")
        self.assertTrue(e.commit_uncertain)
        self.assertEqual(sum(x[0] == "rename" for x in calls), 1)
        self.assertEqual(files[a.ACTIVATION], b"old")
        self.assertIn(a.ACTIVATION_STAGE, files)

    def test_real_replace_detects_stage_metadata_change_before_rename(self):
        stack, e, files, _, calls, expected = self.boundary(corrupt=True)
        with stack, self.assertRaisesRegex(a.Rejected, "fixed-file-metadata"):
            e.replace(a.ACTIVATION, b"committed", 0, 0o644, expected, "commit-activation")
        self.assertFalse(any(x[0] == "rename" for x in calls))
        self.assertEqual(files[a.ACTIVATION], b"old")

    def test_real_adapter_rejects_nonfixed_mutations_before_any_syscall(self):
        e = a.real_effects(s, {})
        with mock.patch.object(a.os, "open", side_effect=AssertionError("unexpected filesystem access")), \
             mock.patch.object(s.Effects, "command", side_effect=AssertionError("unexpected command")):
            for command in (["/usr/bin/systemctl", "enable", s.SOCKET], ["/usr/bin/systemctl", "start", s.SERVICE],
                            ["/usr/sbin/useradd", "anyone"], ["/usr/bin/journalctl", "--system"]):
                with self.assertRaises(a.Rejected):
                    e.command(command)
            with self.assertRaises(a.Rejected):
                e.replace("/tmp/arbitrary", b"bad", 0, 0o644, None, "fixed")
            with self.assertRaises(a.Rejected):
                e.backup("/tmp/arbitrary", "anything", b"bad")

    def test_source_bootstrap_never_compiles_unverified_sibling(self):
        with mock.patch.object(a, "_read", side_effect=[b"reviewed-amend-source", a.Rejected("unsafe-sibling")]), \
             mock.patch("builtins.compile", side_effect=AssertionError("unverified compile")) as compile_:
            with self.assertRaisesRegex(a.Rejected, "unsafe-sibling"):
                a.load_setup()
            compile_.assert_not_called()


if __name__ == "__main__":
    unittest.main()
