"""Portable source fixtures ONLY. No Windows API, manager or browser is executed."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run
import contract as c
import inventory
import windows_native as windows
import linux_native as linux

ROOT = Path(__file__).resolve().parents[2]

def h(text):
    return hashlib.sha256(text.encode()).hexdigest()

def plan():
    p = {"schema": c.SCHEMA, "runId": "source-fixture-only-01", "source": {"commit": h("commit")[:40], "tree": h("tree")[:40], "inventorySHA256": h("inventory")},
         "notBeforeUnix": 1000, "expiresUnix": 2000,
         "targets": {"windows": {"id": "windows-fixture", "machineIdSHA256": h("windows-machine"), "osBuild": "26100", "workspace": "C:\\fixture-private", "sourceRoot": "C:\\source", "sourceInventory": "C:\\inventory.json", "sourceCommitObject": "C:\\commit.object", "publicBootstrap": "C:\\fixture-private\\bootstrap.json"},
                     "linux": {"id": "linux-fixture", "machineIdSHA256": h("linux-machine"), "osBuild": "6.8.0-fixture", "workspace": "/fixture-private", "sourceRoot": "/source", "sourceInventory": "/inventory.json", "sourceCommitObject": "/commit.object", "lanConfig": "/private/lan.json", "enrollmentConfig": "/private/enrollment.json", "webRoot": "/web", "webInventory": "/web-inventory.json", "browserRoot": "/browser", "browserInventory": "/browser-inventory.json"}},
         "tls": {"operatorOrigin": "https://operator.fixture.internal:8443", "agentOrigin": "https://agent.fixture.internal:8444", "custodian": "fixture-custodian", "privateNetworkApprovalRef": "fixture-network", "serverCertificateSHA256": h("public-certificate"), "managerInstanceId": "manager_"+h("manager")[:32], "issuerFingerprint": h("issuer"), "bootstrapServerCASHA256": h("serverca"), "bootstrapIssuerRootSHA256": h("issuerroot")},
         "artifacts": {}, "phases": {}, "syntheticEvent": {}}
    for name in ("setup", "service", "setupManifest", "setupSourceInputs", "manager", "webInventory", "browserInventory", "node", "chromium"):
        path = ("C:\\" + name) if name.startswith("setup") or name == "service" else "/" + name
        p["artifacts"][name] = {"path": path, "sha256": h(name)}
    p["artifacts"]["webInventory"]["path"] = "/web-inventory.json"
    p["artifacts"]["browserInventory"]["path"] = "/browser-inventory.json"
    for phase in c.PHASES:
        p["phases"][phase] = {"approvalRef": "fixture-only-" + phase, "targetId": p["targets"]["linux" if phase == "manager-browser" else "windows"]["id"]}
    p["syntheticEvent"] = {"source": "TraceboltParity-" + p["runId"], "eventId": 42, "messageSHA256": h(c.synthetic_message(p["runId"])), "preparationApprovalRef": "fixture-only-event", "messageResourcePath": "C:\\fixture\\event-resource.dll", "messageResourceSHA256": h("fixture-message-resource")}
    return p

class ContractTests(unittest.TestCase):
    def test_valid_contract_is_not_native_evidence(self):
        self.assertIs(c.validate_plan(plan(), 1500).__class__, dict)
        r = c.report(plan(), h("plan"), "setup", {}, "blocked", "contract_rejected", 0)
        self.assertFalse(r["nativeExecution"])
        self.assertFalse(r["fullAcceptance"])
        self.assertFalse(r["manualStatementsAcceptedAsEvidence"])

    def test_duplicate_keys_and_nonfinite_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b'', b'{'):
            with self.subTest(raw=raw), self.assertRaises(c.Rejected): c.strict_json(raw)

    def test_missing_extra_and_wrong_types(self):
        for key in plan():
            p = plan(); del p[key]
            with self.subTest(key=key), self.assertRaises(c.Rejected): c.validate_plan(p, 1500)
        for key in plan():
            p = plan(); p[key] = True
            with self.subTest(key=key), self.assertRaises((c.Rejected, TypeError)): c.validate_plan(p, 1500)
        p = plan(); p['password'] = 'must-not-be-accepted'
        with self.assertRaises(c.Rejected): c.validate_plan(p)

    def test_phase_target_and_artifact_binding(self):
        for phase in c.PHASES:
            p = plan(); p['phases'][phase]['targetId'] = 'another-machine'
            with self.subTest(phase=phase), self.assertRaises(c.Rejected): c.validate_plan(p)
        for name in plan()['artifacts']:
            p = plan(); p['artifacts'][name]['sha256'] = '0' * 64
            with self.subTest(name=name), self.assertRaises(c.Rejected): c.validate_plan(p)
        for key in ('commit', 'tree', 'inventorySHA256'):
            p = plan(); p['source'][key] = 'main'
            with self.subTest(key=key), self.assertRaises(c.Rejected): c.validate_plan(p)

    def test_private_tls_only(self):
        for value in ('http://manager:8443', 'https://localhost:8443', 'https://127.0.0.1:8443', 'https://manager.invalid:8443', 'https://secret@manager:8443', 'https://manager:8443/?token=a', 'https://manager:8443/#x', 'https://manager', 'https://manager:443'):
            p = plan(); p['tls']['operatorOrigin'] = value
            with self.subTest(value=value), self.assertRaises(c.Rejected): c.validate_plan(p)

    def test_same_actual_machine_rejected(self):
        p = plan(); p['targets']['linux']['machineIdSHA256'] = p['targets']['windows']['machineIdSHA256']
        with self.assertRaises(c.Rejected): c.validate_plan(p)

    def test_real_bounded_time(self):
        for now in (999, 2000, 3000):
            with self.subTest(now=now), self.assertRaises(c.Rejected): c.validate_plan(plan(), now)
        for expiry in (1001, 100000):
            p = plan(); p['expiresUnix'] = expiry
            with self.assertRaises(c.Rejected): c.validate_plan(p)

    def test_synthetic_only_selection(self):
        for key, value in (('source','System'), ('eventId',0), ('eventId',65536), ('messageSHA256',h('other event')), ('preparationApprovalRef','')):
            p = plan(); p['syntheticEvent'][key] = value
            with self.subTest(key=key), self.assertRaises(c.Rejected): c.validate_plan(p)
        p = plan(); p['syntheticEvent']['message'] = 'raw text'
        with self.assertRaises(c.Rejected): c.validate_plan(p)

    def test_paths_no_relative_unc_or_traversal(self):
        for value in ('relative', '/private/../secret', '/private/./secret', '/private\nsecret'):
            with self.subTest(value=value), self.assertRaises(c.Rejected): c.absolute(value, 'linux')
        for value in ('relative', r'\\server\share\secret', r'C:\private\..\secret'):
            with self.subTest(value=value), self.assertRaises(c.Rejected): c.absolute(value, 'windows')

    def test_opt_in_needs_each_binding_and_never_ci(self):
        p = plan(); good = types.SimpleNamespace(execute=True,target_id='linux-fixture',phase='manager-browser',approval_reference='fixture-only-manager-browser')
        with patch.dict(os.environ, {}, clear=True), patch('sys.stdin.isatty', return_value=True), patch('sys.flags', types.SimpleNamespace(isolated=True)):
            with patch('sys.dont_write_bytecode', True):
                pass
            with self.assertRaises(c.Rejected) as blocked:
                c.require_native_opt_in(good,'linux',p)
            self.assertEqual(blocked.exception.reason, 'read_admin_native_gate_unavailable')
            for field in ('execute','target_id','phase','approval_reference'):
                a = copy.copy(good); setattr(a,field,None)
                with self.subTest(field=field), self.assertRaises(c.Rejected): c.require_native_opt_in(a,'linux',p)
            for key in ('CI','GITHUB_ACTIONS','TF_BUILD','BUILD_BUILDID'):
                for value in ('true',''):
                    with self.subTest(key=key,value=value),patch.dict(os.environ, {key:value}),self.assertRaises(c.Rejected):c.require_native_opt_in(good,'linux',p)
            with patch('sys.stdin.isatty',return_value=False), self.assertRaises(c.Rejected): c.require_native_opt_in(good,'linux',p)

    def test_current_setup_is_blocked_before_any_native_operation(self):
        with patch.object(windows, "layout") as layout, patch.object(windows, "inspect") as inspect, patch.object(windows.subprocess, "Popen") as launch:
            checks = {}
            with self.assertRaises(c.Rejected) as blocked:
                windows.operate(plan(), "setup", checks)
            self.assertEqual(blocked.exception.reason, "read_admin_native_gate_unavailable")
            self.assertEqual(checks, {})
            layout.assert_not_called(); inspect.assert_not_called(); launch.assert_not_called()
        # Parser remains available for historical inert v1 fixtures only.
        self.assertEqual(c.validate_plan(plan())["schema"], c.SCHEMA)

    def test_evidence_rejects_raw_or_invented_checks(self):
        for checks in ({'eventText':'secret'}, {'scm_running':1}, {'manual_pass':True}):
            with self.assertRaises(c.Rejected): c.report(plan(),h('plan'),'setup',checks,'observed_phase','complete',1)
        with self.assertRaises(c.Rejected): c.report(plan(),h('plan'),'setup',{},'PASS','complete',1)
        r = c.report(plan(),h('plan'),'setup',{k:True for k in c.REQUIRED_CHECKS['setup']},'observed_phase','complete',1)
        self.assertTrue(r['nativeExecution']); self.assertFalse(r['fullAcceptance'])
        self.assertNotIn('C:\\', c.canonical(r).decode())

    def test_exact_inventory_tree_and_drift(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)/'source'; root.mkdir(); (root/'x').write_bytes(b'x'); (root/'empty').write_bytes(b'')
            rows = inventory.inventory(root); raw = c.canonical(rows); manifest = Path(base)/'inventory'; manifest.write_bytes(raw)
            c.verify_inventory(root,manifest,c.digest(raw),c.inventory_tree(rows))
            (root/'x').write_bytes(b'y')
            with self.assertRaises(c.Rejected): c.verify_inventory(root,manifest,c.digest(raw))
            (root/'x').write_bytes(b'x'); (root/'extra').write_bytes(b'extra')
            with self.assertRaises(c.Rejected): c.verify_inventory(root,manifest,c.digest(raw))

    @unittest.skipIf(os.name == 'nt','POSIX mode and symlink source fixture')
    def test_inventory_rejects_modes_links_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)/'source'; root.mkdir(); f=root/'x'; f.write_bytes(b'x')
            raw=c.canonical(inventory.inventory(root)); manifest=Path(base)/'inventory';manifest.write_bytes(raw)
            f.chmod(0o755)
            with self.assertRaises(c.Rejected): c.verify_inventory(root,manifest,c.digest(raw))
            f.chmod(0o644); (root/'linked').symlink_to(f)
            with self.assertRaises(c.Rejected): inventory.inventory(root)
            (root/'linked').unlink(); os.link(f,root/'hard')
            with self.assertRaises(c.Rejected): inventory.inventory(root)

    def test_dependency_nested_nodes_are_bound(self):
        with tempfile.TemporaryDirectory() as base:
            root=Path(base)/'runtime'; root.mkdir(); nested=root/'node_modules'/'x'/'node_modules'/'y'; nested.mkdir(parents=True); (nested/'index.js').write_bytes(b'export {}')
            raw=c.canonical(inventory.inventory(root)); manifest=Path(base)/'inventory';manifest.write_bytes(raw)
            c.verify_inventory(root,manifest,c.digest(raw),dependencies=True)
            (nested/'index.js').write_bytes(b'changed')
            with self.assertRaises(c.Rejected): c.verify_inventory(root,manifest,c.digest(raw),dependencies=True)

    def test_phase_claim_is_create_only(self):
        with tempfile.TemporaryDirectory() as base:
            p=plan();p['targets']['linux']['workspace']=base
            c.begin_phase(p,'linux','manager-browser',h('p'))
            with self.assertRaises(c.Rejected): c.begin_phase(p,'linux','manager-browser',h('p'))
            value=json.loads((Path(base)/(p['runId']+'-manager-browser.started.json')).read_text())
            self.assertEqual(set(value),{'planSHA256','phase','startedUnix','startedMonotonic'})

    def test_symlink_output_and_public_workspace_rejected(self):
        if os.name == 'nt': self.skipTest('POSIX path fixture')
        with tempfile.TemporaryDirectory() as base:
            folder=Path(base)/'public';folder.mkdir(mode=0o755)
            with self.assertRaises(c.Rejected): c.write_new(folder/'evidence',{})
            folder.chmod(0o700);(folder/'evidence').symlink_to(Path(base)/'elsewhere')
            with self.assertRaises(c.Rejected): c.write_new(folder/'evidence',{})

    def test_cli_default_and_bad_plan_never_call_adapters(self):
        with patch.object(linux,'operate',side_effect=AssertionError('must not execute')),patch.object(windows,'operate',side_effect=AssertionError('must not execute')):
            with tempfile.TemporaryDirectory() as base:
                path=Path(base)/'plan'; path.write_bytes(c.canonical(plan()))
                self.assertEqual(run.main(['--plan',str(path),'--plan-sha256',h('wrong'),'--check-plan']),2)

    def test_sources_no_workflow_native_invocation(self):
        workflows=(ROOT/'.github/workflows').glob('*.yml')
        for p in workflows:
            for line in p.read_text().splitlines():
                if 'windows_linux_native_parity' in line:
                    self.assertNotIn('--execute',line); self.assertNotIn('run.py',line)
        for name in ('run.py','contract.py','windows_native.py','linux_native.py'):
            source=(Path(__file__).parent/name).read_text()
            self.assertNotIn('shell=True',source)
            self.assertNotIn('verify=False',source)
        self.assertNotIn('--upgrade', (Path(__file__).parent/'windows_native.py').read_text())

class WindowsCommandFixtureTests(unittest.TestCase):
    def test_exact_grant_commands_and_independence(self):
        # Inert command seam only. This is not SCM/WUA/native acceptance evidence.
        for phase in windows.GRANTS:
            state={'service':4,'event':phase in {'updates-enable','event-disable'},'updates':phase in {'event-disable','updates-disable'}}
            calls=[]
            def cmd(exe,args,expires,limit=65536,expected_sha256=None):
                calls.append(args)
                mode=args[0][2:]
                if mode=='stop':state['service']=1;return {}
                if mode=='start':state['service']=4;return {}
                kind='event' if mode.startswith('event-content') else 'updates'
                if mode.endswith('-enable'):state[kind]=True
                if mode.endswith('-disable'):state[kind]=False
                return {'scope':windows.GRANTS['event-enable' if kind=='event' else 'updates-enable'][3],'enabled':state[kind],'existingStatePreserved':True}
            p=plan();p['targets']['windows']['sourceRoot']=str(ROOT)
            with patch.object(windows,'layout',return_value=(Path('/fixture-app'),Path('/fixture-data'))),patch.object(windows,'inspect'),patch.object(windows,'wait_state'),patch.object(windows,'command',side_effect=cmd):
                checks={};windows.operate(p,phase,checks)
            expected=windows.GRANTS[phase]; flags=['--'+expected[0],'--apply']+(['--'+expected[1]] if expected[1] else [])
            self.assertIn(flags,calls);self.assertTrue(checks['grant_independence'])
            self.assertEqual(calls[0],['--stop','--apply']);self.assertEqual(calls[-1],['--start','--apply'])

    def test_failed_grant_does_not_restart_or_retry(self):
        with patch.object(windows,'layout',return_value=(Path('/fixture-app'),Path('/fixture-data'))),patch.object(windows,'inspect'),patch.object(windows,'wait_state'),patch.object(windows,'command',side_effect=c.Rejected('native_operation_failed')) as call:
            p=plan();p['targets']['windows']['sourceRoot']=str(ROOT)
            with self.assertRaises(c.Rejected):windows.operate(p,'event-disable',{})
            self.assertEqual(call.call_count,1)

if __name__=='__main__':unittest.main()
