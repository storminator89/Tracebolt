"""Inert regressions for rejected source/host-action seams; never native acceptance."""
import contextlib
import ctypes
import struct
import types
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run
import contract as c
import inventory
import windows_native as windows
import linux_native as linux
from test_contract import plan, h, ROOT

class HardeningTests(unittest.TestCase):
    def test_windows_alias_ads_and_runid_rejected(self):
        for path in (r'C:\safe\file:stream', r'C:\safe\CON.txt', r'C:\safe\x.', r'C:\safe\x ', r'C:\safe\\x', r'C:\safe\x"y', 'C:/safe/x'):
            with self.subTest(path=path), self.assertRaises(c.Rejected): c.absolute(path,'windows')
        for value in ('run:stream','..','run.','run/path'):
            p=plan();p['runId']=value
            with self.subTest(value=value),self.assertRaises(c.Rejected):c.validate_plan(p)

    def test_plan_lexical_windows_paths_reject_before_open(self):
        for path in (r'\\host\share\plan.json', r'C:\safe\plan.json:secret', r'C:\safe\plan.json.', 'relative'):
            with self.subTest(path=path),self.assertRaises(c.Rejected):c.local_input_path(path,windows=True)
        self.assertEqual(c.local_input_path(r'C:\safe\plan.json',windows=True),r'C:\safe\plan.json')
        with patch.object(c,'local_input_path',side_effect=c.Rejected()),patch.object(c,'read_regular',side_effect=AssertionError('must not open')):
            with self.assertRaises(c.Rejected):c.load_plan('rejected',h('p'))

    def test_commit_object_binds_actual_tree(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'commit'; raw=('tree '+h('tree')[:40]+'\nauthor Public Fixture <fixture@example.invalid> 1 +0000\n\nsource fixture\n').encode();f.write_bytes(raw)
            source={'commit':c.git_object('commit',raw).hex(),'tree':h('tree')[:40]}
            c.verify_commit(f,source)
            for changed in ({**source,'tree':h('different')[:40]},{**source,'commit':h('wrong')[:40]}):
                with self.assertRaises(c.Rejected):c.verify_commit(f,changed)

    def test_source_package_shadow_never_executes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            for name in ('run.py','contract.py'):shutil.copy2(Path(__file__).parent/name,p/name)
            package=p/'contract';package.mkdir();(package/'__init__.py').write_text('raise RuntimeError("SHADOW_EXECUTED")')
            (p/'json.py').write_text('raise RuntimeError("STDLIB_SHADOW_EXECUTED")')
            result=subprocess.run([sys.executable,'-I','-B',str(p/'run.py'),'--help'],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0);self.assertNotIn(b'SHADOW_EXECUTED',result.stdout+result.stderr)

    def test_cached_module_directory_fails_before_import(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            for name in ('run.py','contract.py'):shutil.copy2(Path(__file__).parent/name,p/name)
            (p/'__pycache__').mkdir()
            result=subprocess.run([sys.executable,'-I','-B',str(p/'run.py'),'--help'],capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertNotIn(b'Traceback',result.stdout+result.stderr)

    def test_no_isolation_refuses_before_imports(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);shutil.copy2(Path(__file__).parent/'run.py',p/'run.py')
            (p/'argparse.py').write_text('raise RuntimeError("SHADOW_EXECUTED")')
            result=subprocess.run([sys.executable,'-B',str(p/'run.py'),'--help'],capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertNotIn(b'SHADOW_EXECUTED',result.stdout+result.stderr)

    def test_used_phase_cannot_be_hand_written_five_key_pass(self):
        forged={'planSHA256':h('p'),'phase':'setup','status':'observed_phase','nativeExecution':True,'fullAcceptance':False}
        with self.assertRaises(c.Rejected):c.validate_phase_report(forged,plan(),h('p'),'setup')
        correct=c.report(plan(),h('p'),'setup',{k:True for k in c.REQUIRED_CHECKS['setup']},'observed_phase','complete',1)
        c.validate_phase_report(correct,plan(),h('p'),'setup')
        for key in ('nativeExecution','fullAcceptance','manualStatementsAcceptedAsEvidence','rawDataExported','elapsedSeconds'):
            mutated=dict(correct);mutated[key]=int(correct[key]) if type(correct[key]) is bool else True
            with self.subTest(key=key),self.assertRaises(c.Rejected):c.validate_phase_report(mutated,plan(),h('p'),'setup')
        for key in ('source','artifactSHA256','schema','checks'):
            mutated=dict(correct);mutated.pop(key)
            with self.subTest(key=key),self.assertRaises(c.Rejected):c.validate_phase_report(mutated,plan(),h('p'),'setup')

    def test_monotonic_budget_rejects_rollback_and_expiry(self):
        with patch.object(c.time,'time',return_value=100),patch.object(c.time,'monotonic',return_value=200):b=c.RunBudget(110)
        with patch.object(c.time,'time',return_value=99),patch.object(c.time,'monotonic',return_value=202),self.assertRaises(c.Rejected):b.remaining()
        with patch.object(c.time,'time',return_value=111),patch.object(c.time,'monotonic',return_value=211),self.assertRaises(c.Rejected):b.remaining()

    def test_wrong_installed_binary_is_never_launched(self):
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'fake.exe';exe.write_bytes(b'not the approved image')
            with patch.object(windows.subprocess,'Popen',side_effect=AssertionError('must not run')) as launch:
                with self.assertRaises(c.Rejected):windows.command(exe,['--inspect'],time.time()+30,expected_sha256=h('other'))
                launch.assert_not_called()

    def test_command_overflow_and_read_failure_are_not_success(self):
        class Pipe:
            def fileno(self):return 101
            def close(self):pass
        class Child:
            stdout=Pipe();returncode=0
            def poll(self):return 0
            def kill(self):pass
            def wait(self,timeout=None):return 0
        with tempfile.TemporaryDirectory() as d:
            exe=Path(d)/'approved.exe';exe.write_bytes(b'image')
            for data in ((b'{}\n'+b'x'*32),OSError('PRIVATE PROCESS DETAIL')):
                with patch.object(windows,'windows_directory',return_value='C:\\Windows'),patch.object(windows.subprocess,'Popen',return_value=Child()),patch.object(windows.os,'set_blocking'),patch.object(windows.os,'read',side_effect=data if isinstance(data,Exception) else [data]),contextlib.redirect_stderr(io.StringIO()) as err:
                    with self.assertRaises((c.Rejected,OSError)):windows.command(exe,['--inspect'],time.time()+30,limit=8,expected_sha256=c.digest(b'image'))
                    self.assertEqual(err.getvalue(),'')

    def test_windows_acl_inherited_only_and_mutation_masks(self):
        trusted={'SYSTEM'}
        self.assertTrue(windows.acl_grant_safe('SYSTEM',0xFFFFFFFF,trusted))
        self.assertTrue(windows.acl_grant_safe('other',0x120089,trusted))
        self.assertFalse(windows.acl_grant_safe('other',0x1F01FF,trusted))
        self.assertFalse(windows.acl_grant_safe('other',0x40,trusted,ancestor=True))
        self.assertTrue(windows.acl_grant_safe('other',0x4,trusted,ancestor=True))
        self.assertFalse(windows.acl_grant_safe('other',0x120089,trusted,private=True))

    def test_private_material_metadata_check_never_reads_secret(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'key';p.write_bytes(b'fixture-secret-never-read');p.chmod(0o600)
            with patch.object(linux,'read_regular',side_effect=AssertionError('private content copied')):
                self.assertIsNone(linux.protected_file(p,secret=True))

    def test_exact_builder_source_input_schema_and_completeness(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('source_build_fixture',ROOT/'deploy/windows-setup/build-setup.py')
        build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
        files,_=build.source_inputs(ROOT)
        document={'schemaVersion':'tracebolt.windows-setup-source-inputs.v1','files':files}
        windows.validate_setup_inputs(document,ROOT)
        for mutated in (files,{'schemaVersion':document['schemaVersion'],'files':files[:-1]},{'schemaVersion':'wrong','files':files},{'schemaVersion':document['schemaVersion'],'files':[{'path':r'C:\outside','sha256':h('x'),'size':1}]}):
            with self.assertRaises(c.Rejected):windows.validate_setup_inputs(mutated,ROOT)

    def test_ended_node_without_browser_proof_is_not_cleanup_evidence(self):
        child=type('Child',(),{'returncode':0,'poll':lambda self:0,'wait':lambda self,timeout:0})()
        self.assertTrue(linux.stop_owned(child))
        child.returncode=-9
        self.assertFalse(linux.stop_owned(child))
        # This helper proves direct child termination only; browser proof is a
        # separate strictly checked result field, never inferred from this bool.

    def test_template_is_deliberately_non_executable(self):
        value=c.strict_json((Path(__file__).parent/'plan.template.json').read_bytes())
        with self.assertRaises(c.Rejected):c.validate_plan(value)

    def test_private_workspace_rejects_public_inherit_only_acl(self):
        # Full ctypes parser exercised with synthetic buffers and fake functions.
        class Call:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        acl=(ctypes.c_ushort*4)(2,24,1,0)
        ace=ctypes.create_string_buffer(struct.pack('<BBHI',0,0x08,16,0x1f01ff)+b'FAKESID!')
        def assign(ptr,val):ctypes.cast(ptr,ctypes.POINTER(ctypes.c_void_p))[0]=val
        def named(path,obj,fields,owner,group,dacl,sacl,sd):
            assign(owner,100);assign(dacl,ctypes.addressof(acl));assign(sd,200);return 0
        def getace(dacl,index,ptr):assign(ptr,ctypes.addressof(ace));return 1
        adv=types.SimpleNamespace(GetNamedSecurityInfoW=Call(named),GetAce=Call(getace))
        kernel=types.SimpleNamespace(LocalFree=Call(lambda _:None))
        with patch.object(windows,'libraries',return_value=(adv,kernel)),patch.object(windows,'current_sid',return_value='CURRENT'),patch.object(windows,'sid_string',side_effect=lambda sid:'CURRENT' if (sid.value if isinstance(sid,ctypes.c_void_p) else sid)==100 else 'EVERYONE'):
            windows.require_safe_acl('/synthetic/ancestor',ancestor=True)
            with self.assertRaises(c.Rejected):windows.require_safe_acl('/synthetic/private-parent',private=True)

    def test_expired_linux_validation_never_launches_manager(self):
        p=plan();image=b'\x7fELF\x02\x01'+b'\x00'*12+b'\x3e\x00'+b'path\tlocalrmm/cmd/lan-manager\n'+('build\tvcs.revision='+p['source']['commit']+'\n').encode()+b'build\tvcs.modified=false\n'
        with patch.object(linux,'verify_artifact',return_value=image),patch.object(linux,'verify_executable_header',return_value=image[:64]),patch.object(linux,'verify_inventory'),patch.object(linux,'verify_config',return_value={}),patch.object(linux.Path,'is_file',return_value=True),patch.object(linux,'check_time',side_effect=c.Rejected('deadline')),patch.object(linux.subprocess,'Popen',side_effect=AssertionError('must not launch')) as launch:
            with self.assertRaises(c.Rejected):linux.operate(p,h('p'),{})
            launch.assert_not_called()

    def test_signal_cancellation_is_idempotent_and_restores_handlers(self):
        p=plan();p['expiresUnix']=int(time.time())+600;handlers={};restored=[]
        old=lambda *args:None
        def install(sig,handler):
            if handler is old:restored.append(sig)
            else:handlers[sig]=handler
            return old
        def operate(*args):
            handler=handlers[run.signal.SIGTERM]
            with self.assertRaises(c.Rejected):handler(run.signal.SIGTERM,None)
            handler(run.signal.SIGTERM,None) # repeated signal cannot interrupt cleanup
            raise c.Rejected('native_operation_failed')
        adapter=types.SimpleNamespace(verify_target=lambda _:None,target_lock=contextlib.nullcontext,operate=operate)
        with patch.object(run,'load_plan',return_value=p),patch.object(run,'require_native_opt_in'),patch.object(run,'_source_only',return_value=adapter),patch.object(run,'trusted_path'),patch.object(run,'private_directory'),patch.object(run,'verify_commit'),patch.object(run,'verify_inventory'),patch.object(run,'previous_phase'),patch.object(run,'begin_phase',return_value=Path('/fixture-private')),patch.object(run,'write_new'),patch.object(run.signal,'signal',side_effect=install),patch.object(run,'need'),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run.main(['--plan','/plan','--plan-sha256',h('p'),'--execute','--target-id','linux-fixture','--phase','manager-browser','--approval-reference','fixture-only-manager-browser']),2)
        self.assertEqual(set(restored),{run.signal.SIGTERM,run.signal.SIGINT})

    def test_linux_owned_child_timeout_cannot_certify_browser_cleanup(self):
        class Child:
            returncode=None
            def __init__(self):self.actions=[]
            def poll(self):return None
            def terminate(self):self.actions.append('terminate')
            def kill(self):self.actions.append('kill')
            def wait(self,timeout):
                self.actions.append(('wait',timeout))
                if timeout==45:raise subprocess.TimeoutExpired('inert-child',timeout)
                self.returncode=-9
        child=Child();self.assertFalse(linux.stop_owned(child))
        self.assertEqual(child.actions,['terminate',('wait',45),'kill',('wait',10)])

    def test_large_executable_limit_and_streaming_header(self):
        # No large allocation or executable launch. Oversize metadata fails before open.
        mode=0o100755
        fake=types.SimpleNamespace(stat=lambda:types.SimpleNamespace(st_mode=mode,st_nlink=1,st_size=(512<<20)+1))
        with patch.object(c,'trusted_path',return_value=fake),patch.object(c.os,'open',side_effect=AssertionError('oversize must not open')):
            with self.assertRaises(c.Rejected):c.verify_executable_header({'path':'/fake','sha256':h('x')})
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'image';raw=b'\x7fELF\x02\x01'+b'x'*122;path.write_bytes(raw)
            self.assertEqual(c.verify_executable_header({'path':str(path),'sha256':c.digest(raw)}),raw[:64])
            with self.assertRaises(c.Rejected):c.verify_executable_header({'path':str(path),'sha256':h('wrong')})
        self.assertLess(326880088,512<<20) # modern direct Chromium fits the explicit ceiling

if __name__=='__main__':unittest.main()
