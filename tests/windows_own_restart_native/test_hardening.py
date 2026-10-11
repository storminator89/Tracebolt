"""Inert pipe/process-state adapters only: cannot run the native entry point."""
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from contract import Rejected, reject_ci
from supervisor import drain

class Budget:
    def __init__(self,fail=False):self.fail=fail
    def check(self):
        if self.fail:raise Rejected('deadline')
class Process:
    def __init__(self,fault=False):self.end=time.monotonic()+0.15;self.fault=fault;self.calls=0
    def poll(self):
        self.calls+=1
        if self.fault and self.calls==1:raise OSError('injected poll failure')
        return 0 if time.monotonic()>=self.end else None
    def kill(self):raise AssertionError('kill forbidden')
    def terminate(self):raise AssertionError('terminate forbidden')

class Hardening(unittest.TestCase):
    def observe(self,output=b'{}\n',budget=None,poll_fault=False,notify=lambda _:None,cancelled=lambda:False,inspect_report=None):
        pipes={};writers=[]
        for key in ('stdout','stderr','report'):
            r,w=os.pipe();pipes[key]=r
            def write(fd=w,data=output if key=='report' else b''):
                try:
                    for offset in range(0,len(data),4096):os.write(fd,data[offset:offset+4096])
                finally:os.close(fd)
            thread=threading.Thread(target=write);thread.start();writers.append(thread)
        cancelled_calls=[];proc=Process(poll_fault)
        try:result=drain(proc,pipes,budget or Budget(),cancelled,lambda:cancelled_calls.append(True),notify,limit=8192,inspect_report=inspect_report)
        finally:
            for fd in pipes.values():os.close(fd)
            for thread in writers:thread.join()
        self.assertGreaterEqual(time.monotonic(),proc.end);self.assertGreater(proc.calls,1)
        return result,cancelled_calls
    def test_finite_success(self):
        r,c=self.observe();self.assertFalse(r.unknown);self.assertEqual(r.report,b'{}\n');self.assertEqual(c,[])
    def test_flood_bounded_drained_and_irreversible(self):
        r,c=self.observe(b'x'*(1<<20));self.assertTrue(r.unknown);self.assertEqual(len(r.report),8192);self.assertEqual(r.counts['report'],1<<20);self.assertEqual(len(c),1)
    def test_report_fault_cancels_before_controller_exit(self):
        def invalid(_):raise Rejected('unknown_intervention_required')
        r,c=self.observe(inspect_report=invalid);self.assertTrue(r.unknown);self.assertEqual(len(c),1)
    def test_late_completion_never_clears_unknown(self):
        r,c=self.observe(budget=Budget(True));self.assertTrue(r.unknown);self.assertEqual(r.returncode,0);self.assertEqual(len(c),1)
    def test_broken_notification_still_observes_exit(self):
        def broken(_):raise BrokenPipeError()
        r,c=self.observe(budget=Budget(True),notify=broken);self.assertTrue(r.unknown);self.assertEqual(r.returncode,0)
    def test_poll_fault_still_observes_exit(self):
        r,c=self.observe(poll_fault=True);self.assertTrue(r.unknown);self.assertEqual(r.returncode,0)
    def test_cancel_has_no_second_action(self):
        r,c=self.observe(cancelled=lambda:True);self.assertTrue(r.unknown);self.assertEqual(len(c),1)
    def test_run_refuses_nonisolated_and_unknown_flags(self):
        script=str(Path(__file__).with_name('run.py'))
        p=subprocess.run([sys.executable,'-B',script,'--manual-pass'],capture_output=True)
        self.assertEqual(p.returncode,1);self.assertIn(b'Python -I -B',p.stderr)
        p=subprocess.run([sys.executable,'-I','-B',script,'--plan','unused','--plan-sha256','unused','--execute','--manual-pass'],capture_output=True)
        self.assertEqual(p.returncode,2);self.assertIn(b'no host action attempted',p.stderr)
    def test_isolated_bootstrap_and_linux_cleanup_use_only_local_source(self):
        script=Path(__file__).with_name('run.py').resolve()
        probe=r"""
import os, runpy, sys, tempfile, types
from pathlib import Path
entry=Path(sys.argv[1]); ns=runpy.run_path(str(entry),run_name='source_probe')
assert str(entry.parent) not in sys.path
ns['bootstrap_helpers']()
assert sys.modules['supervisor'].__file__==str(entry.with_name('supervisor.py'))
linux=ns['source_only']('linux_native')
class PipeInput:
    closed=False
    def write(self,_):raise OSError('source-only write fault')
    def flush(self):pass
    def close(self):self.closed=True
class Process:
    def __init__(self):
        self.stdin=PipeInput()
        r,w=os.pipe();os.close(w);self.stdout=os.fdopen(r,'rb')
        r,w=os.pipe();os.close(w);self.stderr=os.fdopen(r,'rb')
    def poll(self):return 0
proc=Process()
linux.subprocess=types.SimpleNamespace(Popen=lambda *a,**k:proc,PIPE=-1)
linux.prepare=lambda *a:{}
linux.binding_hash=lambda p:'01'*32
class Budget:
    def check(self):pass
with tempfile.TemporaryDirectory() as tmp:
    p={'runId':'source-only-run','targets':{'linux':{'workspace':tmp,'sourcePaths':{'harness':{'root':str(entry.parents[2])}}}},'handoff':{'linuxCompletion':tmp+'/completion.json'},'artifacts':{'node':{'path':'never-launched'}}}
    try:linux.observe_browser(p,'00'*32,Budget(),lambda:False,lambda _:None)
    except OSError as error:assert str(error)=='source-only write fault'
    else:raise AssertionError('expected pure injected setup failure')
assert proc.stdin.closed and proc.stdout.closed and proc.stderr.closed
# Simulate just the platform-selector value; never change the real os module,
# instantiate a Windows path or call a Windows API.
ns['bootstrap_helpers'].__globals__['os']=types.SimpleNamespace(name='nt')
ns['bootstrap_helpers']()
win=sys.modules['windows_native'];contract=sys.modules['contract'];called=[]
win.require_safe_acl=lambda *a,**k:called.append('acl-helper-resolved')
fake=types.SimpleNamespace(parents=[])
contract.no_links=lambda _:fake;contract.os=types.SimpleNamespace(name='nt')
assert contract.trusted_path('unopened-test-only-path') is fake
assert called==['acl-helper-resolved']
print('ISOLATED_SOURCE_BOOTSTRAP_AND_CLEANUP_OK')
"""
        result=subprocess.run([sys.executable,'-I','-B','-c',probe,str(script)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode());self.assertIn(b'ISOLATED_SOURCE_BOOTSTRAP_AND_CLEANUP_OK',result.stdout)
        source=script.read_text();self.assertLess(source.index('        bootstrap_helpers()'),source.index('        p=load_plan('))
    def test_ci_presence_before_plan_read(self):
        script=str(Path(__file__).with_name('run.py'))
        keys=['CI','ci','CONTINUOUS_INTEGRATION','BUILD_BUILDID','TF_BUILD','TEAMCITY_VERSION','JENKINS_URL','HUDSON_URL','GITHUB_ACTIONS','GITLAB_CI','CIRCLE_CI','BUILDKITE_JOB','TRAVIS_JOB','RUNNER_OS']
        for key in keys:
            with self.assertRaises(Rejected):reject_ci({key:'false'})
            p=subprocess.run([sys.executable,'-I','-B',script,'--plan','not-even-a-local-path','--plan-sha256','unused','--execute'],capture_output=True,env={**os.environ,key:'false'})
            self.assertEqual(p.returncode,2);self.assertIn(b'CI environment',p.stdout)
    def test_manager_namespace_mismatch(self):
        from linux_native import same_namespaces
        same_namespaces(123,lambda path:'same:'+path.rsplit('/',1)[1])
        for name in ('net','mnt','user'):
            def link(path):return 'different' if path=='/proc/123/ns/'+name else 'same'
            with self.assertRaises(Rejected):same_namespaces(123,link)
    def test_native_entry_and_read_only_observer_source_wiring(self):
        root=Path(__file__).parents[2]
        native=(root/'cmd/windows-service/restart_acceptance_native_windows_test.go').read_text()
        observer=(root/'cmd/windows-service/restart_acceptance_observer_windows_test.go').read_text()
        token=(root/'cmd/windows-service/restart_acceptance_token_windows_test.go').read_text()
        portable=(root/'cmd/windows-service/restart_acceptance_contract_test.go').read_text()
        self.assertTrue(native.startswith('//go:build windows && tracebolt_restart_acceptance'))
        self.assertIn('func TestOwnRestartNativeAcceptance(',native)
        self.assertEqual(native.count('!pins.launchReady()'),2)
        self.assertIn('sequence.BeginRejection()',native);self.assertIn('sequence.BeginRestart()',native)
        self.assertIn('windows.OpenProcess(restartProcessRights, false, pid)',observer)
        self.assertIn('windows.OpenService(scm, windows.StringToUTF16Ptr(windowsservice.Name), restartObserverRights)',observer)
        self.assertIn('windows.OpenProcessToken(process, restartTokenRights, &token)',token)
        for expected in ('restartObserverRights uint32 = 0x0005','restartProcessRights uint32 = 0x00101000','restartTokenRights uint32 = 0x0008'):
            self.assertIn(expected,portable)
        for forbidden in ('PROCESS_TERMINATE','TOKEN_ADJUST_PRIVILEGES','SeDebugPrivilege','SERVICE_ALL_ACCESS','SERVICE_START','SERVICE_STOP','os.ReadFile('):
            self.assertNotIn(forbidden,observer+token)
        bridge=(Path(__file__).parent/'windows_native.py').read_text()
        self.assertIn("'-test.run=^TestOwnRestartNativeAcceptance$','-test.timeout=0'",bridge)
        entry=(Path(__file__).parent/'run.py').read_text()
        self.assertLess(entry.index('confirm_windows(p,lambda:cancel[0])'),entry.index('native=adapter.observe_controller'))
        workflow=(root/'.github/workflows/windows-restart-source.yml').read_text()
        self.assertNotIn('run.py --execute',workflow);self.assertNotIn('-run \'^TestOwnRestartNativeAcceptance',workflow)
    def test_no_legacy_operating_paths(self):
        root=Path(__file__).parent
        for name in ('run.py','windows_native.py','linux_native.py'):
            code=(root/name).read_text()
            for forbidden in ('windows_linux_native_parity import','endpoint_binding(','.kill(','.terminate(','.communicate('):self.assertNotIn(forbidden,code)

if __name__=='__main__':unittest.main()
