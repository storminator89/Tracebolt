#!/usr/bin/env python3
"""Separate opt-in existing-agent own-restart gate. No native action by default.
Only --check-plan is source-only. --execute requires separate external approval,
real selected targets and exact pins; a reference or flag is not authorization.
"""
from __future__ import annotations
import sys
if not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('CONTRACT_REJECTED: invoke with Python -I -B.')
import argparse
import os
from pathlib import Path
import signal
import time
_here=Path(__file__).resolve().parent
if sys.pycache_prefix is not None or (_here/'__pycache__').exists() or any(_here.glob('*.py[co]')):
    raise SystemExit('CONTRACT_REJECTED: cached modules are not allowed.')
def source_only(name):
    import types
    path=_here/(name+'.py')
    if path.is_symlink() or not path.is_file():raise SystemExit('CONTRACT_REJECTED: local source unavailable.')
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module
source_only('contract')
from contract import *

def bootstrap_helpers():
    # ACL validation happens inside load_plan, before role adapter selection.
    # Explicit source loading is required because -I excludes this directory.
    source_only('supervisor')
    if os.name=='nt':source_only('windows_native')

class Parser(argparse.ArgumentParser):
    def error(self,message):self.exit(2,'CONTRACT_REJECTED: invalid invocation; no host action attempted.\n')

def main(argv=None):
    parser=Parser(description=__doc__,allow_abbrev=False)
    parser.add_argument('--plan',required=True);parser.add_argument('--plan-sha256',required=True)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-plan',action='store_true');group.add_argument('--execute',action='store_true')
    parser.add_argument('--role',choices=('windows','linux'));parser.add_argument('--target-id')
    parser.add_argument('--approval-reference');parser.add_argument('--transfer-approval-reference');parser.add_argument('--baseline-sha256')
    args=parser.parse_args(argv);p=None;workspace=None;started=False;cancel=[False];old_handlers={}
    try:
        if args.execute:
            try:reject_ci(os.environ)
            except Rejected:
                print('CONTRACT_REJECTED: CI environment; no host action attempted.');return 2
        bootstrap_helpers()
        p=load_plan(args.plan,args.plan_sha256)
        if args.check_plan:
            need(all(getattr(args,k) is None for k in ('role','target_id','approval_reference','transfer_approval_reference','baseline_sha256')))
            print('SOURCE CONTRACT VALIDATED ONLY; no native execution or authorization established.');return 0
        need(sys.version_info>=(3,12) and args.role is not None and args.execute)
        reject_ci(os.environ)
        need(sys.stdin.isatty(),'secure_handoff_required')
        role=args.role;t=p['targets'][role];need(args.target_id==t['id'])
        key='ownRestartTwoInvocations' if role=='windows' else 'linuxBrowserReadOnly'
        need(args.approval_reference==p['approvals'][key] and args.transfer_approval_reference==p['approvals']['publicBoundaryTransfers'])
        need((args.baseline_sha256 is not None)==(role=='windows'))
        need(Path(t['sourcePaths']['harness']['root'])/'tests/windows_own_restart_native'==_here,'source_mismatch')
        adapter=source_only(role+'_native');adapter.verify_target(t)
        workspace=private_directory(t['workspace']);verify_sources(p,role)
        budget=RunBudget(p['expiresUnix']);budget.check()
        for signum in (signal.SIGINT,signal.SIGTERM):
            old_handlers[signum]=signal.signal(signum,lambda *_:cancel.__setitem__(0,True))
        with adapter.target_lock():
            for suffix in ('-case.result.json','-completion.json','-browser.json'):
                need(not (workspace/(p['runId']+suffix)).exists(),'phase_replay')
            write_new(workspace/(p['runId']+'-'+role+'-harness.started.json'),{'schema':SCHEMA+'.started','runId':p['runId'],'planSHA256':args.plan_sha256,'role':role,'startedUnix':time.time_ns()//10**9,'fullAcceptance':False})
            started=True
            notify=lambda text:print(text,flush=True)
            if role=='windows':
                sha(args.baseline_sha256)
                raw=read_regular(trusted_path(p['handoff']['windowsBaseline'],secret=True),32768)
                need(digest(raw)==args.baseline_sha256)
                validate_baseline(strict_json(raw),p,args.plan_sha256)
                confirm_windows(p,lambda:cancel[0]);budget.check()
                native=adapter.observe_controller(p,args.plan_sha256,args.baseline_sha256,budget,lambda:cancel[0],notify)
                budget.check();need(not cancel[0],'unknown_intervention_required');verify_sources(p,role)
                boundary=completion(p,args.plan_sha256,args.baseline_sha256,native)
                output=workspace/(p['runId']+'-completion.json');write_new(output,boundary)
                notify('NATIVE SUBSET OBSERVED. Completion SHA256: '+digest(canonical(boundary))+'\nTransfer only the generated completion to the approved Linux path. Manager acceptance remains pending.')
            else:
                report=adapter.observe_browser(p,args.plan_sha256,budget,lambda:cancel[0],notify)
                budget.check();need(not cancel[0],'unknown_intervention_required');verify_sources(p,role)
                write_new(workspace/(p['runId']+'-case.result.json'),report)
                notify('PASSED LIMITED OWN-RESTART SUBSET: held-lease refusal, exact old-process exit, new Running process, receipt/public identity retained, and two advancing fresh accepted reports. Full acceptance: false. See explicit omissions.')
        return 0
    except (Rejected,OSError,ValueError,KeyError,TypeError):
        if started:
            try:write_new(workspace/(p['runId']+'-'+args.role+'-unknown.json'),{'schema':SCHEMA+'.unknown','runId':p['runId'],'planSHA256':args.plan_sha256,'status':'unknown-intervention-required','fullAcceptance':False,'omissions':OMISSIONS})
            except (OSError,Rejected):pass
        print('UNKNOWN_INTERVENTION_REQUIRED' if started else 'CONTRACT_REJECTED: no host action attempted.',flush=True)
        return 2
    finally:
        for signum,handler in old_handlers.items():signal.signal(signum,handler)

if __name__=='__main__':raise SystemExit(main())
