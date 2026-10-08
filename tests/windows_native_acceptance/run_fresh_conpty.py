#!/usr/bin/env python3
"""Distinct manual-only fresh test launcher; no work occurs on import."""
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
_spec=importlib.util.spec_from_file_location("_fresh_shared_runner",Path(__file__).with_name("run_acceptance.py"))
shared=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)
require=shared.require
PROFILE="fresh-read-conpty-v1"
OWNER="storminator89"
OWNER_ID="30489872"
REPORT_NAME="tracebolt-windows-fresh-conpty-acceptance.json"
APPROVALS=("SERVICES","IDENTITY","APP_ACLS","FIVE_READ_SCOPES","SYNTHETIC_CONSOLE","LOOPBACK_TLS","STOP_OWNED_SERVICE","RETAIN_FOR_VM_DISPOSAL")
FALSE_FIELDS={"humanEntry","humanManagerApproval","productionManagerExercised","productionIngressExercised","sharedDashboardExercised","osRebootExercised","nativeInterruptionAcceptance","applicationCleanupVerified","vmDisposalVerified"}
PASS_FIELDS={"approvalValidated","nativeActionsAttempted","hiddenConsoleExercised","syntheticInput","noEchoVerified","disabledStageVerified","freshOrchestrationAcceptance","receiptAndGrantsVerified","limitedServiceTokenVerified","ownedChildReaped","consoleClosed","fixtureClosed","appStateRetainedForVMDisposal","ownedServiceStopped","automaticStartConfigurationRetained","serviceAndAppStateRetained","platformDisposalRequired"}
BOOL_FIELDS=FALSE_FIELDS|PASS_FIELDS|{"serviceDisabled"}

def authorize(env):
    source=env.get("TRACEBOLT_FRESH_SOURCE","")
    require(shared.valid_source(source) and env.get("GITHUB_SHA")==source)
    require(env.get("TRACEBOLT_FRESH_PROFILE")==PROFILE)
    require(env.get("GITHUB_EVENT_NAME")=="workflow_dispatch" and env.get("GITHUB_REPOSITORY")=="storminator89/Tracebolt")
    require(all(env.get(k)==OWNER for k in ("GITHUB_REPOSITORY_OWNER","GITHUB_ACTOR","GITHUB_TRIGGERING_ACTOR")))
    require(all(env.get(k)==OWNER_ID for k in ("GITHUB_REPOSITORY_OWNER_ID","GITHUB_ACTOR_ID")))
    require(env.get("GITHUB_ACTIONS")=="true" and env.get("RUNNER_OS")=="Windows" and env.get("RUNNER_ENVIRONMENT")=="github-hosted")
    require(all(env.get("TRACEBOLT_FRESH_APPROVE_"+name)=="true" for name in APPROVALS))
    require(re.fullmatch(r"[1-9][0-9]{0,23}",env.get("GITHUB_RUN_ID","")) and env.get("GITHUB_RUN_ATTEMPT")=="1")
    return source

def bind_run(env,source,test,service,host,deadline):
    """Bind owner-approved run scope to observed non-secret facts; no new consent."""
    require(authorize(env)==source and re.fullmatch(r"[A-Za-z0-9_-]{1,80}",host))
    require(host==env.get("COMPUTERNAME") and type(deadline) is int)
    child=shared.child_environment(env)
    child.update(TRACEBOLT_FRESH_MACHINE=host,TRACEBOLT_FRESH_RUN_ID=env["GITHUB_RUN_ID"],TRACEBOLT_FRESH_ATTEMPT=env["GITHUB_RUN_ATTEMPT"],TRACEBOLT_FRESH_EXPIRES_UNIX=str(deadline),TRACEBOLT_FRESH_TEST_SHA256=shared.binary_digest(test),TRACEBOLT_FRESH_SERVICE_SHA256=shared.binary_digest(service),TRACEBOLT_FRESH_SERVICE_ARTIFACT=str(service),TRACEBOLT_FRESH_ROLE="controller",GOTRACEBACK="none")
    return child

def validate_report(raw,source):
    r=shared.strict_json(raw,16<<10)
    require(type(r) is dict and set(r)==BOOL_FIELDS|{"schema","source","status","inventory","extensions"})
    require(r["schema"]=="tracebolt.windows-fresh-conpty-acceptance.v1" and r["source"]==source)
    require(shared.member(r["status"],{"passed_fresh_native_subset","failed","blocked"}))
    require(all(type(r[k]) is bool for k in BOOL_FIELDS) and all(r[k] is False for k in FALSE_FIELDS))
    require(not (r["serviceDisabled"] and r["automaticStartConfigurationRetained"]))
    require(not (r["serviceDisabled"] or r["automaticStartConfigurationRetained"]) or r["ownedServiceStopped"])
    require(not r["nativeActionsAttempted"] or r["approvalValidated"])
    require(not r["syntheticInput"] or r["nativeActionsAttempted"])
    require(not r["hiddenConsoleExercised"] or all(r[k] for k in ("syntheticInput","noEchoVerified","receiptAndGrantsVerified")))
    inv=r["inventory"]
    require(type(inv) is dict and set(inv)=={"frames",*shared.QUALITIES})
    require(type(inv["frames"]) is int and 0<=inv["frames"]<=64)
    allowed={"not_run"} if inv["frames"]==0 else {"healthy","partial","denied","unavailable"}
    require(all(shared.member(inv[k],allowed) for k in shared.QUALITIES))
    is_pass=r["status"]=="passed_fresh_native_subset"
    shared.validate_extensions(r["extensions"],inv["frames"],"passed_native_subset" if is_pass else r["status"])
    if r["freshOrchestrationAcceptance"]:
        require(all(r[k] for k in ("hiddenConsoleExercised","disabledStageVerified","limitedServiceTokenVerified")))
        require(inv["frames"]>0 and all(inv[k] in {"healthy","partial"} for k in shared.QUALITIES))
        shared.validate_extensions(r["extensions"],inv["frames"],"passed_native_subset")
    if is_pass: require(all(r[k] is True for k in PASS_FIELDS) and r["serviceDisabled"] is False)
    if r["status"]=="blocked": require(not r["nativeActionsAttempted"] and inv["frames"]==0)
    return r

def parse_controller(raw,source):
    require(type(raw) is bytes and len(raw)<=32<<10)
    lines=[line[len(b"fresh-native-report="):] for line in raw.splitlines() if line.startswith(b"fresh-native-report=")]
    require(len(lines)==1)
    return validate_report(lines[0],source)

def run_native(env,root=ROOT):
    source=authorize(env)  # Before staging, processes, fixture, or any native action.
    child=shared.child_environment(env)
    shared.verify_checkout(child,source,root)
    shared.verify_go(child,root)
    shared.successful(["go","mod","verify"],child,root,180)
    temp=Path(env.get("RUNNER_TEMP",""))
    require(temp.is_absolute() and temp.is_dir() and not (temp/REPORT_NAME).exists())
    with tempfile.TemporaryDirectory(prefix="tracebolt-fresh-build-",dir=temp) as stage:
        service=Path(stage)/"tracebolt-windows-service.exe"
        test=Path(stage)/"tracebolt-fresh.test.exe"
        shared.successful(["go","build","-mod=readonly","-buildvcs=false","-trimpath","-o",str(service),"./cmd/windows-service"],child,root,300)
        shared.successful(["go","test","-c","-mod=readonly","-buildvcs=false","-trimpath","-tags","tracebolt_fresh_native","-ldflags","-X localrmm/cmd/windows-service.freshCompiledSource="+source,"-o",str(test),"./cmd/windows-service"],child,root,300)
        shared.verify_checkout(child,source,root)
        # Owner approval covers this exact fresh hosted run. Facts below narrow
        # that approval; they do not turn any false approval into true.
        native_env=bind_run(child,source,test,service,socket.gethostname(),int(time.time())+14*60)
        code,raw=shared.command([str(test),"-test.run=^TestFreshReadConPTYNative$","-test.count=1","-test.timeout=16m"],native_env,root,16*60,32<<10)
        report=parse_controller(raw,source)
        require(report["status"]!="passed_fresh_native_subset" or code==0)
    sanitized=(json.dumps(report,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode("ascii")
    validate_report(sanitized,source)
    with (temp/REPORT_NAME).open("xb") as f:f.write(sanitized)
    output=env.get("GITHUB_OUTPUT","")
    require(type(output) is str and output!="")
    with open(output,"a",encoding="utf-8",newline="\n") as f:f.write("report_validated=true\n")
    return report

def main(argv=None,env=None):
    args=sys.argv[1:] if argv is None else argv
    values=dict(os.environ if env is None else env)
    try:
        require(args in (["--check-authorization"],["--run-native"]))
        if args==["--check-authorization"]:
            source=authorize(values);shared.verify_checkout(shared.child_environment(values),source,ROOT)
            print("PASS: separate fresh native run approval and exact source verified; no native effects.")
            return 0
        report=run_native(values)
        print("Fresh Windows native subset: "+report["status"]+"; created state retained, platform disposal required and unverified.")
        return 0 if report["status"]=="passed_fresh_native_subset" else 1
    except Exception:
        print("FAIL: fresh Windows authorization/execution/evidence rejected; private output withheld; inspect run and disposal status.")
        return 1
if __name__=="__main__":raise SystemExit(main())
