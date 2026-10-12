"""Current-profile authorization/report fixtures only. No process or native calls."""
import copy
import importlib.util
import json
import re
from pathlib import Path
import unittest
from unittest import mock
SPEC=importlib.util.spec_from_file_location("_current_gate",Path(__file__).with_name("run_current_setup_gui.py"))
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def allowed():
    source="a"*40
    env={"TRACEBOLT_SETUP_SOURCE":source,"GITHUB_SHA":source,"TRACEBOLT_SETUP_PROFILE":r.PROFILE,"TRACEBOLT_SETUP_CASE":"install-uninstall","GITHUB_EVENT_NAME":"workflow_dispatch","GITHUB_REPOSITORY":"storminator89/Tracebolt","GITHUB_REPOSITORY_OWNER":"storminator89","GITHUB_ACTOR":"storminator89","GITHUB_TRIGGERING_ACTOR":"storminator89","GITHUB_REPOSITORY_OWNER_ID":"30489872","GITHUB_ACTOR_ID":"30489872","GITHUB_RUN_ATTEMPT":"1","GITHUB_ACTIONS":"true","RUNNER_OS":"Windows","RUNNER_ARCH":"X64","RUNNER_ENVIRONMENT":"github-hosted","GITHUB_RUN_ID":"123"}
    env.update({"TRACEBOLT_SETUP_APPROVE_"+a:"true" for a in r.APPROVALS});return env

def progress():
    v=r.zero_frame_progress();v.update(initialCredentialGeneration=1,acceptedFrames=2,lastSequence=2,v16Frames=1,lastFrameSha256="1"*64)
    for s in v["sources"]:
        if s["kind"]=="grant_only":continue
        s.update(frames=1,samples=1,lastSequence=1,lastFrameSha256="2"*64,status="observed" if s["kind"]=="ordinary" else "source_failed")
        if s["kind"]=="independent":s["reason"]="access_denied";s["frames"]=2
        s["qualities"]["denied"]=1
    return v

def receipt():
    return {"verified":True,"receiptSHA256":"3"*64,"consentSHA256":r.digest(json.dumps({"schemaVersion":"tracebolt.windows-capability-consent.v14","collectionProfile":"windows-inventory-v1","scopes":list(r.current_frames.SCOPES),"acknowledged":True,"insecureHTTPAcknowledged":False},separators=(",",":")).encode()),"senderBinding":"5"*64,"manifestSHA256":"6"*64,"credentialGeneration":1,"grantDigests":[{"scope":scope,"sha256":"7"*64} for scope in r.current_frames.SCOPES[1:]]}

def report(case="install-uninstall",machine="8"):
    return {"setupSHA256":"c"*64,"serviceSHA256":"d"*64,"driverSHA256":"b"*64,"sourceInputsSHA256":"e"*64,"runID":"123","machine":"fresh-vm","sourceTree":"f"*40,"machineIDSHA256":machine*64,"osBuild":26100,"osRevision":100,"receiptProof":receipt() if case in r.NORMAL else {"verified":False,"receiptSHA256":"","consentSHA256":"","senderBinding":"","manifestSHA256":"","credentialGeneration":0,"grantDigests":None},"schema":"tracebolt.windows-current-setup-acceptance.v1","source":"a"*40,"case":case,"status":"passed_packaged_gui_subset","stage":"completed","reason":"none","approvalValidated":True,"nativeActionsAttempted":True,"checks":dict.fromkeys(r.CHECKS[case],True),"coverage":dict.fromkeys(r.FALSE_COVERAGE,False),"startup":"absent" if case in r.NORMAL else "disabled","frames":2 if case in r.NORMAL else 0,"platformDisposalRequired":True,"frameProgress":progress() if case in r.NORMAL else r.zero_frame_progress()}

class CurrentSetupContract(unittest.TestCase):
    def validate(self,v):return r.validate_report(json.dumps(v).encode(),"a"*40,v["case"])
    def test_each_approval_exact_source_and_hosted_owner_required_before_process(self):
        env=allowed();self.assertEqual(r.authorize(env),"a"*40)
        for key in env:
            bad=dict(env);bad.pop(key)
            with self.subTest(key=key),mock.patch.object(r.shared,"command") as command,self.assertRaises(r.shared.Rejected):r.authorize(bad)
            command.assert_not_called()
        for old in ("FIVE_READ_SCOPES","TWELVE_READ_ADMIN_SCOPES","HTTP_PLAINTEXT"):
            with self.assertRaises(r.shared.Rejected):r.authorize(dict(env,**{"TRACEBOLT_SETUP_APPROVE_"+old:"true"}))
        for key in r.APPROVALS:
            for v in ("false","True","1",True):
                with self.assertRaises(r.shared.Rejected):r.authorize(dict(env,**{"TRACEBOLT_SETUP_APPROVE_"+key:v}))
    def test_historical_schema_receipt_profile_never_promoted(self):
        for schema in ("tracebolt.windows-setup-acceptance.v2","tracebolt.windows-setup-acceptance.v1"):
            v=report();v["schema"]=schema
            with self.assertRaises(r.shared.Rejected):self.validate(v)
        env=allowed();env["TRACEBOLT_SETUP_PROFILE"]="packaged-setup-gui-read-admin-v2"
        with self.assertRaises(r.shared.Rejected):r.authorize(env)
        v=report();v["receiptProof"]["grantDigests"]=v["receiptProof"]["grantDigests"][:4]
        with self.assertRaises(r.shared.Rejected):self.validate(v)
    def test_denied_protocol_progress_is_honest_and_coverage_stays_false(self):
        for case in r.CHECKS:self.assertEqual(self.validate(report(case)),report(case))
        v=report();self.assertTrue(r.validate_frame_progress(v["frameProgress"]))
        for key in v["coverage"]:
            bad=copy.deepcopy(v);bad["coverage"][key]=True
            with self.assertRaises(r.shared.Rejected):self.validate(bad)
        for i in (0,6,18):
            bad=copy.deepcopy(v);bad["frameProgress"]["sources"][i]=r.zero_frame_progress()["sources"][i]
            with self.assertRaises(r.shared.Rejected):self.validate(bad)
    def test_frame_raw_or_infinite_details_rejected(self):
        for key,value in (("raw", "private"),("acceptedFrames", True),("lastFrameSha256", "private"),("fullAcceptance",True)):
            bad=progress();bad[key]=value
            with self.assertRaises((ValueError,r.shared.Rejected)):r.validate_frame_progress(bad)
        for key in ("rowCount","completeFields","truncatedFields"):
            bad=progress();bad["sources"][0][key]=float("nan")
            with self.assertRaises(ValueError):r.validate_frame_progress(bad)
    def test_exact_three_source_run_machine_and_package_binding(self):
        reports={case:r.canonical(report(case,hex(i+8)[2:])) for i,case in enumerate(r.CHECKS)}
        self.assertEqual(len(r._validated_report_contents(reports,"a"*40,"123")),3)
        with self.assertRaises(r.shared.Rejected):r._validated_reports(reports,"a"*40,"123")
        for field,value in (("sourceTree","0"*40),("serviceSHA256","0"*64),("runID","456")):
            bad=dict(reports);case=list(bad)[1];v=json.loads(bad[case]);v[field]=value;bad[case]=r.canonical(v)
            with self.assertRaises(r.shared.Rejected):r._validated_report_contents(bad,"a"*40,"123")
    def test_receipt_hashes_grants_and_optional_scopes_cannot_be_omitted(self):
        for key in receipt():
            v=receipt();del v[key]
            with self.assertRaises(r.shared.Rejected):r.validate_receipt_proof(v)
        for i in range(20):
            v=receipt();v["grantDigests"][i]["scope"]="wrong"
            with self.assertRaises(r.shared.Rejected):r.validate_receipt_proof(v)
        v=report();v["checks"]["optionalActionsOff"]=False
        with self.assertRaises(r.shared.Rejected):self.validate(v)
    def test_hidden_input_failures_remain_finite_failed_evidence(self):
        go=(r.ROOT/"internal/windowsacceptance/currentsetupgate/hidden_input.go").read_text()
        literal=go.split("var HiddenInputFailureStages = []string{",1)[1].split("}",1)[0]
        self.assertEqual(set(re.findall(r'"([a-z-]+)"',literal)),r.HIDDEN_INPUT_FAILURE_STAGES)
        for case in r.CHECKS:
            for stage in r.HIDDEN_INPUT_FAILURE_STAGES:
                v=report(case)
                v.update(status="failed",stage=stage,reason="operation_failed",startup="inspection_required",frames=0,
                         frameProgress=r.zero_frame_progress(),receiptProof=report("cancel-hidden-input")["receiptProof"],
                         checks=dict.fromkeys(r.CHECKS[case],False))
                self.assertEqual(self.validate(v),v)
                for key,value in (("stage","hidden-input-private-native-text"),("status","passed_packaged_gui_subset"),("reason","private-native-text")):
                    bad=copy.deepcopy(v);bad[key]=value
                    with self.subTest(case=case,stage=stage,key=key),self.assertRaises(r.shared.Rejected):self.validate(bad)
                v["checks"]["hiddenConsoleExercised"]=True
                with self.assertRaises(r.shared.Rejected):self.validate(v)
    def test_installer_diagnostics_are_finite_stage_bound_and_match_source(self):
        go=(r.ROOT/"internal/windowsacceptance/currentsetupgate/hidden_input.go").read_text()
        literal=go.split("var hiddenInputPackageCodes = []string{",1)[1].split("}",1)[0]
        self.assertEqual(set(re.findall(r'"([a-z-]+)"',literal)),r.HIDDEN_INPUT_PACKAGE_CODES)
        service=(r.ROOT/"internal/windowsservice/diagnostics.go").read_text()
        self.assertEqual(set(re.findall(r'Phase\w+\s+Phase = "([a-z_]+)"',service)),r.HIDDEN_INPUT_SERVICE_PHASES)
        self.assertEqual(set(re.findall(r'Reason\w+\s+Reason = "([a-z_]+)"',service)),r.HIDDEN_INPUT_SERVICE_REASONS)
        for case in r.CHECKS:
            for stage,reason in (("hidden-input-installer-before-mutation","setup_package:elevation-required"),
                                 ("hidden-input-installer-failed","setup_service:package-failed:enrollment:input_rejected")):
                v=report(case)
                v.update(status="failed",stage=stage,reason=reason,startup="inspection_required",frames=0,
                         frameProgress=r.zero_frame_progress(),receiptProof=report("cancel-hidden-input")["receiptProof"],
                         checks=dict.fromkeys(r.CHECKS[case],False))
                self.assertEqual(self.validate(v),v)
                for key,value in (("stage","hidden-input-prompt-absent"),("status","passed_packaged_gui_subset"),
                                  ("reason",reason+":private"),("reason","setup_service:package-failed:private:input_rejected"),
                                  ("reason","setup_service:package-failed:enrollment:private"),("reason","setup_package:msi-bounds")):
                    bad=copy.deepcopy(v);bad[key]=value
                    with self.assertRaises(r.shared.Rejected):self.validate(bad)
    def test_prompt_diagnostics_preserve_native_deadline_real_console_and_privacy(self):
        driver=(r.ROOT/"cmd/windows-service/current_setup_acceptance_native_windows_test.go").read_text()
        probe=driver.split('r.Stage = "hidden-input"',1)[1].split('r.Checks["hiddenConsoleExercised"] = true',1)[0]
        self.assertIn("setupAwait(ctx, 40*time.Second",probe)
        self.assertIn("currentgate.ProbeHiddenInput",probe)
        self.assertIn("setupConsoleObserved(g.pid, secret, nil, false, observe)",probe)
        self.assertIn("}) != nil || terminal",probe)
        self.assertNotIn("fmt.",probe)
        console=(r.ROOT/"cmd/windows-service/setup_acceptance_ui_windows_test.go").read_text()
        self.assertIn("return setupConsoleObserved(pid, secret, input, enter, func(string) {})",console)
        self.assertIn("hidden = mode&4 == 0",console)
        self.assertIn("if n > 64<<10",console)
        self.assertIn("bytes.Contains(compact, secret)",console)
    def test_workflow_only_manual_and_defaults_false(self):
        source=(r.ROOT/".github/workflows/windows-current-setup-acceptance.yml").read_text()
        self.assertEqual(source.count("default: false"),len(r.APPROVALS))
        self.assertIn("case: [install-uninstall, cancel-hidden-input, pending-transport]",source)
        self.assertNotIn("http_plaintext",source)
        self.assertIn("run_current_setup_gui.py --aggregate",source)
        self.assertNotIn("workflow_call:",source)
        self.assertIn("d2ec1451a0fb4332a48f0ee48b17c35eca807ad4",(r.ROOT/"deploy/release/publish-windows-prerelease.py").read_text())

if __name__=="__main__":unittest.main()
