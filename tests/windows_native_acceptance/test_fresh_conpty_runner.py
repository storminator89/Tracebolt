import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

P=Path(__file__).with_name('run_fresh_conpty.py')
S=importlib.util.spec_from_file_location('fresh_conpty_runner_tested',P)
r=importlib.util.module_from_spec(S);S.loader.exec_module(r)
SHA='a'*40

def approved():
    e={'TRACEBOLT_FRESH_SOURCE':SHA,'TRACEBOLT_FRESH_PROFILE':r.PROFILE,'GITHUB_SHA':SHA,'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':'storminator89/Tracebolt','GITHUB_ACTIONS':'true','RUNNER_OS':'Windows','RUNNER_ENVIRONMENT':'github-hosted','GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','COMPUTERNAME':'disposable-01'}
    e.update(GITHUB_REPOSITORY_OWNER=r.OWNER,GITHUB_REPOSITORY_OWNER_ID=r.OWNER_ID,GITHUB_ACTOR=r.OWNER,GITHUB_ACTOR_ID=r.OWNER_ID,GITHUB_TRIGGERING_ACTOR=r.OWNER)
    e.update({'TRACEBOLT_FRESH_APPROVE_'+k:'true' for k in r.APPROVALS})
    return e

def passing():
    p={k:False for k in r.BOOL_FIELDS};p.update({k:True for k in r.PASS_FIELDS})
    p.update(schema='tracebolt.windows-fresh-conpty-acceptance.v1',source=SHA,status='passed_fresh_native_subset',inventory={'frames':1,**{k:'healthy' for k in r.shared.QUALITIES}})
    p.update(r.PASS_DIAGNOSTICS)
    q={'observed':1,'denied':0,'unavailable':0,'firstSample':0,'reset':0}
    p['extensions']={'frames':1,'v5Frames':1,'freshOrchestrationAcceptance':False,'eventApplication':'observed','eventSystem':'bounded','volumes':'observed','volumeCapacity':'observed','processCPU':'observed','processMemory':'observed','network':'observed','eventRows':0,'volumeRows':1,'processRows':1,'networkRows':1,'peerLoopbackRows':1,'processCPUFirstSampleRows':0,'volumeCapacityCounts':dict(q),'processCPUCounts':dict(q),'processMemoryCounts':dict(q)}
    return p

def blocked():
    p=passing()
    p.update({k:False for k in r.BOOL_FIELDS})
    p.update(r.DEFAULT_DIAGNOSTICS)
    p.update(status='blocked',inventory={'frames':0,**{k:'not_run' for k in r.shared.QUALITIES}})
    for key,value in p['extensions'].items():
        if type(value) is dict:p['extensions'][key]={name:0 for name in value}
        elif type(value) is bool:p['extensions'][key]=False
        elif type(value) is int:p['extensions'][key]=0
        else:p['extensions'][key]='not_run'
    return p

class FreshRunner(unittest.TestCase):
    def test_each_new_consent_is_required(self):
        self.assertEqual(r.authorize(approved()),SHA)
        for key in r.APPROVALS:
            for value in ('false','True','1',''):
                e=approved();e['TRACEBOLT_FRESH_APPROVE_'+key]=value
                with self.assertRaises(r.shared.Rejected):r.authorize(e)
    def test_exact_context_and_old_profile_rejected(self):
        for key in ('TRACEBOLT_FRESH_SOURCE','TRACEBOLT_FRESH_PROFILE','GITHUB_SHA','GITHUB_EVENT_NAME','GITHUB_REPOSITORY','GITHUB_ACTIONS','RUNNER_OS','RUNNER_ENVIRONMENT','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'):
            e=approved();e[key]='other'
            with self.assertRaises(r.shared.Rejected):r.authorize(e)
    def test_no_process_before_approval(self):
        with mock.patch.object(r.shared,'verify_checkout') as check,mock.patch.object(r.shared,'successful') as proc:
            with self.assertRaises(r.shared.Rejected):r.run_native({})
            check.assert_not_called();proc.assert_not_called()
    def test_finite_report_never_promotes_disabling_disposal_or_humans(self):
        p=passing();self.assertEqual(r.validate_report(json.dumps(p).encode(),SHA),p)
        for k in r.FALSE_FIELDS|{'serviceDisabled'}:
            x=passing();x[k]=True
            with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
        for k in r.PASS_FIELDS:
            x=passing();x[k]=False
            with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
        x=passing();x['secret']='never allowed'
        with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
    def test_skip_zero_exit_is_not_native_acceptance(self):
        for raw in (b'PASS\n',b'fresh-native-report={}\n',b'fresh-native-report={}\nfresh-native-report={}\n'):
            with self.assertRaises(r.shared.Rejected):r.parse_controller(raw,SHA)
    def test_go_python_report_field_sets_match(self):
        import re
        fields=set(re.findall(r'json:"([^"]+)"',(r.ROOT/'internal/windowsacceptance/freshgate/report.go').read_text()))
        self.assertEqual(fields,r.BOOL_FIELDS|set(r.DIAGNOSTIC_VALUES)|{'schema','source','status','inventory','extensions'})
    def test_required_diagnostics_reject_missing_extra_and_invalid_values(self):
        for key in r.DIAGNOSTIC_VALUES:
            x=passing();del x[key]
            with self.subTest(key=key,case='missing'),self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
            for value in ('','raw private diagnostic','PASSED','0','1','passed\n',None,True,False,0,1.5,[],{}):
                x=passing();x['status']='failed';x[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
        x=passing();x['diagnosticError']='raw private diagnostic'
        with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
    def test_diagnostics_require_defaults_without_native_actions(self):
        p=blocked();self.assertEqual(r.validate_report(json.dumps(p).encode(),SHA),p)
        for status in ('blocked','failed'):
            for key,values in r.DIAGNOSTIC_VALUES.items():
                for value in values:
                    x=blocked();x['status']=status;x[key]=value
                    with self.subTest(status=status,key=key,value=value):
                        if value==r.DEFAULT_DIAGNOSTICS[key]:self.assertEqual(r.validate_report(json.dumps(x).encode(),SHA),x)
                        else:
                            with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
    def test_finite_failure_diagnostics_do_not_promote_success(self):
        for key,values in r.DIAGNOSTIC_VALUES.items():
            if key in {"childFailureStage","childFailureCategory"}:continue
            for value in values:
                x=passing();x['status']='failed';x[key]=value
                if key=="naturalChildExit" and value!="zero":x.update(childFailureStage="unknown",childFailureCategory="unknown")
                with self.subTest(key=key,value=value):
                    self.assertEqual(r.validate_report(json.dumps(x).encode(),SHA),x)
                    x['status']='passed_fresh_native_subset'
                    if value==r.PASS_DIAGNOSTICS[key]:self.assertEqual(r.validate_report(json.dumps(x).encode(),SHA),x)
                    else:
                        with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
    def test_coordinator_phases_are_existing_production_states(self):
        import re
        source=(r.ROOT/'cmd/windows-service/read_setup.go').read_text()
        phases=set(re.findall(r'(?:Phase:\s*|save\()"([a-z-]+)"',source))
        self.assertEqual(r.DIAGNOSTIC_VALUES['coordinatorPhase'],phases|{'unknown'})
    def test_one_approved_run_binds_facts_without_creating_consent(self):
        with tempfile.TemporaryDirectory() as temp:
            env=approved();env['RUNNER_TEMP']=temp;env['GITHUB_OUTPUT']=str(Path(temp)/'output')
            calls=[]
            def build(args,environment,root,timeout,*extra):
                calls.append(args)
                if '-o' in args:Path(args[args.index('-o')+1]).write_bytes(('inert '+args[1]).encode())
                return b''
            def execute(args,environment,root,timeout,limit):
                for key in ('GITHUB_REPOSITORY_OWNER','GITHUB_ACTOR','GITHUB_TRIGGERING_ACTOR'):self.assertEqual(environment[key],r.OWNER)
                for key in ('GITHUB_REPOSITORY_OWNER_ID','GITHUB_ACTOR_ID'):self.assertEqual(environment[key],r.OWNER_ID)
                self.assertEqual(environment['TRACEBOLT_FRESH_MACHINE'],'disposable-01')
                self.assertEqual(environment['TRACEBOLT_FRESH_RUN_ID'],'123')
                self.assertEqual(environment['TRACEBOLT_FRESH_ATTEMPT'],'1')
                self.assertEqual(environment['TRACEBOLT_FRESH_EXPIRES_UNIX'],'1900000840')
                self.assertEqual(environment['TRACEBOLT_FRESH_ROLE'],'controller')
                self.assertTrue(all(environment['TRACEBOLT_FRESH_APPROVE_'+k]=='true' for k in r.APPROVALS))
                self.assertNotEqual(environment['TRACEBOLT_FRESH_TEST_SHA256'],environment['TRACEBOLT_FRESH_SERVICE_SHA256'])
                return 0,b'fresh-native-report='+json.dumps(passing()).encode()+b'\nPASS\n'
            with mock.patch.object(r.shared,'verify_checkout'),mock.patch.object(r.shared,'verify_go'),mock.patch.object(r.shared,'successful',side_effect=build),mock.patch.object(r.shared,'command',side_effect=execute),mock.patch.object(r.socket,'gethostname',return_value='disposable-01'),mock.patch.object(r.time,'time',return_value=1900000000):
                self.assertEqual(r.run_native(env)['status'],'passed_fresh_native_subset')
            self.assertEqual((Path(temp)/r.REPORT_NAME).read_text(),json.dumps(passing(),sort_keys=True,separators=(',',':'))+'\n')
            self.assertIn('report_validated=true',(Path(temp)/'output').read_text())
            self.assertTrue(any('tracebolt_fresh_native' in c for c in calls))
    def test_workflow_is_manual_only_and_all_new_consents_false(self):
        raw=(r.ROOT/'.github/workflows/windows-fresh-conpty-acceptance.yml').read_text()
        self.assertIn('workflow_dispatch:',raw)
        for forbidden in ('push:','pull_request:','schedule:','workflow_call:'):self.assertNotIn(forbidden,raw)
        self.assertEqual(raw.count('default: false'),8)
        self.assertIn('runs-on: windows-2025',raw)
        self.assertIn('NO reuse/reboot/uninstall/app-cleanup acceptance',raw)
        self.assertLess(raw.index('--check-authorization'),raw.index('uses: actions/setup-go@'))
        self.assertLess(raw.index('--check-authorization'),raw.index('--run-native'))

class FreshRerunAuthority(unittest.TestCase):
    def test_rerun_cannot_reuse_old_dispatch_consents(self):
        for attempt in ('2','10','01','0',''):
            e=approved();e['GITHUB_RUN_ATTEMPT']=attempt
            with self.assertRaises(r.shared.Rejected):r.authorize(e)
            with mock.patch.object(r.shared,'verify_checkout') as check:
                with self.assertRaises(r.shared.Rejected):r.run_native(e)
                check.assert_not_called()

class FreshOwnerAuthority(unittest.TestCase):
    def test_missing_or_collaborator_actor_facts_rejected_before_work(self):
        keys=('GITHUB_REPOSITORY_OWNER','GITHUB_REPOSITORY_OWNER_ID','GITHUB_ACTOR','GITHUB_ACTOR_ID','GITHUB_TRIGGERING_ACTOR')
        for key in keys:
            for value in (None,'','collaborator','123','STORMINATOR89'):
                env=approved()
                if value is None:env.pop(key)
                else:env[key]=value
                with self.subTest(key=key,value=value),mock.patch.object(r.shared,'verify_checkout') as check,mock.patch.object(r.shared,'successful') as process:
                    with self.assertRaises(r.shared.Rejected):r.run_native(env)
                    check.assert_not_called();process.assert_not_called()
    def test_workflow_requires_owner_and_first_attempt(self):
        raw=(r.ROOT/'.github/workflows/windows-fresh-conpty-acceptance.yml').read_text()
        for term in ("github.repository_owner == 'storminator89'","github.repository_owner_id == '30489872'","github.actor == 'storminator89'","github.actor_id == '30489872'","github.triggering_actor == 'storminator89'","github.run_attempt == 1"):
            self.assertIn(term,raw)
    def test_native_parent_and_child_keep_owner_facts(self):
        parent=(r.ROOT/'cmd/windows-service/fresh_native_windows_test.go').read_text()
        child=(r.ROOT/'cmd/windows-service/fresh_pty_windows_test.go').read_text()
        for key in ('GITHUB_REPOSITORY_OWNER','GITHUB_REPOSITORY_OWNER_ID','GITHUB_ACTOR','GITHUB_ACTOR_ID','GITHUB_TRIGGERING_ACTOR'):
            self.assertIn('get("'+key+'")',parent)
            self.assertIn('"'+key+'"',child)

class ChildFailureDiagnostics(unittest.TestCase):
    def test_pair_vocabulary_exactly_matches_go(self):
        import re
        local=(r.ROOT/'internal/windowsacceptance/freshgate/child_failure.go').read_text().split('const childFailureCodeBase',1)[0]
        pairs=set(re.findall(r'\{"([a-z_]+)", "([a-z_]+)"\}',local))
        self.assertEqual(pairs,r.child_diagnostics.CHILD_FAILURE_PAIRS)

    def test_every_pair_requires_naturally_observed_nonzero_and_cannot_pass(self):
        for stage,category in r.CHILD_FAILURE_PAIRS:
            x=blocked();x.update(status='failed',approvalValidated=True,nativeActionsAttempted=True,naturalChildExit='nonzero',childFailureStage=stage,childFailureCategory=category)
            self.assertEqual(r.validate_report(json.dumps(x).encode(),SHA),x)
            for value in ('unknown','zero'):
                x['naturalChildExit']=value
                with self.subTest(stage=stage,category=category,exit=value),self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
            x=passing();x.update(childFailureStage=stage,childFailureCategory=category)
            with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)

    def test_finite_values_in_invented_pairs_rejected(self):
        for stage in r.DIAGNOSTIC_VALUES['childFailureStage']:
            for category in r.DIAGNOSTIC_VALUES['childFailureCategory']:
                pair=(stage,category)
                if pair in r.CHILD_FAILURE_PAIRS or pair==('unknown','unknown'):continue
                x=blocked();x.update(status='failed',approvalValidated=True,nativeActionsAttempted=True,naturalChildExit='nonzero',childFailureStage=stage,childFailureCategory=category)
                with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)

    def test_new_fields_cannot_leak_raw_details(self):
        for name in ('childExitCode','childError','childStdout','childStderr','nativeError'):
            x=passing();x[name]='PRIVATE_MARKER'
            with self.assertRaises(r.shared.Rejected):r.validate_report(json.dumps(x).encode(),SHA)
        raw=json.dumps(passing()).encode()
        for key in ('childFailureStage','childFailureCategory'):
            duplicate=raw[:-1]+b',"'+key.encode()+b'":"PRIVATE_MARKER"}'
            with self.assertRaises(r.shared.Rejected):r.validate_report(duplicate,SHA)

    def test_service_pair_vocabulary_exactly_matches_go(self):
        import re
        source=(r.ROOT/'internal/windowsservice/setup_diagnostics.go').read_text().split('type setupDiagnosticError',1)[0]
        pairs=set(re.findall(r'\{"([a-z_]+)", "([a-z_]+)"\}',source))-{('unknown','unknown')}
        self.assertEqual(pairs,r.child_diagnostics.SERVICE_FAILURE_PAIRS)

    def test_console_categories_exactly_match_console_api(self):
        import re
        source=(r.ROOT/'internal/windowsconsole/diagnostic.go').read_text().split('func Diagnostic(',1)[1]
        values=set(re.findall(r'return "([a-z_]+)"',source))
        self.assertEqual(values,{c for s,c in r.CHILD_FAILURE_PAIRS if s=='enrollment_console'})
