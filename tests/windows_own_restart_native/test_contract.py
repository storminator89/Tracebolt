"""Portable contracts only. No manager, browser, service or controller launched."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from contract import *

def fixture_plan():
    H=lambda s:digest(s.encode());run='portable-only-001'
    sources={k:{'commit':H(k)[:40],'tree':H(k+'tree')[:40],'inventorySHA256':H(k+'inv')} for k in SOURCE_NAMES}
    sources['application'].update(commit=APP_COMMIT,tree=APP_TREE)
    targets={}
    for role in ('windows','linux'):
        root='C:\\Private' if role=='windows' else '/private'
        sep='\\' if role=='windows' else '/'
        paths={k:{'root':root+sep+k,'inventory':root+sep+k+'.inventory','commitObject':root+sep+k+'.commit'} for k in (('harness','application') if role=='windows' else SOURCE_NAMES)}
        targets[role]={'id':role+'-target','machineIdSHA256':H(role),'osBuild':'26100' if role=='windows' else '6.8.0','workspace':root+sep+'workspace','sourcePaths':paths}
        if role=='linux':targets[role].update(lanConfig='/private/lan.json',enrollmentConfig='/private/enroll.json',webRoot='/private/web',browserRoot='/private/browser')
    artifacts={k:{'path':('C:\\Private\\' if k in ('service','controller') else '/private/')+k,'sha256':H(k)} for k in ('controller','service','manager','node','chromium','webInventory','browserInventory')}
    return {'schema':SCHEMA,'runId':run,'notBeforeUnix':1791662400,'expiresUnix':1791666000,'targetService':'TraceboltWindowsAgent','sources':sources,'targets':targets,'artifacts':artifacts,
      'tls':{'operatorOrigin':'https://manager.test:8443','agentOrigin':'https://manager.test:8444','managerInstanceId':'manager_'+'12'*16,'issuerFingerprint':H('issuer'),'serverCertificateSHA256':H('server'),'bootstrapServerCASHA256':H('ca'),'bootstrapIssuerRootSHA256':H('root'),'custodian':'test-custodian','networkApprovalRef':'test-network-approval'},
      'selected':{'deviceId':'agent_'+'34'*16,'certificateSHA256':H('cert'),'invitationIdSHA256':H('invite'),'receiptSHA256':H('receipt'),'intentSHA256':H('intent'),'publicSHA256':{k:H(k) for k in PUBLIC_NAMES},'grantIds':{k:H(k)[:32] for k in ('events','volumes','processMetrics','network')}},
      'managerProcess':{'pid':1234,'startTicks':'123456','uid':1000,'executableSHA256':H('manager'),'lanConfigSHA256':H('lan'),'enrollmentConfigSHA256':H('enrollment')},
      'approvals':{'ownRestartTwoInvocations':'test-restart-approval','linuxBrowserReadOnly':'test-browser-approval','publicBoundaryTransfers':'test-transfer-approval'},
      'handoff':{'windowsBaseline':'C:\\Private\\workspace\\'+run+'-baseline.json','linuxCompletion':'/private/workspace/'+run+'-completion.json'}}

def native_report(p):
    from windows_native import controller_plan
    r={k:'' for k in NATIVE_KEYS};r.update(schema='tracebolt.windows-own-restart-controller-result.v1',runId=p['runId'],planSHA256=digest(b'plan'),browserBaselineSHA256=digest(b'baseline'),status='passed-native-subset',phase='complete',fullAcceptance=False,commandInvocations=2,oldExitCode=0,deviceId=p['selected']['deviceId'],certificateSHA256=p['selected']['certificateSHA256'],installedSHA256=p['artifacts']['service']['sha256'],controllerSHA256=p['artifacts']['controller']['sha256'],oldProcessGenerationSHA256=digest(b'old'),newProcessGenerationSHA256=digest(b'new'),newProcessCreationUTC='2026-10-11T00:00:00.0000001Z',newProcessCreationFiletime='134361504000000001',windowStartFiletime='134361504000000000',windowEndFiletime='134361504100000000')
    for k in NATIVE_CHECKS:r[k]=True
    return r

class Contracts(unittest.TestCase):
    def test_valid_source_plan_and_template_invalid(self):
        p=fixture_plan();self.assertIs(validate_plan(p),p)
        with self.assertRaises(Rejected):validate_plan(strict_json(Path(__file__).with_name('plan.template.json').read_bytes()))
    def test_exact_and_duplicate_schema(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":{"a":1,"a":2}}',b'{"x":NaN}',b'{}{}'):
            with self.assertRaises(Rejected):strict_json(raw)
        p=fixture_plan();p['manualPass']=True
        with self.assertRaises(Rejected):validate_plan(p)
    def test_application_pin_not_relabelled(self):
        p=fixture_plan();p['sources']['application']['commit']=p['sources']['harness']['commit']
        with self.assertRaises(Rejected):validate_plan(p)
    def test_targets_approvals_and_expiry(self):
        for key,value in [('targetService','OtherService'),('runId','short'),('expiresUnix',0)]:
            p=fixture_plan();p[key]=value
            with self.assertRaises(Rejected):validate_plan(p)
        p=fixture_plan();p['approvals']['ownRestartTwoInvocations']='yes'
        with self.assertRaises(Rejected):validate_plan(p)
        with self.assertRaises(Rejected):validate_plan(fixture_plan(),1791666000)
    def test_lossless_filetime_and_timestamps(self):
        a='2026-10-11T00:00:00.0000001Z';b='2026-10-11T00:00:00.0000002Z'
        self.assertEqual(nanos(b)-nanos(a),100)
        self.assertEqual(filetime_nanos('134361504000000001'),nanos(a))
        for invalid in ('2026-02-30T00:00:00Z','2026-10-11T00:00:60Z','2026-10-11T00:00:00+00:00'):
            with self.assertRaises(Rejected):nanos(invalid)
    def test_native_result_requires_every_independent_observation(self):
        p=fixture_plan();r=native_report(p);validate_native_report(r,p,r['planSHA256'],r['browserBaselineSHA256'])
        for k in NATIVE_CHECKS:
            bad=copy.deepcopy(r);bad[k]=False
            with self.assertRaises(Rejected):validate_native_report(bad,p,r['planSHA256'],r['browserBaselineSHA256'])
        for key,value in [('commandInvocations',1),('oldExitCode',1),('fullAcceptance',True),('newProcessCreationFiletime','134361504000000002'),('manualPass',True)]:
            bad=copy.deepcopy(r);bad[key]=value
            with self.assertRaises(Rejected):validate_native_report(bad,p,r['planSHA256'],r['browserBaselineSHA256'])
    def test_same_clock_progression_not_plus_one(self):
        a={'sequence':2,'generationId':'sample_a','collectedAt':'2026-10-11T00:00:01Z','receivedAt':'2026-10-11T00:00:20Z'}
        b={'sequence':9,'generationId':'sample_b','collectedAt':'2026-10-11T00:00:02Z','receivedAt':'2026-10-11T00:00:21Z'}
        self.assertTrue(advancing(a,b,'134361504000000001'))
        for key in a:
            c=dict(b);c[key]=a[key];self.assertFalse(advancing(a,c,'134361504000000001'))
        self.assertFalse(advancing(a,b,'134361504030000000'))
    def test_fixed_one_second_creation_margin(self):
        a={'sequence':1,'generationId':'a','collectedAt':'2026-10-11T00:00:00Z','receivedAt':'2026-10-11T00:00:10Z'}
        b={'sequence':2,'generationId':'b','collectedAt':'2026-10-11T00:00:01.0000001Z','receivedAt':'2026-10-11T00:00:11Z'}
        self.assertFalse(advancing(a,b,'134361504000000001'))
        b['collectedAt']='2026-10-11T00:00:01.000000099Z';self.assertFalse(advancing(a,b,'134361504000000001'))
        b['collectedAt']='2026-10-11T00:00:01.000000101Z';self.assertTrue(advancing(a,b,'134361504000000001'))
    def test_human_phrase_no_bypass(self):
        p=fixture_plan();phrase='RESTART TraceboltWindowsAgent ON windows-target WITH TWO CLI INVOCATIONS'
        confirm_windows(p,lambda:False,lambda:phrase,lambda _:None)
        for reply in ('yes','',phrase+' ',phrase.replace('windows-target','other-target')):
            with self.assertRaises(Rejected):confirm_windows(p,lambda:False,lambda:reply,lambda _:None)
        def eof():raise EOFError()
        with self.assertRaises(Rejected):confirm_windows(p,lambda:False,eof,lambda _:None)
        with self.assertRaises(Rejected):confirm_windows(p,lambda:True,lambda:phrase,lambda _:None)
    def test_paths_no_aliases(self):
        for path in ('C:\\tmp\\..\\x','C:\\tmp\\NUL','C:\\tmp\\x:stream','\\\\server\\x','C:/tmp/x'):
            with self.assertRaises(Rejected):absolute(path,'windows')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'a').write_text('a');(p/'b').symlink_to(p/'a')
            with self.assertRaises(Rejected):read_regular(p/'b')
    def test_create_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'result.json';write_new(p,{'fullAcceptance':False})
            with self.assertRaises(FileExistsError):write_new(p,{'fullAcceptance':True})
            self.assertEqual(strict_json(p.read_bytes()),{'fullAcceptance':False})
    def test_old_seven_phase_contract_unchanged(self):
        import ast
        raw=Path(__file__).parents[1].joinpath('windows_linux_native_parity/contract.py').read_text()
        assign=next(n for n in ast.parse(raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PHASES' for t in n.targets))
        self.assertEqual(ast.literal_eval(assign.value),('manager-browser','setup','event-fixture','event-enable','updates-enable','event-disable','updates-disable'))

if __name__=='__main__':unittest.main()
