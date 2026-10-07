import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import nodePath from 'node:path';
import {createApplicationCheckSettingsFixture,applicationCheckSettingsFixtureTargets,applicationCheckSettingsEditedTargets,applicationCheckSettingsFixtureDisclosure,applicationCheckSettingsCaseName,createApplicationCheckSettingsDiagnostics} from './application-check-settings-browser.mjs';
import {validApplicationCheckSettings} from '../../web/src/application-check-settings-types.ts';
const path='/api/application-checks/settings';
const save=f=>({expectedRevision:f.settings().revision,operation:'save',intervalSeconds:75,targets:structuredClone(applicationCheckSettingsFixtureTargets)});
const enable=f=>({expectedRevision:f.settings().revision,operation:'enable',checksFromManagerAcknowledged:true,destinationsAcknowledged:true,plaintextAcknowledged:true});
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');

test('invented draft remains disabled until exact enable review; disable preserves targets and rotates revision',()=>{
 const f=createApplicationCheckSettingsFixture();assert.equal(validApplicationCheckSettings(f.settings()),true);assert.equal(f.settings().configured,false);
 const draft=f.handle('POST',path,save(f));assert.equal(validApplicationCheckSettings(draft),true);assert.equal(draft.enabled,false);assert.deepEqual(draft.targets,applicationCheckSettingsFixtureTargets);
 const enabled=f.handle('POST',path,enable(f));assert.equal(validApplicationCheckSettings(enabled),true);assert.equal(enabled.enabled,true);assert.notEqual(enabled.revision,draft.revision);
 const disabled=f.handle('POST',path,{expectedRevision:enabled.revision,operation:'disable'});assert.equal(validApplicationCheckSettings(disabled),true);assert.equal(disabled.enabled,false);assert.deepEqual(disabled.targets,draft.targets);assert.notEqual(disabled.revision,enabled.revision);
 assert.deepEqual(f.counts,{reads:0,saves:1,enables:1,disables:1});
});
test('editing a stored draft rotates its revision and stays off before new enable review',()=>{
 const f=createApplicationCheckSettingsFixture();f.handle('POST',path,save(f));const before=f.settings();
 const changed=f.handle('POST',path,{...save(f),targets:structuredClone(applicationCheckSettingsEditedTargets)});
 assert.equal(changed.enabled,false);assert.equal(changed.targets[1].port,8443);assert.notEqual(changed.revision,before.revision);assert.equal(f.counts.saves,2);
 assert.throws(()=>f.handle('POST',path,{...enable(f),expectedRevision:before.revision}));
});
test('fixture snapshot copies cannot mutate receiver targets',()=>{
 const f=createApplicationCheckSettingsFixture();f.handle('POST',path,save(f));const a=f.settings();a.targets[0].url='https://wrong.invalid';a.targets[0].allowedAddresses.push('10.9.9.9');assert.deepEqual(f.settings().targets,applicationCheckSettingsFixtureTargets);
});
test('fixture rejects other targets, implicit enablement and stale or extra fields',()=>{
 for(const change of [x=>x.targets[0].url='https://unreviewed.invalid',x=>x.enabled=true,x=>x.expectedRevision='f'.repeat(32),x=>delete x.intervalSeconds,x=>x.targets[0].allowPrivateLAN=false]){
  const f=createApplicationCheckSettingsFixture(),body=save(f);change(body);assert.throws(()=>f.handle('POST',path,body));assert.equal(f.counts.saves,0);assert.equal(f.settings().configured,false);
 }
});
test('enable requires saved targets and each distinct manager/destination/plaintext acknowledgement',()=>{
 const empty=createApplicationCheckSettingsFixture();assert.throws(()=>empty.handle('POST',path,enable(empty)));
 for(const change of [x=>x.checksFromManagerAcknowledged=false,x=>x.destinationsAcknowledged=false,x=>x.plaintextAcknowledged=false,x=>delete x.destinationsAcknowledged,x=>x.targets=applicationCheckSettingsFixtureTargets,x=>x.expectedRevision='a'.repeat(32)]){
  const f=createApplicationCheckSettingsFixture();f.handle('POST',path,save(f));const body=enable(f);change(body);assert.throws(()=>f.handle('POST',path,body));assert.equal(f.settings().enabled,false);assert.equal(f.counts.enables,0);
 }
});
test('unknown routes and check/probe methods never reach a real target',()=>{
 for(const [method,url,body] of [['POST','/api/application-checks/status',{}],['GET','/api/application-checks/status?target=x',null],['GET','/api/application-checks/status',{}],['POST','/api/application-checks/run',{}],['POST','/api/application-checks/test',{}],['PUT',path,{}],['GET',`${path}?target=x`,null],['GET',path,{}]])assert.throws(()=>createApplicationCheckSettingsFixture().handle(method,url,body));
});
test('hosted case adds exact intercepted setup without weakening the shared harness',()=>{
 const runner=read('./lan-browser.mjs'),source=read('./application-check-settings-browser.mjs');
 assert.equal((runner.match(/await check\(/g)||[]).length,26);assert.equal((runner.match(/await check\(applicationCheckSettingsCaseName/g)||[]).length,1);
 assert.match(runner,/applicationCheckSettingsBrowserCase\(\{pageAt,login,expect,base,shot\}\),'10m'/);
 assert.match(applicationCheckSettingsCaseName,/Synthetic application check setup/);assert.match(applicationCheckSettingsFixtureDisclosure,/no real configuration persistence, target probe, DNS request, TCP connection or permission grant/);
 assert.doesNotMatch(source,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|ignoreHTTPSErrors|execFile|spawn\(/);
 assert.match(source,/url.origin!==base/);assert.match(source,/url.pathname!=='\/api\/application-checks\/settings'&&!.+method==='GET'&&url.pathname==='\/api\/application-checks\/status'/);assert.match(source,/\|\|url.search/);assert.match(source,/route.abort\('blockedbyclient'\)/);
 assert.match(source,/method==='POST'&&url.pathname!=='\/api\/auth\/login'/);assert.match(source,/expect\(unexpected\)\.toEqual\(\[\]\)/);assert.match(source,/expect\(external\)\.toEqual\(\[\]\)/);
 assert.match(source,/name:'Cancel'/);assert.match(source,/toHaveCount\(3\)/);assert.match(source,/width:390,height:844/);assert.match(source,/application-setup-disabled-mobile-de/);assert.match(source,/localStorage/);assert.match(source,/name:'Edit targets'/);assert.match(source,/namedCapabilities=\['read'\]/);assert.match(source,/namedCapabilities=\['read','manage_application_checks'\]/);assert.match(source,/fixture.counts.reads\)\.toBe\(beforeReadOnly\)/);
});


test('closed application-settings stages are retained by the runner without raw diagnostics',()=>{
 const diagnostics=createApplicationCheckSettingsDiagnostics();assert.equal(diagnostics.current(),'initial');
 for(const stage of ['bootstrap','http-url','tcp-kind','tcp-allowlist','save-edit','confirm-enable','readonly-role','admin-role','final-guards']){diagnostics.mark(stage);assert.equal(diagnostics.current(),stage);}
 for(const invalid of ['https://secret.invalid/?token=never-log','raw DOM or exception text',null,{},42]){diagnostics.mark(invalid);assert.equal(diagnostics.current(),'unknown');}
 const runner=read('./lan-browser.mjs'),source=read('./application-check-settings-browser.mjs');
 assert.match(runner,/name===applicationCheckSettingsCaseName\?\{stage:applicationCheckSettingsFailureStage\(\)\}/);
 assert.match(source,/applicationSettingsDiagnostics.mark\('tcp-kind'\)/);assert.match(source,/applicationSettingsDiagnostics.mark\('tcp-allowlist'\)/);
 assert.match(source,/const field=name=>panel.getByRole\('textbox',\{name,exact:true\}\)/);
 assert.match(source,/getByRole\('combobox',\{name:'Type',exact:true\}\)/);
 assert.doesNotMatch(source,/getByLabel\('(?:Type|Allowed IP addresses)'/);
});

test('actual TargetForm preserves exact role names where Playwright label text includes control contents',()=>{
 // Execute the installed, lockfile-pinned selector implementation in a DOM model.
 // This is a selector regression, not Chromium/layout/actionability acceptance.
 const require=createRequire(new URL('../../web/package.json',import.meta.url));
 const {JSDOM,VirtualConsole}=require('jsdom'),React=require('react');
 const {renderToStaticMarkup}=require('react-dom/server'),{transformSync}=require('esbuild');
 const source=read('../../web/src/application-check-settings.tsx');
 const form=source.slice(source.indexOf('function TargetForm('),source.indexOf('function ApplicationCheckSettingsContent('));
 assert.match(form,/function TargetForm\(/);
 const compiled=transformSync(`import {useId} from 'react';\n${form}\nexport default TargetForm;`,{loader:'tsx',format:'cjs',jsx:'automatic'}).code;
 const module={exports:{}};new Function('require','module','exports',compiled)(require,module,module.exports);
 const TargetForm=module.exports.default;
 const labels={target:'Target',id:'Target ID',kind:'Type',url:'URL',dnsHost:'Hostname',tcpHost:'Hostname or IP address',port:'Port',ips:'Allowed IP addresses',ipsHelp:'Exact invented IPs',privateAck:'Approve private LAN',httpAck:'Approve plaintext HTTP',remove:'Remove target'};
 const draft={kind:'http',id:'fixture',url:'https://fixture-check.invalid/health',host:'',port:'',ips:'',privateAck:false,httpAck:false};
 const target=(index,ips)=>React.createElement(TargetForm,{draft:{...draft,ips},index,count:2,labels,change:()=>{},remove:()=>{}});
 const html=renderToStaticMarkup(React.createElement('form',null,target(0,'10.20.30.40'),target(1,'')));
 const dom=new JSDOM(html,{runScripts:'outside-only',pretendToBeVisual:true,virtualConsole:new VirtualConsole()});
 try{
  const {source:injectedSource}=require(nodePath.join(nodePath.dirname(require.resolve('playwright-core/package.json')),'lib/generated/injectedScriptSource.js'));
  const win=dom.window;win.module={exports:{}};win.eval(injectedSource);
  const InjectedScript=win.eval('InjectedScript');
  const injected=new InjectedScript(win,{isUnderTest:true,sdkLanguage:'javascript',testIdAttributeName:'data-testid',stableRafCount:1,browserName:'chromium',customEngines:[]});
  const query=selector=>injected.querySelectorAll(injected.parseSelector(selector),win.document);
  assert.equal(query('internal:label="Type"s').length,0);
  assert.equal(query('internal:role=combobox[name="Type"s]').length,2);
  assert.equal(query('internal:role=combobox[name="Type"s] >> nth=1')[0],win.document.querySelectorAll('select')[1]);
  assert.equal(query('internal:label="Allowed IP addresses"s').length,1);
  assert.equal(query('internal:label="Allowed IP addresses"s >> nth=1').length,0);
  assert.equal(query('internal:role=textbox[name="Allowed IP addresses"s]').length,2);
  assert.equal(query('internal:role=textbox[name="Allowed IP addresses"s] >> nth=1')[0],win.document.querySelectorAll('textarea')[1]);
 }finally{dom.window.close();}
});

test('direct-entry status fixture is GET-only and cannot configure, probe or grant any target',()=>{
 const f=createApplicationCheckSettingsFixture(),status=f.handle('GET','/api/application-checks/status',null);
 assert.equal(status.enabled,false);assert.deepEqual(status.items,[]);assert.deepEqual(f.counts,{reads:0,saves:0,enables:0,disables:0});
 const source=read('./application-check-settings-browser.mjs');
 assert.match(source,/pageAt\('\/overview'\)/);assert.match(source,/entry.click\(\)/);assert.match(source,/toHaveURL\(`\$\{base\}\/\#\/settings\/application-checks`\)/);
 assert.match(source,/expect\(fixture.counts\).toEqual\(\{reads:1,saves:0,enables:0,disables:0\}\)/);
 assert.match(source,/application-entry-mobile-de/);assert.match(source,/application-entry-draft-mobile-de/);assert.match(source,/name:'Schließen',exact:true/);
 assert.match(source,/requests.filter\(value=>value.startsWith\('POST'\)\)\).toHaveLength\(4\)/);
});
