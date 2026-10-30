import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {windowsMaintenanceBrowserCase,windowsMaintenanceBrowserFixture,windowsMaintenanceBrowserChange,windowsMaintenanceTargetKey,windowsMaintenanceCaseName,windowsMaintenanceDisclosure,requireWindowsMaintenanceEvidence,guardWindowsMaintenanceRoute,windowsMaintenanceRouteState,windowsNotificationBrowserFixture,windowsNotificationBrowserEnable} from './windows-maintenance-browser.mjs';
import {completeAssessmentInbox,windowsIncidentInboxBrowserFixture,windowsIncidentInboxQuery} from './windows-incident-inbox-browser.mjs';
const now='2026-10-12T12:00:00Z',expiry='2026-10-12T13:00:00Z',later='2026-10-12T12:00:01Z',endsAt='2026-10-12T12:30:00Z';
const read=file=>fs.readFileSync(new URL(file,import.meta.url),'utf8');
test('invented exact-target start and early end preserve original end and sibling scopes',()=>{
 const before=windowsMaintenanceBrowserFixture(now,expiry);assert.equal(before.view.targets.length,6);assert.equal(before.metadata.name,'Synthetic Windows Desk');
 const body={key:windowsMaintenanceTargetKey,revision:0,endsAt,intent:'planned-work'},started=windowsMaintenanceBrowserChange(null,'start',body,now),ended=windowsMaintenanceBrowserChange(started,'end',{key:windowsMaintenanceTargetKey,revision:1,windowId:1},later);
 const active=windowsMaintenanceBrowserFixture(later,expiry,started),after=windowsMaintenanceBrowserFixture(later,expiry,ended);
 assert.equal(active.view.targets[3].revision,1);assert.equal(active.view.targets[3].windows[0].endedAt,null);assert.equal(after.view.targets[3].revision,2);assert.equal(after.view.targets[3].windows[0].endedAt,later);assert.equal(after.view.targets[3].windows[0].endsAt,endsAt);
 for(const target of before.view.targets.filter(target=>target.domain!=='disk'))assert.deepEqual(after.view.targets.find(next=>next.key===target.key),target);
 assert.throws(()=>windowsMaintenanceBrowserChange(started,'start',body,later));assert.throws(()=>windowsMaintenanceBrowserChange(ended,'end',{key:windowsMaintenanceTargetKey,revision:1,windowId:1},later));
 for(const patch of [{key:'0'.repeat(64)},{revision:1},{endsAt:'2026-10-12T12:00:30Z'},{endsAt:'2026-10-13T12:00:01Z'},{endsAt:'2026-10-12T12:30:00.000Z'},{intent:'free text'},{command:'no'}])assert.throws(()=>windowsMaintenanceBrowserChange(null,'start',{...body,...patch},now));
});
test('twenty source-bound screenshots include unchecked recipient approval and suppression are required',()=>{
 const source='a'.repeat(40),rows=[],details={screens:20,cases:[],nativeAcceptance:false,liveStoreAcceptance:false};
 for(const locale of ['en','de'])for(const width of [1440,390]){
  for(const kind of ['review','active','ended','notification-review','notification-muted'])rows.push({file:`synthetic-windows-maintenance-${kind}-${width}-${locale}.png`,sourceSha:source,test:windowsMaintenanceCaseName,viewport:{width,height:width===390?844:1000},locale,fullPage:false,publicSafe:true,fixtureDisclosure:windowsMaintenanceDisclosure});
  details.cases.push({notificationCount:1,notificationReads:3,recipientReviewed:true,approvalInitiallyUnchecked:true,maintenanceSuppressed:true,noBacklog:true,locale,width,key:windowsMaintenanceTargetKey,startCount:1,endCount:1,startReadback:1,endReadback:1,reviewedEnd:endsAt,retainedEnd:endsAt,endedAt:later,revision:2,incidentUnchanged:true});
 }
 assert.deepEqual(requireWindowsMaintenanceEvidence(rows,source,details),{review:4,active:4,ended:4,notificationReviews:4,notificationMuted:4,explicitStarts:4,explicitEarlyEnds:4,explicitNotificationEnables:4});
 for(let index=0;index<rows.length;index++)for(const patch of [null,{sourceSha:'b'.repeat(40)},{publicSafe:false},{fullPage:true},{locale:'fr'},{viewport:{width:800,height:600}},{fixtureDisclosure:'native'}])assert.throws(()=>requireWindowsMaintenanceEvidence(patch?rows.map((row,i)=>i===index?{...row,...patch}:row):rows.filter((_,i)=>i!==index),source,details));
 for(const patch of [{key:'0'.repeat(64)},{startCount:0},{startCount:2},{endCount:0},{endCount:2},{startReadback:0},{endReadback:0},{retainedEnd:expiry},{endedAt:null},{endedAt:endsAt},{revision:1},{incidentUnchanged:false},{notificationCount:0},{notificationCount:2},{notificationReads:2},{recipientReviewed:false},{approvalInitiallyUnchecked:false},{maintenanceSuppressed:false},{noBacklog:false}])assert.throws(()=>requireWindowsMaintenanceEvidence(rows,source,{...details,cases:details.cases.map((row,i)=>i===0?{...row,...patch}:row)}));
 assert.throws(()=>requireWindowsMaintenanceEvidence([...rows,rows[0]],source,details));
});
test('route assertion failures are retained without raw diagnostics',async()=>{
 const before=windowsMaintenanceRouteState();await guardWindowsMaintenanceRoute({abort:async()=>{}},async()=>{throw new Error('inert failure');});assert.deepEqual(windowsMaintenanceRouteState(),{failures:before.failures+1,pending:0});
});
test('helper stays inert and requires exact routes, real shared login and two reviewed clicks',()=>{
 const helper=read('./windows-maintenance-browser.mjs'),runner=read('./windows-maintenance-runner.mjs');
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|localStorage|sessionStorage/);
 assert.match(helper,/assert\.equal\(session.loginMode,'shared'\)/);assert.match(helper,/assert\.equal\(req.headers\(\)\['x-csrf-token'\],session.csrfToken\)/);assert.match(helper,/assert\.equal\(body.endsAt,reviewedEnd\)/);assert.match(helper,/assert\.deepEqual\(body,\{key:windowsMaintenanceTargetKey,revision:1,windowId:1\}\)/);
 assert.match(helper,/expect\(startCount\)\.toBe\(0\)/);assert.match(helper,/expect\(endCount\)\.toBe\(0\)/);assert.match(helper,/await expect.poll\(\(\)=>startReadback\)\.toBe\(1\)/);assert.match(helper,/await expect.poll\(\(\)=>endReadback\)\.toBe\(1\)/);assert.match(helper,/expect\(await inbox.innerText\(\)\)\.toBe\(incidentText\)/);assert.match(helper,/expect\(record.windows\[0\].endsAt\)\.toBe\(reviewedEnd\)/);assert.match(helper,/unexpected.push\('unexpected-route'\);return route.abort\('blockedbyclient'\)/);
 assert.match(runner,/http:\/\/127\.0\.0\.1:19912/);assert.match(runner,/requireWindowsMaintenanceEvidence\(screenshots,sourceSha,details\)/);assert.match(runner,/300000/);assert.match(runner,/liveStoreAcceptance:false/);assert.match(runner,/process.exitCode=passed\?0:1/);assert.doesNotMatch(runner,/ignoreHTTPSErrors|executablePath|console\.log\(.*error/);
});
test('ordinary hosted workflow wires inert checks, bounded runner and source-bound artifacts',()=>{
 const workflow=read('../../.github/workflows/validate.yml'),manifest=JSON.parse(read('./inert-suites.json'));
 assert.ok(manifest.entries.includes('windows-maintenance-fixtures.test.mjs'));assert.match(workflow,/node --test tests\/e2e-review\/windows-maintenance-fixtures.test.mjs/);assert.match(workflow,/Bounded Windows maintenance and notification approval \(20 required screenshots\)[\s\S]*?timeout-minutes: 6[\s\S]*?TRACEBOLT_SOURCE_SHA: \$\{\{ github.sha \}\}[\s\S]*?run: node tests\/e2e-review\/windows-maintenance-runner.mjs/);
 for(const suffix of ['results','manifest'])assert.ok(workflow.includes(`artifacts/review/windows-maintenance-${suffix}.json`));assert.ok(workflow.includes('artifacts/review/synthetic-*.png'));
});

test('recipient-specific source approval starts off and separate synthetic suppression survives window end',()=>{
 const started=windowsMaintenanceBrowserChange(null,'start',{key:windowsMaintenanceTargetKey,revision:0,endsAt,intent:'planned-work'},now);
 const off=windowsNotificationBrowserFixture(now,expiry,started);assert.equal(off.targets[2].enabled,false);assert.equal(off.counts.suppressed,0);assert.equal(off.destinationHost,'receiver.example.test');
 const body={key:windowsMaintenanceTargetKey,revision:0,enabled:true,destinationBinding:off.destinationBinding,payloadAcknowledged:true};
 for(const patch of [{key:'0'.repeat(64)},{revision:1},{destinationBinding:'b'.repeat(64)},{payloadAcknowledged:false},{endpoint:'https://forbidden.invalid'}])assert.throws(()=>windowsNotificationBrowserEnable(null,{...body,...patch},now));
 const policy=windowsNotificationBrowserEnable(null,body,now),muted=windowsNotificationBrowserFixture(later,expiry,started,policy);assert.equal(muted.targets[2].effective,true);assert.equal(muted.targets[2].maintenanceUntil,endsAt);assert.equal(muted.counts.suppressed,1);assert.equal(muted.counts.queued,0);assert.throws(()=>windowsNotificationBrowserEnable(policy,body,now));
 const ended=windowsMaintenanceBrowserChange(started,'end',{key:windowsMaintenanceTargetKey,revision:1,windowId:1},later),after=windowsNotificationBrowserFixture(later,expiry,ended,policy);assert.equal(after.targets[2].maintenanceUntil,null);assert.equal(after.counts.queued,0);assert.equal(after.counts.suppressed,1);
});

test('actual Playwright exact labels find the EN/DE notification source without option text',async()=>{
 const {createRequire}=await import('node:module'),require=createRequire(new URL('../../web/package.json',import.meta.url));
 const path=require('node:path'),playwrightRoot=path.dirname(require.resolve('playwright-core/package.json'));
 assert.equal(require(path.join(playwrightRoot,'package.json')).version,'1.58.2');
 const {source}=require(path.join(playwrightRoot,'lib/generated/injectedScriptSource.js'));
 const {JSDOM,VirtualConsole}=require('jsdom'),React=require('react'),{renderToStaticMarkup}=require('react-dom/server');
 const web=new URL('../../web/',import.meta.url).pathname;
 for(const locale of ['en','de']){
  const view=windowsNotificationBrowserFixture(now,expiry);
  const bundle=await require('esbuild').build({entryPoints:[path.join(web,'src/windows-notifications.tsx')],bundle:true,platform:'node',format:'cjs',jsx:'automatic',external:['react','react/jsx-runtime'],write:false,logLevel:'silent',loader:{'.css':'empty'},plugins:[{name:'inert-open-notification-view',setup(build){
   build.onResolve({filter:/^\.\/windows-notifications-resource$/},()=>({path:'resource',namespace:'inert'}));
   build.onResolve({filter:/^\.\/windows-complete-notifications-resource$/},()=>({path:'complete-resource',namespace:'inert'}));
   build.onResolve({filter:/^\.\/i18n$/},()=>({path:'locale',namespace:'inert'}));
   build.onLoad({filter:/.*/,namespace:'inert'},item=>({contents:item.path==='locale'?`export const useLocale=()=>[${JSON.stringify(locale)}];`:item.path==='complete-resource'?`export const useWindowsCompleteNotifications=(open)=>{if(open)throw new Error('Complete source must remain closed in the preview label fixture');return {view:null,generation:0,writing:false,isUncertain(){return false;}};};`:`export const useWindowsNotifications=()=>({view:${JSON.stringify(view)},loading:false,writing:false,error:false,notice:null,generation:0,age:0,refresh(){},save(){},isUncertain(){return false;}});`,loader:'js'}));
  }}]});
  // Render the actual production component open with inert data, without a request.
  let stateCalls=0;const react={...React,useState(initial){return [++stateCalls===1?true:initial,()=>{}];}},mod={exports:{}};
  new Function('require','module','exports',bundle.outputFiles[0].text)(name=>name==='react'?react:require(name),mod,mod.exports);
  const markup=renderToStaticMarkup(React.createElement(mod.exports.WindowsNotifications,{devices:[],sessionKey:expiry,admin:true}));
  const virtualConsole=new VirtualConsole();virtualConsole.on('jsdomError',error=>{if(!error.message.includes('getComputedStyle() method: with pseudo-elements'))throw error;});
  const dom=new JSDOM(markup,{runScripts:'outside-only',virtualConsole});
  try{
   const InjectedScript=dom.window.eval('var module={exports:{}};'+source+'\nInjectedScript');
   const injected=new InjectedScript(dom.window,{isUnderTest:true,sdkLanguage:'javascript',testIdAttributeName:'data-testid',customEngines:[],browserName:'chromium'});
   const query=selector=>Array.from(injected.querySelectorAll(injected.parseSelector(selector),dom.window.document));
   const name=locale==='de'?'Gerät und Prüfung':'Device and check',select=dom.window.document.querySelector('select');
   assert.ok(select);assert.equal(select.getAttribute('aria-label'),name);assert.ok(select.closest('label'));
   assert.deepEqual(query(`internal:label=${JSON.stringify(name)}s`),[select]);
   assert.deepEqual(query(`internal:role=combobox[name=${JSON.stringify(name)}s]`),[select]);
   // Removing only the name in this synthetic DOM reproduces the hosted failure.
   select.removeAttribute('aria-label');
   assert.equal(query(`internal:label=${JSON.stringify(name)}s`).length,0);
   assert.deepEqual(query(`internal:role=combobox[name=${JSON.stringify(name)}s]`),[select]);
  }finally{dom.window.close();}
 }
});


test('existing maintenance walkthrough explicitly selects preview without granting complete notifications',()=>{
 const helper=read('./windows-maintenance-browser.mjs'),component=read('../../web/src/windows-notifications.tsx');
 assert.match(component,/useState<'preview' \| 'complete'>\('preview'\)/);
 assert.match(component,/<WindowsCompleteNotifications \{\.\.\.props\} open=\{open && source === 'complete'\}/);
 const preview="await notifications.getByRole('button',{name:de?'Vorschau':'Preview',exact:true}).click();";
 assert.equal(helper.split(preview).length-1,1);
 assert(helper.indexOf(preview)<helper.indexOf("await notifications.getByLabel(de?'Gerät und Prüfung':'Device and check'"));
 assert(!helper.includes("url.pathname==='/api/fleet/windows-notifications/complete/policy'"));
});


// Capture the actual route installed by this existing real-App consumer. The page
// stub stops before viewport/UI work; no browser, listener or network is opened.
test('installed maintenance consumer serves the v2 inbox and denies legacy, malformed and mutation fallback',async()=>{
 const base='https://maintenance.invalid',stop=new Error('inert route installation complete');let handle,sessionReads=0;
 const session={authenticated:true,loginMode:'shared',serverNow:now,expiresAt:expiry};
 const page={
  request:{get:async(url,options)=>{assert.equal(url,base+'/api/auth/session');assert.deepEqual(options,{maxRedirects:0,timeout:5000});sessionReads++;return {status:()=>200,json:async()=>session,dispose:async()=>{}};}},
  route:async(pattern,installed)=>{assert.equal(pattern,'**/*');assert.equal(handle,undefined);handle=installed;},
  setViewportSize:async()=>{throw stop;},
 };
 await assert.rejects(windowsMaintenanceBrowserCase({page,base,login:async value=>assert.equal(value,page),expect:()=>assert.fail('No UI execution'),shot:()=>assert.fail('No screenshot')}),error=>error===stop);
 assert.equal(typeof handle,'function');assert.deepEqual(windowsMaintenanceRouteState(),{failures:0,pending:0});
 const request=(target,{method='GET',body=null}={})=>{
  const result={reply:null,continued:0,aborted:[]};return {result,request:()=>({url:()=>target.startsWith('https:')?target:base+target,method:()=>method,postData:()=>body,headers:()=>({})}),
   fulfill:async value=>{assert.equal(value.status,200);assert.equal(value.contentType,'application/json');result.reply=JSON.parse(value.body);},
   continue:async()=>{result.continued++;},abort:async reason=>{result.aborted.push(reason);},fetch:async()=>assert.fail('Inbox fixture cannot reach a real endpoint')};
 };
 const original=windowsIncidentInboxBrowserFixture(now,expiry).view,route=request('/api/fleet/windows-incidents/complete'+windowsIncidentInboxQuery);
 await handle(route);assert.deepEqual(route.result,{reply:completeAssessmentInbox(original),continued:0,aborted:[]});assert.equal(sessionReads,1);
 assert.equal(route.result.reply.schemaVersion,'tracebolt.windows-incident-inbox.v2');assert.equal(route.result.reply.items.length,5);
 const restored={...route.result.reply,schemaVersion:'tracebolt.windows-incident-inbox.v1',items:route.result.reply.items.map(({sourceKind,openingSource,lastBadSource,recoverySource,currentSource,...item})=>{
  assert.equal(sourceKind,'assessment_v1');assert.deepEqual([openingSource,lastBadSource,recoverySource,currentSource],[null,null,null,null]);return item;
 })};
 assert.deepEqual(restored,original);assert.deepEqual(route.result.reply.items.map(item=>item.key),original.items.map(item=>item.key));
 for(const target of ['/api/fleet/windows-incidents'+windowsIncidentInboxQuery,'/api/fleet/windows-incidents/complete/acknowledge','https://external.invalid/api/fleet/windows-incidents/complete'+windowsIncidentInboxQuery]){
  const denied=request(target,target.endsWith('/acknowledge')?{method:'POST',body:'{}'}:{});await handle(denied);assert.deepEqual(denied.result,{reply:null,continued:0,aborted:['blockedbyclient']});
 }
 for(const [target,options] of [
  ['/api/fleet/windows-incidents/complete'+windowsIncidentInboxQuery,{method:'POST',body:'{}'}],
  ['/api/fleet/windows-incidents/complete'+windowsIncidentInboxQuery,{body:'{}'}],
  ['/api/fleet/windows-incidents/complete?scope=all',{}],
 ]){
  const denied=request(target,options);await handle(denied);assert.deepEqual(denied.result,{reply:null,continued:0,aborted:['failed']});
 }
 assert.equal(sessionReads,1);assert.deepEqual(windowsMaintenanceRouteState(),{failures:3,pending:0});
});
