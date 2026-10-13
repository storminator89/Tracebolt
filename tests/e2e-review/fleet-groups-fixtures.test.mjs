import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {fleetGroupsBrowserFixture,fleetGroupsPolicyFixture,fleetGroupsMonitoringFixture,fleetGroupsMaintenanceFixture,fleetGroupsMaintenanceEndFixture,fleetGroupsMaintenanceEndWrite,exerciseFleetGroupsMaintenanceEnd,fleetGroupsCaptureMatrix,fleetGroupsScenes,fleetGroupsCaptureName,fleetGroupIds,fleetGroupsCaseName,fleetGroupsDisclosure,requireFleetGroupsEvidence,guardFleetGroupsRoute,fleetGroupsRouteState} from './fleet-groups-browser.mjs';
const now='2026-10-11T12:00:10Z',expiry='2026-10-11T13:00:00Z';
test('invented group fixture projects only public names and exact admitted IDs',()=>{
 const fixture=fleetGroupsBrowserFixture(now,expiry);assert.equal(fixture.view.groups[0].unavailableMembers,1);assert.equal(fixture.view.devices.length,3);assert.deepEqual(Object.keys(fixture.view.groups[0]).sort(),['id','memberIds','name','revision','unavailableMembers']);assert.ok(fixture.metadata.every(d=>d.agentCertificate.checkedAt===now));
 for(const metric of ['disk','cpu','memory'])for(const enabled of [false,true]){const policy={enabled,thresholdPercent:90,revision:enabled?1:0},view=fleetGroupsPolicyFixture(now,expiry,fleetGroupIds.first,metric,policy);assert.deepEqual(view.policy,policy);assert.equal(view.status,enabled?'unknown':'disabled');assert.equal(view.observation,null);assert.equal(view.metric,metric==='disk'?undefined:metric);}
});
test('completion requires every canonical source-bound EN/DE desktop/mobile screenshot',()=>{
 const source='a'.repeat(40),rows=fleetGroupsCaptureMatrix.map(({file,width,height,locale})=>({file,sourceSha:source,test:fleetGroupsCaseName,viewport:{width,height},locale,fullPage:false,publicSafe:true,fixtureDisclosure:fleetGroupsDisclosure}));
 assert.deepEqual(requireFleetGroupsEvidence(rows,source),Object.fromEntries(fleetGroupsScenes.map(scene=>[scene,fleetGroupsCaptureMatrix.filter(row=>row.scene===scene).length])));
 for(let index=0;index<rows.length;index++)for(const changed of [null,{sourceSha:'b'.repeat(40)},{fullPage:true},{publicSafe:false},{fixtureDisclosure:'native'},{test:'other'},{viewport:{width:800,height:600}}])assert.throws(()=>requireFleetGroupsEvidence(changed?rows.map((r,i)=>i===index?{...r,...changed}:r):rows.filter((_,i)=>i!==index),source));
 assert.throws(()=>requireFleetGroupsEvidence([...rows,rows[0]],source));
});
test('hosted capture admission includes every required image and rejects noncontract names',()=>{
 const runner=fs.readFileSync(new URL('./fleet-groups-runner.mjs',import.meta.url),'utf8');
 assert.match(runner,/fleetGroupsCaptureMatrix.find\(row=>row.name===name\)/);
 for(const row of fleetGroupsCaptureMatrix)assert.equal(fleetGroupsCaptureName(row.scene,row.width,row.locale),row.name);
 for(const invalid of [['other',1440,'en'],['draft',800,'en'],['draft',1440,'fr']])assert.throws(()=>fleetGroupsCaptureName(...invalid));
});
test('route assertion failures remain failures and cannot disappear in detached callbacks',async()=>{
 const before=fleetGroupsRouteState(),route={abort:async()=>{}};await guardFleetGroupsRoute(route,async()=>{throw new Error('inert failure');});assert.deepEqual(fleetGroupsRouteState(),{failures:before.failures+1,pending:0});
});
test('helper is inert and hosted runner keeps real loopback login with finite sanitized output',()=>{
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./fleet-groups-runner.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(helper,/chromium\.launch|newContext\(|spawn\(|execFile|writeFile|ignoreHTTPSErrors|localStorage|sessionStorage/);
 assert.match(runner,/http:\/\/127\.0\.0\.1:19909/);assert.match(runner,/requireFleetGroupsEvidence\(screenshots,sourceSha\)/);assert.match(runner,/liveStoreAcceptance:false/);assert.match(runner,/fleet-groups-results.json/);assert.match(runner,/fleet-groups-manifest.json/);assert.match(runner,/300000/);assert.match(runner,/process.exitCode=passed\?0:1/);assert.doesNotMatch(runner,/ignoreHTTPSErrors|console\.log\(.*error/);
 assert.match(helper,/Current policy matches, but this does not prove our write succeeded/);assert.match(helper,/Stop remaining writes/);assert.match(helper,/removeUnavailableMembers,false/);assert.doesNotMatch(helper,/page\.getByRole\('table'\)/);assert.match(helper,/page\.getByRole\('dialog'\)\.getByRole\('table'\)/);assert.match(helper,/await page\.reload\(\)/);
});

test('uncertain readback checks the exact first-device outcome cell and bounded failure stages',()=>{
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8');
 const uncertain=helper.slice(helper.indexOf("stage='uncertain-review';mode='uncertain'"),helper.indexOf("stage='stop';mode='hold'"));
 assert.match(uncertain,/getByRole\('dialog'\)\.getByRole\('row'\)\.filter\(\{hasText:ids.first\}\)\.getByRole\('cell'\)\.last\(\)/);
 assert.match(uncertain,/expect\(uncertainOutcome\)\.toHaveText\('Physical RAM percentageUnconfirmed · write may have happenedCurrent policy matches, but this does not prove our write succeeded\.'\)/);
 assert.doesNotMatch(uncertain,/getByText\('Unconfirmed · write may have happened'/);
 assert.match(uncertain,/expect\(policyPosts\)\.toBe\(uncertainBefore\+1\)/);
 assert.match(uncertain,/getByText\('Not attempted',\{exact:true\}\)/);
 for(const stage of ['review','apply','result','remaining','count','close']){
  assert.ok(uncertain.includes(`stage='uncertain-${stage}'`));
  assert.ok(helper.slice(0,helper.indexOf('export function guardFleetGroupsRoute')).includes(`'uncertain-${stage}'`));
 }
});

test('fleet dialog retains desktop and compact mobile inner spacing',()=>{
 const css=fs.readFileSync(new URL('../../web/src/fleet-groups.css',import.meta.url),'utf8');
 assert.match(css.split('@media')[0],/\.fleet-group-dialog \.dialog\{[^}]*padding:28px[;}]/);
 assert.match(css,/\@media\(max-width:600px\)\{.*\.fleet-group-dialog \.dialog\{padding:22px\}/);
});

test('compact mobile rows keep all policy cells in the viewport without losing table semantics',()=>{
 const css=fs.readFileSync(new URL('../../web/src/fleet-groups.css',import.meta.url),'utf8'),ui=fs.readFileSync(new URL('../../web/src/fleet-groups.tsx',import.meta.url),'utf8'),helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8');
 const mobile=css.slice(css.indexOf('/* Keep the table semantics'));
 assert.doesNotMatch(css,/min-width:450px/);
 assert.match(mobile,/\.fleet-group-table-wrap\{overflow-x:visible\}/);
 assert.match(mobile,/grid-template-columns:minmax\(0,1fr\)/);
 assert.match(mobile,/\.fleet-group-table td\{display:block;min-width:0;padding:0;border:0\}/);
 assert.match(mobile,/\.fleet-group-table thead\{[^}]*clip-path:inset\(50%\)/);
 assert.doesNotMatch(mobile,/display:none/);
 assert.match(mobile,/td\[data-label\]::before\{content:attr\(data-label\)/);
 for(const role of ['table','rowgroup','row','columnheader','cell'])assert.ok(ui.includes(`role="${role}"`));
 assert.match(ui,/data-label=\{c.before\}/);assert.match(ui,/data-label=\{c.outcome\}/);
 assert.match(helper,/expect\(layout.overflow\)\.toBeLessThanOrEqual\(1\)/);
 assert.match(helper,/expect\(cell.right\)\.toBeGreaterThanOrEqual\(-1\)/);
 assert.match(helper,/expect\(cell.overflow\)\.toBeLessThanOrEqual\(1\)/);
 for(const kind of ['review','results'])assert.ok(helper.includes("await verifyPolicyLayout();await shot(page,fleetGroupsCaptureName('"+kind+"',width,locale)"));
});

test('inheritance fixture and capture contract stay exact, unchecked and source-bound',()=>{
 const fixture=fleetGroupsMonitoringFixture(now,expiry);assert.equal(fixture.targets.length,6);assert.equal(fixture.unavailableAssignments,1);assert.deepEqual(new Set(fixture.targets.map(t=>t.metric)),new Set(['disk','cpu','memory']));assert.equal(fixture.targets[4].status,'manual-override');assert.equal(fixture.targets[4].owned,false);
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8'),runner=fs.readFileSync(new URL('./fleet-groups-runner.mjs',import.meta.url),'utf8');
 for(const scene of fleetGroupsScenes.filter(scene=>scene.startsWith('inheritance-')))assert.ok(helper.includes(`fleetGroupsCaptureName('${scene}',width,locale)`));
 assert.match(helper,/expect\(consent\)\.not\.toBeChecked\(\)/);assert.match(helper,/expect\(monitoringPosts\)\.toBe\(inheritanceBefore\+2\)/);assert.match(helper,/policy\)\.toEqual\(previousPolicy\)/);
 assert.match(helper,/screens:fleetGroupsCaptureMatrix.length/);assert.match(runner,/requireFleetGroupsEvidence\(screenshots,sourceSha\)/);assert.match(helper,/getByRole\('combobox',\{name:de\?'Flottengruppen':'Fleet groups',exact:true\}\)/);
});


test('group maintenance adds exactly four canonical views and original-identity synthetic target keys',()=>{
 const fixture=fleetGroupsMaintenanceFixture(now);assert.equal(fixture.members.length,2);assert.equal(fixture.excludedLinuxMembers,1);assert.equal(fixture.unavailableMembers,1);assert.equal(new Set(fixture.members.flatMap(m=>m.targets.map(t=>t.key))).size,12);
 const scenes=fleetGroupsCaptureMatrix.filter(row=>['maintenance-unchecked','maintenance-review','maintenance-results'].includes(row.scene));assert.equal(scenes.length,4);assert.deepEqual(new Set(scenes.map(row=>row.locale)),new Set(['en','de']));assert.deepEqual(new Set(scenes.map(row=>row.width)),new Set([1440,390]));
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8');assert.match(helper,/expect\(maintenanceConsent\)\.not\.toBeChecked\(\)/);assert.match(helper,/expect\(maintenancePosts\)\.toBe\(maintenanceBefore\+2\)/);assert.match(helper,/maintenanceBodies\[0\]\.endsAt\)\.toBe\(maintenanceBodies\[1\]\.endsAt\)/);assert.match(helper,/validGroupMaintenanceView/);
});


test('early-end captures add only four canonical source-bound views',()=>{
 const rows=fleetGroupsCaptureMatrix.filter(row=>row.scene.startsWith('maintenance-end-'));
 assert.deepEqual(rows.map(({scene,locale,width})=>({scene,locale,width})),[{scene:'maintenance-end-unchecked',locale:'en',width:1440},{scene:'maintenance-end-review',locale:'de',width:390},{scene:'maintenance-end-results',locale:'en',width:1440},{scene:'maintenance-end-results',locale:'de',width:390}]);
 assert.equal(fleetGroupsCaptureMatrix.length,40);
 for(const invalid of [['maintenance-end-unchecked',390,'en'],['maintenance-end-review',1440,'en'],['maintenance-end-results',1440,'de']])assert.throws(()=>fleetGroupsCaptureName(...invalid));
});

test('early-end fixture covers all six active domains and excludes ended and expired history',()=>{
 const fixture=fleetGroupsMaintenanceEndFixture(now),active=fixture.members.flatMap(member=>member.targets.filter(target=>target.windows[0]?.endedAt===null&&Date.parse(target.windows[0].endsAt)>Date.parse(now)));
 assert.equal(active.length,6);assert.deepEqual(active.map(target=>target.domain),['all','contact','cpu','disk','memory','service']);
 assert.ok(active.every(target=>target.windows.length===2&&target.windows[1].endedAt!==null));
 assert.equal(fixture.members[0].targets[1].windows[0].endedAt,'2026-10-11T11:58:10Z');assert.equal(fixture.members[0].targets[2].windows[0].endsAt,'2026-10-11T11:58:10Z');
});

test('exact early-end fixture writes preserve original ends and every unrelated historical row',()=>{
 const fixture=fleetGroupsMaintenanceEndFixture(now),before=structuredClone(fixture),target=fixture.members[0].targets[0],body={groupRevision:fixture.groupRevision,key:target.key,revision:target.revision,windowId:target.windows[0].id};
 const ended=fleetGroupsMaintenanceEndWrite(fixture,body,now),changed=ended.members[0].targets[0];assert.deepEqual(fixture,before);assert.equal(changed.revision,target.revision+1);assert.equal(changed.windows[0].endedAt,now);
 assert.deepEqual({...changed,revision:target.revision,changedAt:target.changedAt,windows:[{...changed.windows[0],endedAt:null},...changed.windows.slice(1)]},target);
 assert.deepEqual(ended.members.slice(1),fixture.members.slice(1));assert.deepEqual(ended.members[0].targets.slice(1),fixture.members[0].targets.slice(1));
 for(const invalid of [{...body,groupRevision:3},{...body,key:'f'.repeat(64)},{...body,revision:body.revision+1},{...body,windowId:body.windowId-2},{...body,endsAt:target.windows[0].endsAt},{...body,intent:'other'}])assert.throws(()=>fleetGroupsMaintenanceEndWrite(fixture,invalid,now));
 assert.throws(()=>fleetGroupsMaintenanceEndWrite(ended,body,now));
 for(const candidate of fixture.members[0].targets.slice(1,3))assert.throws(()=>fleetGroupsMaintenanceEndWrite(fixture,{...body,key:candidate.key,revision:candidate.revision,windowId:candidate.windows[0].id},now));
});

test('early-end hosted source keeps exact routes, unchecked review and sequential partial outcomes',()=>{
 const helper=fs.readFileSync(new URL('./fleet-groups-browser.mjs',import.meta.url),'utf8');
 assert.match(helper,/url\.pathname===`\/api\/fleet\/groups\/\$\{ids.group\}\/maintenance\/end`/);
 assert.match(helper,/assert\.equal\(req\.method\(\),starting\|\|ending\?'POST':'GET'\)/);
 assert.match(helper,/assert\.deepEqual\(body,maintenanceEndExpected\[maintenanceEndBodies\.length\]\)/);
 assert.match(helper,/maintenanceEndBodies\.length===2\)return fulfill\(route,\{error:\{code:'windows_maintenance_conflict'\}\},409\)/);
 assert.match(helper,/expect\(consent\)\.not\.toBeChecked\(\)/);assert.match(helper,/expect\(state\(\)\.posts\)\.toBe\(before\+2\)/);
 assert.match(helper,/maintenanceEndWrites:maintenanceEndPosts/);assert.match(helper,/expect\(apply\)\.toHaveCount\(0\)/);
 assert.match(helper,/exerciseFleetGroupsMaintenanceEnd\(\{page,expect,width,locale,fixture:endFixture,shot,verifyLayout:verifyPolicyLayout/);
 assert.doesNotMatch(helper,/\/api\/fleet\/windows-maintenance\/end|page\.route\([^\n]*maintenance\/end/);
});


// Exercise the shared hosted selectors against the real React dialog and the
// pinned Playwright selector engine. These are source/DOM checks, not a browser
// launch, viewport-fit assertion, screenshot, or native acceptance claim.
test('production early-end dialog executes the exact EN/DE hosted selectors and partial write contract',async()=>{
 const root=fileURLToPath(new URL('../../',import.meta.url)),require=createRequire(path.join(root,'web/package.json'));
 const {JSDOM,VirtualConsole}=require('jsdom'),virtualConsole=new VirtualConsole();virtualConsole.on('jsdomError',error=>{if(!error.message.includes('getComputedStyle() method: with pseudo-elements'))throw error;});
 const playwrightRoot=path.dirname(require.resolve('playwright-core/package.json'));assert.equal(require(path.join(playwrightRoot,'package.json')).version,'1.58.2');const {source}=require(path.join(playwrightRoot,'lib/generated/injectedScriptSource.js'));
 const built=await require('esbuild').build({stdin:{contents:"export {GroupMaintenanceEnd} from './fleet-group-maintenance-end'; export {setLocale} from './i18n'; export {APIError} from './api';",resolveDir:path.join(root,'web/src'),loader:'tsx'},bundle:true,platform:'node',format:'cjs',jsx:'automatic',external:['react'],write:false,logLevel:'silent',loader:{'.css':'empty'}});
 const mod={exports:{}};new Function('require','module','exports',built.outputFiles[0].text)(require,mod,mod.exports);const {GroupMaintenanceEnd,setLocale,APIError}=mod.exports;
 const React=require('react'),{createRoot}=require('react-dom/client'),screenshots=[],globals=['window','document','HTMLElement','IS_REACT_ACT_ENVIRONMENT'],previous=new Map(globals.map(key=>[key,Object.getOwnPropertyDescriptor(globalThis,key)]));
 try{for(const locale of ['en','de'])for(const width of [1440,390]){
  const dom=new JSDOM('<div id="root"></div>',{runScripts:'outside-only',virtualConsole}),InjectedScript=dom.window.eval('var module={exports:{}};'+source+'\nInjectedScript'),injected=new InjectedScript(dom.window,{isUnderTest:true,sdkLanguage:'javascript',testIdAttributeName:'data-testid',customEngines:[],browserName:'chromium'});
  for(const [key,value]of Object.entries({window:dom.window,document:dom.window.document,HTMLElement:dom.window.HTMLElement,IS_REACT_ACT_ENVIRONMENT:true}))Object.defineProperty(globalThis,key,{value,configurable:true,writable:true});
  const fixture=fleetGroupsMaintenanceEndFixture(now),group={id:fixture.groupId,name:fixture.groupName,revision:fixture.groupRevision,memberIds:fixture.members.map(member=>member.deviceId),unavailableMembers:1},bodies=[];let view=structuredClone(fixture),closed=0,layouts=0,viewportProbes=0;
  const expected=fixture.members.flatMap(member=>member.targets.filter(target=>target.windows[0]?.endedAt===null&&Date.parse(target.windows[0].endsAt)>Date.parse(now))).slice(0,3).map(target=>({groupRevision:fixture.groupRevision,key:target.key,revision:target.revision,windowId:target.windows[0].id}));
  const resource={admin:true,cancel:()=>{},maintenanceIO:id=>{assert.equal(id,fixture.groupId);return {active:()=>true,get:async()=>structuredClone(view),end:async body=>{assert.deepEqual(body,expected[bodies.length]);bodies.push(body);if(bodies.length===2)throw new APIError('synthetic conflict',409);view=fleetGroupsMaintenanceEndWrite(view,body,now);return structuredClone(view);}};}};
  const ui=createRoot(dom.window.document.getElementById('root'));
  const role=(name,options={})=>`internal:role=${name}${options.name===undefined?'':`[name=${JSON.stringify(options.name)}${options.exact?'s':'i'}]`}`;
  const query=selector=>Array.from(injected.querySelectorAll(injected.parseSelector(selector),dom.window.document));
  function locator(selector){return {selector,all:()=>query(selector),one(){const found=query(selector);assert.equal(found.length,1,selector);return found[0];},locator:next=>locator(`${selector} >> ${next}`),getByRole:(name,options)=>locator(`${selector} >> ${role(name,options)}`),nth:index=>locator(`${selector} >> nth=${index}`),last:()=>locator(`${selector} >> nth=-1`),async click(){await React.act(async()=>{const el=this.one();assert.equal(el.disabled===true,false);el.click();});},async check(){await React.act(async()=>{const el=this.one();assert.equal(el.type,'checkbox');assert.equal(el.disabled,false);assert.equal(el.checked,false);el.click();});}};}
  const page={getByRole:(name,options)=>locator(role(name,options)),evaluate:async read=>{assert.match(read.toString(),/document.documentElement.scrollWidth<=innerWidth/);viewportProbes++;return true;}};
  const normalized=value=>value.replace(/\s+/g,' ').trim();
  function expect(actual){function match(negate=false){return {toBe:value=>assert.equal(actual,value),toEqual:value=>assert.deepEqual(actual,value),toHaveCount:value=>assert.equal(actual.all().length,value,actual.selector),toHaveText:value=>assert.deepEqual(actual.all().map(el=>normalized(el.textContent)),value.map(normalized),actual.selector),toBeDisabled:()=>assert.equal(actual.one().disabled,!negate,actual.selector),toBeChecked:()=>assert.equal(actual.one().checked,!negate,actual.selector),toHaveAttribute:(key,value)=>assert.equal(actual.one().getAttribute(key)===value,!negate,actual.selector),toContainText:value=>assert.equal(normalized(actual.one().textContent).includes(normalized(value)),!negate,`${actual.selector}: ${value}`),get not(){return match(true);}};}return match();}
  try{
   setLocale(locale,false);await React.act(async()=>{ui.render(React.createElement(GroupMaintenanceEnd,{resource,group,onClose:()=>{closed++;}}));});
   await exerciseFleetGroupsMaintenanceEnd({page,expect,width,locale,fixture,state:()=>({posts:bodies.length,bodies,view}),verifyLayout:async()=>{layouts++;assert.equal(query('internal:role=table').length,1);},shot:async(_page,name,disclosure)=>{assert.equal(disclosure,fleetGroupsDisclosure);assert.equal(query('details[open]').length,0);screenshots.push(name);}});
   assert.equal(bodies.length,2);assert.equal(closed,1);assert.equal(layouts,2);assert.equal(viewportProbes,fleetGroupsCaptureMatrix.filter(row=>row.scene.startsWith('maintenance-end-')&&row.locale===locale&&row.width===width).length);
  }finally{await React.act(async()=>ui.unmount());dom.window.close();}
 }}finally{for(const key of globals){const descriptor=previous.get(key);if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];}}
 assert.deepEqual([...screenshots].sort(),fleetGroupsCaptureMatrix.filter(row=>row.scene.startsWith('maintenance-end-')).map(row=>row.name).sort());
});
