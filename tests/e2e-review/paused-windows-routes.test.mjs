/** Inert full-App regression: production React and the pinned Playwright clock
 * execute in fresh jsdom documents. No browser, server, host action or network. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {createRequire} from 'node:module';
import {MessageChannel} from 'node:worker_threads';
import {settlePausedDetailRoute} from './paused-detail-route.mjs';
import {createWindowsManagedMSIFixture,windowsManagedMSIRoute,windowsManagedMSIOrigin,exerciseWindowsManagedMSI} from './windows-managed-msi-browser.mjs';
import {createWindowsMutationCoexistenceFixture,windowsMutationCoexistenceRoute,exerciseWindowsMutationCoexistence} from './windows-mutation-coexistence-browser.mjs';
import {createWindowsServiceActionsFixture,windowsServiceActionsRoute,exerciseWindowsServiceActions} from './windows-service-actions-browser.mjs';
import {createWindowsServiceActionHistoryFixture,windowsServiceActionHistoryRoute,exerciseWindowsServiceActionHistory} from './windows-service-action-history-browser.mjs';
import {createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,exerciseWindowsUpdateJobs} from './windows-update-jobs-browser.mjs';
import {createWindowsUpdateDownloadFixture,windowsUpdateDownloadRoute,exerciseWindowsUpdateDownload} from './windows-update-download-browser.mjs';
import {createWindowsUpdateRetirementFixture,windowsUpdateRetirementRoute,exerciseWindowsUpdateRetirement} from './windows-update-retirement-browser.mjs';
import {createWindowsUpdateScheduleFixture,windowsUpdateScheduleRoute,exerciseWindowsUpdateSchedule} from './windows-update-schedule-browser.mjs';
import {createWindowsSoftwareJobsFixture,windowsSoftwareJobsRoute,exerciseWindowsSoftwareJobs} from './windows-software-jobs-browser.mjs';
import {windowsStorageIOBrowserCase,windowsStorageIOBrowserFixture} from './windows-storage-io-browser.mjs';
import * as storageIOHarness from './windows-storage-io-browser.mjs';
const require=createRequire(new URL('../../web/package.json',import.meta.url));
const {JSDOM}=require('jsdom'),{queryByRole,queryByLabelText}=require('@testing-library/dom');
const {source:clockSource}=require(require.resolve('playwright-core/package.json').replace('package.json','lib/generated/clockSource.js'));
const bundle=(await require('esbuild').build({plugins:[{name:'cold-detail-chunk',setup(build){build.onLoad({filter:/\/route-details\.tsx$/},async({path})=>({contents:(await fs.promises.readFile(path,'utf8')).replaceAll("import('./details')","window.fixtureImport(() => import('./details'))"),loader:'tsx'}));}}],stdin:{contents:`
 import {createElement} from 'react'; import {createRoot} from 'react-dom/client';
 import App from './src/App';
 const root=createRoot(document.getElementById('root'));
 window.fixtureDispose=()=>root.unmount();root.render(createElement(App));
`,resolveDir:new URL('../../web/',import.meta.url).pathname,loader:'tsx'},bundle:true,write:false,platform:'browser',format:'iife',jsx:'automatic',loader:{'.css':'empty'},define:{'process.env.NODE_ENV':'"production"'},logLevel:'silent'})).outputFiles[0].text;
const nativeWait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(predicate){const end=Date.now()+1000;while(!predicate()){assert.ok(Date.now()<end,'Inert full-App condition did not settle');await nativeWait(1);}}
const reachedInventory=Symbol('first inventory interaction');
async function fullApp({fixture,route,locale='en',base=windowsManagedMSIOrigin,stopAtInventory=false,pauseOffset=100,holdDetailImport=true}){
 let dom,window,clock,handler=route?.({base,fixture,state:{blocked:[],external:[]}}),initial=fixture?Date.parse(fixture.now):null,paused=initial===null?null:initial+pauseOffset;
 const channels=[],advances=[],history=[],requests=[],errors=[];
 async function disposeDocument(){if(!window)return;window.fixtureDispose?.();clock?.uninstall();for(const channel of channels.splice(0)){channel.port1.close();channel.port2.close();}window.close();}
 async function documentAt(url){
  await disposeDocument();dom=new JSDOM('<main id="root"></main>',{url,pretendToBeVisual:true,runScripts:'outside-only'});window=dom.window;
  window.localStorage.setItem('tracebolt.locale',locale);
  // Hold only the emitted lazy chunk until its real full-App fallback commits.
  // The compiled production App, boundary, details, auth and resources are intact.
  let releaseChunk;window.fixtureImport=load=>holdDetailImport?new Promise(resolve=>{releaseChunk=()=>resolve(load());}):load();
  window.MessageChannel=class extends MessageChannel{constructor(){super();channels.push(this);}};
  Object.defineProperty(window,'performance',{value:window.performance,writable:true,configurable:true});
  Object.assign(window,{TextDecoder,TextEncoder,Response,Request,Headers});
  window.addEventListener('error',()=>errors.push('runtime'));
  window.fetch=async(input,options={})=>{
   const url=new URL(input,window.location.href).href,method=options.method??'GET',body=options.body??null;
   requests.push({method,path:new URL(url).pathname});let response;
   await handler({request:()=>({url:()=>url,method:()=>method,postData:()=>body,headers:()=>({...Object.fromEntries(new Headers(options.headers)),origin:base})}),
    fulfill:async({status=200,body,contentType})=>{response=new Response(body,{status,headers:{'content-type':contentType}});},
    abort:async()=>{throw Error('Inert route rejected request');},continue:async()=>{throw Error('Inert route attempted network');}});
   assert.ok(response,'Inert route must fulfill response');return response;
  };
  window.eval(`(()=>{const module={};${clockSource};globalThis.__clock=(module.exports.inject())(globalThis);})();`);clock=window.__clock.controller;
  clock.log('install',0,initial);clock.log('pauseAt',0,paused);for(const ms of history)clock.log('runFor',0,ms);clock.now();window.eval(bundle);
  if(holdDetailImport){await until(()=>window.document.querySelector('.loading > span')?.textContent.match(/^(Loading view …|Ansicht wird geladen …)$/));
  releaseChunk();await until(()=>[...clock._timers.values()].some(timer=>timer.delay===300));}
 }
 const locate=get=>({get,or:other=>locate(()=>get()||other.get()),first(){return this;},isVisible:async()=>!!get(),
  async click(){await until(get);if(stopAtInventory&&get()?.getAttribute('role')==='tab'&&/^(Inventory|Inventar)$/.test(get().textContent))throw reachedInventory;get().click();},
  async selectOption(value){await until(get);get().value=value;get().dispatchEvent(new window.Event('change',{bubbles:true}));},
  getByRole:(role,options)=>locate(()=>get()&&queryByRole(get(),role,options)),locator:selector=>locate(()=>get()?.querySelector(selector)),
 });
 const page={
  locator:selector=>locate(()=>window?.document.querySelector(selector)),
  getByRole:(role,options)=>locate(()=>window&&queryByRole(window.document.body,role,options)),
  getByLabel:label=>locate(()=>window&&queryByLabelText(window.document.body,label)),
  getByText:pattern=>locate(()=>window&&[...window.document.querySelectorAll('.loading > span')].find(node=>pattern.test(node.textContent))),
  async goto(url){if(!window||new URL(url).origin!==window.location.origin)await documentAt(url);else{window.history.replaceState(null,'',url);window.dispatchEvent(new window.HashChangeEvent('hashchange'));}},
  async reload(){await documentAt(window.location.href);},async route(pattern,value){assert.equal(pattern,'**/*');handler=value;},async setViewportSize(){},
  async evaluate(fn){return window.eval(`(${fn})()`);},
  clock:{async install({time}){initial=+time;},async pauseAt(time){paused=+time;},async runFor(ms){advances.push(ms);history.push(ms);await clock.runFor(ms);}},
 };
 const expect=value=>({toBe:want=>assert.equal(value,want),async toBeVisible(){await until(value.get);},async toHaveAttribute(name,want){await until(()=>value.get()?.getAttribute(name)===want);}});
 return {page,expect,advances,requests,errors,initial:()=>initial,now:()=>window.Date.now(),monotonic:()=>window.performance.now(),clock:()=>clock,window:()=>window,
  ready:()=>page.getByRole('tab',{name:/^(Inventory|Inventar)$/,exact:true}),fallback:()=>page.getByText(/^(Loading view …|Ansicht wird geladen …)$/),close:disposeDocument};
}

test('true cold full App stays in fallback with the page clock paused; exact 300 ms commits the real Inventory tab',async()=>{
 for(const locale of ['en','de']){
  const fixture=createWindowsManagedMSIFixture(),app=await fullApp({fixture,route:windowsManagedMSIRoute,locale});
  try{await app.page.goto(windowsManagedMSIOrigin+'/#/devices/'+fixture.device.id);await until(app.fallback().get);await until(()=>[...app.clock()._timers.values()].some(timer=>timer.delay===300));
   assert.equal(await app.ready().isVisible(),false);await nativeWait(20);assert.equal(await app.ready().isVisible(),false);
   await app.page.clock.runFor(299);assert.equal(await app.ready().isVisible(),false);await app.page.clock.runFor(1);await app.expect(app.ready()).toBeVisible();assert.deepEqual(app.errors,[]);
   assert.equal(app.now(),Date.parse(fixture.now)+400);assert.equal(app.monotonic(),300);
  }finally{await app.close();}
 }
});

test('full App cold reload replays clock progress and needs one bounded tick; warm list/detail mounts consume none',async()=>{
 const fixture=createWindowsManagedMSIFixture(),app=await fullApp({fixture,route:windowsManagedMSIRoute});
 try{
  await app.page.goto(windowsManagedMSIOrigin+'/#/devices/'+fixture.device.id);await settlePausedDetailRoute(app.page,app.expect,app.ready());
  for(let i=0;i<4;i++){await app.page.goto(windowsManagedMSIOrigin+'/#/devices');await until(()=>!app.ready().get());await app.page.goto(windowsManagedMSIOrigin+'/#/devices/'+fixture.device.id);await settlePausedDetailRoute(app.page,app.expect,app.ready());}
  assert.deepEqual(app.advances,[300]);await app.page.reload();await until(app.fallback().get);assert.equal(await app.ready().isVisible(),false);await settlePausedDetailRoute(app.page,app.expect,app.ready());
  assert.deepEqual(app.advances,[300,300]);assert.equal(app.now(),Date.parse(fixture.now)+700);assert.equal(app.monotonic(),600);const now=app.now();await nativeWait(10);assert.equal(app.now(),now);
  assert.deepEqual(app.errors,[]);assert.equal(app.requests.some(({method})=>method!=='GET'),false);
 }finally{await app.close();}
});

const recipes=[
 ['managed-msi',createWindowsManagedMSIFixture,windowsManagedMSIRoute,exerciseWindowsManagedMSI],
 ['mutation-coexistence',createWindowsMutationCoexistenceFixture,windowsMutationCoexistenceRoute,exerciseWindowsMutationCoexistence],
 ['service-actions',createWindowsServiceActionsFixture,windowsServiceActionsRoute,exerciseWindowsServiceActions,'http://127.0.0.1'],
 ['action-history',createWindowsServiceActionHistoryFixture,windowsServiceActionHistoryRoute,exerciseWindowsServiceActionHistory,'http://127.0.0.1'],
 ['update-jobs',createWindowsUpdateJobsFixture,windowsUpdateJobsRoute,exerciseWindowsUpdateJobs],
 ['update-download',createWindowsUpdateDownloadFixture,windowsUpdateDownloadRoute,exerciseWindowsUpdateDownload],
 ['update-retirement',createWindowsUpdateRetirementFixture,windowsUpdateRetirementRoute,exerciseWindowsUpdateRetirement],
 ['update-schedule',()=>createWindowsUpdateScheduleFixture('standalone'),windowsUpdateScheduleRoute,exerciseWindowsUpdateSchedule],
 ['background-schedule',()=>createWindowsUpdateScheduleFixture('background'),windowsUpdateScheduleRoute,exerciseWindowsUpdateSchedule],
 ['software-jobs',createWindowsSoftwareJobsFixture,windowsSoftwareJobsRoute,exerciseWindowsSoftwareJobs],
];
for(const [name,create,route,exercise,base=windowsManagedMSIOrigin] of recipes){
 test(`actual ${name} driver reaches its unchanged first Inventory interaction on a cold paused full App`,async()=>{
  for(const locale of ['en','de']){
   const fixture=create(),app=await fullApp({fixture,route,locale,base,stopAtInventory:true});
   try{
    await assert.rejects(exercise({page:app.page,expect:app.expect,base,fixture,locale,width:390,shot:()=>assert.fail('No capture before first Inventory interaction')}),error=>error===reachedInventory);
    assert.deepEqual(app.advances,[300]);assert.deepEqual(app.errors,[]);assert.equal(app.requests.some(({method})=>method!=='GET'),false);
    assert.equal(app.now(),Date.parse(fixture.now)+400);assert.ok(app.now()<Date.parse(fixture.session.expiresAt));
    if(name!=='action-history'){
     const moduleName=name==='service-actions'?'windows-service-actions':name==='background-schedule'?'windows-update-schedule':'windows-'+name;
     const source=fs.readFileSync(new URL('./'+moduleName+'-browser.mjs',import.meta.url),'utf8'),start=source.indexOf("stage='reload';await page.reload();"),end=source.indexOf("stage='reload';",start+14);
     assert.ok(start>=0&&end>start,'Actual driver must preserve its reload stage around bounded readiness');
     const fragment=source.slice(start,end+15);
     assert.match(fragment,/stage='reload-detail-route-readiness';await settlePausedDetailRoute/);
     await new Function('page','expect','locale','settlePausedDetailRoute','return (async()=>{let stage;'+fragment+'})()')(app.page,app.expect,locale,settlePausedDetailRoute);
     await app.expect(app.ready()).toBeVisible();assert.deepEqual(app.advances,[300,300]);assert.equal(app.now(),Date.parse(fixture.now)+700);
    }

   }finally{await app.close();}
  }
 });
}
test('actual storage IO driver settles its initial cold detail once and reuses the warm route on its first mount',async()=>{
 const base='http://127.0.0.1',app=await fullApp({base,stopAtInventory:true});
 try{
  await assert.rejects(windowsStorageIOBrowserCase({page:app.page,expect:app.expect,base,shot:()=>assert.fail('No capture before first Inventory interaction')}),error=>error===reachedInventory);
  assert.deepEqual(app.advances,[300]);assert.equal(app.now(),app.initial()+300);assert.deepEqual(app.errors,[]);
 }finally{await app.close();}
});

test('Storage IO retains original capture/expiry bytes after bounded readiness and crosses its unchanged +500 ms deadline',async()=>{
 const capturedAt='2026-10-11T12:00:00Z',initial=Date.parse(capturedAt)+10000,retainedCapturedAt=new Date(initial-86400000+500).toISOString();
 const exported=require('esbuild').buildSync({stdin:{contents:"export {windowsDevice} from './src/windows-inventory-fixture';",resolveDir:new URL('../../web/',import.meta.url).pathname,loader:'ts'},bundle:true,write:false,platform:'node',format:'cjs',logLevel:'silent'}).outputFiles[0].text;
 const module={exports:{}};new Function('module','exports',exported)(module,module.exports);const device=module.exports.windowsDevice();
 const fixture=createWindowsServiceActionsFixture(new Date(initial).toISOString());fixture.device=device;fixture.session.capabilities=['read'];
 const base='http://127.0.0.1',app=await fullApp({fixture,base,pauseOffset:0});let phase='observed';
 try{
  await app.page.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url()),reply=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
   if(url.pathname==='/api/auth/session')return reply(fixture.session);
   if(url.pathname==='/api/session')return reply({csrfToken:fixture.session.csrfToken});
   if(url.pathname==='/api/devices/'+device.id)return reply(device);
   if(url.pathname==='/api/devices/'+device.id+'/windows-inventory')return reply(windowsStorageIOBrowserFixture({serverNow:new Date(app.now()).toISOString(),capturedAt,phase,retainedCapturedAt}));
   return reply({error:{code:'synthetic_unavailable'}},404);
  });
  await app.page.goto(base+'/#/devices/'+device.id);await settlePausedDetailRoute(app.page,app.expect,app.ready());
  for(let i=0;i<4;i++){await app.page.goto(base+'/#/devices');await until(()=>!app.ready().get());await app.page.goto(base+'/#/devices/'+device.id);await settlePausedDetailRoute(app.page,app.expect,app.ready());}
  assert.deepEqual(app.advances,[300]);await app.ready().click();await app.page.getByRole('tab',{name:'Storage',exact:true}).click();
  const panels=()=>app.window().document.querySelectorAll('.windows-storage-io');await until(()=>panels().length===1);
  assert.equal(panels()[0].querySelector('time').getAttribute('datetime'),new Date(Date.parse(capturedAt)+250).toISOString());
  phase='retained';await app.page.getByRole('button',{name:'Refresh Windows inventory',exact:true}).click();await until(()=>panels().length===2);
  assert.equal(windowsStorageIOBrowserFixture({serverNow:new Date(app.now()).toISOString(),capturedAt,phase,retainedCapturedAt}).retainedContext.storageIO.collectedAt,retainedCapturedAt);
  assert.equal(Date.parse(retainedCapturedAt)+86400000-app.now(),200);
  await app.page.clock.runFor(1000);await until(()=>panels().length===1);
  assert.match(panels()[0].textContent,/Sample time limit reached/);assert.equal(app.now(),initial+1300);assert.deepEqual(app.advances,[300,1000]);assert.deepEqual(app.errors,[]);
 }finally{await app.close();}
});

for(const locale of ['en','de'])test(`actual retained sample age assertion matches original sample end before/after readiness (${locale})`,async(t)=>{
 const source=fs.readFileSync(new URL('./windows-storage-io-browser.mjs',import.meta.url),'utf8');
 const prior="await expect(panel.last()).toContainText(de?'Veraltete Messung':'Stale sample');",start=source.indexOf(prior)+prior.length,end=source.indexOf('await panel.last().evaluate',start);
 assert.ok(start>=prior.length&&end>start);const assertion=source.slice(start,end);
 const capturedAt='2026-10-11T12:00:00Z',initial=Date.parse(capturedAt)+10000,retainedCapturedAt='2026-10-11T11:00:00Z',sampleEnd='2026-10-11T11:00:01.250Z';
 const exported=require('esbuild').buildSync({stdin:{contents:"export {windowsDevice} from './src/windows-inventory-fixture';",resolveDir:new URL('../../web/',import.meta.url).pathname,loader:'ts'},bundle:true,write:false,platform:'node',format:'cjs',logLevel:'silent'}).outputFiles[0].text;
 const module={exports:{}};new Function('module','exports',exported)(module,module.exports);const device=module.exports.windowsDevice();
 for(const cold of [false,true]){
  const fixture=createWindowsServiceActionsFixture(new Date(initial).toISOString());fixture.device=device;fixture.session.capabilities=['read'];
  const base='http://127.0.0.1',app=await fullApp({fixture,base,locale,pauseOffset:0,holdDetailImport:cold});
  try{
   await app.page.route('**/*',async route=>{
    const url=new URL(route.request().url()),reply=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)});
    if(url.pathname==='/api/auth/session')return reply(fixture.session);
    if(url.pathname==='/api/session')return reply({csrfToken:fixture.session.csrfToken});
    if(url.pathname==='/api/devices/'+device.id)return reply(device);
    if(url.pathname==='/api/devices/'+device.id+'/windows-inventory')return reply(windowsStorageIOBrowserFixture({serverNow:new Date(app.now()).toISOString(),capturedAt,phase:'retained',retainedCapturedAt}));
    return reply({error:{code:'synthetic_unavailable'}},404);
   });
   await app.page.goto(base+'/#/devices/'+device.id);if(!cold)await app.expect(app.ready()).toBeVisible();await settlePausedDetailRoute(app.page,app.expect,app.ready());assert.deepEqual(app.advances,cold?[300]:[]);
   await app.ready().click();await app.page.getByRole('tab',{name:locale==='de'?'Speicher':'Storage',exact:true}).click();
   const previous=()=>app.window().document.querySelectorAll('.windows-storage-io')[1];await until(previous);
   const panel={last:()=>({get:previous})};
   const expect=value=>({toBe:want=>assert.equal(value,want),async toContainText(text){assert.ok(value.get().textContent.includes(text),'Exact retained age must match the original sample end and controlled clock');}});
   for(const progress of cold?[300]:[0,300]){
    if(progress&&!cold){await app.page.clock.runFor(progress);await app.page.getByRole('button',{name:locale==='de'?'Windows-Inventar aktualisieren':'Refresh Windows inventory',exact:true}).click();}
    const display=(locale==='de'?'Alter der Messung: ':'Sample age: ')+(locale==='de'?progress?'3.609 s':'3.608 s':progress?'3,609 s':'3,608 s');
    await until(()=>previous()?.querySelector('.windows-storage-io-window')?.textContent.includes(display));
    assert.equal(previous().querySelectorAll('time')[1].getAttribute('datetime'),sampleEnd);assert.equal(app.now(),initial+progress);t.diagnostic(JSON.stringify({locale,cold,progress,sampleEndedAt:sampleEnd,display:previous().querySelector('.windows-storage-io-window > span:last-child').textContent}));
    await new Function('page','expect','panel','de','locale','initial','readyAt','retainedCapturedAt','windowsStorageIORetainedAge','stamp','return (async()=>{let stage;'+assertion+'})()')(app.page,expect,panel,locale==='de',locale,initial,app.now(),retainedCapturedAt,storageIOHarness.windowsStorageIORetainedAge,(at,offset)=>new Date(Date.parse(at)+offset).toISOString());
   }
   assert.deepEqual(app.errors,[]);assert.deepEqual(app.advances,[300]);
  }finally{await app.close();}
 }
});

test('actual Storage IO warm-mount checkpoint rejects extra progress even when an initial +300 ms would otherwise be valid',async()=>{
 for(const extra of [1,300]){
  const base='http://127.0.0.1',app=await fullApp({base,stopAtInventory:true,holdDetailImport:false}),goto=app.page.goto;
  app.page.goto=async url=>{if(url===base+'/#/devices')await app.page.clock.runFor(extra);return goto(url);};
  try{
   await assert.rejects(windowsStorageIOBrowserCase({page:app.page,expect:app.expect,base,shot:()=>assert.fail('No capture before warm-mount clock guard')}),error=>error.code==='ERR_ASSERTION'&&error.actual===app.initial()+extra&&error.expected===app.initial());
   assert.deepEqual(app.advances,[extra]);assert.deepEqual(app.errors,[]);assert.equal(storageIOHarness.windowsStorageIOFailureStage(),'mount-detail-route-readiness');
  }finally{await app.close();}
 }
});
