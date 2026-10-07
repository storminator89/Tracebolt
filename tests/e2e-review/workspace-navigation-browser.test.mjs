/** Pure regression-probe contracts, not browser execution. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
import {installWorkspaceContinuity,workspaceRequestMetadata} from './workspace-navigation-browser.mjs';
const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
const zero={documentNavigation:0,overviewReads:0,sessionReads:0,unexpectedMethodOrBody:0,externalRequests:0};
function request(pathname,{method='GET',body=null,navigation=false,type='fetch'}={}){
 return {url:()=>new URL(pathname,'http://127.0.0.1:19886').href,method:()=>method,postData:()=>body,isNavigationRequest:()=>navigation,resourceType:()=>type,allHeaders:()=>{throw new Error('Headers must not be read');},response:()=>{throw new Error('Responses must not be read');}};
}
test('request metadata catches redundant bootstrap/overview reads and document requests without retaining values',()=>{
 const inspect=value=>workspaceRequestMetadata(value,'http://127.0.0.1:19886');
 assert.deepEqual(inspect(request('/api/investigations?scope=open&offset=0')),zero);
 assert.deepEqual(inspect(request('/api/overview')), {...zero,overviewReads:1});
 assert.deepEqual(inspect(request('/api/auth/session')), {...zero,sessionReads:1});
 assert.deepEqual(inspect(request('/#/devices',{navigation:true,type:'document'})), {...zero,documentNavigation:1});
 assert.deepEqual(inspect(request('/api/investigations',{body:'PRIVATE_SENTINEL'})), {...zero,unexpectedMethodOrBody:1});
 assert.deepEqual(inspect(request('/api/auth/login',{method:'POST',body:'PRIVATE_SENTINEL'})), {...zero,unexpectedMethodOrBody:1});
 assert.deepEqual(inspect(request('https://external.invalid/PRIVATE_SENTINEL')), {...zero,externalRequests:1});
 assert.equal(JSON.stringify(inspect(request('/api/overview?PRIVATE_SENTINEL',{body:'PRIVATE_SENTINEL'}))).includes('PRIVATE_SENTINEL'),false);
});

function fixture(){
 const element=(selector,children=[])=>({nodeType:1,isConnected:true,children,matches:query=>query===selector,contains(other){return this===other||this.children.some(child=>child.contains(other));},querySelector(query){for(const child of this.children){if(child.matches(query))return child;const match=child.querySelector(query);if(match)return match;}return null;}});
 const sidebar=element('.sidebar'),topbar=element('.topbar'),main=element('#main-content'),shell=element('.app-shell',[sidebar,topbar,main]);
 const nodes={'.app-shell':shell,'.sidebar':sidebar,'.topbar':topbar,'#main-content':main};
 const queue=[],listeners=new Map();let disconnected=false;
 class MutationObserver{
  observe(target,options){assert.equal(target,shell);assert.deepEqual({...options},{childList:true,subtree:true});}
  takeRecords(){return queue.splice(0);}
  disconnect(){disconnected=true;}
 }
 const sandbox={document:{documentElement:shell,querySelector:selector=>nodes[selector]},performance:{timeOrigin:100},MutationObserver,window:{addEventListener:(name,listener)=>listeners.set(name,listener),removeEventListener:(name,listener)=>{assert.equal(listeners.get(name),listener);listeners.delete(name);}}};
 const probe=vm.runInNewContext('('+installWorkspaceContinuity.toString()+')()',sandbox);
 // JSON roundtrip normalizes VM object prototypes; payload stays booleans/counts.
 return {probe,read:()=>JSON.parse(JSON.stringify(probe.read())),nodes,element,queue,listeners,sandbox,disconnected:()=>disconnected};
}
const healthy={sameDocument:true,identity:{shell:true,sidebar:true,topbar:true,main:true},removedAnchors:{shell:0,sidebar:0,topbar:0,main:0},initialLoadingInsertions:0,pageHides:0};
test('ordinary main content updates preserve every original workspace anchor',()=>{
 const dom=fixture();dom.queue.push({removedNodes:[dom.element('.old-panel')],addedNodes:[dom.element('.new-panel')]});assert.deepEqual(dom.read(),healthy);dom.probe.stop();assert.equal(dom.disconnected(),true);assert.equal(dom.listeners.has('pagehide'),false);
});
test('removing and reinserting the exact shell is detected even when final identity is unchanged',()=>{
 const dom=fixture();dom.queue.push({removedNodes:[dom.nodes['.app-shell']],addedNodes:[dom.nodes['.app-shell']]});
 assert.deepEqual(dom.read(),{...healthy,removedAnchors:{shell:1,sidebar:1,topbar:1,main:1}});
});
test('replaced topbar fails its original node identity while the other anchors remain stable',()=>{
 const dom=fixture(),original=dom.nodes['.topbar'];original.isConnected=false;dom.nodes['.topbar']=dom.element('.topbar');dom.queue.push({removedNodes:[original],addedNodes:[dom.nodes['.topbar']]});
 assert.deepEqual(dom.read(),{...healthy,identity:{...healthy.identity,topbar:false},removedAnchors:{...healthy.removedAnchors,topbar:1}});
});
test('transient global initial loading is detected whether inserted directly or under a wrapper',()=>{
 const dom=fixture(),loader=dom.element('.initial-loading');dom.queue.push({removedNodes:[],addedNodes:[loader,dom.element('.wrapper',[loader])]});assert.equal(dom.read().initialLoadingInsertions,2);
});
test('document identity, time origin and pagehide catch document changes and Back/Forward cache restores',()=>{
 const dom=fixture();dom.listeners.get('pagehide')();assert.equal(dom.read().pageHides,1);dom.sandbox.performance.timeOrigin=200;assert.equal(dom.read().sameDocument,false);dom.sandbox.performance.timeOrigin=100;dom.sandbox.document={...dom.sandbox.document};assert.equal(dom.read().sameDocument,false);
});
test('hosted probe extends the existing real LAN case and keeps runner counts, reads and deadlines intact',()=>{
 const runner=read('./lan-browser.mjs'),module=read('./workspace-navigation-browser.mjs'),ci=read('../../.github/workflows/validate.yml');
 assert.equal((runner.match(/await check\(/g)||[]).length,25);
 const name="Authenticated LAN contract shows unknown awaiting-agent data with no demo fleet or healthy empty-state claim";
 const start=runner.indexOf("await check('"+name+"'");assert.ok(start>=0);const end=runner.indexOf('await check(',start+12),scenario=runner.slice(start,end);
 assert.equal((scenario.match(/await workspaceNavigationBrowserProbe\(\{page,expect,base\}\)/g)||[]).length,1);
 assert.ok(scenario.indexOf('await login(page)')<scenario.indexOf('await workspaceNavigationBrowserProbe'));
 assert.ok(scenario.includes("unavailable.status()).toBe(409)"));assert.ok(scenario.includes("unavailableBody.error.code).toBe('health_unavailable')"));
 assert.ok(runner.includes("async function start(ttl='60s')"));assert.ok(runner.includes("async function check(name,run,ttl='60s')"));assert.ok(ci.includes('node tests/e2e-review/lan-browser.mjs'));assert.ok(ci.includes('tests/e2e-review/investigations-fixtures.test.mjs'));assert.ok(read('./investigations-fixtures.test.mjs').includes("import './workspace-navigation-browser.test.mjs'"));
 assert.equal((module.match(/await page.goBack\(\)/g)||[]).length,2);assert.equal((module.match(/await page.goForward\(\)/g)||[]).length,2);assert.ok(module.includes("['overview','devices','cases','overview','devices','cases']"));
 assert.match(module,/expect\(counts\)\.toEqual\(\{documentNavigation:0,overviewReads:0,sessionReads:0/);
 assert.doesNotMatch(module,/chromium\.launch|newContext\(|setDefaultTimeout|waitForTimeout|timeout:|ignoreHTTPSErrors|\.skip\(|page\.route\(|page\.goto\(|page\.reload\(|page\.clock|screenshot\(|allHeaders\(|\.json\(|\.text\(|\.body\(|localStorage|sessionStorage|cookies\(/);
});
