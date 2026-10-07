/** Production UI with bounded invented DTOs. No source, helper or grant runs. */
import fs from 'node:fs';
import {validJournalQuery,validJournalView,validJournalPage,JOURNAL_WARNING} from '../../web/src/journal-types.ts';
export const journalBrowseCaseName='Synthetic retained journal browsing opens approved services directly and pages sparse searches without export';
export const journalBrowseDisclosure='UI-only production rendering with real loopback HTTP-test login and CSRF reads; invented versioned browsing DTOs checked by production validators. No host journal read, helper, installation, permission grant, AI provider, key entry or native acceptance.';
const stored=JSON.parse(fs.readFileSync(new URL('../../web/src/journal-go-fixture.json',import.meta.url),'utf8'));
const originalDevice=JSON.parse(fs.readFileSync(new URL('../../docs/lan-api-examples.json',import.meta.url),'utf8')).approvedAwaitingObservation;
const clone=v=>structuredClone(v),requireFixture=v=>{if(!v)throw Error('Unsupported synthetic retained-journal request');};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
const stages=new Set(['setup','login','direct-read','sparse-search','continuation','mobile','expiry','guards']);let stage='setup';
export const journalBrowseFailureStage=()=>stage;
let diagnostic=null;
export const journalBrowseFailureDetails=()=>diagnostic;
export function journalBrowseDiagnostic({counts={},rejected='none',state='unknown'}={}){
 const finite=v=>Number.isSafeInteger(v)&&v>=0&&v<=100?v:null;
 return {reads:finite(counts.reads),creates:finite(counts.creates),pages:finite(counts.pages),cancels:finite(counts.cancels),rejected:['none','authentication','csrf','payload','device','unrelated-write'].includes(rejected)?rejected:'unknown',state:['missing-panel','failure','paused','blocked','loading','expired','rendered','unknown'].includes(state)?state:'unknown'};
}
const mark=s=>{stage=stages.has(s)?s:'unknown';};
export function createJournalBrowseFixture({anchor='2026-10-07T12:00:00.000Z'}={}){
 let now=Date.parse(anchor),request=null,source=null,sequence=0;requireFixture(Number.isFinite(now));
 const device=originalDevice.id,prefix=`/api/devices/${device}/journal`,counts={reads:0,creates:0,pages:0,cancels:0};
 const iso=ms=>new Date(ms).toISOString(),generation={schemaVersion:'tracebolt.journal-generation-view.v3',browsingContract:'tracebolt.journal-browse.v1',policyEnabled:true,serviceAuthorization:'all-system-services',allowedUnits:[],policyGeneration:{revision:'1',generation:'a'.repeat(64),policyDigest:`sha256:${'b'.repeat(64)}`},sequence:'1',observedAt:iso(now),receivedAt:iso(now),expiresAt:iso(now+300000),fresh:true};
 const view=()=>{const v={schemaVersion:'tracebolt.journal-view.v2',deviceId:device,serverNow:iso(now),configured:true,expectedFloor:String(sequence),request:clone(request),localStatus:'unknown',contentStatus:request?.contentStatus??'unavailable',generation:{...clone(generation),fresh:now<Date.parse(generation.expiresAt)}};requireFixture(validJournalView(v,device));return v;};
 const page=()=>{requireFixture(request?.state==='accepted'&&source);const p={...clone(source),serverNow:iso(now)};requireFixture(validJournalPage(p,view(),'',0));return p;};
 return {device,prefix,counts,view,page,get latestQuery(){return clone(request?.description.query)},deviceView(){return {...clone(originalDevice),platform:'linux',os:'Synthetic retained journal fixture',agentVersion:'fixture'};},expire(){requireFixture(request);now=Date.parse(request.description.expiresAt);request.state='expired';request.contentStatus='unavailable';source=null;},handle(method,path,body){
  if(method==='GET'&&path===prefix){requireFixture(body===null);counts.reads++;return view();}
  if(method==='POST'&&path===prefix+'/create'){
   requireFixture(exact(body,['expectedFloor','query','acknowledgeLogContent','acknowledgePlaintext','expectedPolicyGeneration'])&&body.expectedFloor===String(sequence)&&body.acknowledgeLogContent===false&&body.acknowledgePlaintext===false&&JSON.stringify(body.expectedPolicyGeneration)===JSON.stringify(generation.policyGeneration)&&generation.fresh&&now<Date.parse(generation.expiresAt)&&body.query.browseMode==='retained-v1'&&validJournalQuery(body.query,iso(now)));
   if(body.query.cursor)requireFixture(source?.nextCursor===body.query.cursor&&JSON.stringify({...request.description.query,cursor:body.query.cursor})===JSON.stringify(body.query));
   now+=2500;sequence++;const query=clone(body.query),identity={id:`journal_${sequence.toString(16).padStart(32,'0')}`,sequence:String(sequence),queryDigest:`sha256:${sequence.toString(16).padStart(64,'0')}`},expiresAt=iso(now+900000),snapshotDigest=`sha256:${(sequence+100).toString(16).padStart(64,'0')}`;
   const description={schemaVersion:'tracebolt.journal-request.v3',identity,deviceId:device,certificateHash:'a'.repeat(64),query,budgets:clone(stored.status.request.description.budgets),createdAt:iso(now),expiresAt,policyGeneration:clone(generation.policyGeneration)};
   request={description,state:'accepted',contentStatus:'available',receipt:{identity:clone(identity),policyDigest:generation.policyGeneration.policyDigest,resultDigest:snapshotDigest,acceptedAt:iso(now),expiresAt}};
   const exhausted=Boolean(query.cursor),sparse=Boolean(query.search)&&!exhausted,rows=sparse?[]:[{timestamp:query.end,unit:query.unit,priority:Math.min(3,query.maxPriority),message:exhausted?`Synthetic older ${query.search??''} retained message`:'Synthetic newest retained message'}];
   source={schemaVersion:'tracebolt.journal-page.v2',deviceId:device,serverNow:iso(now),expiresAt,identity:clone(identity),snapshotDigest,scope:'agent-visible-system-journal-service-and-manager',query,observedAt:iso(now),coverage:exhausted?'complete':'partial',reason:exhausted?'none':'item_limit',rows,observedCount:rows.length,countExact:exhausted,redactionApplied:false,redactionWarning:JOURNAL_WARNING,totalCapturedRows:rows.length,matchedRows:rows.length,search:'',searchScope:'retained_source_page',offset:0,nextOffset:null,...(exhausted?{exhausted:true}:{nextCursor:`s=fixture;i=${sequence}`})};
   counts.creates++;page();return view();
  }
  if(method==='POST'&&path===prefix+'/query'){requireFixture(exact(body,['identity','snapshotDigest','search','offset','limit'])&&request?.state==='accepted'&&JSON.stringify(body.identity)===JSON.stringify(request.description.identity)&&body.snapshotDigest===request.receipt.resultDigest&&body.search===''&&body.offset===0&&body.limit===100);counts.pages++;return page();}
  if(method==='POST'&&path===prefix+'/cancel'){requireFixture(exact(body,['identity'])&&request&&JSON.stringify(body.identity)===JSON.stringify(request.description.identity));request.state='canceled';request.contentStatus='unavailable';source=null;counts.cancels++;return view();}
  requireFixture(false);
 }};
}
export async function journalBrowseBrowserCase({pageAt,login,expect,base,shot}){
 diagnostic=null;mark('setup');const page=await pageAt(`/devices/${originalDevice.id}/logs/fixture.service`),start=Date.now();await page.clock.install({time:new Date(start)});await page.clock.pauseAt(new Date(start+1000));
 const fixture=createJournalBrowseFixture({anchor:new Date(start-5000).toISOString()}),unexpected=[],external=[];let csrf='',sessionSequence=0,consumedSession=0,authenticated=false,rejected='none',gate='payload';
 await page.route('**/*',async route=>{const request=route.request(),url=new URL(request.url()),method=request.method();const fail=(reason='payload')=>{rejected=reason;unexpected.push('rejected-fixture-request');return route.abort('blockedbyclient');};
  if(url.origin!==base){external.push('external');return route.abort('blockedbyclient');}
  if(method==='GET'&&url.pathname==='/api/auth/session'&&url.search===''){requireFixture(request.postData()===null);const response=await route.fetch();if(response.status()===200)authenticated=(await response.json()).authenticated===true;return route.fulfill({response});}
  if(method==='GET'&&url.pathname==='/api/session'&&url.search===''){requireFixture(request.postData()===null);const response=await route.fetch();if(response.status()===200){const value=await response.json();csrf=value.csrfToken;sessionSequence++;}return route.fulfill({response});}
  if(url.pathname===`/api/devices/${fixture.device}`&&method==='GET'&&url.search===''){if(!authenticated||request.postData()!==null)return fail('device');return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(fixture.deviceView())});}
  if(url.pathname.startsWith(fixture.prefix))try{gate='authentication';requireFixture(authenticated&&url.search==='');gate='payload';if(method==='GET')requireFixture(request.postData()===null);else{const headers=await request.allHeaders();gate='csrf';requireFixture(method==='POST'&&headers['content-type']==='application/json'&&csrf!==''&&headers['x-csrf-token']===csrf&&sessionSequence>consumedSession);consumedSession=sessionSequence;}gate='payload';const body=fixture.handle(method,url.pathname,method==='GET'?null:request.postDataJSON());return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});}catch{return fail(gate);}
  if(method!=='GET'&&!(method==='POST'&&url.pathname==='/api/auth/login'))return fail('unrelated-write');return route.continue();
 });
 mark('login');await login(page);const panel=page.locator('.journal-panel');
 mark('direct-read');try{await expect(panel).toContainText('Synthetic newest retained message');}catch(error){
  // Return only finite invented-state classifications, never DOM text, URLs,
  // request bodies, tokens or raw Playwright exceptions.
  let state='missing-panel';
  try{if(await panel.count())state=await panel.evaluate(el=>{
   const text=el.textContent??'';
   return text.includes('The read could not be confirmed.')?'failure':text.includes('Reading is paused.')?'paused':text.includes('Retained browsing is unavailable')?'blocked':text.includes('Reading the selected service')?'loading':text.includes('This page is expired')?'expired':text.includes('Synthetic newest retained message')?'rendered':'unknown';
  });}catch{state='unknown';}
  diagnostic=journalBrowseDiagnostic({counts:fixture.counts,rejected,state});
  try{if(authenticated&&await page.locator('input[type="password"]').count()===0&&await panel.count()===1){await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-retained-journal-direct-read-failure',journalBrowseDisclosure);}}catch{/* Diagnostic capture cannot replace the original failure. */}
  throw error;
 }
 expect(fixture.counts.creates).toBe(1);expect(fixture.latestQuery.start).toBe('1970-01-01T00:00:00Z');await expect(page.getByRole('dialog')).toHaveCount(0);await expect(panel).not.toContainText('I understand');
 const label=async()=>page.evaluate(()=>{let el=document.getElementById('synthetic-journal-browse-label');if(!el){el=document.createElement('aside');el.id='synthetic-journal-browse-label';el.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:99999;background:#102a43;color:white;padding:6px 12px;font:12px sans-serif;text-align:center;pointer-events:none';document.body.append(el)}el.textContent='SYNTHETIC UI FIXTURE · No journal read, local grant or AI export';});
 await label();await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-retained-journal-desktop-en',journalBrowseDisclosure);
 mark('sparse-search');await page.clock.runFor(2200);await panel.getByLabel('Search retained messages').fill('rare');await panel.getByRole('button',{name:'Search logs',exact:true}).click();await expect(panel).toContainText('No matching messages in this source page. Older entries may still contain matches.');expect(fixture.counts.creates).toBe(2);const original=fixture.latestQuery;
 mark('continuation');await page.clock.runFor(2200);await panel.getByRole('button',{name:'Continue searching older logs',exact:true}).click();await expect(panel).toContainText('Synthetic older rare retained message');expect(fixture.counts.creates).toBe(3);expect(fixture.latestQuery.end).toBe(original.end);expect(fixture.latestQuery.search).toBe(original.search);await expect(panel).toContainText('No more currently accessible entries');await expect(panel).not.toContainText('Synthetic newest retained message');
 mark('mobile');await page.setViewportSize({width:390,height:844});await page.getByLabel('Language',{exact:true}).selectOption('de');await expect(panel).toContainText('Keine weiteren aktuell zugänglichen Einträge');expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth&&document.body.scrollWidth<=innerWidth)).toBe(true);await label();await panel.scrollIntoViewIfNeeded();await shot(page,'synthetic-retained-journal-mobile-de',journalBrowseDisclosure);
 await page.getByLabel('Sprache',{exact:true}).selectOption('en');mark('expiry');fixture.expire();await panel.getByRole('button',{name:'Refresh status',exact:true}).click();await expect(panel).not.toContainText('Synthetic older rare retained message');expect(fixture.counts.creates).toBe(3);
 mark('guards');expect(unexpected).toEqual([]);expect(external).toEqual([]);const storage=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));expect(storage.includes('Synthetic older')||storage.includes('s=fixture')).toBe(false);
}
