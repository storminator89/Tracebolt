/** Synthetic macOS source UI, with every browser request fulfilled or blocked.
 * No listener, real network, login, key generation, enrollment or host action.
 * --check only bundles and checks the inert DTO/route contract. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {captureDiagnostic} from './macos-enrollment-diagnostics.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url)),require=createRequire(new URL('../package.json',import.meta.url));
export const origin='https://macos-enrollment.invalid';
export const disclosure='Synthetic macOS TLS/basic enrollment DTOs; actual compiled EnrollmentSection and protected request code, not the whole App. All requests intercepted. No real login, network, invitation, key, endpoint, host action, service or native acceptance.';
export const contract=JSON.parse(await readFile(new URL('./macos-enrollment-scenes.json',import.meta.url),'utf8'));
assert.deepEqual(contract.scenes,['ready','unavailable','created','review']);
assert.deepEqual(contract.viewports,['en','de'].flatMap(locale=>[1440,390].map(width=>({locale,width,height:width===390?844:1100}))));
export const captureMatrix=contract.viewports.flatMap(view=>contract.scenes.map(scene=>({...view,scene,file:`macos-enrollment-${scene}-${view.locale}-${view.width}.png`})));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
async function bundle(contents,platform='browser'){
 const {build}=require('esbuild');
 return build({stdin:{contents,resolveDir:path.join(root,'web/src'),loader:'tsx'},absWorkingDir:root,outdir:'web/.macos-enrollment-memory-only',entryNames:'app',bundle:true,platform,format:'esm',jsx:'automatic',define:{'process.env.NODE_ENV':'"production"'},loader:{'.woff':'dataurl','.woff2':'dataurl','.svg':'dataurl','.png':'dataurl'},write:false,metafile:true,minify:platform==='browser',logLevel:'silent'});
}
export async function compile(){
 const fixtures=await bundle("export * from './enrollment-macos-fixture'; export { validEnrollmentList, validSnapshot } from './enrollment-types';",'node');
 const data=await import(`data:text/javascript;base64,${Buffer.from(fixtures.outputFiles[0].contents).toString('base64')}`);
 const result=await bundle(`import React from 'react'; import {createRoot} from 'react-dom/client'; import './styles.css'; import {EnrollmentSection} from './enrollment'; import {setLocale} from './i18n'; setLocale(window.__MACOS_LOCALE__,false); createRoot(document.getElementById('root')).render(<main style={{maxWidth:1050,margin:'0 auto',padding:16}}><p role="note">SYNTHETIC · macOS source UI · No endpoint actions</p><EnrollmentSection onChanged={()=>{}} onDevice={()=>{}} deviceIds={[]}/></main>);`);
 const assets=new Map(result.outputFiles.map(file=>[`/${path.basename(file.path)}`,{body:Buffer.from(file.contents),contentType:file.path.endsWith('.css')?'text/css':'text/javascript'}]));
 assert(assets.has('/app.js')&&assets.has('/app.css'));
 assets.set('/',{contentType:'text/html',body:'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><link rel="stylesheet" href="/app.css"><title>Synthetic macOS enrollment</title></head><body><div id="root"></div><script type="module" src="/app.js"></script></body></html>'});
 const files=[...new Set([...Object.keys(fixtures.metafile.inputs),...Object.keys(result.metafile.inputs)].filter(file=>file.startsWith('web/src/')).concat(['web/scripts/capture-macos-enrollment.mjs','web/scripts/macos-enrollment-scenes.json','web/scripts/run-macos-enrollment-ci.mjs','web/scripts/check-macos-enrollment-evidence.mjs','web/scripts/macos-enrollment-diagnostics.mjs']))].sort();
 const sourceInputs=await Promise.all(files.map(async file=>({file,sha256:hash(await readFile(path.join(root,file)))})));
 return {assets,data,sourceInputs,sourceDigest:hash(JSON.stringify(sourceInputs))};
}
export function routeFixture(compiled,scene,state){
 const data=compiled.data,created=data.macOSFixtureCreation(origin),record=data.macOSFixtureRecord(origin,'claimed_pending',2);
 let items=scene==='review'?[record]:[];
 return async route=>{
  const req=route.request(),url=new URL(req.url()),method=req.method(),raw=req.postData();
  const blocked=kind=>{state[kind]++;return route.abort('blockedbyclient');};
  if(url.origin!==origin)return blocked('external');if(url.search)return blocked('unexpected');
  const respond=body=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});
  if(method==='GET'&&raw===null){
   if(url.pathname==='/api/session')return respond({csrfToken:'synthetic-csrf-not-a-session'});
   if(url.pathname==='/api/enrollment')return respond({...data.macOSFixtureList(),platforms:['linux']});
   if(url.pathname==='/api/macos/enrollment'){state.reads++;return respond({...data.macOSFixtureList(items),enabled:scene!=='unavailable'});}
   const asset=compiled.assets.get(url.pathname);if(asset)return route.fulfill({status:200,...asset});return blocked('unexpected');
  }
  if(method==='POST'&&scene==='created'&&url.pathname==='/api/macos/enrollment/invitations'){
   let body;try{body=JSON.parse(raw);}catch{return blocked('unexpected');}
   if(Object.keys(body).sort().join(',')!=='platform,requestId'||body.platform!=='darwin'||!/^request_[a-f0-9]{32}$/.test(body.requestId)||req.headers()['x-csrf-token']!=='synthetic-csrf-not-a-session'||items.length)return blocked('unexpected');
   state.syntheticCreates++;items=[created.snapshot];return respond(created);
  }
  return blocked('writes');
 };
}
export async function check(){
 const compiled=await compile(),data=compiled.data;
 assert(data.validEnrollmentList(data.macOSFixtureList(),'darwin'));assert.equal(data.macOSFixtureSecret.length,43);
 assert(data.validSnapshot(data.macOSFixtureRecord(origin)));assert.equal(data.validEnrollmentList({...data.macOSFixtureList(),platforms:['linux','darwin']},'darwin'),false);
 const state={external:0,unexpected:0,writes:0,reads:0,syntheticCreates:0},handler=routeFixture(compiled,'ready',state);let response;
 const fake=(method,url,raw=null)=>({request:()=>({method:()=>method,url:()=>url,postData:()=>raw,headers:()=>({})}),fulfill:value=>{response=value;},abort:()=>{}});
 await handler(fake('GET',origin+'/api/macos/enrollment'));assert.equal(JSON.parse(response.body).enabled,true);
 await handler(fake('POST',origin+'/api/macos/enrollment/invitations','{}'));await handler(fake('GET','https://untrusted.invalid/'));
 assert.deepEqual(state,{external:1,unexpected:0,writes:1,reads:1,syntheticCreates:0});
 return {sourceDigest:compiled.sourceDigest,scenes:contract.scenes.length,screenshots:captureMatrix.length,browserExecuted:false,nativeAcceptance:false,disclosure};
}
/** Scope controls to the review dialog: expanded history also has a checkbox. */
export function reviewControls(page,de){
 const dialog=page.getByRole('dialog',{name:de?'Einladung prüfen':'Review invitation',exact:true});
 return {comparison:dialog.getByRole('checkbox'),approve:dialog.getByRole('button',{name:de?'Gerät freigeben':'Approve device',exact:true})};
}
export async function capture({browser,expect,output,onStage=()=>{}}){
 const mark=(stage,index=null)=>onStage(captureDiagnostic(stage,index));
 mark('compile');const compiled=await compile(),captures=[];mark('prepare-output');await mkdir(output,{recursive:true});
 for(const [index,{locale,width,height,scene,file}] of captureMatrix.entries()){
  const de=locale==='de',state={external:0,unexpected:0,writes:0,reads:0,syntheticCreates:0};let runtimeErrors=0,completed=false;
  mark('new-context',index);const context=await browser.newContext({viewport:{width,height},reducedMotion:'reduce',locale:de?'de-DE':'en-US',serviceWorkers:'block'});
  try{
   mark('route',index);await context.route('**/*',routeFixture(compiled,scene,state));await context.addInitScript(locale=>{window.__MACOS_LOCALE__=locale;},locale);
   mark('new-page',index);const page=await context.newPage();page.on('pageerror',()=>{runtimeErrors++;});mark('navigate',index);await page.goto(origin+'/');
   mark('initial-status',index);await expect(page.getByRole('button',{name:de?'Enrollment-Status aktualisieren':'Refresh enrollment status',exact:true})).toBeEnabled();
   mark('select-macos',index);await page.getByRole('combobox').selectOption('darwin');
   const add=page.getByRole('button',{name:de?'Gerät hinzufügen':'Add device',exact:true});
   if(scene==='unavailable'){mark('unavailable-state',index);await expect(add).toBeDisabled();await expect(page.getByText(de?/Dieser Manager bietet kein macOS-Enrollment an/:/This manager does not offer macOS enrollment/)).toBeVisible();}
   else if(scene==='review'){
    mark('open-history',index);await page.getByRole('button',{name:de?/Einladungen/:/Invitations/}).click();mark('open-review',index);await page.getByRole('button',{name:de?`Einladung ${compiled.data.macOSFixtureInvitation} prüfen`:`Review invitation ${compiled.data.macOSFixtureInvitation}`,exact:true}).click();
    const {comparison,approve}=reviewControls(page,de);
    mark('review-consent',index);await expect(comparison).not.toBeChecked();mark('review-approval',index);await expect(approve).toBeDisabled();
   }else{
    mark('wait-add',index);await expect(add).toBeEnabled();mark('open-create',index);await add.click();
    if(scene==='ready'){mark('open-scope',index);await page.getByText(de?'Erfassungsgrenzen':'Collection limits',{exact:true}).click();mark('create-ready',index);await expect(page.getByRole('button',{name:de?'Einladung erstellen':'Create invitation',exact:true})).toBeEnabled();}
    else{
     mark('submit-create',index);await page.getByRole('button',{name:de?'Einladung erstellen':'Create invitation',exact:true}).click();const input=page.getByLabel(de?'Einmaliger Einladungsschlüssel':'One-time invitation secret',{exact:true});mark('secret-masked',index);await expect(input).toHaveAttribute('type','password');
     // Exercise interruption cleanup before capture; even the inert synthetic
     // invitation value is excluded from screenshot DOM and exported evidence.
     mark('interrupt-clear',index);await page.evaluate(()=>{window.dispatchEvent(new Event('pagehide'));window.dispatchEvent(new Event('pageshow'));});await expect(input).toHaveCount(0);mark('refresh-restored',index);await expect(page.getByRole('button',{name:de?'Enrollment-Status aktualisieren':'Refresh enrollment status',exact:true})).toBeEnabled();
     mark('open-source-steps',index);await page.getByText(de?'Lokale Schritte & Voraussetzungen':'Local steps & prerequisites',{exact:true}).click();
     mark('source-instructions',index);await expect(page.getByRole('dialog')).toContainText('--foreground');
    }
   }
   mark('fonts',index);await page.evaluate(()=>document.fonts.ready);
   mark('no-overflow',index);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   mark('secret-excluded',index);const visible=await page.evaluate(()=>document.body.innerText+'\n'+[...document.querySelectorAll('input')].map(input=>input.value).join('\n'));assert(!visible.includes(compiled.data.macOSFixtureSecret));
   mark('linux-command-excluded',index);assert(!visible.includes('agent-service'));assert(!visible.includes('systemd'));
   mark('screenshot',index);await page.screenshot({path:path.join(output,file),animations:'disabled',fullPage:false});
   mark('runtime-errors',index);assert.equal(runtimeErrors,0);mark('route-boundary',index);assert.equal(state.external+state.unexpected+state.writes,0);mark('creation-count',index);assert.equal(state.syntheticCreates,scene==='created'?1:0);
   mark('image-hash',index);captures.push({file,scene,locale,width,height,synthetic:true,publicSafe:true,fullPage:false,sha256:hash(await readFile(path.join(output,file))),sourceDigest:compiled.sourceDigest,syntheticCreates:state.syntheticCreates});completed=true;
  }finally{if(completed)mark('close-context',index);await context.close();}
 }
 return {sourceInputs:compiled.sourceInputs,sourceDigest:compiled.sourceDigest,captures,disclosure,browserExecuted:true,appMounted:false,nativeAcceptance:false,actualMutationRequests:0,requestsToRealAPI:0};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--check'))console.log(JSON.stringify(await check()));
 else if(process.argv.includes('--capture')){
  const {chromium,expect}=require('@playwright/test');let browser,tag=captureDiagnostic('launch'),failure=null;
  try{browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{})});const output=path.resolve(process.env.TRACEBOLT_CAPTURE_OUTPUT??path.join(root,'artifacts/macos-enrollment'));const manifest=await capture({browser,expect,output,onStage:value=>{tag=value;}});tag=captureDiagnostic('manifest');await writeFile(path.join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');console.log(`PASS: ${manifest.captures.length} synthetic macOS source captures; no actual mutations or native acceptance.`);}catch{failure=tag;process.exitCode=1;}finally{try{await browser?.close();}catch{failure??=captureDiagnostic('close-browser');process.exitCode=1;}if(failure)console.log(`FAIL: synthetic macOS UI gate ${JSON.stringify(failure)}; raw diagnostics withheld.`);}
 }else throw new Error('Use --check for inert validation or --capture for the isolated synthetic UI.');
}
