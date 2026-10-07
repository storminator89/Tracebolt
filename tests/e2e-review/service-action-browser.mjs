/** Built React + real named auth, manager API/store, agent ingress and framed
 * helper IPC. The synthetic protocol driver and fake Backend never run systemctl.
 * Injected fixture authority/peer are not native root/helper isolation evidence.
 * No API routing, response substitution, saved traces or raw diagnostics.
 * Test-only observation forwards the original primary response/reader unchanged.
 */
import {createRequire} from 'node:module';
import {execFileSync,spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createBrowserTransportDiagnostics,reportTransportFailure} from './browser-transport-diagnostics.mjs';
import {installJournalPrimaryBody} from './journal-primary-body.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const out=path.join(root,'artifacts/review/service-action-browser-results.json');
// A dependency/startup failure must never leave an older PASS artifact behind.
await fs.rm(out,{force:true});
const require=createRequire(path.join(root,'web/package.json'));
const {chromium,expect:baseExpect}=require('@playwright/test');
const expect=baseExpect.configure({timeout:15000});
const sourceSha=/^[a-f0-9]{40}$/.test(process.env.TRACEBOLT_SOURCE_SHA??'')?process.env.TRACEBOLT_SOURCE_SHA:null;
const password='TRACEBOLT_ACTION_BROWSER_FIXTURE_NOT_A_REAL_PASSWORD';
const names=[
 'Named operator preview binds the selected service and cancellation leaves zero jobs and helper calls',
 'Explicit interruption approval commits one job and held helper execution remains unconfirmed',
 'Agent-reported completion survives reload without automatic approval or execution replay',
 'Repeating the exact approved preview is idempotent and cannot execute again',
];
const scope={
 builtReactUI:true,namedOperatorAuth:true,realManagerAPI:true,durableEnrollmentStore:true,
 realAgentIngress:true,realFramedHelperIPC:true,fakeBackend:true,
 injectedHelperAuthorityAndPeer:true,syntheticProtocolDriver:true,
 secretsExported:false,realTelemetryExported:false,nativeHelperExecuted:false,
 realSystemctlExecuted:false,hostGrantChanged:false,userVmAccessed:false,
 productionActionSenderExecuted:false,apiMocked:false,
};
const fixture='Disposable loopback HTTP test with invented inventory and a synthetic protocol-driving agent; real framed net.Pipe helper ServeConn uses injected fixture authority/peer and a fake Backend. This does not establish native root/helper/systemd isolation, production actionSender acceptance or mTLS browser acceptance.';
const results=[];
let temporary,browser,context,page,server,pipe,waiting,device,actor,approval,savedJob,transportDiagnostics;
let runtimeErrorCount=0,setupFailure=false,stage='setup',base='',approveRequests=0;
const mark=value=>{stage=value;};
const endpoint=()=>`/api/devices/${device.deviceId}/service-actions`;
const review=()=>page.getByRole('region',{name:'Review service action',exact:true});
const saved=()=>page.getByRole('region',{name:'Saved action',exact:true});
const selector=()=>page.getByRole('button',{name:'Preview try-restart: fixture.service',exact:true});

async function control(action){
 if(waiting||!server||server.exitCode!==null)throw new Error('CONTROL_UNAVAILABLE');
 let entry;
 const answer=new Promise((resolve,reject)=>{entry={resolve,reject};waiting=entry;});
 const timer=setTimeout(()=>{if(waiting===entry){waiting=null;entry.reject(new Error('CONTROL_TIMEOUT'));}},15000);
 try{server.stdin.write(JSON.stringify({action})+'\n');const value=await answer;expect(value.ok).toBe(true);return value;}
 finally{clearTimeout(timer);if(waiting===entry)waiting=null;}
}
async function stop(){
 if(server&&server.exitCode===null){
  const exited=new Promise(resolve=>server.once('exit',resolve));
  const bounded=async()=>{let timer;try{await Promise.race([exited,new Promise(resolve=>{timer=setTimeout(resolve,1500);})]);}finally{clearTimeout(timer);}};
  server.stdin.end();await bounded();
  for(const signal of ['SIGTERM','SIGKILL'])if(server.exitCode===null){server.kill(signal);await bounded();}
  if(server.exitCode===null)setupFailure=true;
 }
 pipe?.close();waiting=null;
}
async function read(route){
 const response=await context.request.get(base+route);
 expect(response.status()).toBe(200);
 return body(response);
}
async function body(response){
 // Preserve the fixed caller stage and distinguish transport, bounds and JSON
 // failures without exporting response content or the caught browser error.
 const callerStage=stage;
 mark(callerStage+' / retrieve response bytes');
 const began=performance.now();let bytes;
 try{bytes=await response.body();}
 catch(error){
  reportTransportFailure(transportDiagnostics,'response-body',error,{response,elapsedMs:performance.now()-began});
  throw error;
 }
 mark(callerStage+' / check response byte bound');
 expect(bytes.length).toBeLessThanOrEqual(32768);
 mark(callerStage+' / decode response JSON');
 const value=JSON.parse(bytes.toString('utf8'));
 mark(callerStage);return value;
}
async function primaryBody(capture,request){
 // Browser POSTs are observed only through the application's original bounded
 // consumer. Context-request reads/replays keep their independent body() checks.
 const callerStage=stage;mark(callerStage+' / await primary response consumption');
 await expect.poll(()=>page.evaluate(id=>window.__traceboltJournalBody.state(id),capture)).not.toMatch(/^(armed|waiting|reading)$/);
 mark(callerStage+' / require complete primary response');expect(await page.evaluate(id=>window.__traceboltJournalBody.state(id),capture)).toBe('complete');
 const consumed=await page.evaluate(id=>window.__traceboltJournalBody.take(id),capture);expect(consumed).not.toBeNull();expect(consumed.status).toBe(200);expect(consumed.requestBody).toBe(request.postData());
 mark(callerStage+' / check response byte bound');expect(Number.isSafeInteger(consumed.bytes)).toBe(true);expect(consumed.bytes).toBeGreaterThanOrEqual(0);expect(consumed.bytes).toBeLessThanOrEqual(32768);
 mark(callerStage);return consumed.body;
}
function counters(value,calls,claims,jobs){
 expect(value.calls).toBe(calls);expect(value.claims).toBe(claims);expect(value.jobs).toBe(jobs);
}
async function status(calls,claims,jobs,jobState){
 const value=await control('status');counters(value,calls,claims,jobs);
 if(jobState!==undefined)expect(value.jobState).toBe(jobState);
 return value;
}
async function openServices(){
 await expect(page.getByRole('region',{name:'Device QA synthetic action alpha',exact:true})).toBeVisible();
 await page.getByRole('tab',{name:'Inventory',exact:true}).click();
 await page.getByRole('tab',{name:'Services',exact:true}).click();
 await expect(page.locator('.system-inventory')).toHaveAttribute('aria-busy','false');
 await expect(page.locator('.system-inventory').getByRole('alert')).toHaveCount(0);
 await expect(selector()).toBeVisible();
}
async function preview(){
 mark('await preview selector enabled');
 await expect(selector()).toBeEnabled();
 mark('request exact preview');
 const capture=await page.evaluate(()=>window.__traceboltJournalBody.arm('actionPreview'));
 const [request]=await Promise.all([
  page.waitForRequest(value=>value.url()===base+endpoint()+'/preview'&&value.method()==='POST'),
  selector().click(),
 ]);
 const received=await request.response();expect(received).not.toBeNull();
 mark('assert preview HTTP status');expect(received.status()).toBe(200);
 mark('assert exact preview request');expect(received.request().postDataJSON()).toEqual({unit:'fixture.service'});
 mark('read preview response');const value=await primaryBody(capture,request);
 mark('assert preview present');expect(value.preview).not.toBeNull();
 const p=value.preview;
 mark('assert preview identity');
 expect(p.deviceId).toBe(device.deviceId);expect(p.actorId).toBe(actor);
 mark('assert preview service action');
 expect(p.plan.unit).toBe('fixture.service');expect(p.plan.action).toBe('service.try-restart');
 mark('assert preview transport profile');
 expect(p.transportProfile).toBe('disposable-http-test');
 mark('await preview visible');await expect(review()).toBeVisible();
 mark('await preview focused');await expect(review()).toBeFocused();
 mark('assert preview disclosure');
 for(const text of [device.deviceId,actor,'fixture.service','service.try-restart','interrupt the service and its dependents','Disposable HTTP test'])await expect(review()).toContainText(text);
 mark('assert fresh preview consent');
 await expect(review().getByRole('checkbox',{name:'I accept the interruption risk for this exact action.',exact:true})).not.toBeChecked();
 mark('assert unapproved preview disabled');
 await expect(review().getByRole('button',{name:'Approve try-restart',exact:true})).toBeDisabled();
 return {previewId:p.id,previewDigest:p.digest};
}
async function clean(){
 // No screenshots or browser traces are emitted; private API material stays in
 // memory and is also forbidden from persistent browser storage.
 expect(await page.evaluate(values=>{
  const stored=JSON.stringify({...localStorage,...sessionStorage});
  return values.some(value=>stored.includes(value));
 },[password,device.deviceId,actor,approval?.previewId??'never-a-real-preview',approval?.previewDigest??'never-a-real-digest'])).toBe(false);
 expect(new URL(page.url()).search).toBe('');
 await expect(page.locator('.enrollment-secret,.enrollment-fingerprint,.enrollment-comparison')).toHaveCount(0);
}
async function check(index,run){
 const began=Date.now();
 try{await run();results.push({name:names[index],status:'PASS',durationMs:Date.now()-began});console.log(`PASS ${names[index]}`);}
 catch{results.push({name:names[index],status:'FAIL',durationMs:Date.now()-began});console.log(`FAIL ${names[index]} (${stage}); raw diagnostics withheld.`);throw new Error('CASE_FAILED');}
}

try{
 if(typeof sourceSha!=='string'||!/^[a-f0-9]{40}$/.test(sourceSha))throw new Error('SOURCE_REQUIRED');
 const port=Number(process.env.ACTION_REVIEW_PORT??19897);
 if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('INVALID_LOOPBACK_PORT');
 base=`http://127.0.0.1:${port}`;
 temporary=await fs.mkdtemp(path.join(os.tmpdir(),'tracebolt-service-action-browser-'));
 mark('compile fixture');
 execFileSync(process.env.GO_BIN||'go',['build','-buildvcs=false','-o',path.join(temporary,'actionfixture'),'./tests/e2e-review/actionfixture'],{cwd:root,stdio:'ignore',timeout:180000});
 mark('start fixture');
 const state=path.join(temporary,'state');await fs.mkdir(state,{mode:0o700});
 server=spawn(path.join(temporary,'actionfixture'),['--listen',new URL(base).host,'--state',state,'--web',path.join(root,'web/dist')],{cwd:root,stdio:['pipe','pipe','ignore']});
 pipe=createInterface({input:server.stdout});
 pipe.on('line',line=>{const pending=waiting;waiting=null;if(pending){try{if(line.length>4096)throw new Error('CONTROL_BOUNDS');pending.resolve(JSON.parse(line));}catch{pending.reject(new Error('CONTROL_RESPONSE'));}}});
 for(const emitter of [server,server.stdin])emitter.on('error',()=>{waiting?.reject(new Error('FIXTURE_FAILED'));waiting=null;});
 server.on('exit',()=>{waiting?.reject(new Error('FIXTURE_EXITED'));waiting=null;});
 device=await control('info');
 expect(device.deviceId).toMatch(/^agent_[a-f0-9]{32}$/);expect(device.unit).toBe('fixture.service');expect(device.deviceName).toBe('QA synthetic action alpha');counters(device,0,0,0);
 mark('launch Chromium');
 const launch={headless:true,args:['--no-sandbox'],env:{...process.env,HOME:temporary,XDG_CONFIG_HOME:temporary,XDG_CACHE_HOME:temporary}};
 if(process.env.CHROMIUM_PATH)launch.executablePath=process.env.CHROMIUM_PATH;
 browser=await chromium.launch(launch);
 context=await browser.newContext({viewport:{width:1440,height:1000},locale:'en-GB',acceptDownloads:false,serviceWorkers:'block'});
 context.setDefaultTimeout(15000);context.setDefaultNavigationTimeout(15000);
 page=await context.newPage();transportDiagnostics=createBrowserTransportDiagnostics(page,browser);page.on('pageerror',()=>runtimeErrorCount++);
 await page.addInitScript(installJournalPrimaryBody,{url:base+`/api/devices/${device.deviceId}/journal/query`});
 page.on('request',request=>{if(request.url()===base+endpoint()+'/approve'&&request.method()==='POST')approveRequests++;});

 await check(0,async()=>{
  mark('require named authentication');
  expect((await context.request.get(base+endpoint())).status()).toBe(401);
  await page.goto(base+'/#/devices/'+device.deviceId);
  await page.getByLabel('Operator username',{exact:true}).fill('maintainer');
  await page.getByLabel('Operator password',{exact:true}).fill(password);
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.locator('.app-shell')).toBeVisible();
  const session=await read('/api/auth/session');expect(session.authenticated).toBe(true);expect(session.loginMode).toBe('named');expect(session.insecureTestMode).toBe(true);expect(session.capabilities).toContain('restart_service');actor=session.actorId;expect(actor).toMatch(/^operator_[a-f0-9]{32}$/);
  mark('open selected inventory service');await openServices();await status(0,0,0);expect(approveRequests).toBe(0);
  mark('review without execution');await preview();mark('assert unapproved preview zero counters');await status(0,0,0);expect(approveRequests).toBe(0);
  mark('close without execution');await review().getByRole('button',{name:'Close preview',exact:true}).click();await expect(review()).toHaveCount(0);await status(0,0,0);
  mark('escape without execution');await preview();mark('escape without execution');await review().getByRole('checkbox').check();await page.keyboard.press('Escape');await expect(review()).toHaveCount(0);await status(0,0,0);expect(approveRequests).toBe(0);await clean();
 });

 await check(1,async()=>{
  mark('refresh fixture capabilities');await control('refresh');approval=await preview();
  mark('assert fresh preview zero fixture counters');await status(0,0,0);
  mark('assert fresh preview zero approval requests');expect(approveRequests).toBe(0);
  mark('check interruption consent');await review().getByRole('checkbox',{name:'I accept the interruption risk for this exact action.',exact:true}).check();
  mark('submit exact approval');
  const capture=await page.evaluate(()=>window.__traceboltJournalBody.arm('actionApprove'));
  const [request]=await Promise.all([
   page.waitForRequest(value=>value.url()===base+endpoint()+'/approve'&&value.method()==='POST'),
   review().getByRole('button',{name:'Approve try-restart',exact:true}).click(),
  ]);
  const received=await request.response();expect(received).not.toBeNull();
  mark('assert approval HTTP status');expect(received.status()).toBe(200);
  mark('assert exact approval request');expect(received.request().postDataJSON()).toEqual(approval);
  mark('read approval response');const approved=await primaryBody(capture,request);savedJob=approved.job;
  mark('assert approved job identity');expect(savedJob.id).toBe(approval.previewId);
  mark('assert approved job actor');expect(savedJob.actorId).toBe(actor);
  mark('assert approved job unit');expect(savedJob.unit).toBe('fixture.service');
  mark('assert approved job state');expect(savedJob.state).toBe('approved');
  mark('await preview dismissal');await expect(review()).toHaveCount(0);
  mark('await approved pending label');await expect(saved()).toContainText('Approved; awaiting agent delivery. Execution is unconfirmed.');
  mark('assert approved fixture counters');await status(0,0,1,'approved');
  mark('assert single browser approval request');expect(approveRequests).toBe(1);
  mark('hold real helper protocol in fake backend');const dispatched=await control('dispatch');counters(dispatched,1,1,1);expect(dispatched.pending).toBe(true);
  await expect(saved()).toContainText('Claimed for delivery. Delivery, execution and outcome are unconfirmed until a result arrives.');
  await expect(saved()).toContainText('No automatic retry.');await expect(saved()).not.toContainText('Agent reports command completion.');await expect(selector()).toBeDisabled();
  await status(1,1,1,'claimed');const claimed=await read(endpoint());expect(claimed.job.id).toBe(savedJob.id);expect(claimed.job.state).toBe('claimed');expect(claimed.job.result).toBeNull();expect(approveRequests).toBe(1);await clean();
 });

 await check(2,async()=>{
  mark('commit real result ingress');const completed=await control('complete');counters(completed,1,1,1);expect(completed.jobState).toBe('operation_completed');
  await expect(saved()).toContainText('Agent reports command completion. Restart and service health remain unconfirmed.');await expect(saved()).toContainText('Agent-reported result: operation_completed');
  const before=await read(endpoint());expect(before.job.id).toBe(savedJob.id);expect(before.job.state).toBe('operation_completed');expect(before.job.result.phase).toBe('operation_completed');
  mark('reload durable saved action');await page.reload();await openServices();await expect(saved()).toContainText('Agent-reported result: operation_completed');await expect(saved()).toContainText('Restart and service health remain unconfirmed.');await expect(review()).toHaveCount(0);await expect(page.locator('.service-action-consent')).toHaveCount(0);
  const after=await read(endpoint());expect(after.job).toEqual(before.job);await status(1,1,1,'operation_completed');expect(approveRequests).toBe(1);await clean();
 });

 await check(3,async()=>{
  mark('repeat exact committed approval');const csrf=await read('/api/session');
  // Real authenticated requests intentionally replay only the exact preview the
  // browser already approved. Neither command permit nor envelope is exposed.
  for(let repeat=0;repeat<2;repeat++){
   const response=await context.request.post(base+endpoint()+'/approve',{headers:{Origin:base,'X-CSRF-Token':csrf.csrfToken},data:approval});expect(response.status()).toBe(200);
   const value=await body(response);expect(value.job.id).toBe(savedJob.id);expect(value.job.state).toBe('operation_completed');await status(1,1,1,'operation_completed');
  }
  mark('no second deliverable action');const idle=await control('recover');counters(idle,1,1,1);expect(idle.recoveryPeekStatus).toBe('not_found');expect(idle.pending).toBe(false);expect(idle.jobState).toBe('operation_completed');
  await page.getByRole('button',{name:'Check action status',exact:true}).click();await expect(saved()).toContainText('Agent-reported result: operation_completed');await expect(review()).toHaveCount(0);await status(1,1,1,'operation_completed');expect(approveRequests).toBe(1);await clean();
 });
}catch{
 if(!results.some(result=>result.status==='FAIL'))setupFailure=true;
 console.log(`Service-action browser stopped (${stage}); raw diagnostics withheld.`);
}finally{
 try{if(context)await context.close();}catch{setupFailure=true;}
 try{await stop();}catch{setupFailure=true;}
 try{if(browser)await browser.close();}catch{setupFailure=true;}
 transportDiagnostics?.dispose();
 try{if(temporary)await fs.rm(temporary,{recursive:true,force:true});}catch{setupFailure=true;}
 const report={schemaVersion:'tracebolt.service-action-browser.v1',sourceSha,createdAt:new Date().toISOString(),transportProfile:'disposable-http-test',fixture,scope,runtimeErrorCount,results,summary:{passed:results.filter(result=>result.status==='PASS').length,failed:results.filter(result=>result.status==='FAIL').length,setupFailure}};
 await fs.mkdir(path.dirname(out),{recursive:true});await fs.writeFile(out,JSON.stringify(report,null,2),{mode:0o600});
 process.exitCode=setupFailure||runtimeErrorCount||results.length!==names.length||results.some(result=>result.status!=='PASS')?1:0;
}
