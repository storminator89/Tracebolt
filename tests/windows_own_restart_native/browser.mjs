/** Real isolated Chromium observation only. Import is inert; fixtures cannot emit
 * native evidence. No route interception, mock server, remote browser or manual
 * result path. Production validators are compiled from the pinned application.
 */
import { createHash } from 'node:crypto';
import { readFile, lstat, realpath, open, readlink } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
export const SCHEMA='tracebolt.windows-own-restart-native.v1';
export const OMISSIONS=['graceful_worker_or_descendant_drain','native_fault_or_cancellation_timing','pending_body_signature_retry_retention','memory_only_result_retention','durable_local_consume_once_floors','original_expiry_under_inflight_request','bitwise_private_state_retention','privileged_external_races','other_service_actions','repair_upgrade_reset_reenrollment','reboot_or_os_persistence','dashboard_rendering','full_windows_parity'];
export class Refusal extends Error { constructor(reason='contract_rejected'){super(reason);this.reason=reason;} }
export function need(ok,reason='contract_rejected'){if(!ok)throw new Refusal(reason);}
export function exact(v,keys){return v!==null && typeof v==='object' && !Array.isArray(v) && Object.keys(v).length===keys.length && keys.every(k=>Object.hasOwn(v,k));}
export const hash=v=>createHash('sha256').update(v).digest('hex');
export const hex=(v,n=64)=>typeof v==='string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v) && new Set(v).size>1;
export function canonical(v){const sort=x=>Array.isArray(x)?x.map(sort):x!==null&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,sort(x[k])])):x;return JSON.stringify(sort(v)).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))+'\n';}
export function strictJSON(raw,max=131072){
 need(typeof raw==='string' && Buffer.byteLength(raw)<=max && raw.length>0,'invalid_response');let i=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(raw[i]??'\0'))i++;};
 const str=()=>{need(raw[i]==='"','invalid_response');const start=i++;while(i<raw.length){const c=raw[i++];if(c==='"'){try{return JSON.parse(raw.slice(start,i));}catch{throw new Refusal('invalid_response');}}if(c==='\\')i++;}throw new Refusal('invalid_response');};
 const value=depth=>{need(depth<64,'invalid_response');ws();const c=raw[i];
  if(c==='"')return str();
  if(c==='{'){i++;ws();const v=Object.create(null);if(raw[i]==='}'){i++;return v;}for(;;){ws();const k=str();need(!Object.hasOwn(v,k),'invalid_response');ws();need(raw[i++]===':','invalid_response');v[k]=value(depth+1);ws();const end=raw[i++];if(end==='}')return v;need(end===',','invalid_response');}}
  if(c==='['){i++;ws();const v=[];if(raw[i]===']'){i++;return v;}for(;;){v.push(value(depth+1));ws();const end=raw[i++];if(end===']')return v;need(end===',','invalid_response');}}
  const m=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(raw.slice(i));need(m,'invalid_response');i+=m[0].length;const v=JSON.parse(m[0]);need(typeof v!=='number'||Number.isFinite(v),'invalid_response');return v;
 };const v=value(0);ws();need(i===raw.length,'invalid_response');return v;
}
export function nanos(value){
 need(typeof value==='string','invalid_timestamp');const m=/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);need(m,'invalid_timestamp');
 const whole=m[1]+'Z',millis=Date.parse(whole);need(Number.isSafeInteger(millis)&&millis>0&&new Date(millis).toISOString().slice(0,19)===m[1],'invalid_timestamp');
 return BigInt(millis)*1000000n+BigInt((m[2]??'').padEnd(9,'0'));
}
export function filetimeNanos(value){need(typeof value==='string'&&/^[1-9][0-9]{0,19}$/.test(value),'invalid_timestamp');const ticks=BigInt(value);need(ticks>116444736000000000n,'invalid_timestamp');return(ticks-116444736000000000n)*100n;}
export function advancing(before,after,creation){return Number.isSafeInteger(after.sequence)&&after.sequence>before.sequence&&after.generationId!==before.generationId&&nanos(after.collectedAt)>nanos(before.collectedAt)&&nanos(after.receivedAt)>nanos(before.receivedAt)&&nanos(after.collectedAt)>filetimeNanos(creation)+1000000000n;}
export function budget(expires){const wall=Date.now(),mono=performance.now();return()=>{need(Math.abs((Date.now()-wall)-(performance.now()-mono))<=1500,'clock_changed');need(Date.now()<expires*1000,'deadline');};}
export function validateSpec(s){
 need(exact(s,['schema','plan','planSHA256','bindingSHA256','baselinePath','resultPath'])&&s.schema===SCHEMA+'.browser-spec'&&hex(s.planSHA256)&&hex(s.bindingSHA256));
 const p=s.plan;need(p?.schema===SCHEMA&&p.targetService==='TraceboltWindowsAgent'&&/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/.test(p.runId));
 need(p.sources.application.commit==='858d7846b4fa2f7b3cdaf672c067400d894369a4'&&p.sources.application.tree==='91999db7fcf6687795ba052b0029e670c01b01c7');
 need(Number.isSafeInteger(p.notBeforeUnix)&&Number.isSafeInteger(p.expiresUnix)&&p.expiresUnix-p.notBeforeUnix>=240&&p.expiresUnix-p.notBeforeUnix<=3600);
 need(Date.now()>=p.notBeforeUnix*1000&&Date.now()<p.expiresUnix*1000,'deadline');
 const w=p.targets.linux.workspace;need(resolve(w)===w&&s.baselinePath===join(w,p.runId+'-baseline.json')&&s.resultPath===join(w,p.runId+'-browser.json')&&p.handoff.linuxCompletion===join(w,p.runId+'-completion.json'));
 need(s.bindingSHA256===hash(canonical({selected:p.selected,windowsTarget:p.targets.windows.id,windowsMachineIdSHA256:p.targets.windows.machineIdSHA256,serviceSHA256:p.artifacts.service.sha256,tls:p.tls})));
 return s;
}
export function selectIdentity(list,p,validators,now=Date.now()){
 need(validators.validEnrollmentList(list,'windows')&&list.enabled,'invalid_response');
 need(Math.abs(Number(nanos(list.serverNow)/1000000n)-now)<=30000,'clock_skew');
 const rows=list.items.filter(r=>r.approval.deviceID===p.selected.deviceId);need(rows.length===1,'identity_changed');const r=rows[0];
 need(r.state==='activated'&&r.intent.deviceID===p.selected.deviceId&&r.issuance.certificateHash===p.selected.certificateSHA256&&hash(r.invitationID)===p.selected.invitationIdSHA256,'identity_changed');
 need(r.binding.instanceID===p.tls.managerInstanceId&&r.binding.origin===p.tls.operatorOrigin&&r.binding.profile==='tls'&&r.binding.collectionProfile==='windows-inventory-v1'&&r.binding.issuerFingerprint===p.tls.issuerFingerprint,'identity_changed');
 need(Number.isSafeInteger(r.intent.notBefore)&&Number.isSafeInteger(r.intent.notAfter)&&r.intent.notBefore*1000<=now&&now<r.intent.notAfter*1000,'authority_expired');
 return {deviceId:r.approval.deviceID,certificateSHA256:r.issuance.certificateHash,invitationIdSHA256:hash(r.invitationID)};
}
export function sample(view,p,validators,observed=Date.now(),elapsed=0){
 need(validators.validWindowsInventoryView(view,p.selected.deviceId)&&view.status==='fresh'&&view.snapshot,'invalid_response');
 const grantIds={};for(const name of ['events','volumes','processMetrics','network','serviceStartup','updates'])if(Object.hasOwn(view,name))grantIds[name]=view[name].grantId;
 need(canonical(grantIds)===canonical(p.selected.grantIds),'grant_changed');
 const server=nanos(view.serverNow),capture=nanos(view.snapshot.collectedAt),receipt=nanos(view.receivedAt),local=BigInt(observed)*1000000n,delay=BigInt(Math.ceil(elapsed))*1000000n;
 need(delay>=0n&&delay<=10000000000n&&server>=capture&&server-capture+delay<=120000000000n&&server>=receipt&&server-receipt+delay<=120000000000n,'stale_capture');
 need(capture-receipt<=30000000000n&&(server>local?server-local:local-server)<=30000000000n&&local-capture<=150000000000n,'clock_skew');
 for(const name of Object.keys(grantIds)){const ts=nanos(view[name].collectedAt);need(ts<=server&&server-ts+delay<=120000000000n,'stale_capture');}
 return {sequence:view.sequence,generationId:view.snapshot.generationId,collectedAt:view.snapshot.collectedAt,receivedAt:view.receivedAt,serverNow:view.serverNow,observedAt:new Date(observed).toISOString(),grantIds};
}
export function validateCompletion(c,s,baselineHash){
 const p=s.plan;need(exact(c,['schema','runId','planSHA256','sources','bindingSHA256','browserBaselineSHA256','native','fullAcceptance','omissions']));
 need(c.schema===SCHEMA+'.completion'&&c.runId===p.runId&&c.planSHA256===s.planSHA256&&canonical(c.sources)===canonical(p.sources)&&c.bindingSHA256===s.bindingSHA256&&c.browserBaselineSHA256===baselineHash&&c.fullAcceptance===false&&canonical(c.omissions)===canonical(OMISSIONS),'identity_changed');
 const n=c.native;need(exact(n,['schema','runId','planSHA256','browserBaselineSHA256','status','phase','fullAcceptance','installerContentionRefused','oldProcessExited','newRunningProcess','receiptPublicIdentityRetained','commandInvocations','oldExitCode','newProcessCreationFiletime','newProcessCreationUTC','oldProcessGenerationSHA256','newProcessGenerationSHA256','deviceId','certificateSHA256','installedSHA256','controllerSHA256','windowStartFiletime','windowEndFiletime']));
 need(n.schema==='tracebolt.windows-own-restart-controller-result.v1'&&n.runId===p.runId&&n.planSHA256===s.planSHA256&&n.browserBaselineSHA256===baselineHash&&n.status==='passed-native-subset'&&n.phase==='complete'&&n.fullAcceptance===false&&n.commandInvocations===2&&n.oldExitCode===0,'native_incomplete');
 need(['installerContentionRefused','oldProcessExited','newRunningProcess','receiptPublicIdentityRetained'].every(k=>n[k]===true),'native_incomplete');
 need(n.deviceId===p.selected.deviceId&&n.certificateSHA256===p.selected.certificateSHA256&&n.installedSHA256===p.artifacts.service.sha256&&n.controllerSHA256===p.artifacts.controller.sha256,'identity_changed');
 need(hex(n.oldProcessGenerationSHA256)&&hex(n.newProcessGenerationSHA256)&&n.oldProcessGenerationSHA256!==n.newProcessGenerationSHA256,'native_incomplete');
 const creation=filetimeNanos(n.newProcessCreationFiletime);need(creation===nanos(n.newProcessCreationUTC)&&filetimeNanos(n.windowStartFiletime)<=creation&&creation<=filetimeNanos(n.windowEndFiletime),'invalid_timestamp');return c;
}
async function noLinks(path){for(let x=path;;x=dirname(x)){need(!(await lstat(x)).isSymbolicLink(),'private_path_rejected');if(dirname(x)===x)break;}need(await realpath(path)===path,'private_path_rejected');}
async function privateRead(path,max=65536){await noLinks(path);const s=await lstat(path);need(s.isFile()&&s.nlink===1&&s.uid===process.geteuid()&&(s.mode&0o777)===0o600&&s.size>0&&s.size<=max,'private_path_rejected');const raw=await readFile(path);need(raw.length===s.size,'private_path_rejected');return raw;}
async function writeNew(path,value){const raw=canonical(value);need(Buffer.byteLength(raw)<=65536);const f=await open(path,'wx',0o600);try{await f.writeFile(raw);await f.sync();}finally{await f.close();}return hash(raw);}

export async function pinnedDependencies(root, dependencyRoot) {
  need(!Object.hasOwn(process.env, 'ESBUILD_BINARY_PATH'), 'dependency_unavailable');
  need(process.platform === 'linux' && process.arch === 'x64', 'dependency_unavailable');
  const require = createRequire(join(dependencyRoot, 'package.json'));
  const lock = JSON.parse(await readFile(join(root, 'web/package-lock.json'), 'utf8'));
  const entries = {};
  for (const name of ['esbuild', '@playwright/test', 'playwright', 'playwright-core', '@esbuild/linux-x64']) {
    const packageRoot = join(dependencyRoot, 'node_modules', name), packageFile = join(packageRoot, 'package.json');
    await noLinks(packageFile);
    const value = JSON.parse(await readFile(packageFile, 'utf8'));
    need(value.name === name && value.version === lock.packages?.[`node_modules/${name}`]?.version, 'dependency_unavailable');
    const request = name === '@esbuild/linux-x64' ? '@esbuild/linux-x64/bin/esbuild' : name;
    let entry; try { entry = require.resolve(request); } catch { throw new Refusal('dependency_unavailable'); }
    need(entry.startsWith(packageRoot + '/'), 'dependency_unavailable'); await noLinks(entry); entries[name] = entry;
  }
  // Assert transitive resolution as the packages themselves perform it, not
  // merely the top-level require: no ancestor or ambient dependency fallback.
  for (const [from, request, target] of [['@playwright/test', 'playwright/test', 'playwright'], ['playwright', 'playwright-core', 'playwright-core'], ['esbuild', '@esbuild/linux-x64/bin/esbuild', '@esbuild/linux-x64']]) {
    need(createRequire(entries[from]).resolve(request).startsWith(join(dependencyRoot, 'node_modules', target) + '/'), 'dependency_unavailable');
  }
  return require;
}
export async function loadValidators(root, dependencyRoot) {
  // Compile the real production validators in memory. No generated fixture DTOs
  // or weakened parallel wire contract can turn an invalid response into a pass.
  const require = await pinnedDependencies(root, dependencyRoot);
  const esbuild = require('esbuild');
  const source = ['windows-inventory-types', 'enrollment-types'].map(name => `export * from ${JSON.stringify(join(root, 'web/src', `${name}.ts`))};`).join('\n');
  const built = await esbuild.build({ stdin: { contents: source, resolveDir: root, loader: 'ts' }, bundle: true, write: false, platform: 'node', format: 'esm', logLevel: 'silent' });
  return import(`data:text/javascript;base64,${Buffer.from(built.outputFiles[0].text).toString('base64')}`);
}

async function managerGuard(p){
 const m=p.managerProcess,t=p.targets.linux,root='/proc/'+m.pid;
 for(const ns of ['net','mnt','user'])need(await readlink(root+'/ns/'+ns)===await readlink('/proc/self/ns/'+ns),'manager_changed');
 const statStart=raw=>{const rest=raw.slice(raw.lastIndexOf(')')+2).trim().split(/\s+/);need(!['Z','X'].includes(rest[0])&&rest[19]===m.startTicks,'manager_changed');};
 statStart(await readFile(root+'/stat','utf8'));
 const status=await readFile(root+'/status','utf8'),uid=/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m.exec(status);
 need(uid&&uid.slice(1).every(v=>Number(v)===m.uid&&Number(v)===process.geteuid()),'manager_changed');
 need(await readlink(root+'/exe')===p.artifacts.manager.path,'manager_changed');
 const args=(await readFile(root+'/cmdline')).toString('utf8');need(args===[p.artifacts.manager.path,'--lan-config',t.lanConfig,'--enrollment-config',t.enrollmentConfig,''].join('\0'),'manager_changed');
 for(const k of ['lanConfig','enrollmentConfig'])need(hash(await readFile(t[k]))===m[k+'SHA256'],'manager_changed');
 statStart(await readFile(root+'/stat','utf8'));
}
export function initialReport(s){return {schema:SCHEMA+'.browser-result',runId:s.plan.runId,planSHA256:s.planSHA256,sources:s.plan.sources,bindingSHA256:s.bindingSHA256,browserBaselineSHA256:'',completionSHA256:'',status:'blocked',reason:'browser_incomplete',nativeExecution:false,fullAcceptance:false,dashboardRendered:false,checks:{retainedManager:false,realBrowser:false,sameActivatedIdentity:false,baselineObserved:false,nativeCompletionObserved:false,twoAdvancingSamples:false,browserClosed:false},samples:[],omissions:[...OMISSIONS]};}
const NATIVE_TOKEN=Symbol('real pinned native observer');
const REAL_IO={writeNew,privateRead,managerGuard,pause:()=>new Promise(r=>setTimeout(r,1000)),emit:line=>process.stdout.write(line)};
// Source-test seams cannot acquire the unexported native token. Native main
// always supplies real pinned implementations and exposes no adapter option.
async function observe(s,report,validators,chromium,getDigest,stopped,io,nativeToken){
 const p=s.plan,checkTime=budget(p.expiresUnix);let browser,page,fatal=null,loggedIn=false;
 const guard=async()=>{checkTime();need(!stopped(),'observer_lost');if(fatal)throw fatal;await io.managerGuard(p);if(page)need(!page.isClosed()&&new URL(page.url()).origin===p.tls.operatorOrigin,'session_lost');};
 const pause=io.pause;
 const read=async path=>{
  await guard();need(path==='/api/windows/enrollment'||path===`/api/devices/${p.selected.deviceId}/windows-inventory`);const start=performance.now();
  const response=await page.evaluate(async({path,origin})=>{
   if(location.origin!==origin)return {status:0,raw:''};const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),10000);
   try{const r=await fetch(path,{method:'GET',credentials:'same-origin',cache:'no-store',redirect:'error',signal:abort.signal});if(r.status!==200)return {status:r.status,raw:''};if(!r.body||Number(r.headers.get('content-length'))>131072)return {status:0,raw:''};
    const reader=r.body.getReader(),chunks=[];let size=0;try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>131072){await reader.cancel();return {status:0,raw:''};}chunks.push(value);}}finally{reader.releaseLock();}
    const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}return {status:200,raw:new TextDecoder('utf-8',{fatal:true}).decode(raw)};
   }catch{return {status:0,raw:''};}finally{clearTimeout(timer);}
  },{path,origin:p.tls.operatorOrigin});await guard();return {...response,elapsed:performance.now()-start};
 };
 const identity=async allowLogin=>{const r=await read('/api/windows/enrollment');if(allowLogin&&[401,403].includes(r.status))return false;need(r.status===200,'session_lost');selectIdentity(strictJSON(r.raw),p,validators);return true;};
 const capture=async()=>{await identity(false);const r=await read(`/api/devices/${p.selected.deviceId}/windows-inventory`);need(r.status===200,'inventory_unavailable');const value=sample(strictJSON(r.raw),p,validators,Date.now(),r.elapsed);await identity(false);return value;};
 let timer,closing;
 const close=()=>closing??=(async()=>{if(!browser)return false;let timeout;try{return await Promise.race([browser.close().then(()=>true,()=>false),new Promise(resolve=>{timeout=setTimeout(()=>resolve(false),35000);})]);}finally{clearTimeout(timeout);}})();
 try{
  await guard();browser=await chromium.launch({executablePath:p.artifacts.chromium.path,headless:false,chromiumSandbox:true,env:Object.fromEntries(['DISPLAY','WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','HOME','TMPDIR','LANG'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]))});report.nativeExecution=nativeToken===NATIVE_TOKEN;
  const context=await browser.newContext({acceptDownloads:false,serviceWorkers:'block',ignoreHTTPSErrors:false});page=await context.newPage();page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(30000);
  page.on('request',request=>{try{const u=new URL(request.url());if(u.origin!==p.tls.operatorOrigin||(!['GET','HEAD'].includes(request.method())&&(u.pathname!=='/api/auth/login'||loggedIn)))fatal=new Refusal('unexpected_request');}catch{fatal=new Refusal('unexpected_request');}});
  context.on('page',other=>{if(other!==page){fatal=new Refusal('unexpected_page');void other.close();}});page.on('crash',()=>{fatal=new Refusal('browser_lost');});page.on('download',download=>{fatal=new Refusal('unexpected_download');void download.cancel();});
  timer=setInterval(()=>{try{checkTime();need(!stopped(),'observer_lost');}catch(e){fatal??=e;void close();}},250);
  await page.goto(p.tls.operatorOrigin+'/#/devices',{waitUntil:'domcontentloaded'});io.emit('RESTART_BROWSER_HUMAN_LOGIN\n');
  while(!await identity(true))await pause();loggedIn=true;report.checks.realBrowser=true;report.checks.sameActivatedIdentity=true;
  const baseline=await capture();report.samples.push(baseline);const record={schema:SCHEMA+(nativeToken===NATIVE_TOKEN?'.baseline':'.source-only-baseline'),runId:p.runId,planSHA256:s.planSHA256,sources:p.sources,bindingSHA256:s.bindingSHA256,managerProcess:p.managerProcess,sample:baseline,fullAcceptance:false};
  report.browserBaselineSHA256=await io.writeNew(s.baselinePath,record);report.checks.baselineObserved=true;io.emit('RESTART_BASELINE_SHA256 '+report.browserBaselineSHA256+'\n');
  let expected;
  while(!(expected=getDigest())){await guard();await identity(false);await pause();}
  need(hex(expected));const raw=await io.privateRead(p.handoff.linuxCompletion);need(hash(raw)===expected,'completion_digest_mismatch');
  const completion=validateCompletion(strictJSON(raw.toString('utf8')),s,report.browserBaselineSHA256);report.completionSHA256=expected;report.checks.nativeCompletionObserved=true;
  let before=baseline;while(report.samples.length<3){await guard();const next=await capture();if(next.sequence<before.sequence||nanos(next.collectedAt)<nanos(before.collectedAt)||nanos(next.receivedAt)<nanos(before.receivedAt))throw new Refusal('regressing_sample');
   if(advancing(before,next,completion.native.newProcessCreationFiletime)){report.samples.push(next);before=next;}await pause();}
  await guard();report.checks.twoAdvancingSamples=true;report.checks.retainedManager=true;report.status='passed-subset';report.reason='complete';
 }catch(e){report.status='unknown';report.reason=e instanceof Refusal?e.reason:'browser_incomplete';}
 finally{clearInterval(timer);report.checks.browserClosed=await close();if(!report.checks.browserClosed){report.status='unknown';report.reason='browser_cleanup_unverified';}if(fatal){report.status='unknown';report.reason=fatal.reason??'browser_incomplete';}}
 if(nativeToken!==NATIVE_TOKEN){report.schema=SCHEMA+'.source-only-browser-result';report.nativeExecution=false;if(report.status==='passed-subset'){report.status='source-only';report.reason='source_only';}}
 return report;
}
export async function observeSourceOnly(s,validators,chromium,getDigest,stopped,io){
 need(exact(io,['writeNew','privateRead','managerGuard','pause','emit'])&&Object.values(io).every(v=>typeof v==='function'));
 return observe(s,initialReport(s),validators,chromium,getDigest,stopped,io,null);
}
export function rejectCI(env){need(!Object.keys(env).some(key=>{const k=key.toUpperCase();return ['CI','CONTINUOUS_INTEGRATION','BUILD_BUILDID','TF_BUILD','TEAMCITY_VERSION','JENKINS_URL','HUDSON_URL'].includes(k)||['GITHUB_','GITLAB_','CIRCLE_','BUILDKITE_','TRAVIS_','RUNNER_'].some(p=>k.startsWith(p));}));}
async function main(){
 need(process.platform==='linux'&&process.arch==='x64'&&process.geteuid()>0&&process.argv.length===2&&process.execArgv.length===0);
 rejectCI(process.env);need(!['NODE_OPTIONS','NODE_PATH','ESBUILD_BINARY_PATH'].some(k=>Object.hasOwn(process.env,k)));
 let spec,digestValue='',closed=false,failed=false,count=0,pending=Buffer.alloc(0),resolveFirst,rejectFirst;
 const first=new Promise((resolve,reject)=>{resolveFirst=resolve;rejectFirst=reject;});
 const fail=()=>{failed=true;rejectFirst(new Refusal('invalid_input'));process.stdin.destroy();};
 process.stdin.on('data',chunk=>{try{
  need(pending.length+chunk.length<=65602,'invalid_input');pending=Buffer.concat([pending,chunk]);
  for(;;){const end=pending.indexOf(10);if(end<0){need(pending.length<=(count===0?65536:64),'invalid_input');break;}
   const bytes=pending.subarray(0,end);pending=pending.subarray(end+1);count++;
   const line=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
   if(count===1){need(bytes.length<=65536);resolveFirst(validateSpec(strictJSON(line,65536)));}
   else{need(count===2&&hex(line));digestValue=line;}
  }
 }catch{fail();}});
 const closedInput=()=>{closed=true;if(count===0)rejectFirst(new Refusal('observer_lost'));};
 process.stdin.on('end',closedInput);process.stdin.on('close',closedInput);process.stdin.on('error',fail);
 process.once('SIGINT',()=>{failed=true;});process.once('SIGTERM',()=>{failed=true;});
 spec=await first;const t=spec.plan.targets.linux;await noLinks(t.workspace);const w=await lstat(t.workspace);need(w.uid===process.geteuid()&&(w.mode&0o777)===0o700&&w.isDirectory());
 for(const name of ['node','chromium']){await noLinks(spec.plan.artifacts[name].path);need(hash(await readFile(spec.plan.artifacts[name].path))===spec.plan.artifacts[name].sha256,'artifact_mismatch');}
 need(await realpath(process.execPath)===spec.plan.artifacts.node.path,'artifact_mismatch');
 const require=await pinnedDependencies(t.sourcePaths.application.root,t.browserRoot);const validators=await loadValidators(t.sourcePaths.application.root,t.browserRoot);
 const report=await observe(spec,initialReport(spec),validators,require('playwright').chromium,()=>digestValue,()=>closed||failed,REAL_IO,NATIVE_TOKEN);
 await writeNew(spec.resultPath,report);process.stdin.destroy();process.exitCode=report.status==='passed-subset'?0:2;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{process.stdin.destroy();process.stderr.write('RESTART_BROWSER_BLOCKED\n');process.exitCode=2;});
