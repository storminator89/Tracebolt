import { useCallback, useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, useOperator, validOperatorSession } from './auth';
import { useLocale } from './i18n';
import { sameSoftware } from './windows-software-jobs-types';
import { sameManagedArtifact, validManagedArtifact, validManagedReview, type ManagedArtifactView, type ManagedReview } from './windows-managed-msi-types';

const path='/windows-managed-msi/artifact';
const pending=new Map<string,{review:ManagedReview;artifactId:string}>();
const copy={en:{title:'One shared MSI',file:'Exact x64 machine MSI',review:'Package review JSON',upload:'Upload exact package',resume:'Continue exact upload',read:'Read artifact status',empty:'No package uploaded',incomplete:'Upload incomplete; only the exact bytes can resume',uploaded:'Uploaded',notice:'Up to 128 MiB. Upload does not accept terms or approve delivery or installation.',evidence:'Hashes & review evidence',unavailable:'Artifact status unavailable. Read saved status before continuing.',uncertain:'Upload response unconfirmed. Read artifact status; continue only the same reviewed bytes.',invalid:'Package, review, artifact or session is invalid or changed.'},de:{title:'Eine gemeinsame MSI',file:'Exakte x64-Geräte-MSI',review:'Paketprüfung als JSON',upload:'Exaktes Paket hochladen',resume:'Exakten Upload fortsetzen',read:'Artefaktstatus lesen',empty:'Kein Paket hochgeladen',incomplete:'Upload unvollständig; nur exakte Bytes können fortgesetzt werden',uploaded:'Hochgeladen',notice:'Höchstens 128 MiB. Hochladen akzeptiert keine Bedingungen und genehmigt weder Verteilung noch Installation.',evidence:'Hashes & Prüfnachweise',unavailable:'Artefaktstatus nicht verfügbar. Vor dem Fortfahren gespeicherten Status lesen.',uncertain:'Uploadantwort unbestätigt. Artefaktstatus lesen; nur dieselben geprüften Bytes fortsetzen.',invalid:'Paket, Prüfung, Artefakt oder Sitzung ist ungültig oder geändert.'}};
const matchesReview=(v:ManagedArtifactView,r:ManagedReview)=>!!v.package&&sameSoftware(v.package,r.package)&&v.nativeAcceptanceDigest===r.nativeAcceptanceDigest;

/** Global custody only. This session has no device delivery or installation route. */
export function ManagedMSIArtifact({actor,expires,onArtifact}:{actor:string;expires:string;onArtifact:(value:ManagedArtifactView|null)=>void}){
 const operator=useOperator(),[locale]=useLocale(),c=copy[locale],key=`${actor}:${expires}`;
 const [view,setView]=useState<ManagedArtifactView|null>(null),[file,setFile]=useState<File|null>(null),[review,setReview]=useState<ManagedReview|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const live=useRef(true),lock=useRef(false),controller=useRef<AbortController|null>(null),generation=useRef(0),current=useRef<ManagedArtifactView|null>(null),pin=useRef<ManagedArtifactView|null>(null),anchor=useRef<{server:number;mono:number;wall:number}|null>(null),onArtifactRef=useRef(onArtifact);
 onArtifactRef.current=onArtifact;
 const fresh=()=>{const a=anchor.current;if(!a)return false;const elapsed=performance.now()-a.mono;return elapsed>=0&&Math.abs(Date.now()-a.wall-elapsed)<1500&&Date.parse(expires)>a.server*1000+elapsed};
 const accept=(v:ManagedArtifactView)=>{if(pin.current&&!sameManagedArtifact(v,pin.current)||anchor.current&&v.serverNow<anchor.current.server)throw Error();if(v.package)pin.current=v;anchor.current={server:v.serverNow,mono:performance.now(),wall:Date.now()};current.current=v;setView(v);onArtifactRef.current(v)};
 const run=useCallback(async(upload:boolean)=>{
  if(lock.current||!live.current||hasLogoutIntent()||document.hidden)return;
  const old=current.current,prior=pending.get(key);
  if(upload&&(!old||!fresh()||!['empty','upload_incomplete'].includes(old.state)||!file||!review||file.size!==review.package.size||old.package!==null&&!matchesReview(old,review)||prior&&(!sameSoftware(prior.review.package,review.package)||prior.review.nativeAcceptanceDigest!==review.nativeAcceptanceDigest))){setError(c.invalid);return}
  lock.current=true;setBusy(true);setError('');const ac=new AbortController();controller.current=ac;const token=++generation.current,epoch=getProtectedRequestEpoch();let timer=window.setTimeout(()=>ac.abort(),15000);const arm=()=>{window.clearTimeout(timer);timer=window.setTimeout(()=>ac.abort(),15000)};
  const active=()=>live.current&&!ac.signal.aborted&&token===generation.current&&epoch===getProtectedRequestEpoch()&&!hasLogoutIntent()&&!document.hidden;
  try{
   if(upload){const raw=await file!.arrayBuffer(),hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');if(`sha256:${hash}`!==review!.package.sha256)throw Error()}
   const session=await request<unknown>('/auth/session',{signal:ac.signal},16384);
   if(!validOperatorSession(session)||session.mode!=='lan'||!session.authenticated||session.loginMode!=='named'||session.actorId!==actor||session.expiresAt!==expires||session.insecureTestMode||Date.parse(expires)<=Date.parse(session.serverNow)||!session.capabilities?.some(cap=>cap==='windows_managed_msi_deliver'||!upload&&cap==='windows_managed_msi_install')||!active()||upload&&!fresh())throw Error();
   let value:unknown;
   if(!upload)value=await request<unknown>(path,{signal:ac.signal},16384);
   else{
    if(pending.size>=512&&!prior)throw Error();pending.set(key,{review:review!,artifactId:prior?.artifactId??old!.artifactId});
    let progress=old!;
    if(old!.state==='empty'){arm();const reserved=await mutateRaw<unknown>(`${path}/reserve`,JSON.stringify(review),{},ac.signal,16384);if(!active()||!validManagedArtifact(reserved)||reserved.state!=='upload_incomplete'||!matchesReview(reserved,review!))throw Error();progress=reserved;accept(progress)}
    if(!matchesReview(progress,review!)||prior?.artifactId&&progress.artifactId!==prior.artifactId)throw Error();
    pending.set(key,{review:review!,artifactId:progress.artifactId});
    while(progress.uploadOffset<file!.size){
     if(!active()||!fresh())throw Error();const start=progress.uploadOffset,chunk=new Uint8Array(await file!.slice(start,Math.min(file!.size,start+32768)).arrayBuffer()),hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',chunk)),b=>b.toString(16).padStart(2,'0')).join(''),digest=`sha256:${hash}`;
     if(!active()||!fresh()||progress.uploadPendingDigest!==''&&progress.uploadPendingDigest!==digest)throw Error();arm();
     const acknowledged=await mutateRaw<unknown>(`${path}/upload`,JSON.stringify({packageDigest:review!.package.sha256,index:start/32768,digest,data:btoa(String.fromCharCode(...chunk))}),{},ac.signal,16384);
     if(!active()||!validManagedArtifact(acknowledged)||acknowledged.state!=='upload_incomplete'||acknowledged.uploadOffset!==start+chunk.length||acknowledged.uploadPendingDigest!==''||!sameManagedArtifact(acknowledged,progress))throw Error();progress=acknowledged;accept(progress);
    }
    if(!active()||!fresh())throw Error();arm();value=await mutateRaw<unknown>(`${path}/complete`,'{}',{},ac.signal,16384);
   }
   if(!active())throw Error();if(!validManagedArtifact(value)||upload&&(value.state!=='uploaded'||!matchesReview(value,review!)))throw Error();
   const intent=pending.get(key);if(intent&&value.package&&(!matchesReview(value,intent.review)||intent.artifactId&&value.artifactId!==intent.artifactId))throw Error();
   accept(value);if(value.state==='uploaded')pending.delete(key);if(pending.has(key))setError(c.uncertain);if(upload){setFile(null);setReview(null)}
  }catch{if(live.current&&token===generation.current){setError(pending.has(key)?c.uncertain:c.unavailable);current.current=null;setView(null);onArtifactRef.current(null)}}finally{window.clearTimeout(timer);if(token===generation.current){controller.current=null;lock.current=false;if(live.current)setBusy(false)}}
 },[actor,expires,key,file,review,c]);
 const runRef=useRef(run);runRef.current=run;
 useEffect(()=>{live.current=true;void runRef.current(false);const lose=()=>{generation.current++;controller.current?.abort();controller.current=null;lock.current=false;anchor.current=null;current.current=null;setView(null);setBusy(false);setFile(null);setReview(null);onArtifactRef.current(null)};const tick=window.setInterval(()=>{if(anchor.current&&!fresh())lose()},500);for(const event of ['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])window.addEventListener(event,lose);document.addEventListener('visibilitychange',lose);return()=>{live.current=false;generation.current++;controller.current?.abort();window.clearInterval(tick);for(const event of ['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])window.removeEventListener(event,lose);document.removeEventListener('visibilitychange',lose)}},[key]);
 const selected=view?.package??review?.package;
 return <section className="managed-msi-panel managed-msi-artifact" aria-label={c.title} aria-busy={busy}><h3>{c.title}</h3>{error&&<p role="alert">{error}</p>}{view&&<p role="status">{c[view.state==='upload_incomplete'?'incomplete':view.state]}</p>}{selected&&<><p><strong>{selected.name}</strong> · {selected.version} · x64 · {(selected.size/1048576).toFixed(1)} MiB</p>{view?.state==='upload_incomplete'&&<><progress aria-label={locale==='de'?'Uploadfortschritt':'Upload progress'} max={selected.size} value={view.uploadOffset}/><p>{(view.uploadOffset/1048576).toFixed(2)} / {(selected.size/1048576).toFixed(2)} MiB</p></>}<details><summary>{c.evidence}</summary><dl><dt>SHA-256</dt><dd>{selected.sha256}</dd><dt>ProductCode</dt><dd>{selected.productCode}</dd><dt>PackageCode</dt><dd>{selected.packageCode}</dd><dt>{locale==='de'?'Bedingungsprüfung':'Terms review'}</dt><dd>{selected.termsReviewDigest}</dd><dt>{locale==='de'?'Prüfverweis':'Review reference'}</dt><dd>{selected.reviewReference}</dd><dt>{locale==='de'?'Nativer Abnahmenachweis':'Native acceptance'}</dt><dd>{view?.nativeAcceptanceDigest||review?.nativeAcceptanceDigest}</dd>{view?.artifactId&&<><dt>{locale==='de'?'Artefaktkennung':'Artifact identity'}</dt><dd>{view.artifactId}</dd></>}</dl></details></>}
 {view&&view.state!=='uploaded'&&operator?.capabilities?.includes('windows_managed_msi_deliver')&&<fieldset disabled={busy}><p>{c.notice}</p><label>{c.file}<input type="file" accept=".msi" onChange={e=>{const f=e.target.files?.[0]??null;setFile(f&&f.size>=512&&f.size<=128*1048576?f:null)}}/></label><label>{c.review}<input type="file" accept=".json" onChange={async e=>{setReview(null);const f=e.target.files?.[0],token=generation.current;if(!f||f.size>4096)return;try{const value:unknown=JSON.parse(await f.text());if(live.current&&token===generation.current&&validManagedReview(value))setReview(value);else if(live.current&&token===generation.current)setError(c.invalid)}catch{if(live.current&&token===generation.current)setError(c.invalid)}}}/></label><button type="button" className="button small" disabled={!file||!review} onClick={()=>void run(true)}>{view.state==='empty'?c.upload:c.resume}</button></fieldset>}
 <button type="button" className="button small" disabled={busy} onClick={()=>void run(false)}>{c.read}</button></section>;
}
