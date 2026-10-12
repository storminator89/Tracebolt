import { useEffect, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw, request } from './api';
import { hasLogoutIntent, useOperator, validOperatorSession } from './auth';
import { useLocale } from './i18n';
import { sameSoftware } from './windows-software-jobs-types';
import { ManagedMSIArtifact } from './windows-managed-msi-artifact';
import { ManagedMSIReviewForm, MSIReference } from './windows-managed-msi-review';
import { sameManagedArtifactOccurrence, validReusableManagedReview, type ManagedArtifactView, type ReusableManagedReview } from './windows-managed-msi-types';
import { catalogueWorklistVersion, validWorklistsView, worklistPath } from './windows-managed-msi-worklist-types';
import { managedCataloguePath, validManagedCatalogue, type ManagedCatalogueView } from './windows-managed-msi-catalogue-types';

const copy={en:{title:'Retained MSI packages',read:'Read package catalogue',choose:'Select a package to open its device worklists.',empty:'No retained packages.',storage:'Reserved manager storage',retained:'retained packages',select:'Select package',selected:'Selected package',review:'New package review JSON',reserve:'Reserve reviewed package',notice:'Up to four retained packages share 128 MiB. The complete declared size is reserved before upload. Partial and uncertain uploads keep their reservation. Each device still has one package slot.',scope:'Reservation and upload approve neither delivery nor installation. Device choices and each stage need separate explicit approval.',archiveRequired:'Archive a retired package’s active worklist before reusing its catalogue slot.',full:'Catalogue storage is full. Review eligible package cleanup separately before adding another package.',invalid:'Catalogue, package or session could not be verified. Read the catalogue before continuing.',uncertain:'Reservation response unconfirmed. Read the catalogue to reconcile this exact package; do not reserve it again.',evidence:'Catalogue references',occurrence:'Package occurrence',revision:'Catalogue revision',uploaded:'Uploaded',upload_incomplete:'Upload incomplete',retired:'Payload retired',intervention_required:'Custody requires attention'},de:{title:'Gespeicherte MSI-Pakete',read:'Paketkatalog lesen',choose:'Ein Paket auswählen, um seine Geräte-Arbeitslisten zu öffnen.',empty:'Keine gespeicherten Pakete.',storage:'Reservierter Manager-Speicher',retained:'gespeicherte Pakete',select:'Paket auswählen',selected:'Ausgewähltes Paket',review:'Neue Paketprüfung als JSON',reserve:'Geprüftes Paket reservieren',notice:'Bis zu vier gespeicherte Pakete teilen sich 128 MiB. Vor dem Upload wird die gesamte angegebene Größe reserviert. Teilweise und unbestätigte Uploads behalten ihre Reservierung. Jedes Gerät hat weiterhin einen Paketplatz.',scope:'Reservierung und Upload genehmigen weder Verteilung noch Installation. Geräteauswahl und jeder Schritt benötigen eine separate ausdrückliche Zustimmung.',archiveRequired:'Vor Wiederverwendung seines Katalogplatzes die aktive Arbeitsliste eines stillgelegten Pakets archivieren.',full:'Der Katalogspeicher ist voll. Vor einem weiteren Paket geeignete Paketbereinigung separat prüfen.',invalid:'Katalog, Paket oder Sitzung nicht verifiziert. Vor dem Fortfahren Katalog lesen.',uncertain:'Reservierungsantwort unbestätigt. Katalog zum Abgleich genau dieses Pakets lesen; nicht erneut reservieren.',evidence:'Katalogverweise',occurrence:'Paketvorkommen',revision:'Katalogrevision',uploaded:'Hochgeladen',upload_incomplete:'Upload unvollständig',retired:'Paket stillgelegt',intervention_required:'Paketspeicherung muss geprüft werden'}};
type Reservation={review:ReusableManagedReview;revision:string;occurrences:string[]};
// Uncertainty survives remount; no approval or authority is stored here.
const pending=new Map<string,Reservation>();
const matches=(entry:ManagedArtifactView,review:ReusableManagedReview)=>!!entry.package&&sameSoftware(entry.package,review.package)&&entry.nativeAcceptanceDigest===review.nativeAcceptanceDigest&&entry.publisherStatus===review.publisherStatus&&entry.publisherEvidenceDigest===review.publisherEvidenceDigest;

/** Reads the explicit manager mode before exposing either the catalogue or singleton flow. */
export function ManagedMSICatalogue({actor,expires,onArtifact,onMode}:{actor:string;expires:string;onArtifact:(value:ManagedArtifactView|null)=>void;onMode:(enabled:boolean|null)=>void}){
 const operator=useOperator(),[locale]=useLocale(),c=copy[locale],key=`${actor}:${expires}`;
 const [selectedFile,setSelectedFile]=useState<File|null>(null),[preparedFile,setPreparedFile]=useState<{occurrence:string;file:File}|null>(null);
 const [data,setData]=useState<ManagedCatalogueView|null>(null),[selected,setSelected]=useState<string|null>(null),[review,setReview]=useState<ReusableManagedReview|null>(null),[busy,setBusy]=useState(false),[ready,setReady]=useState(false),[error,setError]=useState('');
 const live=useRef(true),locked=useRef(false),generation=useRef(0),abort=useRef<AbortController|null>(null),current=useRef<ManagedCatalogueView|null>(null),anchor=useRef<{server:number;wall:number;mono:number}|null>(null),callbacks=useRef({onArtifact,onMode});callbacks.current={onArtifact,onMode};
 const fresh=()=>{const a=anchor.current;if(!a)return false;const elapsed=performance.now()-a.mono;return elapsed>=0&&Math.abs(Date.now()-a.wall-elapsed)<1500&&Date.parse(expires)>a.server*1000+elapsed};
 const run=async(reserve=false)=>{
  if(locked.current||!live.current||hasLogoutIntent()||document.hidden)return;
  const old=current.current,chosen=review,chosenFile=selectedFile;
  if(reserve&&(!old?.enabled||!chosen||!validReusableManagedReview(chosen)||!fresh()||pending.has(key)||old.entries.filter(e=>e.state!=='retired').length>=old.maxEntries||chosen.package.size>old.maxRetainedPayloadBytes-old.reservedBytes)){setError(c.invalid);return}
  locked.current=true;setBusy(true);setReady(false);setError('');callbacks.current.onArtifact(null);
  const ac=new AbortController();abort.current=ac;const token=++generation.current,epoch=getProtectedRequestEpoch(),timer=setTimeout(()=>ac.abort(),15000);
  const active=()=>live.current&&!ac.signal.aborted&&generation.current===token&&epoch===getProtectedRequestEpoch()&&!hasLogoutIntent()&&!document.hidden;
  try{
   const session=await request<unknown>('/auth/session',{signal:ac.signal},16384);
   if(!validOperatorSession(session)||session.mode!=='lan'||!session.authenticated||session.loginMode!=='named'||session.actorId!==actor||session.expiresAt!==expires||session.insecureTestMode||Date.parse(expires)<=Date.parse(session.serverNow)||!session.capabilities?.some(cap=>cap==='windows_managed_msi_deliver'||!reserve&&cap==='windows_managed_msi_install')||!active()||reserve&&!fresh())throw Error();
   let value:unknown;
   if(reserve){
    if(old!.entries.length===old!.maxEntries){
     const lists=await request<unknown>(worklistPath,{signal:ac.signal},4*1024*1024);
     if(!active()||!fresh()||!validWorklistsView(lists)||!lists.enabled||lists.version!==catalogueWorklistVersion)throw Error();
     if(!old!.entries.some(entry=>entry.state==='retired'&&!lists.worklists.some(w=>w.archivedAt===0&&w.artifactRetiredCount===entry.retiredCount))){setReady(true);callbacks.current.onMode(true);setError(c.archiveRequired);return}
    }
    if(!active()||!fresh())throw Error();
    if(pending.size>=512&&!pending.has(key))throw Error();
    pending.set(key,{review:chosen!,revision:old!.revision,occurrences:old!.entries.map(e=>e.retiredCount!)});
    value=await mutateRaw<unknown>(`${managedCataloguePath}/reserve`,JSON.stringify({revision:old!.revision,...chosen}),{},ac.signal,262144,()=>active()&&fresh());
   }else value=await request<unknown>(managedCataloguePath,{signal:ac.signal},262144);
   if(!active()||!validManagedCatalogue(value)||old&&(value.enabled!==old.enabled||BigInt(value.revision)<BigInt(old.revision))||anchor.current&&value.serverNow<anchor.current.server)throw Error();
   for(const entry of value.entries){const previous=old?.entries.find(e=>e.retiredCount===entry.retiredCount);if(previous&&!sameManagedArtifactOccurrence(entry,previous))throw Error()}
   const intent=pending.get(key);
   if(intent){const found=value.entries.filter(e=>!intent.occurrences.includes(e.retiredCount!)&&matches(e,intent.review));if(found.length===1&&BigInt(value.revision)>BigInt(intent.revision)){pending.delete(key);setSelected(found[0].retiredCount!);setReview(null);setPreparedFile(reserve&&chosenFile?{occurrence:found[0].retiredCount!,file:chosenFile}:null)}else if(reserve)throw Error()}
   current.current=value;anchor.current={server:value.serverNow,wall:Date.now(),mono:performance.now()};setData(value);setReady(true);callbacks.current.onMode(value.enabled);
   if(pending.has(key))setError(c.uncertain);
  }catch{if(live.current&&generation.current===token){setReady(false);callbacks.current.onArtifact(null);callbacks.current.onMode(null);setError(pending.has(key)?c.uncertain:c.invalid)}}finally{clearTimeout(timer);if(generation.current===token){abort.current=null;locked.current=false;if(live.current)setBusy(false)}}
 };
 const runRef=useRef(run);runRef.current=run;
 useEffect(()=>{live.current=true;void runRef.current();const lose=()=>{generation.current++;abort.current?.abort();abort.current=null;locked.current=false;anchor.current=null;setReady(false);setBusy(false);setReview(null);setSelectedFile(null);setPreparedFile(null);callbacks.current.onArtifact(null);callbacks.current.onMode(null)};const timer=setInterval(()=>{if(anchor.current&&!fresh())lose()},500);for(const event of ['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])window.addEventListener(event,lose);document.addEventListener('visibilitychange',lose);return()=>{live.current=false;generation.current++;abort.current?.abort();clearInterval(timer);for(const event of ['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])window.removeEventListener(event,lose);document.removeEventListener('visibilitychange',lose)}},[key]);
 if(ready&&data?.enabled===false)return <ManagedMSIArtifact actor={actor} expires={expires} onArtifact={onArtifact}/>;
 const entry=data?.entries.find(e=>e.retiredCount===selected),retained=data?.entries.filter(e=>e.state!=='retired').length??0,capacity=!!data&&retained<data.maxEntries&&data.reservedBytes<data.maxRetainedPayloadBytes;
 return <section className="managed-msi-catalogue" aria-label={c.title} aria-busy={busy}>
  <header><h3>{c.title}</h3><button type="button" className="button small" disabled={busy} onClick={()=>void run()}>{c.read}</button></header>
  {error&&<p role="alert">{error}</p>}
  {data?.enabled&&<><p>{c.storage}: {(data.reservedBytes/1048576).toFixed(1)} / 128 MiB · {retained} / 4 {c.retained}</p><progress aria-label={c.storage} max={data.maxRetainedPayloadBytes} value={data.reservedBytes}/><p>{c.choose}</p>
   <ul className="managed-msi-catalogue-list">{data.entries.map(item=><li key={item.retiredCount}><div><strong>{item.package!.name}</strong><small>{item.package!.version} · {(item.package!.size/1048576).toFixed(1)} MiB · {c[item.state as Exclude<ManagedArtifactView['state'],'empty'>]}</small></div><button type="button" className="button small" aria-label={`${c.select}: ${item.package!.name} ${item.package!.version} · ${item.retiredCount}`} aria-pressed={selected===item.retiredCount} disabled={busy||!ready} onClick={()=>{callbacks.current.onArtifact(null);setSelected(item.retiredCount!);setReview(null);setSelectedFile(null);setPreparedFile(null)}}>{selected===item.retiredCount?c.selected:c.select}</button></li>)}</ul>
   {!data.entries.length&&<p>{c.empty}</p>}
   <details><summary>{c.evidence}</summary><dl><dt>{c.revision}</dt><dd>{data.revision}</dd>{data.entries.map(item=><div key={item.retiredCount}><dt>{c.occurrence} {item.retiredCount}</dt><dd><MSIReference value={item.artifactId}/></dd></div>)}</dl></details>
   {operator?.capabilities?.includes('windows_managed_msi_deliver')&&<fieldset disabled={busy||!ready||pending.has(key)||!capacity}><legend>{c.reserve}</legend><ManagedMSIReviewForm key={`${generation.current}:${selected}`} reusable disabled={busy||!ready||pending.has(key)||!capacity} importLabel={c.review} onChange={(file,value)=>{setSelectedFile(file);setReview(value&&validReusableManagedReview(value)?value:null)}}/>{review&&<p>{review.package.name} · {review.package.version} · {(review.package.size/1048576).toFixed(1)} MiB</p>}<button type="button" className="button small" disabled={!review||review.package.size>data.maxRetainedPayloadBytes-data.reservedBytes} onClick={()=>void run(true)}>{c.reserve}</button></fieldset>}
   {!capacity&&<p>{c.full}</p>}<details><summary>{locale==='de'?'Speicher & Genehmigungen':'Storage & approvals'}</summary><p>{c.notice}</p><p>{c.scope}</p></details>
   {ready&&entry&&<ManagedMSIArtifact key={`${key}:${entry.retiredCount}:${generation.current}`} actor={actor} expires={expires} catalogueEntry={entry} preparedFile={preparedFile&&preparedFile.occurrence===entry.retiredCount?preparedFile.file:undefined} onArtifact={value=>{callbacks.current.onArtifact(value);if(value&&value.state!==entry.state)void runRef.current()}}/>}
  </>}
 </section>;
}
